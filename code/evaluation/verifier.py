"""Independent verifier: checks every prediction against the raw evidence text.

Independence: this module imports nothing from the predictor's decision code
(ghost_audit.audit / planner / policy / intent / parsers). It re-derives identifiers from
user_identities.csv + user_audit_log.csv itself, reads raw file text itself (pdftotext /
tesseract for binaries, cached under its own key), locates the cited record context by
plain text search, and applies its own token rules and its own treatment table.

Shared assumptions with the predictor (documented, not hidden):
  * email_hash = sha256(lower(email))      * resource-id prefixes name the owning system
  * OCR output of the same Tesseract binary * deletion_rules.csv is the policy of record
"""
from __future__ import annotations

import csv
import hashlib
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def ts(v):
    if not v:
        return None
    return datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(timezone.utc)


ALLOWED = {  # prefix -> remediation operations a correct plan may use
    "account_": {"DELETE_RECORD"}, "search_": {"DELETE_RECORD"}, "export_": {"DELETE_RECORD"},
    "object_": {"DELETE_RECORD"}, "marketing_": {"DELETE_RECORD"}, "cache_": {"DELETE_RECORD"},
    "support_": {"DELETE_RECORD", "REDACT_RECORD"}, "analytics_": {"ANONYMIZE_RECORD", "DELETE_RECORD"},
    "email_delivery_": {"REDACT_RECORD"}, "tombstone_": {"REDACT_RECORD"},
    "data_flow_": {"DISABLE_DATA_FLOW"}, "backup_": {"BLOCK_RESTORE"},
    "audit_record_": {"DELETE_RECORD"},   # only when retention expired (checked below)
    "legal_hold_": {"DELETE_RECORD"},     # only when hold expired (checked below)
}
FIND_TO_REM = {"REPORT_ACTIVE_DATA_FLOW": {"DISABLE_DATA_FLOW"}, "REPORT_RESTORE_RISK": {"BLOCK_RESTORE"},
               "REPORT_REMAINING_RECORD": {"DELETE_RECORD"},
               "REPORT_EXPOSED_PII": {"REDACT_RECORD", "ANONYMIZE_RECORD"}}
REM_TO_VER = {"DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED", "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
              "DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
              "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED"}

# Token rules run on a normalised context: quotes/backslashes removed, "k": v -> k=v
ABSENT_TOK = re.compile(r"http_status=404|status_code=404|result=NOT_FOUND|\| NOT_FOUND|rows=0\b|profile=null")
PRESENT_TOK = re.compile(r"rows=[1-9]|result=hit|result=(FOUND|IDENTIFIABLE|ACTIVE|REDACTED|ANONYMIZED|BLOCKED|DISABLED)|"
                         r"\| (FOUND|IDENTIFIABLE|ACTIVE|REDACTED|ANONYMIZED|BLOCKED|DISABLED)\b|available=true|"
                         r"marker_found=false|INSERT INTO|_read_completed|_pii_scan|identity_scan|message_read|"
                         r"connector_heartbeat|restore_candidate_evaluated|restore_authorization_completed|"
                         r"status_code=200|resource_id=|repopulated")
FLOW_ON = re.compile(r"enabled=(true|1)\b|result=ACTIVE|DATA_FLOW \| ACTIVE|Continuous|remains enabled|"
                     r"'1', '(delivered|stopped)'|,'1','delivered'", re.I)
FLOW_OFF = re.compile(r"enabled=(false|0)\b|result=DISABLED|DATA_FLOW \| DISABLED|stopped", re.I)
RESTORE_ON = re.compile(r"restore_allowed=(true|1)\b|eligible=true|result=ACTIVE|BACKUP_ARCHIVE \| ACTIVE|"
                        r"'1', '20|can still be restored", re.I)
RESTORE_OFF = re.compile(r"restore_allowed=(false|0)\b|decision=deny|result=BLOCKED|BACKUP_ARCHIVE \| BLOCKED|"
                         r"'0', '20", re.I)


def norm(ctx: str) -> str:
    c = ctx.replace('\\"', '"')
    c = re.sub(r'"([\w.]+)":\s*', r"\1=", c)
    return c.replace('"', "")


class Verifier:
    def __init__(self, dataset: Path, cache_dir: Path):
        self.dataset = dataset
        self.cache_dir = cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.files = {r["file_id"]: r for r in csv.DictReader(open(dataset / "evidence_files.csv", encoding="utf-8"))}
        self.acts = {r["activity_id"]: r for r in csv.DictReader(open(dataset / "system_activity.csv", encoding="utf-8"))}
        self.audits = {}
        self.ids = defaultdict(set)    # user_id -> identifier strings (lower)
        self.names = {}
        self.email_user = defaultdict(set)
        for r in csv.DictReader(open(dataset / "user_identities.csv", encoding="utf-8")):
            u = r["user_id"]
            self.names[u] = r["name"]
            self._add(u, r["email"])
            self._add(u, r["phone"])
            self.ids[u].add(r["email_hash"].lower())
        ap = dataset / "user_audit_log.csv"
        if ap.exists():
            for r in csv.DictReader(open(ap, encoding="utf-8")):
                self.audits[r["audit_id"]] = r
                for v in (r["old_value"], r["new_value"]):
                    if v:
                        self._add(r["user_id"], v)
        self._text = {}

    def _add(self, u, v):
        v = v.strip()
        if "@" in v:
            self.ids[u].add(v.lower())
            self.ids[u].add(hashlib.sha256(v.lower().encode()).hexdigest())
            self.email_user[v.lower()].add(u)
        elif re.fullmatch(r"[0-9a-f]{64}", v.lower()):
            self.ids[u].add(v.lower())
        else:
            d = re.sub(r"\D", "", v)
            if len(d) >= 7:
                self.ids[u].add("tel:" + d)
        self.ids[u].add(u)

    # -------------------------------------------------------------- raw text
    def text(self, fid: str) -> str:
        if fid in self._text:
            return self._text[fid]
        meta = self.files.get(fid)
        if not meta:
            return ""
        p = self.dataset / meta["file_path"]
        if not p.exists():
            self._text[fid] = ""
            return ""
        key = hashlib.sha256(p.read_bytes()).hexdigest()[:24] + "_verifier_v2.txt"
        c = self.cache_dir / key
        if c.exists():
            t = c.read_text(encoding="utf-8")
        elif p.suffix == ".pdf":
            t = subprocess.run(["pdftotext", "-layout", str(p), "-"], capture_output=True, text=True).stdout
            c.write_text(t, encoding="utf-8")
        elif p.suffix == ".png":
            # two independent readings: the default pass and the verifier's own x2-upscaled, uniform-block pass
            # (small table rows are dropped by the default pass alone); only the Tesseract binary is shared
            t = subprocess.run(["tesseract", str(p), "-"], capture_output=True, text=True).stdout
            try:
                from PIL import Image
                import tempfile as _tf
                im = Image.open(p).convert("L")
                im = im.resize((im.width * 2, im.height * 2))
                with _tf.TemporaryDirectory() as td:
                    q = Path(td) / "v.png"
                    im.save(q)
                    t2 = subprocess.run(["tesseract", str(q), "-", "--psm", "6"], capture_output=True, text=True).stdout
                t = t + "\n----- verifier second reading (x2, psm 6) -----\n" + t2
            except (OSError, ImportError):
                pass
            c.write_text(t, encoding="utf-8")
        else:
            t = p.read_text(encoding="utf-8", errors="replace")
        self._text[fid] = t
        return t

    def contexts(self, fid: str, rid: str) -> list:
        """Every record context mentioning rid: log line + its trace, JSON object, SQL row, text line."""
        t = self.text(fid)
        out = []
        pat = re.compile(re.escape(rid) + r"(?![0-9])")
        lines = t.splitlines()
        for i, line in enumerate(lines):
            if not pat.search(line):
                continue
            ctx = line
            m = re.search(r"(?:trace_id[=\":]+|\[|requestId=| \| )\"?((?:tr|rb)-[\w-]+)", line)
            if m:
                tid = m.group(1)
                ctx = "\n".join(l for l in lines if tid in l)
            elif fid and self.files[fid]["file_path"].endswith(".json"):
                # enclosing JSON object: walk back to the line opening this record
                j = i
                while j > 0 and not re.match(r"^\s*\{\s*$", lines[j]):
                    j -= 1
                k = i
                depth = 0
                for k in range(j, len(lines)):
                    depth += lines[k].count("{") - lines[k].count("}")
                    if depth <= 0 and k > j:
                        break
                ctx = "\n".join(lines[j:k + 1])
            elif self.files[fid]["file_path"].endswith(".pdf"):
                ctx = "\n".join(lines)
            elif self.files[fid]["file_path"].endswith(".png"):
                # a screen row asserts ownership on its own line; a page-level subject filter applies to all
                # rows. Other text on the page (detail panels, other rows) is not this row's context.
                ctx = "\n".join([line] + [l for l in lines if re.search(r"subject filter", l, re.I)])
            out.append(ctx)
        return out

    def subject_in(self, ctx: str, uid: str) -> bool:
        low = ctx.lower()
        digits = re.sub(r"\D", "", ctx)
        for v in self.ids[uid]:
            if v.startswith("tel:"):
                if len(v) > 11 and v[4:] in digits:
                    return True
            elif re.search(r"(?<![\w.])" + re.escape(v) + r"(?![\w])", low):
                if v.startswith("user_") and not re.search(re.escape(v) + r"(?!\d)", low):
                    continue
                return True
        name = self.names.get(uid, "")
        return bool(name) and name.lower() in low

    # -------------------------------------------------------------- occurrence index
    TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
    RID_RE = re.compile(r"\b(?:account|search|support|analytics|export|backup|data_flow|audit_record|tombstone|"
                        r"legal_hold|marketing|object|email_delivery)_\d+\b")

    def occurrences(self) -> dict:
        """rid -> [(file_id, capture time, record time, normalised context)] over every evidence file."""
        if hasattr(self, "_occ"):
            return self._occ
        occ = defaultdict(list)
        for fid, meta in self.files.items():
            cap = ts(meta["captured_at"])
            t = self.text(fid)
            for rid in sorted(set(self.RID_RE.findall(t))):
                for ctx in self.contexts(fid, rid):
                    first = ctx.strip().splitlines()[0] if ctx.strip() else ""
                    m = re.match(r"^\s*-?\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", first)
                    if not m:
                        m = re.search(r"\"?(?:observed_at|recorded_at|updated_at)\"?[=:]\s*\"?(\d{4}-\d{2}-\d{2}T"
                                      r"\d{2}:\d{2}:\d{2}Z)", ctx)
                    rec_t = ts(m.group(1)) if m else cap
                    occ[rid].append((fid, cap, rec_t, norm(ctx)))
        for a in self.acts.values():
            for rid in set(self.RID_RE.findall(a["resource_id"] + " " + a["details"])):
                occ[rid].append((a["activity_id"], ts(a["event_time"]), ts(a["event_time"]),
                                 a["event_type"] + " " + a["details"]))
        self._occ = occ
        return occ

    def discoverable(self, rid: str, cut) -> bool:
        return any(cap <= cut and (rt is None or rt <= cut) for _, cap, rt, _ in self.occurrences().get(rid, []))

    def users_named(self, ctx: str) -> set:
        low = ctx.lower()
        out = set(re.findall(r"\buser_\d+\b", low))
        for e in re.findall(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", low):
            out |= self.email_user.get(e, set())
        return out

    @staticmethod
    def canonical_order_ok(steps: list) -> bool:
        order = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
                 "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
                 "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
                 "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
        keys = [(order.index(s["operation"]), s["system_id"], s["resource_id"]) for s in steps]
        return keys == sorted(keys) and [s["step_no"] for s in steps] == list(range(1, len(steps) + 1))

    # -------------------------------------------------------------- checks
    def verify(self, requests: list, predictions: dict) -> dict:
        report = defaultdict(list)
        stats = defaultdict(int)
        for q in requests:
            cid = q["case_id"]
            if cid not in predictions:
                report["missing_prediction"].append(cid)
                continue
            status, steps = predictions[cid]
            audit_at, req_at = ts(q["audit_at"]), ts(q["requested_at"])
            users = self.email_user.get(q["email"].lower(), set())
            uid = sorted(users)[0] if users else None
            if status == "NOT_APPLICABLE":
                stats["not_applicable"] += 1
                continue
            phases = [s["phase"] for s in steps]
            if status == "COMPLETE" and any(p != "VERIFICATION" for p in phases):
                report["complete_with_findings"].append(cid)
            if status == "COMPLETE" and (not steps or any(not s["evidence_id"] for s in steps)):
                report["complete_with_unsupported_verification"].append(cid)
            if status == "INCOMPLETE" and not steps:
                report["incomplete_empty_plan"].append(cid)
            elif status == "INCOMPLETE" and "FINDING" not in phases:
                # verification-only plan: no supported violation, but completion not proven either
                report["incomplete_without_findings"].append(cid)
            if steps and not self.canonical_order_ok(steps):
                report["noncanonical_order_or_numbering"].append(cid)
            planned = {s["resource_id"] for s in steps}
            for rid in sorted(planned):
                if not self.discoverable(rid, audit_at):
                    report["resource_not_discoverable_by_audit_at"].append(f"{cid}:{rid}")
            if uid:
                self._coverage_checks(cid, uid, status, steps, req_at, audit_at, report, stats)
            rem = [s for s in steps if s["phase"] == "REMEDIATION"]
            seen_record_op = False
            for s in rem:
                if s["operation"] in ("DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"):
                    seen_record_op = True
                elif seen_record_op:
                    report["recreation_path_after_record_treatment"].append(cid)
            for s in steps:
                rid, op, ev = s["resource_id"], s["operation"], s["evidence_id"]
                prefix = next((p for p in ALLOWED if rid.startswith(p)), None)
                if s["phase"] == "REMEDIATION":
                    if prefix and op not in ALLOWED[prefix]:
                        report["policy_disallowed_treatment"].append(f"{cid}:{rid}:{op}")
                    if prefix in ("audit_record_", "legal_hold_") and op == "DELETE_RECORD":
                        # must be justified by an expired retention date in some cited finding
                        f = [x for x in steps if x["resource_id"] == rid and x["phase"] == "FINDING"]
                        ok = False
                        for x in f:
                            for ctx in self.contexts(x["evidence_id"], rid):
                                for d in re.findall(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", ctx):
                                    if "retention" in ctx.lower() or "retain" in ctx.lower():
                                        ok = ok or ts(d) < audit_at
                        if not ok:
                            report["retention_violation"].append(f"{cid}:{rid}")
                if s["phase"] == "FINDING":
                    rems = {x["operation"] for x in rem if x["resource_id"] == rid}
                    if not (rems & FIND_TO_REM[op]):
                        report["finding_without_matching_remediation"].append(f"{cid}:{rid}")
                if s["phase"] == "REMEDIATION" and status == "INCOMPLETE":
                    vers = {x["operation"] for x in steps if x["phase"] == "VERIFICATION" and x["resource_id"] == rid}
                    if REM_TO_VER[op] not in vers:
                        report["remediation_without_verification"].append(f"{cid}:{rid}")
                if not ev:
                    continue
                stats["cited_steps"] += 1
                # existence + temporal eligibility
                if ev.startswith("evidence_"):
                    meta = self.files.get(ev)
                    if not meta:
                        report["unknown_evidence"].append(f"{cid}:{ev}")
                        continue
                    if ts(meta["captured_at"]) > audit_at:
                        report["future_evidence_cited"].append(f"{cid}:{ev}")
                    ctxs = self.contexts(ev, rid)
                elif ev.startswith("activity_"):
                    a = self.acts.get(ev)
                    if not a:
                        report["unknown_evidence"].append(f"{cid}:{ev}")
                        continue
                    if ts(a["event_time"]) > audit_at:
                        report["future_evidence_cited"].append(f"{cid}:{ev}")
                    ctxs = [a["details"] + " " + a["resource_id"]] if rid in a["details"] or rid == a["resource_id"] else []
                else:
                    ctxs = []
                if not ctxs:
                    # absence proven by a complete capture that covers the subject: a replica dump
                    # (topology header), or a JSON bundle holding exactly one capture of that collection
                    if op == "VERIFY_RECORD_ABSENT" and ev.startswith("evidence_"):
                        full = self.text(ev)
                        ok_capture = False
                        if "Database topology" in full and "snapshot_scope" not in full:
                            ok_capture = True
                        elif '"snapshots"' in full:
                            stores = re.findall(r'"data_store":\s*"([a-z_]+)",\s*"collection":\s*"([a-z_]+)"', full)
                            sysname = next((p for p in ("account_service", "search_service", "analytics_platform",
                                                        "support_platform", "export_service", "identity_service")
                                            if rid.split("_")[0] in p), None)
                            same = [x for x in stores if x[0] == sysname]
                            ok_capture = len(same) == 1 and bool(uid and self.subject_in(full, uid))
                        if ok_capture:
                            stats["absence_by_capture"] += 1
                            continue
                        report["absence_from_partial_capture"].append(f"{cid}:{rid}:{ev}")
                        continue
                    # catalog alias (document cites a business reference rather than the id)
                    alias_ok = False
                    for a in self.acts.values():
                        if a["event_type"] == "LINK_RESOURCE_IDENTITY" and a["resource_id"] == rid:
                            m = re.search(r"\(([^)]*)\)", a["details"])
                            if m and m.group(1).lower() in self.text(ev).lower():
                                alias_ok = True
                                ctxs = [self.text(ev)]
                    if not alias_ok:
                        report["citation_does_not_mention_resource"].append(f"{cid}:{rid}:{ev}")
                        continue
                ctx = norm("\n".join(ctxs))
                ok = True
                if op in ("REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "VERIFY_RECORD_PRESENT"):
                    ok = bool(PRESENT_TOK.search(ctx) or "repopulated" in ctx or ev.startswith("evidence_") and
                              self.files[ev]["file_path"].endswith((".png", ".pdf"))) and not (
                        ABSENT_TOK.search(ctx) and not PRESENT_TOK.search(ctx))
                elif op == "VERIFY_RECORD_ABSENT":
                    ok = bool(ABSENT_TOK.search(ctx))
                elif op == "REPORT_ACTIVE_DATA_FLOW":
                    ok = bool(FLOW_ON.search(ctx))
                elif op == "VERIFY_DATA_FLOW_DISABLED":
                    ok = bool(FLOW_OFF.search(ctx))
                elif op == "REPORT_RESTORE_RISK":
                    ok = bool(RESTORE_ON.search(ctx)) or self.files.get(ev, {}).get("file_path", "").endswith(".png")
                elif op == "VERIFY_RESTORE_BLOCKED":
                    ok = bool(RESTORE_OFF.search(ctx))
                elif op in ("VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED"):
                    ok = not (uid and self.subject_in(ctx.replace(uid, ""), uid)) and "IDENTIFIABLE" not in ctx
                if op == "REPORT_EXPOSED_PII":
                    ok = ok and (bool(uid and self.subject_in(ctx, uid)) or "IDENTIFIABLE" in ctx
                                 or "direct_identifiers=\"1\"" in ctx or "matched_value" in ctx)
                if not ok:
                    report["state_not_supported_by_citation"].append(f"{cid}:{rid}:{op}:{ev}")
                else:
                    stats["supported_cited_steps"] += 1
                named = self.users_named(ctx)
                if uid and named and uid not in named and not self.subject_in(ctx, uid):
                    report["context_names_other_subject"].append(f"{cid}:{rid}:{ev}")
                # subject link: the cited context should name the subject (or the catalog does)
                if uid and not self.subject_in(ctx, uid):
                    linked = any(a["event_type"] == "LINK_RESOURCE_IDENTITY" and a["resource_id"] == rid
                                 and uid in a["details"] for a in self.acts.values())
                    if not linked:
                        stats["cited_without_subject_identifier"] += 1
        return {"issues": {k: v for k, v in report.items()}, "stats": dict(stats)}

    def _coverage_checks(self, cid, uid, status, steps, req_at, audit_at, report, stats):
        """What a correct answer must contain, derived independently from admissible raw text."""
        ops = defaultdict(set)
        for s_ in steps:
            ops[s_["resource_id"]].add(s_["operation"])
        latest = {}
        for rid, occ in self.occurrences().items():
            if not rid.startswith(("audit_record_", "legal_hold_", "data_flow_", "backup_", "account_")):
                continue
            for fid, cap, rt, ctx in occ:
                if cap > audit_at or (rt and rt > audit_at) or not fid.startswith("evidence_"):
                    continue
                if not self.subject_in(ctx, uid):
                    continue
                if rid not in latest or (rt or cap) > latest[rid][0]:
                    latest[rid] = (rt or cap, fid, ctx)
        for rid, (t, fid, ctx) in latest.items():
            if rid.startswith(("audit_record_", "legal_hold_")):
                dates = [ts(d) for d in re.findall(r"(?:retention_until|retained_until)=(\d{4}-\d{2}-\d{2}T[\d:]+Z)", ctx)]
                if dates and all(d < audit_at for d in dates):
                    continue
                if "VERIFY_RECORD_PRESENT" not in ops.get(rid, set()):
                    report["missing_retained_record"].append(f"{cid}:{rid}:{fid}")
            elif rid.startswith(("data_flow_", "backup_")):
                if rid.startswith("data_flow_"):
                    explicit = re.findall(r"\benabled=(true|false|1|0)\b", ctx, re.I)
                    on = explicit[-1].lower() in ("true", "1") if explicit else bool(FLOW_ON.search(ctx)) and not FLOW_OFF.search(ctx)
                else:
                    explicit = re.findall(r"\brestore_allowed=(true|false|1|0)\b", ctx, re.I)
                    on = explicit[-1].lower() in ("true", "1") if explicit else bool(RESTORE_ON.search(ctx)) and not RESTORE_OFF.search(ctx)
                later_claim = any(a["resource_id"] == rid and a["source_system"] == "deletion_worker"
                                  and t < ts(a["event_time"]) <= audit_at for a in self.acts.values())
                if on and not later_claim and t >= req_at and not (ops.get(rid, set()) & {"REPORT_ACTIVE_DATA_FLOW",
                                                                                          "REPORT_RESTORE_RISK"}):
                    report["missing_recreation_risk"].append(f"{cid}:{rid}:{fid}")
            elif rid.startswith("account_") and status == "COMPLETE":
                if not any(s_["resource_id"] == rid and s_["evidence_id"] for s_ in steps):
                    report["complete_without_account_proof"].append(f"{cid}:{rid}:{fid}")
        if status == "COMPLETE" and not any(s_["system_id"] == "account_service" for s_ in steps):
            stats["complete_account_not_verified"] += 1

    def _false_complete_scan(self, cid, uid, req_at, audit_at, steps, report):
        """Independent presence sweep: any admissible line naming the subject next to a positive
        presence marker for a resource that the COMPLETE answer does not account for."""
        if not uid:
            return
        covered = {s["resource_id"] for s in steps}
        for fid, meta in self.files.items():
            if ts(meta["captured_at"]) > audit_at:
                continue
            p = self.dataset / meta["file_path"]
            if p.suffix not in (".log", ".txt"):
                continue
            for line in self.text(fid).splitlines():
                m = re.match(r"^\s*-?\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", line)
                if not m or not (req_at <= ts(m.group(1)) <= audit_at):
                    continue
                if not self.subject_in(line, uid):
                    continue
                if re.search(r"result=\"?hit|IDENTIFIABLE|\| FOUND|enabled=true|restore_allowed=true", line) and \
                        "SECURITY_AUDIT_LOG" not in line and "LEGAL_HOLD" not in line:
                    rids = re.findall(r"\b(?:search|support|analytics|export|data_flow|backup|account|tombstone)_\d+", line)
                    for rid in rids:
                        if rid not in covered:
                            report["possible_false_complete"].append(f"{cid}:{rid}:{fid}")
