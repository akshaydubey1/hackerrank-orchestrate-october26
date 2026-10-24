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
        key = hashlib.sha256(p.read_bytes()).hexdigest()[:24] + "_verifier_v1.txt"
        c = self.cache_dir / key
        if c.exists():
            t = c.read_text(encoding="utf-8")
        elif p.suffix == ".pdf":
            t = subprocess.run(["pdftotext", "-layout", str(p), "-"], capture_output=True, text=True).stdout
            c.write_text(t, encoding="utf-8")
        elif p.suffix == ".png":
            t = subprocess.run(["tesseract", str(p), "-"], capture_output=True, text=True).stdout
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
            elif self.files[fid]["file_path"].endswith((".png", ".pdf")):
                ctx = "\n".join(lines)
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
                    # absence proven by a complete capture that covers the subject
                    if op == "VERIFY_RECORD_ABSENT" and ev.startswith("evidence_"):
                        full = self.text(ev)
                        if ("Database topology" in full or "snapshots" in full) and \
                                (uid and (self.subject_in(full, uid) or "customer_profiles" in full)):
                            stats["absence_by_capture"] += 1
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
                # subject link: the cited context should name the subject (or the catalog does)
                if uid and not self.subject_in(ctx, uid):
                    linked = any(a["event_type"] == "LINK_RESOURCE_IDENTITY" and a["resource_id"] == rid
                                 and uid in a["details"] for a in self.acts.values())
                    if not linked:
                        stats["cited_without_subject_identifier"] += 1
            if status == "COMPLETE":
                self._false_complete_scan(cid, uid, req_at, audit_at, steps, report)
        return {"issues": {k: v for k, v in report.items()}, "stats": dict(stats)}

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
