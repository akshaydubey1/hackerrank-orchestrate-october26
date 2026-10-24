"""Evaluation harness.

    python3 code/evaluation/main.py            # full suite, writes code/evaluation/evaluation_report.md
    python3 code/evaluation/main.py --quick    # samples + fixtures + verifier only

Sections (reported separately on purpose):
  A. public samples (sample-tuned: the predictor was developed while looking at these)
  B. independent synthetic fixtures with hand-written expectations
  C. metamorphic tests on the real dataset (meaning-preserving + deliberate semantic changes)
  D. mutation testing of the suite itself
  E. independent verifier over the final 518-case output
Sample answers are only read here, after prediction; the predictor never sees them.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import io
import json
import random
import re
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
ROOT = CODE.parent
sys.path.insert(0, str(CODE))

from evaluation import fixtures  # noqa: E402
from evaluation.verifier import Verifier  # noqa: E402
from ghost_audit.pipeline import Engine, read_requests  # noqa: E402

DATASET = ROOT / "dataset"
KEYS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


# ---------------------------------------------------------------------------- helpers
def run_engine(dataset: Path, requests_file: str = "deletion_requests.csv", extra_pools=(), cache=True,
               requests=None):
    eng = Engine(dataset, (CODE / ".cache") if cache else None)
    reqs = requests if requests is not None else read_requests(dataset / requests_file)
    # each request is audited on its own: no cross-request pools (extra_pools kept for API compatibility)
    results = eng.run(reqs)
    eng.last_results = results
    return {r.case_id: (r.status, r.steps) for r in results}, eng


def tup(s):
    return tuple(s[k] for k in KEYS)


def score(pred: dict, gold: dict) -> dict:
    n = len(gold)
    status_ok = sum(pred[c][0] == g[0] for c, g in gold.items())
    tp = fp = fn = 0
    exact = 0
    field_tot = defaultdict(int)
    field_ok = defaultdict(int)
    cite_tot = cite_ok = 0
    false_complete = []
    false_incomplete = []
    for c, (gs, gsteps) in gold.items():
        ps, psteps = pred[c]
        P, G = [tup(s) for s in psteps], [tup(s) for s in gsteps]
        Pc, Gc = Counter(P), Counter(G)
        tp += sum((Pc & Gc).values())
        fp += sum((Pc - Gc).values())
        fn += sum((Gc - Pc).values())
        exact += ps == gs and P == G
        if ps == "COMPLETE" and gs == "INCOMPLETE":
            false_complete.append(c)
        if ps == "INCOMPLETE" and gs == "COMPLETE":
            false_incomplete.append(c)
        # field-level: align gold steps to predicted steps on (system_id, resource_id, phase)
        pidx = {(s["phase"], s["system_id"], s["resource_id"]): s for s in psteps}
        for g in gsteps:
            p = pidx.get((g["phase"], g["system_id"], g["resource_id"]))
            for k in ("system_id", "resource_id", "operation", "state", "evidence_id", "step_no"):
                field_tot[k] += 1
                field_ok[k] += bool(p) and p[k] == g[k]
            if g["evidence_id"]:
                cite_tot += 1
                cite_ok += bool(p) and p["evidence_id"] == g["evidence_id"]
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {"cases": n, "status_accuracy": status_ok / n, "status_correct": status_ok,
            "step_precision": prec, "step_recall": rec,
            "step_f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "tp": tp, "fp": fp, "fn": fn, "exact_sequence": exact / n, "exact_sequence_n": exact,
            "field_accuracy": {k: field_ok[k] / field_tot[k] for k in field_tot},
            "citation_accuracy": cite_ok / cite_tot if cite_tot else 1.0,
            "false_complete": false_complete, "false_incomplete": false_incomplete}


def load_gold(path: Path) -> dict:
    return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
            for r in csv.DictReader(open(path, encoding="utf-8"))}


def copy_dataset(dst: Path) -> Path:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(DATASET, dst, ignore=shutil.ignore_patterns("sample_output.csv", "output.csv"))
    return dst


def rewrite_csv(path: Path, fn):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    fields = list(rows[0].keys()) if rows else open(path).readline().strip().split(",")
    rows = fn(rows)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------- B. fixtures
def run_fixtures(cache=False) -> list:
    root = Path(tempfile.mkdtemp(prefix="ghost_fx_")) / "data"
    exp = fixtures.build(root)
    eng = Engine(root, None)
    reqs = read_requests(root / "deletion_requests.csv")
    results = []
    failures_expected = exp.pop("__extraction_failures__", set())
    got_failures = {f for f, _ in eng.store.failures}
    results.append(("fx_extraction_failures_recorded", failures_expected <= got_failures,
                    f"recorded={sorted(got_failures)}"))
    for r in eng.run(reqs):
        x = exp[r.case_id]
        k = lambda s: (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["evidence_id"])
        ok = ("status" not in x or r.status == x["status"]) and r.status in x.get("status_in", [r.status])
        if "steps" in x:
            ok = ok and [k(s) for s in r.steps] == [k(s) for s in x["steps"]]
        for m in x.get("must_include", []):
            ok = ok and k(m) in {k(s) for s in r.steps}
        if x.get("must_have_unresolved"):
            ok = ok and any(x["must_have_unresolved"] in json.dumps(u) for u in r.unresolved)
        for rid in x.get("must_exclude_resources", []):
            ok = ok and not any(s["resource_id"] == rid for s in r.steps)
        for rid in x.get("must_not_cite", []):
            ok = ok and not any(s["resource_id"] == rid and s["evidence_id"] for s in r.steps)
        for sysid, rid, op in x.get("must_exclude_ops", []):
            ok = ok and not any(s["system_id"] == sysid and s["resource_id"] == rid and s["operation"] == op
                                for s in r.steps)
        results.append((r.case_id, ok, f"{r.status} {len(r.steps)} steps"))
    shutil.rmtree(root.parent, ignore_errors=True)
    return results


# ---------------------------------------------------------------------------- C. metamorphic
PARAPHRASE_DEL = [
    "Kindly erase my account together with every piece of personal data tied to it.",
    "I want this account deleted for good, along with my personal information.",
    "Por favor eliminen mi cuenta y todos mis datos personales.",
    "Bitte löschen Sie mein Konto und alle damit verbundenen Daten.",
    "Veuillez supprimer mon compte et mes données personnelles.",
    "Quero que apaguem a minha conta e os meus dados.",
    "アカウントを削除してください。",
    "Please wipe my account and purge my personal data.",
]
PARAPHRASE_NON = [
    "Could you email me a copy of everything you store about me? Please don't delete anything.",
    "Please unsubscribe me from marketing emails only; keep my account as it is.",
    "Please exclude me from marketing campaigns; I still use my account.",
    "My phone number changed, please update it on my profile.",
    "¿Qué datos personales tienen sobre mí? Es una solicitud de acceso, no de eliminación.",
]


def meta_shuffle(base: dict, tmp: Path) -> tuple:
    d = copy_dataset(tmp / "shuffle")
    rnd = random.Random(7)
    for name in ("deletion_requests.csv", "sample_deletion_requests.csv", "user_identities.csv",
                 "user_audit_log.csv", "system_activity.csv", "evidence_files.csv"):
        rewrite_csv(d / name, lambda rows: rnd.sample(rows, len(rows)))
    pred, _ = run_engine(d)
    diff = [c for c in base if pred.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(base)} cases changed"


def meta_rename_files(base: dict, tmp: Path) -> tuple:
    d = copy_dataset(tmp / "rename")

    def fn(rows):
        for r in rows:
            p = Path(r["file_path"])
            new = p.with_name("blob_" + hashlib.sha1(p.name.encode()).hexdigest()[:10] + p.suffix)
            (d / p).rename(d / new)
            r["file_path"] = str(new)
        return rows
    rewrite_csv(d / "evidence_files.csv", fn)
    pred, _ = run_engine(d)
    diff = [c for c in base if pred.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(base)} cases changed"


def meta_reid_evidence_and_cases(base: dict, tmp: Path) -> tuple:
    """evidence_N -> evidence_(N+700) and case_N -> case_(N+3000); predictions must map back."""
    d = copy_dataset(tmp / "reid")
    emap = {}

    def ev(rows):
        for r in rows:
            n = int(r["file_id"].split("_")[1])
            emap[f"evidence_{n + 700}"] = r["file_id"]
            r["file_id"] = f"evidence_{n + 700}"
        return rows
    rewrite_csv(d / "evidence_files.csv", ev)
    cmap = {}

    def cs(rows):
        for r in rows:
            n = int(r["case_id"].split("_")[1])
            cmap[f"case_{n + 3000}"] = r["case_id"]
            r["case_id"] = f"case_{n + 3000}"
        return rows
    rewrite_csv(d / "deletion_requests.csv", cs)
    rewrite_csv(d / "sample_deletion_requests.csv", cs)
    pred, _ = run_engine(d, cache=False)
    back = {}
    for c, (st, steps) in pred.items():
        steps = [dict(s, evidence_id=emap.get(s["evidence_id"], s["evidence_id"])) for s in steps]
        back[cmap[c]] = (st, steps)
    diff = [c for c in base if back.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(base)} cases changed"


def meta_reid_people(base: dict, tmp: Path) -> tuple:
    """Consistently replace every e-mail address (and its sha256) in all text inputs.
    Screenshots/PDFs cannot be rewritten, so cases citing them are excluded from the comparison."""
    d = copy_dataset(tmp / "people")
    emails = set()
    text_files = [p for p in d.rglob("*") if p.is_file() and p.suffix in (".csv", ".json", ".log", ".sql", ".txt")]
    rx = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
    for p in text_files:
        emails |= set(rx.findall(p.read_text(encoding="utf-8", errors="replace")))
    mapping = {}
    for e in sorted(emails):
        new = "p" + hashlib.sha1(e.lower().encode()).hexdigest()[:12] + "@mail.test"
        mapping[e] = new.upper() if e.isupper() else new
    hmap = {hashlib.sha256(e.lower().encode()).hexdigest(): hashlib.sha256(mapping[e].lower().encode()).hexdigest()
            for e in emails}
    for p in text_files:
        t = p.read_text(encoding="utf-8", errors="replace")
        t = rx.sub(lambda m: mapping.get(m.group(0), m.group(0)), t)
        t = re.sub(r"\b[0-9a-f]{64}\b", lambda m: hmap.get(m.group(0), m.group(0)), t)
        p.write_text(t, encoding="utf-8")
    pred, eng = run_engine(d, cache=False)
    binary = {fid for fid, ef in eng.store.files.items() if ef.path.suffix in (".png", ".pdf")}
    comparable = [c for c in base if not any(s["evidence_id"] in binary for s in base[c][1])
                  and not any(s["evidence_id"] in binary for s in pred.get(c, ("", []))[1])]
    diff = [c for c in comparable if pred.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(comparable)} comparable cases changed ({len(base) - len(comparable)} doc/screen cases excluded)"


def meta_unrelated_records(base: dict, tmp: Path) -> tuple:
    d = copy_dataset(tmp / "noise")
    with open(d / "user_identities.csv", "a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for i in range(50):
            e = f"noise.person{i}@unrelated.test"
            w.writerow([f"user_{8000 + i}", f"Noise Person {i}", e, f"+1 555 010 {1000 + i}",
                        hashlib.sha256(e.encode()).hexdigest(), "2026-01-01T00:00:00Z"])
    lines = []
    for i in range(50):
        lines.append(f"2026-06-01T10:{i % 60:02d}:00Z level=INFO service=search_service trace_id=tr-88{i:04d} "
                     f"resource_id=search_{88000 + i} event=index_query_completed result=hit "
                     f"correlation_key=\"noise.person{i}@unrelated.test\"")
    (d / "evidence" / "logs" / "noise_trace.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(d / "evidence_files.csv", "a", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow(["evidence_95", "evidence/logs/noise_trace.log", "noise", "2026-06-02T00:00:00Z"])
    pred, _ = run_engine(d)
    diff = [c for c in base if pred.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(base)} cases changed"


def meta_future_evidence(base: dict, tmp: Path) -> tuple:
    """A file captured after every audit_at that shows every requester's data present."""
    d = copy_dataset(tmp / "future")
    reqs = read_requests(d / "deletion_requests.csv")
    lines = []
    for i, q in enumerate(reqs):
        lines.append(f"2027-01-01T00:{i % 60:02d}:00Z level=INFO service=search_service trace_id=tr-77{i:04d} "
                     f"resource_id=search_{77000 + i} event=index_query_completed result=hit "
                     f"correlation_key=\"{q['email']}\"")
    (d / "evidence" / "logs" / "future_trace.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(d / "evidence_files.csv", "a", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow(["evidence_96", "evidence/logs/future_trace.log", "future", "2027-01-01T01:00:00Z"])
    pred, _ = run_engine(d)
    diff = [c for c in base if pred.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(base)} cases changed"


def meta_late_capture(base: dict, tmp: Path) -> tuple:
    """Files exported after every audit_at whose lines are time-stamped BEFORE each case's audit_at
    (the pattern that leaks if only embedded times are checked): no output may change."""
    d = copy_dataset(tmp / "late")
    reqs = read_requests(d / "deletion_requests.csv")
    from ghost_audit.util import iso, parse_ts
    from datetime import timedelta
    lines = []
    for i, q in enumerate(reqs):
        t = iso(parse_ts(q["audit_at"]) - timedelta(hours=1))
        lines.append(f"{t} level=INFO service=security_service trace_id=tr-78{i:04d} resource_id=audit_record_{78000 + i} "
                     f"event=audit_record_read_completed rows=1 correlation_key=\"{q['email']}\" "
                     f"retention_until=2031-01-01T00:00:00Z")
        lines.append(f"{t} level=INFO service=account_service trace_id=tr-79{i:04d} resource_id=account_{79000 + i} "
                     f"event=profile_lookup_completed rows=0 http_status=404 correlation_key=\"{q['email']}\"")
    (d / "evidence" / "logs" / "late_export.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(d / "evidence_files.csv", "a", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow(["evidence_97", "evidence/logs/late_export.log", "late", "2027-01-01T01:00:00Z"])
    pred, _ = run_engine(d)
    diff = [c for c in base if pred.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(base)} cases changed"


def meta_future_activity(base: dict, tmp: Path) -> tuple:
    """Activity rows dated after each case's audit_at (identity links, deletion claims, syncs)."""
    d = copy_dataset(tmp / "factivity")
    reqs = read_requests(d / "deletion_requests.csv")
    from ghost_audit.util import iso, parse_ts
    from datetime import timedelta
    with open(d / "system_activity.csv", "a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for i, q in enumerate(reqs):
            t = iso(parse_ts(q["audit_at"]) + timedelta(minutes=5))
            w.writerow([f"activity_{90000 + 2 * i}", t, "LINK_RESOURCE_IDENTITY", "data_catalog", "search_service",
                        f"search_{80000 + i}", "SUCCESS",
                        f"Data catalog linked search_{80000 + i} (search_{80000 + i}) to {q['email']}."])
            w.writerow([f"activity_{90001 + 2 * i}", t, "SYNC_RECORD", "integration_service", "search_service",
                        f"data_flow_{80000 + i}", "SUCCESS",
                        f"Active connector repopulated downstream resource search_{80000 + i}."])
    pred, _ = run_engine(d)
    diff = [c for c in base if pred.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(base)} cases changed"


def meta_format(base: dict, tmp: Path) -> tuple:
    """Formatting only: every CSV field quoted, CRLF line endings, request e-mails upper-cased and
    padded, request text with extra whitespace."""
    d = copy_dataset(tmp / "fmt")
    for name in ("deletion_requests.csv", "user_identities.csv", "user_audit_log.csv", "system_activity.csv",
                 "evidence_files.csv"):
        rows = list(csv.DictReader(open(d / name, encoding="utf-8")))
        if name == "deletion_requests.csv":
            for r in rows:
                r["email"] = "  " + r["email"].upper() + " "
                r["request_text"] = "  " + r["request_text"].replace(" ", "  ") + "\n"
        with open(d / name, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), quoting=csv.QUOTE_ALL, lineterminator="\r\n")
            w.writeheader()
            w.writerows(rows)
    pred, _ = run_engine(d)
    diff = [c for c in base if pred.get(c) != base[c]]
    return not diff, f"{len(diff)} of {len(base)} cases changed"


def meta_paraphrase(base: dict, tmp: Path) -> tuple:
    d = copy_dataset(tmp / "para")
    rnd = random.Random(11)

    def fn(rows):
        for r in rows:
            if base.get(r["case_id"], ("",))[0] == "NOT_APPLICABLE":
                r["request_text"] = rnd.choice(PARAPHRASE_NON)
            elif r["case_id"] in base:
                r["request_text"] = rnd.choice(PARAPHRASE_DEL)
        return rows
    rewrite_csv(d / "deletion_requests.csv", fn)
    pred, _ = run_engine(d)
    diff = [c for c in base if pred.get(c, ("",))[0] != base[c][0]]
    return not diff, f"{len(diff)} of {len(base)} statuses changed"


def _pick(base, status, op):
    """First case (by id) whose step `op` cites a file captured >= 10 min before audit_at, so an injected
    observation 5 minutes before audit_at is unambiguously the latest one."""
    from datetime import datetime, timedelta
    reqs = {q["case_id"]: q for q in read_requests(DATASET / "deletion_requests.csv")}
    cap = {r["file_id"]: r["captured_at"] for r in csv.DictReader(open(DATASET / "evidence_files.csv"))}
    p = lambda t: datetime.fromisoformat(t.replace("Z", "+00:00"))
    for c in sorted(base, key=lambda x: int(x.split("_")[1])):
        st, steps = base[c]
        if st != status:
            continue
        audit = p(reqs[c]["audit_at"])
        if any(s["evidence_id"] in cap and p(cap[s["evidence_id"]]) > audit - timedelta(minutes=10) for s in steps):
            continue
        for s in steps:
            if s["operation"] == op:
                return c, s
    return None, None


def semantic_tests(base: dict, tmp: Path) -> list:
    out = []
    reqs = {q["case_id"]: q for q in read_requests(DATASET / "deletion_requests.csv")}

    def with_extra_log(name, line, captured):
        d = copy_dataset(tmp / name)
        (d / "evidence" / "logs" / f"{name}.log").write_text(line + "\n", encoding="utf-8")
        with open(d / "evidence_files.csv", "a", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(["evidence_97", f"evidence/logs/{name}.log", "semantic_test", captured])
        return run_engine(d)[0]

    def minus(ts, minutes):
        from datetime import datetime, timedelta
        t = datetime.fromisoformat(ts.replace("Z", "+00:00")) - timedelta(minutes=minutes)
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    # S1 activate a restore path
    c, s = _pick(base, "COMPLETE", "VERIFY_RESTORE_BLOCKED")
    if c:
        q = reqs[c]
        pred = with_extra_log("s1", f"{minus(q['audit_at'], 2)} level=INFO service=backup_service trace_id=tr-990001 "
                              f"resource_id={s['resource_id']} event=restore_policy_read_completed archive_present=true "
                              f"restore_allowed=true customer_email={q['email']}", minus(q["audit_at"], 1))
        st, steps = pred[c]
        ok = st == "INCOMPLETE" and any(x["operation"] == "REPORT_RESTORE_RISK" and x["resource_id"] == s["resource_id"]
                                        and x["evidence_id"] == "evidence_97" for x in steps)
        out.append(("S1 activate restore path", ok, f"{c}: {st}"))
    # S2 expose a prohibited identifier on an anonymised record
    c, s = _pick(base, "COMPLETE", "VERIFY_RECORD_ANONYMIZED")
    if c:
        q = reqs[c]
        pred = with_extra_log("s2", f"{minus(q['audit_at'], 2)} level=WARN service=analytics_platform trace_id=tr-990002 "
                              f"resource_id={s['resource_id']} event=analytics_identity_scan matched_value=\"{q['email']}\" "
                              f"direct_identifiers=1", minus(q["audit_at"], 1))
        st, steps = pred[c]
        ok = st == "INCOMPLETE" and any(x["operation"] == "REPORT_EXPOSED_PII" and x["resource_id"] == s["resource_id"]
                                        for x in steps)
        out.append(("S2 expose prohibited identifier", ok, f"{c}: {st}"))
    # S3 introduce a surviving replica of a deleted account
    c, s = _pick(base, "COMPLETE", "VERIFY_RECORD_ABSENT")
    if c:
        q = reqs[c]
        d = copy_dataset(tmp / "s3")
        cap = minus(q["audit_at"], 1)
        (d / "evidence" / "databases" / "s3.sql").write_text(f"""-- Captured at: {cap}
-- Database topology: failover_replica
BEGIN TRANSACTION;
CREATE TABLE customer_profiles_failover_replica (resource_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, full_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL, account_status TEXT NOT NULL, updated_at TEXT NOT NULL);
INSERT INTO "customer_profiles_failover_replica" VALUES('{s['resource_id']}','user_x','Test Person','{q['email']}','+1 555 0100','ACTIVE','{cap}');
COMMIT;
""", encoding="utf-8")
        with open(d / "evidence_files.csv", "a", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(["evidence_98", "evidence/databases/s3.sql", "semantic_test", cap])
        st, steps = run_engine(d)[0][c]
        ok = st == "INCOMPLETE" and any(x["operation"] == "REPORT_REMAINING_RECORD" and x["resource_id"] == s["resource_id"]
                                        and x["evidence_id"] == "evidence_98" for x in steps)
        out.append(("S3 surviving failover replica", ok, f"{c}: {st}"))
    # S4 remove deletion authorisation
    c = next((c for c in sorted(base) if base[c][0] == "INCOMPLETE"), None)
    if c:
        d = copy_dataset(tmp / "s4")
        rewrite_csv(d / "deletion_requests.csv", lambda rows: [
            dict(r, request_text="I only need a copy of my order history; please do not delete or change anything.")
            if r["case_id"] == c else r for r in rows])
        st, steps = run_engine(d)[0][c]
        out.append(("S4 remove deletion authorisation", st == "NOT_APPLICABLE" and steps == [], f"{c}: {st}"))
    return out


# ---------------------------------------------------------------------------- operational reliability
def operational_tests(tmp: Path) -> list:
    import http.server
    import os
    import threading
    from ghost_audit import llm
    out = []
    # 1) model fallback: malformed body, schema violation, timeout, then a valid answer
    current = {"mode": "ok"}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", 0)))
            mode = current["mode"]
            if mode == "sleep":
                time.sleep(1.5)
            body = {"malformed": b"{not json",
                    "schema": json.dumps({"model": "test-model", "usage": {"input_tokens": 10, "output_tokens": 3},
                                          "content": [{"text": json.dumps({"is_deletion": "maybe"})}]}).encode(),
                    "ok": json.dumps({"model": "test-model", "usage": {"input_tokens": 12, "output_tokens": 4},
                                      "content": [{"text": json.dumps({"is_deletion": True, "label": "DELETION"})}]}).encode(),
                    "sleep": b"{}"}[mode]
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    saved = {k: os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL")}
    os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"
    os.environ["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{srv.server_port}"
    usage_before = llm.USAGE.summary()
    try:
        for mode in ("malformed", "schema", "sleep"):  # sleep = server slower than the client timeout
            current["mode"] = mode
            llm._CACHE.clear()
            r = llm.classify_intent(f"undecidable text {mode}", timeout=0.5, retries=1)
            out.append((f"model fallback survives {mode} response", r is None, "returned None -> safe default"))
        current["mode"] = "ok"
        r = llm.classify_intent("undecidable text ok", timeout=2, retries=1)
        out.append(("model fallback accepts valid structured output", r == {"is_deletion": True, "label": "DELETION"},
                    str(r)))
        r2 = llm.classify_intent("undecidable text ok", timeout=2, retries=1)
        out.append(("model fallback caches repeated prompts", r2 == r and llm.USAGE.cache_hits >= 1,
                    f"cache_hits={llm.USAGE.cache_hits}"))
    finally:
        srv.shutdown()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        # do not let test traffic leak into the production usage report
        llm.USAGE.__init__()
        llm._CACHE.clear()
    out.append(("no API key -> zero model calls in production run", usage_before["calls"] == 0,
                f"calls before tests={usage_before['calls']}"))
    # 1b) MOCK transport for the investigation policy (not a provider call): malformed, out-of-list,
    #     explicit stop, valid choice; every response is counted, nothing outside the list is accepted
    allowed = ["ocr_x2_psm6", "ocr_x3_psm6"]
    mocks = {"malformed": {"content": [{"text": "{nope"}]},
             "out_of_list": {"model": "mock", "usage": {"input_tokens": 9, "output_tokens": 2},
                             "content": [{"text": json.dumps({"action": "read_other_file"})}]},
             "stop": {"model": "mock", "usage": {"input_tokens": 9, "output_tokens": 2},
                      "content": [{"text": json.dumps({"action": "stop"})}]},
             "valid": {"model": "mock", "usage": {"input_tokens": 9, "output_tokens": 2},
                       "content": [{"text": json.dumps({"action": "ocr_x3_psm6"})}]}}
    got = {k: llm.choose_investigation_action({"observed_token": "a@b.c"}, allowed, transport=lambda b, k=k: mocks[k],
                                              retries=0) for k in mocks}
    calls = llm.USAGE.calls
    llm.USAGE.__init__()
    out.append(("MOCK investigation policy: malformed / out-of-list / stop -> None, valid -> that action",
                got == {"malformed": None, "out_of_list": None, "stop": None, "valid": "ocr_x3_psm6"},
                f"{got}; mock responses counted: {calls} (usage reset afterwards)"))
    # 2) stale cache: same file id + capture time, changed bytes -> must re-extract
    d = copy_dataset(tmp / "stale")
    cache = tmp / "cache"
    e1 = Engine(d, cache)
    target = d / "evidence" / "records" / "customer_account_handover_20261001.txt"
    target.write_text(target.read_text(encoding="utf-8").replace("| FOUND | noor-khalil@proton.me",
                                                                 "| NOT_FOUND | noor-khalil@proton.me"), encoding="utf-8")
    e2 = Engine(d, cache)
    out.append(("content change invalidates the extraction cache",
                e2.store.cache_misses == 1 and e1.store.cache_misses == len(e1.store.files),
                f"first run misses={e1.store.cache_misses}, after edit misses={e2.store.cache_misses}"))
    # 3) missing evidence file listed in the manifest is reported, run still completes
    os.remove(d / "evidence" / "logs" / "support_replica.log")
    e3 = Engine(d, cache)
    n = len(e3.run(read_requests(d / "deletion_requests.csv")))
    out.append(("missing evidence file recorded, all cases still answered",
                any("not found" in err for _, err in e3.store.failures) and n == 518, f"{n} cases"))
    # 4) interrupted write never leaves a truncated output.csv
    from ghost_audit import pipeline
    target_csv = tmp / "out.csv"
    target_csv.write_text("previous complete file\n")
    class Boom(Exception):
        pass
    orig_validate = pipeline.validate_rows
    pipeline.validate_rows = lambda rows, ids: (_ for _ in ()).throw(Boom())
    try:
        pipeline.write_output([], target_csv, [])
    except Boom:
        pass
    finally:
        pipeline.validate_rows = orig_validate
    out.append(("interrupted run keeps the previous output intact",
                target_csv.read_text() == "previous complete file\n", "atomic replace"))
    # 5) fresh vs cached extraction timing
    t = time.time()
    Engine(DATASET, None)
    fresh = time.time() - t
    t = time.time()
    Engine(DATASET, CODE / ".cache")
    cached = time.time() - t
    out.append(("fresh vs cached evidence loading", True, f"fresh {fresh:.1f}s (OCR + PDF + SQL), cached {cached:.1f}s"))
    # 6) every manifest-listed file is accounted for with a distinct status; raw text is kept for
    #    PDFs/screenshots next to the normalised observations
    e6 = Engine(DATASET, CODE / ".cache")
    with open(DATASET / "evidence_files.csv", encoding="utf-8") as fh:
        listed = [r["file_id"] for r in csv.DictReader(fh)]
    statuses = Counter(e6.store.files[f].status for f in listed if f in e6.store.files)
    allowed = {"ok", "facts-only", "no-direct-facts", "empty", "missing", "error", "unsupported"}
    raw_ok = all(e6.store.files[f].text for f in listed
                 if e6.store.files[f].path.suffix.lower() in (".pdf", ".png", ".jpg", ".jpeg"))
    out.append(("every manifest file accounted for; raw OCR/PDF text preserved",
                len(listed) == sum(statuses.values()) and set(statuses) <= allowed and raw_ok,
                f"{len(listed)} listed, statuses {dict(statuses)}, raw text for all PDFs/images: {raw_ok}"))
    # 7) no dataset-specific substitutions or look-alike hacks in the parsers
    src = (CODE / "ghost_audit" / "parsers.py").read_text(encoding="utf-8") + \
        (CODE / "ghost_audit" / "audit.py").read_text(encoding="utf-8")
    hacks = [w for w in ("OCR_FIXES", "_fuzzy_token", "'jr'", '"jr"') if w in src]
    out.append(("no dataset-specific OCR substitutions or fuzzy-link hacks in the predictor", not hacks,
                f"found: {hacks or 'none'}"))
    return out


# ---------------------------------------------------------------------------- D. mutations
@contextlib.contextmanager
def patched(obj, name, value):
    # read the raw attribute so staticmethod/classmethod wrappers are restored intact
    old = obj.__dict__[name] if isinstance(obj, type) and name in obj.__dict__ else getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, old)


def mutations():
    from ghost_audit import audit, identity, intent, parsers, planner, policy

    def m_hist():
        orig = identity.IdentityIndex.__init__

        def init(self, d):
            orig(self, d)
            import csv as _c
            cur = {r["user_id"]: r for r in _c.DictReader(open(d / "user_identities.csv", encoding="utf-8"))}
            for p in self.people.values():
                r = cur.get(p.user_id)
                if r:
                    p.emails = {r["email"].lower()}
                    p.hashes = {r["email_hash"].lower()}
            self.index.clear()
            for p in self.people.values():
                for k in p.identifier_keys():
                    self.index[k].add(p.user_id)
        return patched(identity.IdentityIndex, "__init__", init)

    def m_trust():
        orig = audit.Auditor.audit

        def a(self, q):
            r = orig(self, q)
            if q["reported_status"] == "COMPLETE" and r.status == "INCOMPLETE":
                r.status = "COMPLETE"
                r.steps = [dict(s, step_no=i + 1) for i, s in enumerate(x for x in r.steps if x["phase"] == "VERIFICATION")]
            return r
        return patched(audit.Auditor, "audit", a)

    def m_images():
        return patched(parsers, "ocr_text", lambda p: "")

    def m_future():
        return patched(audit.Auditor, "admissible", lambda self, o, cut: True)

    def m_replicas():
        orig = audit.Auditor.state_at

        def st(self, rid, cut, uid, v, request_at, runs, known_since=None):
            saved = self.obs_by_resource.get(rid, [])
            self.obs_by_resource[rid] = [o for o in saved if o.replica in ("primary",)]
            try:
                return orig(self, rid, cut, uid, v, request_at, runs, known_since)
            finally:
                self.obs_by_resource[rid] = saved
        return patched(audit.Auditor, "state_at", st)

    def m_hash():
        orig = identity.identifier_key
        return patched(identity, "identifier_key",
                       lambda v: None if (orig(v) or ("",))[0] == "hash" else orig(v))

    def m_delete_retained():
        orig = policy.Policy.decide

        def d(self, category, **kw):
            if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
                return "DELETE", "x", "mutant"
            return orig(self, category, **kw)
        return patched(policy.Policy, "decide", d)

    def m_flow():
        orig = planner.plan_one

        def p(t):
            if t.category == "DATA_FLOW":
                return None, None, "VERIFY_DATA_FLOW_DISABLED", ""
            return orig(t)
        return patched(planner, "plan_one", p)

    def m_order():
        orig = planner.build_steps

        def b(ts, **kw):
            status, steps, notes = orig(ts, **kw)
            steps = list(reversed(steps))
            return status, [dict(s, step_no=i + 1) for i, s in enumerate(steps)], notes
        return patched(audit, "build_steps", b)

    def m_negation():
        return patched(intent, "NEGATION_PATTERNS", [])

    def m_window():
        # ignore embedded event times: admit on file capture time only
        def adm(self, o, cut):
            cap = audit.parse_ts(o.captured_at)
            return cap is not None and cap <= cut
        return patched(audit.Auditor, "admissible", adm)

    def m_prior():
        # forget pre-request history: treat any observation before requested_at as unknown
        orig = audit.Auditor.state_at

        def st(self, rid, cut, uid, v, request_at, runs, known_since=None):
            saved = self.obs_by_resource.get(rid, [])
            self.obs_by_resource[rid] = [o for o in saved if not (audit.parse_ts(o.observed_at) and request_at
                                                                   and audit.parse_ts(o.observed_at) < request_at)]
            try:
                return orig(self, rid, cut, uid, v, request_at, runs, known_since)
            finally:
                self.obs_by_resource[rid] = saved
        return patched(audit.Auditor, "state_at", st)

    def m_undecided():
        # equate UNDECIDED intent with deletion
        orig = intent.classify_rules

        def c(text):
            r = orig(text)
            if r.label == "UNDECIDED":
                return intent.IntentResult(True, "DELETION", "mutant")
            return r
        return patched(intent, "classify_rules", c)

    def m_drop_unproven():
        # call a case COMPLETE even when no evidence-backed verification exists
        orig = planner.build_steps

        def b(ts, **kw):
            status, steps, unresolved = orig(ts)  # ignores the caller's request to withhold COMPLETE
            if status == "UNCERTIFIED":
                status = "COMPLETE"
            return status, steps, unresolved
        return patched(audit, "build_steps", b)

    def m_guess_account():
        # resolve an ambiguous workflow window by picking the submission nearest to reported_at
        orig = audit.Auditor.correlate_account

        def c(self, q, uid, cut, v):
            acct, how, cands = orig(self, q, uid, cut, v)
            if acct is None and cands:
                rep = audit.parse_ts(q["reported_at"])
                pool = [a for a in self.account_subs if a.resource_id in cands]
                return min(pool, key=lambda a: abs((a.ts - rep).total_seconds())), "mutant nearest", []
            return acct, how, cands
        return patched(audit.Auditor, "correlate_account", c)

    def m_unvalidated_investigation():
        from ghost_audit import investigate as inv
        return patched(inv, "verbatim", lambda hypothesis, text: True)

    def m_partial_rows():
        from ghost_audit import investigate as inv
        orig = inv._accept

        def acc(pb, text):
            ok, new = orig(pb, text)
            if pb.kind == "row_gap" and not ok:
                from ghost_audit.util import RESOURCE_RE
                new = sorted({m.group(0) for m in RESOURCE_RE.finditer(text.lower())} - set(pb.known_ids))
                return bool(new), new
            return ok, new
        return patched(inv, "_accept", acc)

    return [("accept investigation hypothesis without verbatim read", m_unvalidated_investigation, False),
            ("accept recovered rows without completing the declared count", m_partial_rows, False),
            ("ignore historical identifiers", m_hist, False), ("guess ambiguous account (nearest time)", m_guess_account, False), ("trust reported_status", m_trust, False),
            ("skip images (no OCR)", m_images, True), ("accept future evidence", m_future, False),
            ("overlook replicas", m_replicas, False), ("drop hash identifiers", m_hash, False),
            ("delete required retained record", m_delete_retained, False), ("miss active data flow", m_flow, False),
            ("scramble step order", m_order, False), ("ignore negation in requests", m_negation, False),
            ("ignore embedded event time (capture time only)", m_window, False),
            ("forget pre-request history", m_prior, False), ("treat UNDECIDED intent as deletion", m_undecided, False),
            ("certify COMPLETE without proof", m_drop_unproven, False)]


def suite_for_mutation(gold, base_scores, cache: bool) -> list:
    """The detection suite: fixtures + sample regression guard + structural validation."""
    from ghost_audit.validate import validate_rows
    fails = []
    from evaluation import unit_tests
    for name, ok, detail in unit_tests.run():
        if not ok:
            fails.append(f"unit {name.split()[0]}")
    for name, ok, detail in run_fixtures():
        if not ok:
            fails.append(f"fixture {name}")
    pred, _ = run_engine(DATASET, "sample_deletion_requests.csv", cache=cache)
    sc = score(pred, gold)
    if sc["status_correct"] < base_scores["status_correct"]:
        fails.append(f"samples status {sc['status_correct']}<{base_scores['status_correct']}")
    if sc["tp"] < base_scores["tp"] or sc["fp"] > base_scores["fp"]:
        fails.append(f"samples steps tp {sc['tp']} fp {sc['fp']}")
    rows = [{"case_id": c, "deletion_status": s, "steps_json": json.dumps(st)} for c, (s, st) in sorted(pred.items())]
    errs = [e for e in validate_rows(rows, list(pred)) if "WARNING" not in e and "sorted" not in e]
    if errs:
        fails.append(f"validation: {errs[0]}")
    return fails


# ---------------------------------------------------------------------------- report
def contract_check(path: Path, fresh: dict) -> dict:
    """Independent re-check of the submitted CSV file on disk (not of in-memory predictions)."""
    from ghost_audit.util import sha256_file
    from ghost_audit.validate import validate_rows
    if not path.exists():
        return {"present": False}
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    header = text.splitlines()[0] if text else ""
    rows = list(csv.DictReader(io.StringIO(text)))
    req_ids = [r["case_id"] for r in read_requests(DATASET / "deletion_requests.csv")]
    known = {r["file_id"] for r in csv.DictReader(open(DATASET / "evidence_files.csv", encoding="utf-8"))}
    known |= {r["activity_id"] for r in csv.DictReader(open(DATASET / "system_activity.csv", encoding="utf-8"))}
    known |= {r["audit_id"] for r in csv.DictReader(open(DATASET / "user_audit_log.csv", encoding="utf-8"))}
    issues = validate_rows(rows, req_ids, known)
    errors = [e for e in issues if "WARNING" not in e]
    warnings = [e for e in issues if "WARNING" in e]
    disk = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in rows}
    n_steps = sum(len(v[1]) for v in disk.values())
    empty_incomplete = [c for c, (st, sp) in disk.items() if st == "INCOMPLETE" and not sp]
    return {"present": True, "sha256": sha256_file(path), "header": header, "rows": len(rows),
            "unique_case_ids": len(set(r["case_id"] for r in rows)), "expected_rows": len(req_ids),
            "errors": errors, "warnings_count": len(warnings), "steps": n_steps,
            "empty_incomplete": empty_incomplete, "matches_fresh_prediction": disk == fresh,
            "status_counts": dict(Counter(v[0] for v in disk.values()))}


def environment() -> dict:
    import platform
    import sqlite3
    import subprocess
    from importlib import metadata
    from ghost_audit import parsers
    from ghost_audit.util import code_fingerprint, sha256_file

    def tool(cmd):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return (out.stdout or out.stderr).strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            return "not available"

    def pkg(name):
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            return "not installed"
    return {"code_fingerprint": code_fingerprint(CODE), "parser_version": parsers.PARSER_VERSION,
            "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
            "tesseract": tool(["tesseract", "--version"]), "pdftotext": tool(["pdftotext", "-v"]),
            "pypdf": pkg("pypdf"), "reportlab": pkg("reportlab"), "pillow": pkg("pillow"),
            "inputs_sha256": {p.name: sha256_file(p)[:16] for p in sorted(DATASET.glob("*.csv"))
                              if p.name != "output.csv"},
            "model_env": "ANTHROPIC_API_KEY set" if __import__("os").environ.get("ANTHROPIC_API_KEY")
            else "ANTHROPIC_API_KEY not set (rule-only run)"}


def pct(x):
    return f"{100 * x:.1f}%"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=str(HERE / "evaluation_report.md"))
    ap.add_argument("--json", default=str(CODE / "runs" / "evaluation_results.json"))
    ap.add_argument("--invariance-json", default=str(CODE / "runs" / "invariance" / "invariance.json"),
                    help="output of evaluation/invariance.py for this code (section reported as NOT RUN if absent)")
    ap.add_argument("--compare-json", default=str(CODE / "runs" / "compare_base.json"),
                    help="compare.py output vs the original implementation (NOT RUN if absent)")
    ap.add_argument("--compare-prev-json", default=str(CODE / "runs" / "compare_prev.json"),
                    help="compare.py output vs the last reviewed implementation (NOT RUN if absent)")
    ap.add_argument("--failfirst-dir", default=str(CODE / "runs" / "failfirst"),
                    help="directory holding base.json and new.json from evaluation/failfirst.py")
    args = ap.parse_args(argv)
    t0 = time.time()
    res = {}
    gold = load_gold(DATASET / "sample_output.csv")
    pred, eng = run_engine(DATASET, "sample_deletion_requests.csv")
    res["samples"] = sc = score(pred, gold)
    res["samples_cases"] = {c: {"pred": pred[c][0], "gold": gold[c][0],
                                "missing": [tup(s) for s in gold[c][1] if tup(s) not in {tup(x) for x in pred[c][1]}],
                                "extra": [tup(s) for s in pred[c][1] if tup(s) not in {tup(x) for x in gold[c][1]}]}
                            for c in gold}
    res["fixtures"] = run_fixtures()
    from evaluation import unit_tests
    res["unit_tests"] = unit_tests.run()
    ver0 = Verifier(DATASET, CODE / ".cache" / "verifier")
    gold_nd = set(ver0.verify(read_requests(DATASET / "sample_deletion_requests.csv"), gold)["issues"]
                  .get("resource_not_discoverable_by_audit_at", []))
    tr = {r.case_id: r.trace for r in eng.last_results}
    causes = []
    internal_s = {r.case_id: r.internal_status for r in eng.last_results}
    req_s = {q["case_id"]: q for q in read_requests(DATASET / "sample_deletion_requests.csv")}
    occ = ver0.occurrences()
    from ghost_audit.util import parse_ts as _pt
    for c, x in res["samples_cases"].items():
        cut = _pt(req_s[c]["audit_at"])
        uid = ((tr[c].get("identity") or {}).get("user_ids") or [None])[0]
        for t in x["missing"]:
            rid = t[2]
            cands = (tr[c].get("account_correlation") or {}).get("candidates", [])
            same = [p for p in pred[c][1] if p["resource_id"] == rid and p["operation"] == t[3]]
            if same:
                cause = ("implementation choice: uncertified case, the same check is emitted as future work without "
                         "a citation" if internal_s.get(c) == "UNCERTIFIED" else
                         f"implementation choice: same check cites {same[0]['evidence_id'] or 'nothing'}")
            elif any(p["resource_id"] == rid for p in pred[c][1]):
                cause = "implementation choice: same resource, different required operation"
            elif f"{c}:{rid}" in gold_nd:
                cause = ("ambiguous specification: gold names a resource visible only in evidence captured after audit_at"
                         if rid in occ else "unsupported sample answer: gold names a resource that appears in no participant file")
            elif rid.startswith("account_") and rid in cands:
                cause = f"account not attributable: {len(cands)} unowned workflow submissions in the report window"
            elif rid.startswith("analytics_"):
                cause = "anonymised analytics record: no identifier; attribution would need other requests"
            else:
                adm = [(f, ver0.users_named(ctx)) for f, cap, rt, ctx in occ.get(rid, [])
                       if cap <= cut and (rt is None or rt <= cut)]
                if any(uid in named for _, named in adm):
                    cause = "PARSER/RETRIEVAL OMISSION: an admissible occurrence names the subject"
                elif adm:
                    cause = "not linked: admissible occurrences do not name the subject"
                else:
                    cause = "other (see trace)"
            causes.append((c, t[3], rid, t[5], cause))
    res["sample_miss_causes"] = causes
    full_pred, full_eng = run_engine(DATASET)
    ver = Verifier(DATASET, CODE / ".cache" / "verifier")
    lc = Counter()
    for cid, (st, steps) in full_pred.items():
        if st == "NOT_APPLICABLE":
            continue
        lc["deletions"] += 1
        if st == "COMPLETE":
            lc["complete"] += 1
            lc["complete_no_acct"] += not any(s["system_id"] == "account_service" for s in steps)
    for r in full_eng.last_results:
        lc["internal_" + r.internal_status] += 1
        if r.unresolved:
            lc["with_unresolved"] += 1
        acct = ((r.trace or {}).get("account_correlation") or {}).get("basis", "")
        if "ambiguous" in str(acct):
            lc["amb"] += 1
    res["limitation_counts"] = dict(lc)
    res["verifier_eval"] = ver.verify(read_requests(DATASET / "deletion_requests.csv"), full_pred)
    res["verifier_gold"] = ver.verify(read_requests(DATASET / "sample_deletion_requests.csv"), gold)
    res["verifier_samples_pred"] = ver.verify(read_requests(DATASET / "sample_deletion_requests.csv"), pred)
    from evaluation import verifier_defects
    res["verifier_defects"] = verifier_defects.run(DATASET, ver)
    for key, path in (("invariance", args.invariance_json), ("compare", args.compare_json),
                      ("compare_prev", args.compare_prev_json)):
        if Path(path).exists():
            res[key] = json.loads(Path(path).read_text(encoding="utf-8"))
    ff = Path(args.failfirst_dir)
    if (ff / "new.json").exists():
        res["failfirst"] = {"new": json.loads((ff / "new.json").read_text())}
        for tag in ("base", "prev"):
            if (ff / f"{tag}.json").exists():
                res["failfirst"][tag] = json.loads((ff / f"{tag}.json").read_text())
                res["failfirst"][tag + "_rev"] = (ff / f"{tag}.rev").read_text().strip() \
                    if (ff / f"{tag}.rev").exists() else tag
    from ghost_audit import investigate as inv
    res["investigation"] = inv.summary(full_eng.investigation)
    saved_apply = inv.apply
    try:  # ablation: the same run without verified reads
        inv.apply = lambda store, outs: None
        abl, _ = run_engine(DATASET)
    finally:
        inv.apply = saved_apply
    res["investigation_ablation_changed"] = sorted(c for c in full_pred if abl.get(c) != full_pred[c])
    if not args.quick:
        from evaluation import agent_eval
        res["agent_eval"] = agent_eval.run(60)
    res["internal"] = {r.case_id: {"internal": r.internal_status,
                                   "blocking": [u["reason"] for u in r.unresolved if u.get("blocking", True)]}
                       for r in full_eng.last_results}
    res["final_counts"] = dict(Counter(st for st, _ in full_pred.values()))
    res["contract"] = contract_check(ROOT / "output.csv", full_pred)
    res["internal_counts"] = dict(Counter(r.internal_status for r in full_eng.last_results))
    res["unresolved_reasons"] = dict(Counter(
        u["reason"].split(":")[0].split(" (")[0] for r in full_eng.last_results for u in r.unresolved
        if u.get("blocking", True)))
    if not args.quick:
        tmp = Path(tempfile.mkdtemp(prefix="ghost_meta_"))
        meta = []
        for name, fn in [("shuffle all CSV rows and manifest order", meta_shuffle),
                         ("rename every evidence file (manifest updated)", meta_rename_files),
                         ("re-id evidence file ids and case ids, map back", meta_reid_evidence_and_cases),
                         ("consistently replace every e-mail and its hash", meta_reid_people),
                         ("add 50 unrelated people and records", meta_unrelated_records),
                         ("add evidence captured after every audit_at", meta_future_evidence),
                         ("add late-captured files with pre-audit_at line times", meta_late_capture),
                         ("add activity dated after each audit_at", meta_future_activity),
                         ("CSV quoting, CRLF, upper-case/padded e-mails, extra whitespace", meta_format),
                         ("paraphrase every request (same intent)", meta_paraphrase)]:
            t = time.time()
            ok, detail = fn(full_pred, tmp)
            meta.append((name, ok, detail, round(time.time() - t, 1)))
        res["metamorphic"] = meta
        res["semantic"] = semantic_tests(full_pred, tmp)
        res["operational"] = operational_tests(tmp)
        shutil.rmtree(tmp, ignore_errors=True)
        base_scores = sc
        clean = suite_for_mutation(gold, base_scores, cache=True)
        res["suite_clean_failures"] = clean
        muts = []
        for name, ctx, needs_fresh in mutations():
            with ctx():
                fails = suite_for_mutation(gold, base_scores, cache=not needs_fresh)
            muts.append((name, bool(fails), fails[:4]))
        res["mutations"] = muts
    res["seconds"] = round(time.time() - t0, 1)
    res["environment"] = environment()
    Path(args.json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    write_report(res, Path(args.out), full_eng)
    print(f"evaluation done in {res['seconds']}s -> {args.out}")


def write_report(res, path: Path, eng):
    from evaluation.report import render
    path.write_text(render(res, eng), encoding="utf-8")


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    main()
