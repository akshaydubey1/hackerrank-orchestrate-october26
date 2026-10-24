"""Before/after comparison of two prediction sets (e.g. the previous committed code vs the current code).

    python3 code/evaluation/compare.py --before-dir <invariance dir of old code> \
        --after-dir <invariance dir of new code> --out code/runs/compare.json

Each directory is the output of invariance.py (full.csv, samples.csv, invariance.json). The same
scoring and the same independent verifier are applied to both sides, so the columns are comparable.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
ROOT = CODE.parent
sys.path.insert(0, str(CODE))

from evaluation.main import DATASET, load_gold, score  # noqa: E402
from evaluation.verifier import Verifier  # noqa: E402
from ghost_audit.pipeline import read_requests  # noqa: E402

TEMPORAL = ("resource_not_discoverable_by_audit_at", "future_evidence_cited")
RETENTION = ("retention_violation", "missing_retained_record")


def load(path: Path) -> dict:
    return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
            for r in csv.DictReader(open(path, encoding="utf-8"))}


def side(d: Path, ver: Verifier, gold: dict) -> dict:
    full, samples = load(d / "full.csv"), load(d / "samples.csv")
    inv = json.loads((d / "invariance.json").read_text())
    v_full = ver.verify(read_requests(DATASET / "deletion_requests.csv"), full)
    v_s = ver.verify(read_requests(DATASET / "sample_deletion_requests.csv"), samples)
    sc = score(samples, gold)
    n = lambda v, keys: sum(len(v["issues"].get(k, [])) for k in keys)
    return {
        "full": full,
        "metrics": {
            "sample status": f"{sc['status_correct']}/{sc['cases']}",
            "sample exact sequence": f"{sc['exact_sequence_n']}/{sc['cases']}",
            "sample step TP / FP / FN": f"{sc['tp']} / {sc['fp']} / {sc['fn']}",
            "sample step F1": f"{100 * sc['step_f1']:.1f}%",
            "sample field accuracy (min over fields)": f"{100 * min(sc['field_accuracy'].values()):.1f}%",
            "sample citation accuracy": f"{100 * sc['citation_accuracy']:.1f}%",
            "temporal-eligibility issues, 518 output (verifier)": n(v_full, TEMPORAL),
            "temporal-eligibility issues, sample output (verifier)": n(v_s, TEMPORAL),
            "retention issues, 518 output (verifier)": n(v_full, RETENTION),
            "all verifier issues, 518 output": sum(len(x) for x in v_full["issues"].values()),
            "COMPLETE without account proof, 518 output": v_full["stats"].get("complete_account_not_verified", 0),
            "batch invariance: changed / compared": f"{inv['total_changed']} / {inv['total_compared']}",
            "status counts, 518 output": dict(Counter(s for s, _ in full.values())),
        },
        "verifier_full": v_full,
        "invariance": inv,
    }


def explain(before: dict, after: dict, after_trace: dict) -> list:
    """Root cause per changed case: first matching rule wins."""
    out = []
    bv = before["verifier_full"]["issues"]
    late = {x.split(":")[0] for k in TEMPORAL for x in bv.get(k, [])}
    batch = set(before["invariance"].get("alone_changed", []))
    for var in before["invariance"]["by_variation"].values():
        batch |= set(var["changed_cases"])
    for cid in sorted(after["full"], key=lambda c: int(c.split("_")[1])):
        b, a = before["full"].get(cid), after["full"][cid]
        if b == a:
            continue
        t = after_trace.get(cid, {})
        key = lambda x: (x["operation"], x["resource_id"])
        removed = {key(x) for x in b[1]} - {key(x) for x in a[1]}
        added = {key(x) for x in a[1]} - {key(x) for x in b[1]}
        reextracted = {x.get("resource") for x in (t.get("trace") or {}).get("resources", [])
                       if any("re-extraction" in str(bs) for bs in (x.get("state_basis") or []))}
        if added and {r for _, r in added} <= reextracted and not removed and b[0] == a[0]:
            cause = "extraction: row recovered by the bounded re-extraction step (declared count completed)"
        elif (b[0] == "NOT_APPLICABLE") != (a[0] == "NOT_APPLICABLE"):
            cause = "intent: target-aware rules / negation (" + (t.get("intent", {}).get("reason", "")[:60]) + ")"
        elif cid in late:
            cause = "temporal: old answer used a resource or citation not available at audit_at"
        elif t.get("internal_status") == "UNCERTIFIED":
            cause = "certification: nothing admissible proves the required state (restore needs affirmative evidence)"
        elif (t.get("account_correlation") or {}).get("account") is None and \
                any(s["system_id"] == "account_service" for s in b[1]):
            cause = "attribution: old account came from cross-request pools / queue order; now unresolved"
        elif removed and all(r.startswith("analytics_") for _, r in removed) and not added:
            cause = "attribution: anonymised-analytics run attribution relied on other requests; now unresolved"
        elif added and all(op == "VERIFY_RECORD_PRESENT" for op, _ in added) and not removed:
            cause = "extraction: screen subject filter now links retained records"
        elif cid in batch:
            cause = "attribution: old answer depended on which other requests were in the batch"
        elif any(u.get("reason", "").startswith("account absence unproven") or "prior" in u.get("reason", "")
                 for u in t.get("unresolved", [])):
            cause = "state: pre-request history / unproven absence now tracked as unresolved"
        else:
            cause = "state reconstruction / evidence handling (see trace)"
        out.append((cid, b[0], a[0], len(b[1]), len(a[1]), cause))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--before-dir", required=True)
    ap.add_argument("--after-dir", required=True)
    ap.add_argument("--after-trace", default=str(CODE / "runs" / "trace.jsonl"))
    ap.add_argument("--out", default=str(CODE / "runs" / "compare.json"))
    a = ap.parse_args(argv)
    ver = Verifier(DATASET, CODE / ".cache" / "verifier")
    gold = load_gold(DATASET / "sample_output.csv")
    before, after = side(Path(a.before_dir), ver, gold), side(Path(a.after_dir), ver, gold)
    trace = {}
    tp = Path(a.after_trace)
    if tp.exists():
        for line in tp.read_text(encoding="utf-8").splitlines():
            d = json.loads(line)
            trace[d["case_id"]] = d
    changes = explain(before, after, trace)
    res = {"before": before["metrics"], "after": after["metrics"], "changes": changes,
           "change_causes": dict(Counter(c[-1].split(" (")[0] for c in changes))}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    for k in before["metrics"]:
        print(f"{k:55s} {str(before['metrics'][k]):30s} {after['metrics'][k]}")
    print(res["change_causes"])


if __name__ == "__main__":
    main()
