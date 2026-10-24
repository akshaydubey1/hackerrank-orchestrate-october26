"""Output-contract validation (structure only; evidence support is checked by verifier.py)."""
from __future__ import annotations

import csv
import io
import json
import re

from .planner import ORDER, PHASE_OF, STATE_OF

STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
EVIDENCE_RE = re.compile(r"^(evidence|activity|audit)_\d+$")


def case_key(cid: str):
    m = re.match(r"^(.*?)(\d+)$", cid)
    return (m.group(1), int(m.group(2))) if m else (cid, 0)


def validate_steps(status: str, steps: list, known_evidence: set | None = None) -> list:
    errs = []
    if status == "NOT_APPLICABLE":
        return [] if steps == [] else ["NOT_APPLICABLE must have []"]
    if not steps:
        errs.append(f"{'WARNING: ' if status == 'INCOMPLETE' else ''}{status} with no steps")
    prev = -1
    seen = set()
    for i, s in enumerate(steps, 1):
        if set(s) != FIELDS:
            errs.append(f"step {i}: fields {sorted(set(s) ^ FIELDS)}")
            continue
        if s["step_no"] != i:
            errs.append(f"step {i}: step_no {s['step_no']}")
        op = s["operation"]
        if op not in ORDER:
            errs.append(f"step {i}: unknown operation {op}")
            continue
        if PHASE_OF[op] != s["phase"] or STATE_OF[op] != s["state"]:
            errs.append(f"step {i}: phase/state mismatch for {op}")
        k = (ORDER[op], s["system_id"], s["resource_id"])
        if k[0] < prev:
            errs.append(f"step {i}: ordering")
        prev = k[0]
        if k in seen:
            errs.append(f"step {i}: duplicate")
        seen.add(k)
        ev = s["evidence_id"]
        if s["phase"] == "FINDING" and not ev:
            errs.append(f"step {i}: finding without evidence")
        if status == "INCOMPLETE" and s["phase"] != "FINDING" and ev:
            errs.append(f"step {i}: future work must have empty evidence_id")
        if status == "COMPLETE":
            if s["phase"] != "VERIFICATION":
                errs.append(f"step {i}: COMPLETE may only contain verification")
            if not ev:
                errs.append(f"step {i}: COMPLETE verification without evidence")
        if ev and not EVIDENCE_RE.match(ev):
            errs.append(f"step {i}: malformed evidence id {ev}")
        if ev and known_evidence is not None and ev not in known_evidence:
            errs.append(f"step {i}: unknown evidence id {ev}")
    if status == "INCOMPLETE":
        phases = [s.get("phase") for s in steps]
        if "FINDING" not in phases:
            errs.append("WARNING: INCOMPLETE without findings (uncertified case)")
        # every finding needs remediation and a verification on the same resource
        fres = {(s["system_id"], s["resource_id"]) for s in steps if s.get("phase") == "FINDING"}
        rres = {(s["system_id"], s["resource_id"]) for s in steps if s.get("phase") == "REMEDIATION"}
        vres = {(s["system_id"], s["resource_id"]) for s in steps if s.get("phase") == "VERIFICATION"}
        if fres - rres:
            errs.append(f"findings without remediation: {sorted(fres - rres)}")
        if rres - vres:
            errs.append(f"remediation without verification: {sorted(rres - vres)}")
    return errs


def validate_rows(rows: list, expected_ids: list, known_evidence: set | None = None) -> list:
    errs = []
    ids = [r["case_id"] for r in rows]
    if sorted(ids, key=case_key) != ids:
        errs.append("rows not sorted by case_id")
    if set(ids) != set(expected_ids) or len(ids) != len(expected_ids):
        errs.append(f"case coverage mismatch: {len(ids)} rows vs {len(expected_ids)} expected")
    # CSV/JSON round trip
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["case_id", "deletion_status", "steps_json"])
    w.writeheader()
    w.writerows(rows)
    back = list(csv.DictReader(io.StringIO(buf.getvalue())))
    for a, b in zip(rows, back):
        if a != b:
            errs.append(f"{a['case_id']}: CSV round trip changed the row")
    for r in rows:
        if r["deletion_status"] not in STATUSES:
            errs.append(f"{r['case_id']}: bad status")
        try:
            steps = json.loads(r["steps_json"])
        except json.JSONDecodeError:
            errs.append(f"{r['case_id']}: invalid JSON")
            continue
        if not isinstance(steps, list):
            errs.append(f"{r['case_id']}: steps_json not an array")
            continue
        errs += [f"{r['case_id']}: {e}" for e in validate_steps(r["deletion_status"], steps, known_evidence)]
    return errs
