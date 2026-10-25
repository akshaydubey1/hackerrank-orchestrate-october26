"""Labelled defect fixtures for the independent verifier.

Each fixture starts from a public gold sample answer (or a clean prediction), injects exactly one
defect, and states which verifier issue must be raised for that case. A fixture passes only if
the clean row does NOT raise that issue and the defective row DOES -- so the verifier is shown to
detect the defect rather than to complain about everything.
"""
from __future__ import annotations

import copy
import csv
import json
from pathlib import Path


def _renumber(steps):
    return [dict(s, step_no=i + 1) for i, s in enumerate(steps)]


def _case(gold, cid):
    st, steps = gold[cid]
    return st, copy.deepcopy(steps)


def build_defects(gold: dict, verifier) -> list:
    """Return [(name, case_id, clean_row, defective_row, expected_issue)]."""
    out = []
    # D1 unsupported COMPLETE: an INCOMPLETE answer relabelled COMPLETE with its findings dropped
    st, steps = _case(gold, "case_13")
    bad = _renumber([s for s in steps if s["phase"] == "VERIFICATION"])
    out.append(("unsupported COMPLETE", "case_13", (st, steps), ("COMPLETE", bad), "complete_with_unsupported_verification"))
    # D2 empty INCOMPLETE plan
    st, steps = _case(gold, "case_16")
    out.append(("empty INCOMPLETE plan", "case_16", (st, steps), ("INCOMPLETE", []), "incomplete_empty_plan"))
    # D3 missing retained record: drop the security record's VERIFY_RECORD_PRESENT
    st, steps = _case(gold, "case_11")
    bad = _renumber([s for s in steps if s["resource_id"] != "audit_record_9394"])
    out.append(("missing retained record", "case_11", (st, steps), (st, bad), "missing_retained_record"))
    # D4 future evidence used for planning: add a resource visible only in a file captured after audit_at
    st, steps = _case(gold, "case_25")
    extra = {"step_no": 0, "phase": "VERIFICATION", "system_id": "security_service", "resource_id": "audit_record_1707",
             "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": "evidence_92"}
    bad = _renumber(sorted(steps + [extra], key=lambda s: (s["phase"] != "VERIFICATION",)))
    out.append(("future-only resource planned", "case_25", (st, steps), (st, bad), "resource_not_discoverable_by_audit_at"))
    # D5 wrong subject: another person's search entry reported for this request
    st, steps = _case(gold, "case_20")
    bad = copy.deepcopy(steps)
    for s in bad:
        if s["resource_id"] == "search_4262":
            s["resource_id"] = "search_4013"  # belongs to mori.ren (case_18), same evidence file
    out.append(("incorrect subject attribution", "case_20", (st, steps), (st, bad), "context_names_other_subject"))
    # D6 partial snapshot treated as complete: account absence cited to a multi-capture bundle
    st, steps = _case(gold, "case_25")
    bad = copy.deepcopy(steps)
    for s in bad:
        if s["system_id"] == "account_service":
            s["evidence_id"] = "evidence_45"
    out.append(("partial snapshot used as absence proof", "case_25", (st, steps), (st, bad), "absence_from_partial_capture"))
    # D7 missing recreation risk: the active data flow is left out of the plan
    st, steps = _case(gold, "case_15")
    bad = _renumber([s for s in steps if s["resource_id"] != "data_flow_9846"])
    out.append(("missing recreation risk", "case_15", (st, steps), (st, bad), "missing_recreation_risk"))
    # D8 wrong citation: a finding cites a file that never mentions the resource
    st, steps = _case(gold, "case_06")
    bad = copy.deepcopy(steps)
    for s in bad:
        if s["phase"] == "FINDING":
            s["evidence_id"] = "evidence_56"
    out.append(("wrong citation", "case_06", (st, steps), (st, bad), "citation_does_not_mention_resource"))
    # D9 wrong step order
    st, steps = _case(gold, "case_11")
    bad = copy.deepcopy(steps)
    bad[0], bad[1] = bad[1], bad[0]
    bad = _renumber(bad)
    out.append(("non-canonical step order", "case_11", (st, steps), (st, bad), "noncanonical_order_or_numbering"))
    # D10 citation captured after audit_at
    st, steps = _case(gold, "case_09")
    bad = copy.deepcopy(steps)
    bad[0]["evidence_id"] = "evidence_06"
    out.append(("post-cutoff citation", "case_09", (st, steps), (st, bad), "future_evidence_cited"))
    # D11 incomplete plan: a finding whose remediation was left out
    st, steps = _case(gold, "case_15")
    rem = [s for s in steps if s["phase"] == "REMEDIATION"]
    bad = _renumber([s for s in steps if s is not rem[-1]])
    out.append(("finding without remediation", "case_15", (st, steps), (st, bad), "finding_without_matching_remediation"))
    # D12 retained record deleted: the security record's retention is ignored
    st, steps = _case(gold, "case_11")
    bad = copy.deepcopy(steps)
    for s in bad:
        if s["resource_id"] == "audit_record_9394":
            s.update(phase="REMEDIATION", operation="DELETE_RECORD", state="ABSENT", evidence_id="")
    bad = _renumber(sorted(bad, key=lambda s: ["FINDING", "REMEDIATION", "VERIFICATION"].index(s["phase"])))
    out.append(("retained record deleted", "case_11", (st, steps), (st, bad), "retention_violation"))
    # D13 record treated before the recreation path is closed
    st, steps = _case(gold, "case_11")
    rem = [s for s in steps if s["phase"] == "REMEDIATION"]
    others = [s for s in steps if s["phase"] != "REMEDIATION"]
    bad = _renumber([s for s in others if s["phase"] == "FINDING"] + list(reversed(rem))
                    + [s for s in others if s["phase"] == "VERIFICATION"])
    out.append(("record treated before flow disabled", "case_11", (st, steps), (st, bad),
                "recreation_path_after_record_treatment"))
    # D14 another subject's connector on the same screen: the subject's own flow must be demanded (defective
    # row omits it), but a row naming someone else must not be (clean row is not flagged). Hand-written rows.
    f, r, v = "FINDING", "REMEDIATION", "VERIFICATION"
    clean = [{"step_no": 1, "phase": f, "system_id": "integration_service", "resource_id": "data_flow_1121",
              "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": "evidence_14"},
             {"step_no": 2, "phase": r, "system_id": "integration_service", "resource_id": "data_flow_1121",
              "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""},
             {"step_no": 3, "phase": v, "system_id": "integration_service", "resource_id": "data_flow_1121",
              "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""}]
    out.append(("other subject's flow on the same screen is not demanded; own flow is", "case_39",
                ("INCOMPLETE", clean), ("COMPLETE", []), "missing_recreation_risk"))
    return out


def run(dataset: Path, verifier) -> list:
    gold = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
            for r in csv.DictReader(open(dataset / "sample_output.csv", encoding="utf-8"))}
    reqs = {r["case_id"]: r for f in ("sample_deletion_requests.csv", "deletion_requests.csv")
            for r in csv.DictReader(open(dataset / f, encoding="utf-8"))}
    results = []
    for name, cid, clean, bad, expected in build_defects(gold, verifier):
        def flagged(row):
            res = verifier.verify([reqs[cid]], {cid: row})["issues"].get(expected, [])
            return any(x == cid or x.startswith(cid + ":") for x in res)
        c, b = flagged(clean), flagged(bad)
        results.append((name, cid, expected, (not c) and b, f"clean flagged={c}, defective flagged={b}"))
    return results
