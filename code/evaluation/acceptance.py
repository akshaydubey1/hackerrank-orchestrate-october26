"""Acceptance gate over the evaluation results: execution and correctness are reported separately.

    python3 code/evaluation/acceptance.py [--results code/runs/evaluation_results.json]
                                          [--out code/evaluation/acceptance_report.md]

Every check is PASS, FAIL, EXCEPTION or NOT RUN.
  EXCEPTION  a known, unresolved semantic issue recorded in `known_exceptions.json` with a rationale
             and the exact affected cases. It is never shown as PASS. If the affected cases differ
             from the recorded list in any way (new case, missing case), the check is FAIL, so a
             new issue cannot hide behind an old exception.
  NOT RUN    the input for the check was not produced (e.g. --quick, no invariance run).
Exit status is 1 if any check FAILs (exceptions and NOT RUN do not fail the gate, but are listed).
Sample metrics are compared with the recorded values: any drop is FAIL (unexplained regression);
the recorded values are not a correctness threshold.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(CODE / "runs" / "evaluation_results.json"))
    ap.add_argument("--invariance", default=str(CODE / "runs" / "invariance" / "invariance.json"))
    ap.add_argument("--exceptions", default=str(HERE / "known_exceptions.json"))
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    res, inv, exc = load(Path(a.results)), load(Path(a.invariance)), load(Path(a.exceptions)) or {}
    checks = []  # (area, name, status, detail)

    def add(area, name, status, detail=""):
        checks.append((area, name, status, detail))

    # ------------------------------------------------------------ execution
    if res is None:
        add("execution", "evaluation results present", "FAIL", f"{a.results} missing")
    else:
        add("execution", "evaluation results present", "PASS", f"suite runtime {res.get('seconds')} s")
        ct = res.get("contract", {})
        add("execution", "output.csv present and identical to a fresh prediction",
            "PASS" if ct.get("present") and ct.get("matches_fresh_prediction") else "FAIL",
            f"sha256 {ct.get('sha256', '?')[:16]}…")
    if res is None:
        return finish(checks, a.out)

    def all_pass(area, name, items, idx_ok=1, label=lambda x: x[0]):
        if items is None:
            add(area, name, "NOT RUN", "not produced in this run")
            return
        bad = [label(x) for x in items if not x[idx_ok]]
        add(area, name, "PASS" if not bad else "FAIL", f"{len(items) - len(bad)}/{len(items)}" + (f"; failing: {bad}" if bad else ""))

    # ------------------------------------------------------------ evaluation coverage
    all_pass("coverage", "unit tests", res.get("unit_tests"))
    all_pass("coverage", "independent synthetic cases", res.get("fixtures"))
    all_pass("coverage", "metamorphic transformations", res.get("metamorphic"))
    all_pass("coverage", "deliberate semantic changes", res.get("semantic"))
    all_pass("coverage", "operational reliability", res.get("operational"))
    all_pass("coverage", "mutants detected", res.get("mutations"))
    vd = res.get("verifier_defects")
    all_pass("coverage", "verifier labelled defects detected", vd, idx_ok=3)
    if inv is None:
        add("coverage", "request-batch invariance", "NOT RUN", "no invariance.json")
    else:
        add("coverage", "request-batch invariance", "PASS" if inv["total_changed"] == 0 else "FAIL",
            f"{inv['total_changed']}/{inv['total_compared']} changed")
    ff = res.get("failfirst")
    if not ff:
        add("coverage", "fail-first evidence", "NOT RUN", "no failfirst results")
    else:
        newbad = [c for c, v in ff["new"].items() if not v["pass"]]
        add("coverage", "fail-first: every regression test passes on this code", "PASS" if not newbad else "FAIL",
            f"{len(ff['new']) - len(newbad)}/{len(ff['new'])}")

    # ------------------------------------------------------------ structural output validity
    ct = res.get("contract", {})
    add("structure", "output contract (fields, op/state, order, numbering, evidence ids, sort, round trip)",
        "PASS" if ct.get("present") and not ct.get("errors") and ct.get("rows") == ct.get("expected_rows") else "FAIL",
        f"{ct.get('rows')} rows, {len(ct.get('errors', []))} errors")
    add("structure", "no empty INCOMPLETE rows in the 518 output",
        "PASS" if not ct.get("empty_incomplete") else "FAIL", f"{ct.get('empty_incomplete')}")

    # ------------------------------------------------------------ semantic correctness
    def issue_check(name, issues: dict, recorded: dict):
        keys = sorted(set(issues) | set(recorded))
        if not keys:
            add("semantic", f"{name}: no issues", "PASS")
        for k in keys:
            got = sorted(issues.get(k, []))
            rec = recorded.get(k)
            if not got and rec:
                add("semantic", f"{name}: `{k}`", "FAIL", f"recorded exception no longer occurs ({len(rec['cases'])} cases): update the record")
            elif got and not rec:
                add("semantic", f"{name}: `{k}`", "FAIL", f"{len(got)} unrecorded: {got[:12]}")
            elif got and sorted(rec["cases"]) != got:
                new = sorted(set(got) - set(rec["cases"]))
                gone = sorted(set(rec["cases"]) - set(got))
                add("semantic", f"{name}: `{k}`", "FAIL", f"case set changed: +{new[:10]} -{gone[:10]}")
            elif got:
                add("semantic", f"{name}: `{k}`", "EXCEPTION", f"{len(got)} cases — {rec['rationale']}")
    issue_check("verifier on the 518 output", res["verifier_eval"]["issues"], exc.get("verifier_eval", {}))
    issue_check("verifier on the sample predictions", res["verifier_samples_pred"]["issues"], exc.get("verifier_samples_pred", {}))
    issue_check("verifier on the gold answers (false-alarm check)", res["verifier_gold"]["issues"], exc.get("verifier_gold", {}))
    unc = sorted(c for c, v in res.get("internal", {}).items() if v["internal"] == "UNCERTIFIED")
    rec = exc.get("uncertified", {})
    if unc:
        if sorted(rec.get("cases", [])) == unc:
            add("semantic", "uncertified decisions (no proof either way)", "EXCEPTION", f"{len(unc)} cases — {rec['rationale']}")
        else:
            add("semantic", "uncertified decisions (no proof either way)", "FAIL",
                f"case set differs from the record: +{sorted(set(unc) - set(rec.get('cases', [])))[:10]} "
                f"-{sorted(set(rec.get('cases', [])) - set(unc))[:10]}")
    s = res["samples"]
    exp = exc.get("sample_expected", {})
    cur = {"status_correct": s["status_correct"], "exact_sequence_n": s["exact_sequence_n"], "tp": s["tp"],
           "fp": s["fp"], "fn": s["fn"]}
    worse = [k for k in ("status_correct", "exact_sequence_n", "tp") if k in exp and cur[k] < exp[k]] + \
            [k for k in ("fp", "fn") if k in exp and cur[k] > exp[k]]
    add("semantic", "sample metrics vs recorded values (regression check, not a correctness threshold)",
        "FAIL" if worse else "PASS", f"current {cur}; recorded {exp}" + (f"; worse: {worse}" if worse else ""))
    other = [t for t in res.get("sample_miss_causes", []) if t[4].startswith(("other", "PARSER/RETRIEVAL"))]
    add("semantic", "every sample miss has a classified cause and none is a missed admissible link",
        "PASS" if not other else "FAIL",
        f"{len(res.get('sample_miss_causes', []))} misses; unclassified: {[t[:3] for t in other][:6]}")

    # ------------------------------------------------------------ agent capability
    ae = res.get("agent_eval")
    if not ae:
        add("agent", "labelled investigation evaluation", "NOT RUN", "--quick")
    else:
        lad = next(r for r in ae if r["strategy"] == "ladder_b3")
        base = next(r for r in ae if r["strategy"] == "baseline")
        add("agent", "deterministic investigation: no decoy accepted", "PASS" if lad["decoys_wrongly_verified"] == 0 else "FAIL",
            f"{lad['decoys_wrongly_verified']}/{lad['decoy_cases']} decoys accepted")
        add("agent", "deterministic investigation vs no investigation (labelled set)", "PASS"
            if lad["true_verified"] >= base["true_verified"] else "FAIL",
            f"{lad['true_verified']} vs {base['true_verified']} of {lad['true_cases']} true identifiers")
        mod = next(r for r in ae if r["strategy"] == "model")
        add("agent", "model-driven investigation policy against a real provider",
            "NOT RUN" if mod["status"] != "RUN" else "PASS", mod["status"])
    # ------------------------------------------------------------ transcript
    tr = exc.get("transcript")
    if tr:
        add("transcript", "agent trace completeness", tr["status"], tr["rationale"])
    return finish(checks, a.out)


VERDICT_AREAS = [("execution", "Reproducibility (execution)"), ("structure", "Structural output validity"),
                 ("semantic", "Semantic correctness"), ("coverage", "Evaluation coverage"),
                 ("agent", "Agent capability"), ("transcript", "Transcript completeness")]


def finish(checks, out) -> int:
    def verdict(area):
        sts = [c[2] for c in checks if c[0] == area]
        if not sts:
            return "NOT RUN"
        if "FAIL" in sts:
            return "FAIL"
        if "EXCEPTION" in sts:
            return f"NOT ESTABLISHED ({sts.count('EXCEPTION')} recorded exceptions)"
        if "NOT RUN" in sts:
            return f"PARTIAL ({sts.count('NOT RUN')} checks not run)"
        if "PARTIAL" in sts:
            return "PARTIAL"
        return "PASS"
    L = ["# Acceptance report", "",
         "_Generated by `python3 code/evaluation/acceptance.py` from `code/runs/evaluation_results.json`. "
         "EXCEPTION = known unresolved issue with a recorded rationale and exact case list (never counted as PASS); "
         "the gate fails on any FAIL._", "", "## Verdicts by area", "", "| Area | Verdict |", "|---|---|"]
    for area, label in VERDICT_AREAS:
        L.append(f"| {label} | {verdict(area)} |")
    L += ["", "## Checks", "", "| Area | Check | Status | Detail |", "|---|---|---|---|"]
    for area, name, st, detail in checks:
        L.append(f"| {area} | {name} | {'**' + st + '**' if st in ('FAIL', 'EXCEPTION') else st} | {detail} |")
    text = "\n".join(L) + "\n"
    if out:
        Path(out).write_text(text, encoding="utf-8")
    summ = os.environ.get("GITHUB_STEP_SUMMARY")
    if summ:
        with open(summ, "a", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return 1 if any(c[2] == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    sys.exit(main())
