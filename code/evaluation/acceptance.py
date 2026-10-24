"""Acceptance gate over the evaluation results: execution and correctness are reported separately.

    python3 code/evaluation/acceptance.py [--results code/runs/evaluation_results.json]
                                          [--out code/evaluation/acceptance_report.md]

Two gates:
  --mode dev      regression gate: fails on any FAIL (unexpected change, stale/malformed/empty results,
                  missing test identities); recorded exceptions and NOT RUN do not fail it.
  --mode release  strict approval gate: also fails on any EXCEPTION or NOT RUN in the required areas
                  (execution, structure, semantic, coverage). Agent capability and transcript are advisory.
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


MALFORMED = object()


def load(p: Path):
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return MALFORMED


def expected_identities() -> dict:
    """Test identities derived from the CURRENT suite source, independent of any results file."""
    import re as _re
    import tempfile as _tf
    sys.path.insert(0, str(CODE))
    from evaluation import fixtures
    src_main = (HERE / "main.py").read_text(encoding="utf-8")
    src_unit = (HERE / "unit_tests.py").read_text(encoding="utf-8")
    src_vd = (HERE / "verifier_defects.py").read_text(encoding="utf-8")
    with _tf.TemporaryDirectory() as td:
        fx = set(fixtures.build(Path(td) / "w")) - {"__extraction_failures__"}
    fx.add("fx_extraction_failures_recorded")
    meta_block = src_main[src_main.index('for name, fn in [("shuffle'):]
    meta_block = meta_block[:meta_block.index("]:")]
    mut_block = src_main[src_main.index("    return [(\"accept investigation"):]
    mut_block = mut_block[:mut_block.index("]\n")]
    return {
        "fixtures": fx,
        "unit_tests": set(_re.findall(r'\(\(?"(U\d+) ', src_unit)) | set(_re.findall(r'out\.append\(\("(U\d+) ', src_unit)),
        "metamorphic": set(_re.findall(r'\("([^"]+)", meta_\w+\)', meta_block)),
        "mutations": set(_re.findall(r'\("([^"]+)", m_\w+, (?:True|False)\)', mut_block)),
        "semantic": set(_re.findall(r'"(S\d [^"]+)": "', src_main)),
        "verifier_defects": set(_re.findall(r'out\.append\(\("([^"]+)"', src_vd)),
    }


def current_fingerprints() -> dict:
    sys.path.insert(0, str(CODE))
    from ghost_audit.util import code_fingerprint, sha256_file
    ds = CODE.parent / "dataset"
    return {"code": code_fingerprint(CODE),
            "inputs": {p.name: sha256_file(p)[:16] for p in sorted(ds.glob("*.csv")) if p.name != "output.csv"}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(CODE / "runs" / "evaluation_results.json"))
    ap.add_argument("--invariance", default=str(CODE / "runs" / "invariance" / "invariance.json"))
    ap.add_argument("--exceptions", default=str(HERE / "known_exceptions.json"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--mode", choices=["dev", "release"], default="dev",
                    help="dev: regression gate (recorded exceptions tolerated); release: strict approval gate")
    ap.add_argument("--gate-tests", default=str(CODE / "runs" / "gate_tests.json"))
    a = ap.parse_args(argv)
    res, inv, exc = load(Path(a.results)), load(Path(a.invariance)), load(Path(a.exceptions)) or {}
    checks = []  # (area, name, status, detail)

    def add(area, name, status, detail=""):
        checks.append((area, name, status, detail))

    for label, obj, path in (("evaluation results", res, a.results), ("invariance results", inv, a.invariance),
                             ("known exceptions", exc, a.exceptions)):
        if obj is MALFORMED:
            add("execution", f"{label} readable", "FAIL", f"{path} is not valid JSON")
    if res is MALFORMED:
        return finish(checks, a.out, a.mode)
    if inv is MALFORMED:
        inv = None
    if exc is MALFORMED:
        exc = {}

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
        return finish(checks, a.out, a.mode)

    # ------------------------------------------------------------ freshness (results belong to this code + data)
    cur = current_fingerprints()
    env = res.get("environment") or {}
    add("execution", "results produced by the current code (fingerprint)",
        "PASS" if env.get("code_fingerprint") == cur["code"] else "FAIL",
        f"results {str(env.get('code_fingerprint'))[:16]}… vs code {cur['code'][:16]}…")
    add("execution", "results produced from the current inputs (dataset fingerprints)",
        "PASS" if env.get("inputs_sha256") == cur["inputs"] else "FAIL",
        "match" if env.get("inputs_sha256") == cur["inputs"] else
        f"differs: {sorted(k for k in set(cur['inputs']) | set(env.get('inputs_sha256') or {}) if (env.get('inputs_sha256') or {}).get(k) != cur['inputs'].get(k))}")
    inv_manifest = Path(a.invariance).parent / "traces" / "full.manifest.json"
    if inv is not None:
        im = load(inv_manifest)
        fp = im.get("code_fingerprint") if isinstance(im, dict) else None
        add("execution", "invariance results produced by the current code",
            "PASS" if fp == cur["code"] else "FAIL", f"{str(fp)[:16]}…")

    expected = expected_identities()

    def all_pass(area, name, items, idx_ok=1, label=lambda x: x[0], key=None):
        if items is None:
            add(area, name, "NOT RUN", "not produced in this run")
            return
        if not isinstance(items, list) or any(not isinstance(x, (list, tuple)) or len(x) <= idx_ok for x in items):
            add(area, name, "FAIL", "malformed result entries")
            return
        if not items:
            add(area, name, "FAIL", "empty result list (a suite that ran nothing is not a pass)")
            return
        bad = [label(x) for x in items if x[idx_ok] is not True]
        detail = f"{len(items) - len(bad)}/{len(items)}" + (f"; failing: {bad}" if bad else "")
        missing = []
        if key and key in expected:
            got = {label(x) for x in items} if key != "unit_tests" else {label(x).split()[0] for x in items}
            missing = sorted(expected[key] - got)
            detail += f"; expected identities {len(expected[key])}" + (f", MISSING {missing[:6]}" if missing else ", all present")
        add(area, name, "PASS" if not bad and not missing else "FAIL", detail)

    # ------------------------------------------------------------ evaluation coverage
    all_pass("coverage", "unit tests", res.get("unit_tests"), key="unit_tests")
    all_pass("coverage", "independent synthetic cases", res.get("fixtures"), key="fixtures")
    all_pass("coverage", "metamorphic transformations", res.get("metamorphic"), key="metamorphic")
    all_pass("coverage", "deliberate semantic changes", res.get("semantic"), key="semantic")
    all_pass("coverage", "operational reliability", res.get("operational"))
    all_pass("coverage", "mutants detected", res.get("mutations"), key="mutations")
    vd = res.get("verifier_defects")
    all_pass("coverage", "verifier labelled defects detected", vd, idx_ok=3, key="verifier_defects")
    gt = load(Path(a.gate_tests))
    if gt is None:
        add("coverage", "acceptance-gate self-tests", "NOT RUN", "no gate_tests.json")
    elif gt is MALFORMED or not isinstance(gt, list) or not gt:
        add("coverage", "acceptance-gate self-tests", "FAIL", "malformed or empty")
    else:
        bad = [t["name"] for t in gt if t.get("passed") is False]
        na = [t["name"] for t in gt if t.get("passed") is None]
        add("coverage", "acceptance-gate self-tests", "FAIL" if bad else ("NOT RUN" if na else "PASS"),
            f"{len(gt) - len(bad) - len(na)}/{len(gt)} passed" + (f"; failing: {bad}" if bad else "")
            + (f"; not applicable: {na}" if na else ""))
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
    return finish(checks, a.out, a.mode)


VERDICT_AREAS = [("execution", "Reproducibility (execution)"), ("structure", "Structural output validity"),
                 ("semantic", "Semantic correctness"), ("coverage", "Evaluation coverage"),
                 ("agent", "Agent capability"), ("transcript", "Transcript completeness")]


RELEASE_REQUIRED = ("execution", "structure", "semantic", "coverage")   # agent, transcript: advisory


def finish(checks, out, mode="dev") -> int:
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
        return "PASS"
    fails = [c for c in checks if c[2] == "FAIL"]
    blockers = [c for c in checks if c[0] in RELEASE_REQUIRED and c[2] in ("FAIL", "EXCEPTION", "NOT RUN")]
    regression_ok = not fails
    release_ok = not blockers
    L = ["# Acceptance report", "",
         "_Generated by `python3 code/evaluation/acceptance.py` from `code/runs/evaluation_results.json`. "
         "EXCEPTION = known unresolved issue with a recorded rationale and exact case list; it documents "
         "uncertainty and never establishes correctness._", "",
         "## Gate results", "",
         "| Gate | Result | Meaning |", "|---|---|---|",
         f"| Regression gate (dev) | {'PASS' if regression_ok else 'FAIL'} | no unexpected change: every check is "
         "PASS, a recorded EXCEPTION with an identical case set, or NOT RUN |",
         f"| Release gate (strict) | {'APPROVED' if release_ok else 'BLOCKED'} | every required area "
         "(execution, structure, semantic, coverage) fully PASS: no exceptions, nothing missing, empty, stale or "
         "malformed |", "",
         f"_Exit status of this run (`--mode {mode}`): {0 if (regression_ok if mode == 'dev' else release_ok) else 1}._", ""]
    if blockers:
        L += ["Release blockers:", ""] + [f"* {c[0]} / {c[1]}: {c[2]} — {c[3][:200]}" for c in blockers] + [""]
    L += ["## Verdicts by area", "", "| Area | Verdict | Release |", "|---|---|---|"]
    for area, label in VERDICT_AREAS:
        L.append(f"| {label} | {verdict(area)} | {'required' if area in RELEASE_REQUIRED else 'advisory'} |")
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
    return 0 if (regression_ok if mode == "dev" else release_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
