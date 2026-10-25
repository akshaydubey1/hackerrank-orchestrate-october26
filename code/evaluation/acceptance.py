"""Acceptance gates over the evaluation results. Three separate verdicts:

    python3 code/evaluation/acceptance.py --mode dev         # regression gate (development)
    python3 code/evaluation/acceptance.py --mode release     # strict release gate
    python3 code/evaluation/acceptance.py --mode submission  # submission-readiness assessment

  dev         fails on any FAIL: an unexpected change, stale or foreign results (prediction code,
              evaluation code, evidence contents, configuration), missing / duplicate / unexpected /
              malformed test identities against `test_registry.json`, empty or incomplete fail-first or
              batch-invariance coverage, a sample mismatch without a classification. Recorded exceptions
              (`known_exceptions.json`) and NOT RUN do not fail it.
  release     additionally fails on any EXCEPTION or NOT RUN in the required areas (execution, structure,
              semantic, coverage), and on a required area with no checks at all. An exception documents
              uncertainty; it never establishes correctness.
  submission  checks the artifacts the official contract requires (output.csv, code.zip contents, log.txt
              entries with tool= and model=, the separately submitted agent trace). Running a model at
              runtime is not a contract requirement and is not checked here.
Every check is PASS, FAIL, EXCEPTION or NOT RUN.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
ROOT = CODE.parent
MALFORMED = object()
SECRET_RE = re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|"
                       rb"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{40,}|AKIA[0-9A-Z]{16}")
# a key header without a key body (e.g. the text of a scan pattern) is not a credential


def load(p: Path):
    if p is None or not Path(p).exists():
        return None
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return MALFORMED


def current_fingerprints() -> dict:
    sys.path.insert(0, str(CODE))
    from ghost_audit.util import code_fingerprint, config_fingerprint, dataset_digest, sha256_file
    from evaluation.fingerprints import evaluation_fingerprint
    ds = ROOT / "dataset"
    return {"code_fingerprint": code_fingerprint(CODE), "evaluation_fingerprint": evaluation_fingerprint(),
            "dataset_digest": dataset_digest(ds), "config": config_fingerprint(),
            "inputs_sha256": {p.name: sha256_file(p)[:16] for p in sorted(ds.glob("*.csv")) if p.name != "output.csv"}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(CODE / "runs" / "evaluation_results.json"))
    ap.add_argument("--invariance", default=str(CODE / "runs" / "invariance" / "invariance.json"))
    ap.add_argument("--exceptions", default=str(HERE / "known_exceptions.json"))
    ap.add_argument("--registry", default=str(HERE / "test_registry.json"))
    ap.add_argument("--gate-tests", default=str(CODE / "runs" / "gate_tests.json"))
    ap.add_argument("--mode", choices=["dev", "release", "submission"], default="dev")
    ap.add_argument("--code-zip", default=str(ROOT / "code.zip"))
    ap.add_argument("--log", default=str(ROOT / "log.txt"))
    ap.add_argument("--agent-trace", default=None, help="path of agent-trace.zip (kept outside the repository)")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    checks = []

    def add(area, name, status, detail=""):
        checks.append((area, name, status, str(detail)))

    res, inv, exc, reg = load(a.results), load(a.invariance), load(a.exceptions), load(a.registry)
    for label, obj, path in (("evaluation results", res, a.results), ("invariance results", inv, a.invariance),
                             ("known exceptions", exc, a.exceptions), ("test registry", reg, a.registry)):
        if obj is MALFORMED:
            add("execution", f"{label} readable", "FAIL", f"{path} is not valid JSON")
    reg = reg if isinstance(reg, dict) else None
    exc = exc if isinstance(exc, dict) else {}
    inv = inv if isinstance(inv, dict) else None
    if res is None or res is MALFORMED or not isinstance(res, dict):
        add("execution", "evaluation results present", "FAIL", f"{a.results} missing or unreadable")
        checks += submission_checks(ROOT / "output.csv", Path(a.code_zip), Path(a.log),
                                    Path(a.agent_trace) if a.agent_trace else None)
        return finish(checks, a.out, a.mode)
    if reg is None:
        add("coverage", "test registry present", "FAIL", f"{a.registry} missing or unreadable")
        reg = {}

    # ------------------------------------------------------------ execution: presence and freshness
    ct = res.get("contract") or {}
    add("execution", "evaluation results present", "PASS", f"suite runtime {res.get('seconds')} s")
    add("execution", "output.csv present and identical to a fresh prediction",
        "PASS" if ct.get("present") and ct.get("matches_fresh_prediction") else "FAIL", f"sha256 {str(ct.get('sha256'))[:16]}…")
    cur = current_fingerprints()
    env = res.get("environment") or {}
    for key, label in (("code_fingerprint", "prediction code"), ("evaluation_fingerprint", "evaluation code"),
                       ("dataset_digest", "evidence-file contents (every dataset file)"),
                       ("inputs_sha256", "input CSVs"), ("config", "run configuration")):
        got = env.get(key)
        ok = got is not None and got == cur[key]
        add("execution", f"results are fresh: {label}", "PASS" if ok else "FAIL",
            "match" if ok else ("absent from results" if got is None else "differs from the current files"))
    if inv is not None:
        im = load(Path(a.invariance).parent / "traces" / "full.manifest.json")
        im = im if isinstance(im, dict) else {}
        ok = im.get("code_fingerprint") == cur["code_fingerprint"] and im.get("dataset_digest") == cur["dataset_digest"]
        add("execution", "invariance results are fresh (prediction code and evidence contents)",
            "PASS" if ok else "FAIL", "match" if ok else "manifest missing or differs")

    # ------------------------------------------------------------ coverage: exact identities
    def suite(name, items, key, ok_idx=1, id_of=lambda x: x[0]):
        expected = reg.get(key)
        if not isinstance(expected, list) or not expected:
            add("coverage", name, "FAIL", f"registry has zero expected identities for `{key}`")
            return
        if items is None:
            add("coverage", name, "NOT RUN", "not produced in this run")
            return
        if not isinstance(items, list) or not items:
            add("coverage", name, "FAIL", "empty or non-list results (a suite that ran nothing is not a pass)")
            return
        bad_shape = [x for x in items if not isinstance(x, (list, tuple)) or len(x) <= ok_idx
                     or not isinstance(x[0], str) or not isinstance(x[ok_idx], bool)]
        if bad_shape:
            add("coverage", name, "FAIL", f"{len(bad_shape)} malformed entries (identity must be a string, result a boolean)")
            return
        ids = [id_of(x) for x in items]
        dup = sorted(i for i, n in Counter(ids).items() if n > 1)
        missing = sorted(set(expected) - set(ids))
        unexpected = sorted(set(ids) - set(expected))
        failing = [id_of(x) for x in items if x[ok_idx] is not True]
        problems = [f"MISSING {missing[:5]}" if missing else "", f"DUPLICATE {dup[:5]}" if dup else "",
                    f"UNEXPECTED {unexpected[:5]}" if unexpected else "", f"failing {failing[:5]}" if failing else ""]
        problems = [p for p in problems if p]
        add("coverage", name, "FAIL" if problems else "PASS",
            f"{len(items) - len(failing)}/{len(items)} pass; {len(expected)} registered identities, "
            + ("; ".join(problems) if problems else "exact match"))

    suite("unit tests", res.get("unit_tests"), "unit_tests", id_of=lambda x: x[0].split()[0])
    suite("independent synthetic cases", res.get("fixtures"), "fixtures")
    suite("metamorphic transformations", res.get("metamorphic"), "metamorphic")
    suite("deliberate semantic changes", res.get("semantic"), "semantic")
    suite("operational reliability", res.get("operational"), "operational")
    suite("mutants detected", res.get("mutations"), "mutations")
    suite("verifier labelled defects detected", res.get("verifier_defects"), "verifier_defects", ok_idx=3)

    gt = load(a.gate_tests)
    exp_gt = reg.get("gate_tests")
    if gt is None:
        add("coverage", "acceptance-gate self-tests", "NOT RUN", "no gate_tests.json")
    elif gt is MALFORMED or not isinstance(gt, list) or not gt or not exp_gt:
        add("coverage", "acceptance-gate self-tests", "FAIL", "malformed, empty, or no registered identities")
    else:
        names = [t.get("name") for t in gt]
        missing, unexpected = sorted(set(exp_gt) - set(names)), sorted(set(names) - set(exp_gt))
        bad = [t["name"] for t in gt if t.get("passed") is False]
        na = [t["name"] for t in gt if t.get("passed") is None]
        st = "FAIL" if bad or missing or unexpected or len(set(names)) != len(names) else ("NOT RUN" if na else "PASS")
        add("coverage", "acceptance-gate self-tests", st,
            f"{len(gt) - len(bad) - len(na)}/{len(gt)} passed" + (f"; failing {bad[:3]}" if bad else "")
            + (f"; not applicable {na}" if na else "") + (f"; MISSING {missing[:3]}" if missing else "")
            + (f"; UNEXPECTED {unexpected[:3]}" if unexpected else ""))

    ff = res.get("failfirst")
    exp_ff = sorted(set(reg.get("fixtures", [])) - {"fx_extraction_failures_recorded"}) + list(reg.get("unit_tests", []))
    if not ff:
        add("coverage", "fail-first evidence", "NOT RUN", "no fail-first results")
    else:
        new = ff.get("new") if isinstance(ff.get("new"), dict) else {}
        missing, unexpected = sorted(set(exp_ff) - set(new)), sorted(set(new) - set(exp_ff))
        failing = sorted(k for k, v in new.items() if not (isinstance(v, dict) and v.get("pass") is True))
        st = "FAIL" if (not new or missing or unexpected or failing) else "PASS"
        add("coverage", "fail-first: every registered regression test passes on this code", st,
            f"{len(new)} results for {len(exp_ff)} registered tests" + (f"; MISSING {missing[:4]}" if missing else "")
            + (f"; UNEXPECTED {unexpected[:4]}" if unexpected else "") + (f"; failing {failing[:4]}" if failing else ""))
        for tag in ("base", "prev"):
            old = ff.get(tag)
            if isinstance(old, dict) and old:
                kinds = Counter((v.get("kind", "behaviour"), bool(v.get("pass"))) for v in old.values())
                add("coverage", f"fail-first against {ff.get(tag + '_rev', tag)} (informational)", "PASS",
                    f"behavioural failures {kinds[('behaviour', False)]}, harness-incompatible "
                    f"{kinds[('harness-incompatible', False)]}, passing {kinds[('behaviour', True)] + kinds[('harness-incompatible', True)]}")

    spec = reg.get("invariance") or {}
    if inv is None:
        add("coverage", "request-batch invariance", "NOT RUN", "no invariance.json")
    elif not spec:
        add("coverage", "request-batch invariance", "FAIL", "registry has no invariance specification")
    else:
        byv = inv.get("by_variation") or {}
        wrong = {k: (byv.get(k, {}).get("compared"), n) for k, n in spec.get("variations", {}).items()
                 if byv.get(k, {}).get("compared") != n}
        extra = sorted(set(byv) - set(spec.get("variations", {})))
        ok = (not wrong and not extra and inv.get("alone_runs") == spec.get("alone_runs")
              and inv.get("total_compared") == spec.get("total_compared") and inv.get("total_changed") == 0)
        add("coverage", "request-batch invariance (complete coverage, zero changes)", "PASS" if ok else "FAIL",
            f"{inv.get('total_changed')}/{inv.get('total_compared')} changed; expected {spec.get('total_compared')} comparisons"
            + (f"; wrong or missing variations {wrong}" if wrong else "") + (f"; unexpected {extra}" if extra else "")
            + (f"; alone runs {inv.get('alone_runs')} vs {spec.get('alone_runs')}" if inv.get("alone_runs") != spec.get("alone_runs") else ""))

    # ------------------------------------------------------------ structural output validity
    add("structure", "output contract (fields, op/state, order, numbering, evidence ids, sort, round trip)",
        "PASS" if ct.get("present") and not ct.get("errors") and ct.get("rows") == ct.get("expected_rows") else "FAIL",
        f"{ct.get('rows')} rows, {len(ct.get('errors') or [])} errors")
    add("structure", "no empty INCOMPLETE rows in the 518 output",
        "PASS" if ct.get("present") and not ct.get("empty_incomplete") else "FAIL", f"{ct.get('empty_incomplete')}")

    # ------------------------------------------------------------ semantic correctness
    def issue_check(name, issues, recorded):
        issues = issues if isinstance(issues, dict) else {}
        recorded = recorded if isinstance(recorded, dict) else {}
        keys = sorted(set(issues) | set(recorded))
        if not keys:
            add("semantic", f"{name}: no issues", "PASS")
        for k in keys:
            got, rec = sorted(issues.get(k, [])), recorded.get(k)
            if not got and rec:
                add("semantic", f"{name}: `{k}`", "FAIL", f"recorded exception no longer occurs: update the record")
            elif got and not rec:
                add("semantic", f"{name}: `{k}`", "FAIL", f"{len(got)} unrecorded: {got[:10]}")
            elif got and sorted(rec["cases"]) != got:
                add("semantic", f"{name}: `{k}`", "FAIL",
                    f"case set changed: +{sorted(set(got) - set(rec['cases']))[:8]} -{sorted(set(rec['cases']) - set(got))[:8]}")
            elif got:
                add("semantic", f"{name}: `{k}`", "EXCEPTION", f"{len(got)} cases — {rec['rationale']}")
    issue_check("verifier on the 518 output", (res.get("verifier_eval") or {}).get("issues"), exc.get("verifier_eval"))
    issue_check("verifier on the sample predictions", (res.get("verifier_samples_pred") or {}).get("issues"),
                exc.get("verifier_samples_pred"))
    issue_check("verifier on the gold answers (false-alarm check)", (res.get("verifier_gold") or {}).get("issues"),
                exc.get("verifier_gold"))
    unc = sorted(c for c, v in (res.get("internal") or {}).items() if v.get("internal") == "UNCERTIFIED")
    rec = exc.get("uncertified") or {}
    if unc:
        if sorted(rec.get("cases", [])) == unc:
            add("semantic", "uncertified decisions (no proof either way)", "EXCEPTION", f"{len(unc)} unique cases — {rec['rationale']}")
        else:
            add("semantic", "uncertified decisions (no proof either way)", "FAIL",
                f"case set differs from the record: +{sorted(set(unc) - set(rec.get('cases', [])))[:8]} "
                f"-{sorted(set(rec.get('cases', [])) - set(unc))[:8]}")
    s = res.get("samples") or {}
    exp = exc.get("sample_expected", {})
    curm = {k: s.get(k) for k in ("status_correct", "exact_sequence_n", "tp", "fp", "fn")}
    worse = [k for k in ("status_correct", "exact_sequence_n", "tp") if k in exp and (curm[k] or 0) < exp[k]] + \
            [k for k in ("fp", "fn") if k in exp and (curm[k] or 0) > exp[k]]
    add("semantic", "sample metrics vs recorded values (regression check, not a correctness threshold)",
        "FAIL" if worse or not exp else "PASS", f"current {curm}; recorded {exp}" + (f"; worse: {worse}" if worse else ""))
    causes = res.get("sample_miss_causes")
    total = res.get("sample_missing_steps_total")
    if causes is None or total is None:
        add("semantic", "every missing sample step has a classification (bookkeeping)", "NOT RUN", "fields absent")
    else:
        unclassified = [c[:3] for c in causes if not c[4] or c[4].startswith("other")]
        ok = len(causes) == total and not unclassified
        add("semantic", "every missing sample step has a classification (bookkeeping)", "PASS" if ok else "FAIL",
            f"{len(causes)} classifications for {total} missing steps" + (f"; unclassified {unclassified[:4]}" if unclassified else ""))
    rc = res.get("sample_retrieval_check")
    name_r = "retrieval: no missed sample step whose resource is absent from the prediction is named with the subject in admissible evidence"
    name_c = "citation: missed cited steps whose resource IS predicted (same case) and whose admissible evidence names the subject"
    if rc is None:
        add("semantic", name_r, "NOT RUN", "field absent")
    elif any("resource_in_prediction" not in x for x in rc) or len(rc) != (total or 0):
        add("semantic", name_r, "FAIL", f"{len(rc)} entries for {total} missed steps, or entries without `resource_in_prediction`")
    else:
        hits = [x for x in rc if x["admissible_files_naming_subject"]]
        omitted = [(x["case"], x["resource"], x["admissible_files_naming_subject"]) for x in hits if not x["resource_in_prediction"]]
        add("semantic", name_r, "FAIL" if omitted else "PASS",
            f"{len(rc)} missed steps searched in the verifier's own extraction; {len(omitted)} retrieval omissions"
            + (f": {omitted[:3]}" if omitted else "")
            + f" among the {sum(1 for x in rc if not x['resource_in_prediction'])} whose resource is absent from the prediction. "
            "Scope: only the 32 public samples, only resources the gold answers name, matched by plain-text search "
            "of the verifier's own extraction for a user_id or e-mail (current or historical) of the subject in the "
            "same context, in files and lines dated by audit_at. Phones and hashes are not searched. This is not "
            "exhaustive evidence discovery and does not cover the 518 evaluation cases.")
        withheld = [x for x in hits if x["resource_in_prediction"]]
        outside = sorted({x["case"] for x in withheld if x.get("internal_status") != "UNCERTIFIED"})
        if not withheld:
            add("semantic", name_c, "PASS", "none")
        elif outside:
            add("semantic", name_c, "FAIL", f"{len(withheld)} steps; in cases that are not uncertified: {outside[:5]}")
        else:
            add("semantic", name_c, "EXCEPTION",
                f"{len(withheld)} steps in {len({x['case'] for x in withheld})} uncertified sample cases "
                f"{sorted({x['case'] for x in withheld})}: the resource is retrieved and the check emitted, but without a "
                "citation, because an uncertified row carries future checks only (review packet 3, owner decision)")

    # ------------------------------------------------------------ agent capability (advisory)
    ae = res.get("agent_eval")
    if not ae:
        add("agent", "labelled investigation evaluation", "NOT RUN", "--quick")
    else:
        lad = next((r for r in ae if r.get("strategy") == "ladder_b3" and r.get("set") != "row_gap"), None)
        base = next((r for r in ae if r.get("strategy") == "baseline" and r.get("set") != "row_gap"), None)
        rows = next((r for r in ae if r.get("strategy") == "ladder_b3" and r.get("set") == "row_gap"), None)
        if lad and base:
            add("agent", "identifier misreads: no decoy accepted", "PASS" if lad["decoys_wrongly_verified"] == 0 else "FAIL",
                f"{lad['decoys_wrongly_verified']}/{lad['decoy_cases']}")
            add("agent", "identifier misreads: deterministic step vs none", "PASS" if lad["true_verified"] >= base["true_verified"] else "FAIL",
                f"{lad['true_verified']} vs {base['true_verified']} of {lad['true_cases']}")
        if rows:
            add("agent", "row gaps: no false row accepted", "PASS" if rows["false_rows_accepted"] == 0 else "FAIL",
                f"{rows['rows_recovered']} recovered of {rows['rows_missed_by_default_ocr']} missed; {rows['false_rows_accepted']} false")
        mod = next((r for r in ae if r.get("strategy") == "model"), None)
        add("agent", "model-driven investigation against a real provider", "NOT RUN" if not mod or mod["status"] != "RUN" else "PASS",
            mod["status"] if mod else "absent")
    tr = exc.get("transcript")
    if tr:
        add("transcript", "agent trace completeness", tr["status"], tr["rationale"])

    checks += submission_checks(ROOT / "output.csv", Path(a.code_zip), Path(a.log), Path(a.agent_trace) if a.agent_trace else None, ct)
    return finish(checks, a.out, a.mode)


def submission_checks(output_csv: Path, code_zip: Path, log_txt: Path, agent_trace: Path | None, contract=None) -> list:
    """Artifacts required by the official contract (README / AGENTS.md / agent_trace_instructions.md)."""
    out = []

    def add(name, status, detail=""):
        out.append(("submission", name, status, str(detail)))
    if contract is not None:
        add("output.csv valid and reproducible", "PASS" if contract.get("present") and not contract.get("errors")
            and contract.get("matches_fresh_prediction") else "FAIL", f"{contract.get('rows')} rows")
    else:
        add("output.csv present", "PASS" if output_csv.exists() else "FAIL", str(output_csv))
    if not code_zip.exists():
        add("code.zip present", "FAIL", f"{code_zip} missing")
    else:
        with zipfile.ZipFile(code_zip) as z:
            names = z.namelist()
            req = ["README.md", "code/evaluation/evaluation_report.md", "code/evaluation/usage_report.md", "code/main.py"]
            missing = [r for r in req if r not in names]
            forbidden = [n for n in names if n.startswith("dataset/") or re.search(r"\.(zip|tar|gz|tgz|7z|rar)$", n)
                         or "/.cache/" in n or "/runs/" in n or "__pycache__" in n or n.endswith(".env")]
            secrets = [n for n in names if not n.endswith("/") and SECRET_RE.search(z.read(n))]
        add("code.zip contains README, entry point and both evaluation reports", "FAIL" if missing else "PASS",
            f"missing {missing}" if missing else f"{len(names)} entries")
        add("code.zip excludes dataset, caches, run outputs and nested archives", "FAIL" if forbidden else "PASS",
            f"{forbidden[:4]}" if forbidden else "none found")
        add("code.zip contains no credential patterns", "FAIL" if secrets else "PASS", f"{secrets[:3]}" if secrets else "none found")
    if not log_txt.exists():
        add("log.txt present", "FAIL", f"{log_txt} missing")
    else:
        text = log_txt.read_text(encoding="utf-8")
        entries = re.split(r"(?m)^## \[", text)[1:]
        bad = []
        for i, e in enumerate(entries, 1):
            tools = re.findall(r"(?m)^tool=(.*)$", e)
            models = re.findall(r"(?m)^model=(.*)$", e)
            if len(tools) != 1 or len(models) != 1 or not tools[0].strip() or not models[0].strip() \
                    or any(x.strip().lower() in ("unknown", "ai", "<exact_harness_or_coding_agent_name>", "<exact_runtime_model_name>")
                           for x in tools + models):
                bad.append(i)
        add("log.txt: every entry has exactly one populated tool= and model= line", "FAIL" if bad or not entries else "PASS",
            f"{len(entries)} entries" + (f"; invalid entries {bad[:6]}" if bad else ""))
        add("log.txt contains no credential patterns", "FAIL" if SECRET_RE.search(text.encode()) else "PASS")
    if agent_trace is None:
        add("agent-trace.zip prepared outside code.zip", "NOT RUN", "path not given (it is kept outside the repository)")
    else:
        ok = agent_trace.exists() and zipfile.is_zipfile(agent_trace)
        sec = []
        if ok:
            with zipfile.ZipFile(agent_trace) as z:
                sec = [n for n in z.namelist() if not n.endswith("/") and SECRET_RE.search(z.read(n))]
        add("agent-trace.zip prepared outside code.zip, no credential patterns", "PASS" if ok and not sec else "FAIL",
            "ok" if ok and not sec else (f"credential pattern in {sec[:2]}" if sec else "missing or not a zip"))
    return out


VERDICT_AREAS = [("execution", "Reproducibility (execution)"), ("structure", "Structural output validity"),
                 ("semantic", "Semantic correctness"), ("coverage", "Evaluation coverage"),
                 ("agent", "Agent capability"), ("transcript", "Transcript completeness"),
                 ("submission", "Submission artifacts")]
RELEASE_REQUIRED = ("execution", "structure", "semantic", "coverage")


def finish(checks, out, mode="dev") -> int:
    def verdict(area):
        sts = [c[2] for c in checks if c[0] == area]
        if not sts:
            return "NOT RUN (no checks)"
        if "FAIL" in sts:
            return "FAIL"
        if "EXCEPTION" in sts:
            return f"NOT ESTABLISHED ({sts.count('EXCEPTION')} recorded exceptions)"
        if "NOT RUN" in sts:
            return f"PARTIAL ({sts.count('NOT RUN')} checks not run)"
        return "PASS"
    fails = [c for c in checks if c[2] == "FAIL" and c[0] != "submission"]  # submission has its own verdict
    blockers = [c for c in checks if c[0] in RELEASE_REQUIRED and c[2] in ("FAIL", "EXCEPTION", "NOT RUN")]
    blockers += [(a, "area has no checks", "NOT RUN", "required area missing") for a in RELEASE_REQUIRED
                 if not any(c[0] == a for c in checks)]
    sub = [c for c in checks if c[0] == "submission"]
    regression_ok = not fails and bool(checks)
    release_ok = not blockers
    submission_ok = bool(sub) and all(c[2] == "PASS" for c in sub)
    semantic_pass = verdict("semantic") == "PASS"
    submission_label = ("NOT READY" if not submission_ok else
                        "PACKAGE READY" if semantic_pass else "PACKAGE READY; semantic correctness unresolved")
    L = ["# Acceptance report", "",
         "_Generated by `python3 code/evaluation/acceptance.py`. EXCEPTION = known unresolved issue with a recorded "
         "rationale and exact case list; it documents uncertainty and never establishes correctness._", "",
         "## Verdicts", "",
         "| Verdict | Result | Meaning |", "|---|---|---|",
         f"| Development (regression gate) | {'PASS' if regression_ok else 'FAIL'} | no unexpected change; results fresh "
         "for prediction code, evaluation code, evidence contents and configuration; every registered test identity "
         "present exactly once |",
         f"| Release (strict) | {'APPROVED' if release_ok else 'BLOCKED'} | execution, structure, semantic and coverage "
         "all fully PASS: no exceptions, nothing missing, empty, stale or malformed |",
         f"| Submission readiness | {submission_label} | artifacts the official contract requires "
         "are present and valid (runtime model execution is not a contract requirement) |", "",
         f"_Exit status of this run (`--mode {mode}`): "
         f"{0 if {'dev': regression_ok, 'release': release_ok, 'submission': submission_ok}[mode] else 1}._", ""]
    if blockers:
        L += ["Release blockers:", ""] + [f"* {c[0]} / {c[1]}: {c[2]} — {c[3][:220]}" for c in blockers] + [""]
    L += ["## Verdicts by area", "", "| Area | Verdict | Release |", "|---|---|---|"]
    for area, label in VERDICT_AREAS:
        role = "required" if area in RELEASE_REQUIRED else ("submission" if area == "submission" else "advisory")
        L.append(f"| {label} | {verdict(area)} | {role} |")
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
    return 0 if {"dev": regression_ok, "release": release_ok, "submission": submission_ok}[mode] else 1


if __name__ == "__main__":
    sys.exit(main())
