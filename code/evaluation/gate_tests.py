"""Self-tests of the acceptance gate: does it reject what it must reject?

    python3 code/evaluation/gate_tests.py                      # -> code/runs/gate_tests.json
    python3 code/evaluation/gate_tests.py --acceptance OLD.py  # run the same tests against another gate

Each test derives a variant from the real, fresh results (code/runs/evaluation_results.json) and runs
the gate on it. Expectations are fixed here, independently of the gate's implementation.
A test that cannot even be executed against a given gate (an option or function the gate does not
have) is reported as `harness-incompatible`, separately from a behavioural failure.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import importlib.util
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
ROOT = CODE.parent
sys.path.insert(0, str(CODE))


def load_gate(path: Path):
    spec = importlib.util.spec_from_file_location("acceptance_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Harness:
    def __init__(self, gate_mod):
        self.g = gate_mod
        self.td = Path(tempfile.mkdtemp(prefix="gate_tests_"))
        real_inv = CODE / "runs" / "invariance"
        self.inv_dir = self.td / "inv"
        if (real_inv / "invariance.json").exists():
            (self.inv_dir / "traces").mkdir(parents=True)
            shutil.copy(real_inv / "invariance.json", self.inv_dir / "invariance.json")
            if (real_inv / "traces" / "full.manifest.json").exists():
                shutil.copy(real_inv / "traces" / "full.manifest.json", self.inv_dir / "traces" / "full.manifest.json")

    def run(self, res, mode, exc=None, inv=None, gate_tests=None, raw=None, registry=None):
        d = Path(tempfile.mkdtemp(dir=self.td))
        rp = d / "results.json"
        rp.write_text(raw if raw is not None else json.dumps(res), encoding="utf-8")
        args = ["--results", str(rp), "--mode", mode, "--gate-tests", str(gate_tests or d / "none.json")]
        if exc is not None:
            (d / "exc.json").write_text(json.dumps(exc), encoding="utf-8")
            args += ["--exceptions", str(d / "exc.json")]
        inv_path = self.inv_dir / "invariance.json"
        if inv is not None:
            (d / "inv" / "traces").mkdir(parents=True)
            (d / "inv" / "invariance.json").write_text(json.dumps(inv), encoding="utf-8")
            m = self.inv_dir / "traces" / "full.manifest.json"
            if m.exists():
                shutil.copy(m, d / "inv" / "traces" / "full.manifest.json")
            inv_path = d / "inv" / "invariance.json"
        args += ["--invariance", str(inv_path)]
        if registry is not None:
            (d / "reg.json").write_text(json.dumps(registry), encoding="utf-8")
            args += ["--registry", str(d / "reg.json")]
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return self.g.main(args)
        except SystemExit as e:  # argparse rejects an option this gate does not know
            return f"harness-incompatible: unsupported option ({e.code})"
        except Exception as e:  # noqa: BLE001
            return f"error: {type(e).__name__}: {e}"


def run(gate_path: Path) -> list:
    g = load_gate(gate_path)
    h = Harness(g)
    real = json.loads((CODE / "runs" / "evaluation_results.json").read_text(encoding="utf-8"))
    exc = json.loads((HERE / "known_exceptions.json").read_text(encoding="utf-8"))
    reg = json.loads((HERE / "test_registry.json").read_text(encoding="utf-8"))
    inv = json.loads((CODE / "runs" / "invariance" / "invariance.json").read_text(encoding="utf-8"))
    out = []

    def t(name, got, want):
        if isinstance(got, str):
            status = "harness-incompatible" if got.startswith("harness-incompatible") else "error"
            out.append({"name": name, "expected_exit": want, "exit": got, "passed": False, "kind": status})
        else:
            out.append({"name": name, "expected_exit": want, "exit": got, "passed": got == want,
                        "kind": "behaviour"})

    # ---- original self-tests
    t("real fresh results: regression gate passes", h.run(real, "dev"), 0)
    t("real fresh results: release gate is blocked (semantic exceptions)", h.run(real, "release"), 1)
    v = copy.deepcopy(real); v["fixtures"] = []
    t("empty synthetic-case list fails the regression gate", h.run(v, "dev"), 1)
    v = copy.deepcopy(real); v.pop("metamorphic", None)
    t("omitted metamorphic suite: regression gate tolerates NOT RUN", h.run(v, "dev"), 0)
    t("omitted metamorphic suite blocks release", h.run(v, "release"), 1)
    v = copy.deepcopy(real); v["environment"]["code_fingerprint"] = "0" * 64
    t("stale code fingerprint fails the regression gate", h.run(v, "dev"), 1)
    v = copy.deepcopy(real); k = next(iter(v["environment"]["inputs_sha256"])); v["environment"]["inputs_sha256"][k] = "f" * 16
    t("mismatched input fingerprint fails the regression gate", h.run(v, "dev"), 1)
    t("malformed results file fails the regression gate", h.run(None, "dev", raw="{not json"), 1)
    v = copy.deepcopy(real); v["fixtures"] = v["fixtures"][1:]
    t("a missing expected synthetic case fails the regression gate", h.run(v, "dev"), 1)
    v = copy.deepcopy(real); v["unit_tests"][0][1] = "yes"
    t("a non-boolean test result fails the regression gate", h.run(v, "dev"), 1)
    e = copy.deepcopy(exc); e["uncertified"]["cases"] = e["uncertified"]["cases"][1:]
    t("an uncertified case not in the recorded exception fails the regression gate", h.run(real, "dev", exc=e), 1)
    # ---- identities against the explicit registry
    r2 = copy.deepcopy(reg); r2["semantic"] = []
    t("a registry suite with zero expected identities fails", h.run(real, "dev", registry=r2), 1)
    v = copy.deepcopy(real); v["fixtures"].append(list(v["fixtures"][0]))
    t("a duplicate test identity fails", h.run(v, "dev"), 1)
    v = copy.deepcopy(real); v["mutations"].append(["unregistered mutant", True, []])
    t("an unexpected (unregistered) test identity fails", h.run(v, "dev"), 1)
    v = copy.deepcopy(real); v["metamorphic"][0][0] = 42
    t("a malformed (non-string) test identity fails", h.run(v, "dev"), 1)
    # ---- fail-first and invariance coverage
    v = copy.deepcopy(real); v["failfirst"]["new"] = {}
    t("empty fail-first results fail", h.run(v, "dev"), 1)
    v = copy.deepcopy(real); v["failfirst"]["new"] = dict(list(v["failfirst"]["new"].items())[:-1])
    t("fail-first results missing a registered test fail", h.run(v, "dev"), 1)
    i2 = dict(inv, total_compared=0, total_changed=0, by_variation={}, alone_runs=0, alone_changed=[])
    t("zero batch-invariance comparisons fail", h.run(real, "dev", inv=i2), 1)
    i3 = copy.deepcopy(inv); i3["by_variation"].pop("half_b")
    t("incomplete batch-invariance comparisons (a variation missing) fail", h.run(real, "dev", inv=i3), 1)
    # ---- staleness beyond prediction code
    for field, label in (("evaluation_fingerprint", "evaluation code"), ("dataset_digest", "evidence-file contents")):
        v = copy.deepcopy(real); v["environment"][field] = "0" * 64
        t(f"stale results after a change to {label} fail", h.run(v, "dev"), 1)
    v = copy.deepcopy(real); v["environment"]["config"] = dict(v["environment"].get("config") or {},
                                                               GHOST_AUDIT_INVESTIGATOR="model")
    t("stale results after a configuration change fail", h.run(v, "dev"), 1)
    # ---- sample mismatch bookkeeping and the separate retrieval check
    v = copy.deepcopy(real); v["sample_miss_causes"] = v["sample_miss_causes"][1:]
    t("a sample mismatch without a classification fails", h.run(v, "dev"), 1)
    v = copy.deepcopy(real)
    if v.get("sample_retrieval_check"):
        v["sample_retrieval_check"][0]["admissible_files_naming_subject"] = ["evidence_00"]
    t("a missed step whose admissible evidence names the subject fails the retrieval check", h.run(v, "dev"), 1)
    v = copy.deepcopy(real)
    w = [x for x in v.get("sample_retrieval_check", []) if x.get("resource_in_prediction")]
    if w:
        w[0]["internal_status"] = "INCOMPLETE"
        w[0]["admissible_files_naming_subject"] = w[0]["admissible_files_naming_subject"] or ["evidence_00"]
    t("a withheld citation in a case that is not uncertified fails", h.run(v, "dev"), 1)
    # ---- verdict areas and submission readiness
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            got = g.finish([], None, "release")
    except Exception as e:  # noqa: BLE001
        got = f"error: {type(e).__name__}"
    t("release mode with no checks at all (finish([])) is blocked", got, 1)
    if hasattr(g, "submission_checks"):
        d = Path(tempfile.mkdtemp(dir=h.td))
        (d / "log.txt").write_text("## [2026-01-01T00:00:00Z] SESSION START\n\nmodel=x\n", encoding="utf-8")
        sc = g.submission_checks(ROOT / "output.csv", d / "missing.zip", d / "log.txt", None)
        t("submission readiness fails without code.zip and with a log entry lacking tool=",
          0 if all(c[2] == "PASS" for c in sc) else 1, 1)
    else:
        t("submission readiness fails without code.zip and with a log entry lacking tool=",
          "harness-incompatible: no submission_checks()", 1)
    # ---- reachability: release can be approved when nothing blocks it
    if any(real.get(k) is None for k in ("metamorphic", "semantic", "operational", "mutations")):
        out.append({"name": "hypothetical blocker-free results: release gate approves", "expected_exit": 0,
                    "exit": None, "passed": None, "kind": "not-applicable",
                    "note": "results come from a --quick run"})
        return out
    v = copy.deepcopy(real)
    for kk in ("verifier_eval", "verifier_samples_pred", "verifier_gold"):
        v[kk]["issues"] = {}
    v["internal"] = {c: dict(x, internal="COMPLETE") for c, x in v["internal"].items()}
    for x in v.get("sample_retrieval_check", []):
        x["admissible_files_naming_subject"] = []
    e = {"sample_expected": exc["sample_expected"]}
    d = Path(tempfile.mkdtemp(dir=h.td))
    gp = d / "gt.json"
    gp.write_text(json.dumps([{"name": n, "passed": True, "kind": "behaviour"} for n in reg.get("gate_tests", ["x"])]),
                  encoding="utf-8")
    t("hypothetical blocker-free results: release gate approves", h.run(v, "release", exc=e, gate_tests=gp), 0)
    shutil.rmtree(h.td, ignore_errors=True)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--acceptance", default=str(HERE / "acceptance.py"))
    ap.add_argument("--out", default=str(CODE / "runs" / "gate_tests.json"))
    a = ap.parse_args()
    res = run(Path(a.acceptance))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    for r in res:
        tag = {True: "PASS", False: "FAIL", None: "N/A "}[r["passed"]]
        print(tag, f"[{r['kind']}]", r["name"], f"(exit {r['exit']}, expected {r['expected_exit']})")
    sys.exit(0 if all(r["passed"] is not False for r in res) else 1)
