"""Self-tests of the acceptance gate: does it reject what it must reject?

    python3 code/evaluation/gate_tests.py   # -> code/runs/gate_tests.json, exit 1 if any test fails

Each test derives a variant from the real, fresh results (code/runs/evaluation_results.json) and
runs the gate in dev and/or release mode on it. Expectations are fixed here, independently of the
gate's implementation.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
sys.path.insert(0, str(CODE))

from evaluation import acceptance  # noqa: E402


def gate(res, mode, exc=None, inv_path=None, gate_tests=None, raw=None) -> int:
    with tempfile.TemporaryDirectory() as td:
        rp = Path(td) / "results.json"
        rp.write_text(raw if raw is not None else json.dumps(res), encoding="utf-8")
        args = ["--results", str(rp), "--mode", mode, "--gate-tests", str(gate_tests or Path(td) / "none.json")]
        if exc is not None:
            ep = Path(td) / "exc.json"
            ep.write_text(json.dumps(exc), encoding="utf-8")
            args += ["--exceptions", str(ep)]
        if inv_path:
            args += ["--invariance", str(inv_path)]
        with contextlib.redirect_stdout(io.StringIO()):
            return acceptance.main(args)


def run() -> list:
    real = json.loads((CODE / "runs" / "evaluation_results.json").read_text(encoding="utf-8"))
    exc = json.loads((HERE / "known_exceptions.json").read_text(encoding="utf-8"))
    out = []

    def t(name, got, want):
        out.append({"name": name, "expected_exit": want, "exit": got, "passed": got == want})

    t("real fresh results: regression gate passes", gate(real, "dev"), 0)
    t("real fresh results: release gate is blocked (semantic exceptions)", gate(real, "release"), 1)
    v = copy.deepcopy(real); v["fixtures"] = []
    t("empty synthetic-case list fails the regression gate", gate(v, "dev"), 1)
    v = copy.deepcopy(real); v.pop("metamorphic", None)
    t("omitted metamorphic suite: regression gate tolerates NOT RUN", gate(v, "dev"), 0)
    t("omitted metamorphic suite blocks release", gate(v, "release"), 1)
    v = copy.deepcopy(real); v["environment"]["code_fingerprint"] = "0" * 64
    t("stale code fingerprint fails the regression gate", gate(v, "dev"), 1)
    v = copy.deepcopy(real); k = next(iter(v["environment"]["inputs_sha256"])); v["environment"]["inputs_sha256"][k] = "f" * 16
    t("mismatched input fingerprint fails the regression gate", gate(v, "dev"), 1)
    t("malformed results file fails the regression gate", gate(None, "dev", raw="{not json"), 1)
    v = copy.deepcopy(real); v["fixtures"] = v["fixtures"][1:]
    t("a missing expected synthetic case fails the regression gate", gate(v, "dev"), 1)
    v = copy.deepcopy(real); v["unit_tests"][0][1] = "yes"
    t("a non-boolean test result fails the regression gate", gate(v, "dev"), 1)
    e = copy.deepcopy(exc); e["uncertified"]["cases"] = e["uncertified"]["cases"][1:]
    t("an uncertified case not in the recorded exception fails the regression gate", gate(real, "dev", exc=e), 1)
    # all-clean variant: semantic blockers removed -> release becomes reachable. Only meaningful when the
    # real results are complete (a --quick run lacks suites, so release is blocked for that reason instead)
    if any(real.get(k) is None for k in ("metamorphic", "semantic", "operational", "mutations")):
        out.append({"name": "hypothetical blocker-free results: release gate approves", "expected_exit": 0,
                    "exit": None, "passed": None, "note": "not applicable: results come from a --quick run"})
        return out
    v = copy.deepcopy(real)
    for kk in ("verifier_eval", "verifier_samples_pred", "verifier_gold"):
        v[kk]["issues"] = {}
    v["internal"] = {c: dict(x, internal="COMPLETE") for c, x in v["internal"].items()}
    e = {"sample_expected": exc["sample_expected"]}
    with tempfile.TemporaryDirectory() as td:
        gp = Path(td) / "gt.json"
        gp.write_text(json.dumps([{"name": "x", "passed": True}]), encoding="utf-8")
        t("hypothetical blocker-free results: release gate approves", gate(v, "release", exc=e, gate_tests=gp), 0)
    return out


if __name__ == "__main__":
    res = run()
    (CODE / "runs").mkdir(exist_ok=True)
    (CODE / "runs" / "gate_tests.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    for r in res:
        print({True: "PASS", False: "FAIL", None: "N/A "}[r["passed"]], r["name"],
              f"(exit {r['exit']}, expected {r['expected_exit']})" + (f" — {r['note']}" if r.get("note") else ""))
    sys.exit(0 if all(r["passed"] is not False for r in res) else 1)
