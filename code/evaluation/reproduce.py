"""Regenerate every submission artifact from the current code, in order.

    python3 code/evaluation/reproduce.py                 # predictions + invariance + reports
    python3 code/evaluation/reproduce.py --baseline f280a63   # also the before/after comparison

Steps
  1. code/main.py                      -> output.csv (repository root) + run manifest/trace in code/runs/
  2. evaluation/invariance.py          -> code/runs/invariance/ (batch-invariance of this code)
  3. [--baseline REV] git archive REV  -> code/runs/baseline/  ; invariance.py on it ; compare.py ;
                                          failfirst.py on both trees with today's fixtures
  4. evaluation/main.py                -> code/evaluation/evaluation_report.md
  5. evaluation/make_usage_report.py   -> code/evaluation/usage_report.md
Step 3 needs a git checkout (it reads the baseline revision from git); it is skipped otherwise and
the report then marks the before/after and fail-first sections NOT RUN.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tarfile
import io
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
ROOT = CODE.parent
RUNS = CODE / "runs"


def sh(*cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default=None, help="git revision of the previous implementation")
    ap.add_argument("--alone", default="25", help="number of single-request runs for invariance")
    ap.add_argument("--quick", action="store_true", help="skip metamorphic, operational and mutation tests")
    a = ap.parse_args(argv)
    py = sys.executable
    RUNS.mkdir(exist_ok=True)
    sh(py, CODE / "main.py", "--no-cache")  # fresh extraction: preprocessing is attributable to this run
    inv = RUNS / "invariance"
    shutil.rmtree(inv, ignore_errors=True)
    sh(py, HERE / "invariance.py", "--code", CODE, "--out", inv, "--alone", a.alone)
    if a.baseline:
        base = RUNS / "baseline"
        shutil.rmtree(base, ignore_errors=True)
        base.mkdir(parents=True)
        blob = subprocess.run(["git", "-C", str(ROOT), "archive", a.baseline, "code"], check=True,
                              capture_output=True).stdout
        tarfile.open(fileobj=io.BytesIO(blob)).extractall(base, filter="data")
        sh(py, HERE / "invariance.py", "--code", base / "code", "--out", base / "inv", "--alone", a.alone)
        sh(py, HERE / "compare.py", "--before-dir", base / "inv", "--after-dir", inv,
           "--after-trace", inv / "traces" / "full.trace.jsonl", "--out", RUNS / "compare.json")
        ff = RUNS / "failfirst"
        shutil.rmtree(ff, ignore_errors=True)
        ff.mkdir()
        shutil.copy(HERE / "fixtures.py", base / "code" / "evaluation" / "fixtures.py")
        for tree, name in ((base / "code", "base"), (CODE, "new")):
            with open(ff / f"{name}.json", "w", encoding="utf-8") as fh:
                sh(py, HERE / "failfirst.py", tree, ff / f"world_{name}", stdout=fh)
    cmd = [py, HERE / "main.py"] + (["--quick"] if a.quick else [])
    sh(*cmd)
    sh(py, HERE / "make_usage_report.py")


if __name__ == "__main__":
    main()
