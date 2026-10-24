"""Regenerate every submission artifact from the current code, in order.

    python3 code/evaluation/reproduce.py                 # predictions + invariance + reports
    python3 code/evaluation/reproduce.py --baseline f280a63 --previous 3be6cb1

Steps
  1. code/main.py                      -> output.csv (repository root) + run manifest/trace in code/runs/
  2. evaluation/invariance.py          -> code/runs/invariance/ (batch-invariance of this code)
  3. for --baseline REV and --previous REV: git archive REV -> code/runs/tree_<tag>/ ; invariance.py on
     it ; compare.py (before/after) ; failfirst.py with today's fixtures and unit tests;
     failfirst.py on this code ; investigate_cases.py -> evaluation/case_investigation.md
  4. evaluation/main.py                -> code/evaluation/evaluation_report.md
  5. evaluation/make_usage_report.py   -> code/evaluation/usage_report.md
  6. evaluation/acceptance.py          -> code/evaluation/acceptance_report.md (exit status = gate)
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


def sh(*cmd, check=True, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], check=check, **kw)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default=None, help="git revision of the original implementation (before/after)")
    ap.add_argument("--previous", default=None, help="git revision of the last reviewed implementation (fail-first)")
    ap.add_argument("--alone", default="25", help="number of single-request runs for invariance")
    ap.add_argument("--quick", action="store_true", help="skip metamorphic, operational and mutation tests")
    a = ap.parse_args(argv)
    py = sys.executable
    RUNS.mkdir(exist_ok=True)
    sh(py, CODE / "main.py", "--no-cache")  # fresh extraction: preprocessing is attributable to this run
    inv = RUNS / "invariance"
    shutil.rmtree(inv, ignore_errors=True)
    sh(py, HERE / "invariance.py", "--code", CODE, "--out", inv, "--alone", a.alone)
    ff = RUNS / "failfirst"
    shutil.rmtree(ff, ignore_errors=True)
    ff.mkdir()
    for rev, tag in ((a.baseline, "base"), (a.previous, "prev")):
        if not rev:
            continue
        tree = RUNS / f"tree_{tag}"
        shutil.rmtree(tree, ignore_errors=True)
        tree.mkdir(parents=True)
        blob = subprocess.run(["git", "-C", str(ROOT), "archive", rev, "code"], check=True,
                              capture_output=True).stdout
        tarfile.open(fileobj=io.BytesIO(blob)).extractall(tree, filter="data")
        sh(py, HERE / "invariance.py", "--code", tree / "code", "--out", tree / "inv", "--alone", a.alone)
        sh(py, HERE / "compare.py", "--before-dir", tree / "inv", "--after-dir", inv,
           "--after-trace", inv / "traces" / "full.trace.jsonl", "--out", RUNS / f"compare_{tag}.json")
        shutil.copy(HERE / "fixtures.py", tree / "code" / "evaluation" / "fixtures.py")
        with open(ff / f"{tag}.json", "w", encoding="utf-8") as fh:
            sh(py, HERE / "failfirst.py", tree / "code", ff / f"world_{tag}", stdout=fh)
        (ff / f"{tag}.rev").write_text(rev, encoding="utf-8")
    with open(ff / "new.json", "w", encoding="utf-8") as fh:
        sh(py, HERE / "failfirst.py", CODE, ff / "world_new", stdout=fh)
    sh(py, HERE / "investigate_cases.py")
    cmd = [py, HERE / "main.py"] + (["--quick"] if a.quick else [])
    sh(*cmd)
    sh(py, HERE / "make_usage_report.py")
    sh(py, HERE / "acceptance.py", "--out", HERE / "acceptance_report.md", check=False)


if __name__ == "__main__":
    main()
