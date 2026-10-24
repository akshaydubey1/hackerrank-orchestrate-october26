"""Run any version of the predictor under request-batch variations and save every prediction set.

    python3 code/evaluation/invariance.py --code <code dir> --out <dir> [--alone N]

Variations (each runs the given code's main.py in a subprocess on a private copy of dataset/):
  full        all 518 requests, sample request file present (the submission configuration)
  samples     the 32 public sample requests
  no_sample   all 518 requests, sample_deletion_requests.csv and sample_output.csv removed
  shuffled    all 518 requests in a shuffled order
  half_a/b    the 518 requests split into two random halves, each run separately
  plus_noise  all 518 requests plus 40 unrelated fictional requests
  alone_<id>  N randomly chosen requests, each run completely alone
A request's prediction must be identical in every variation in which it appears.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"


def _write(path: Path, rows: list):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def _run(code: Path, data: Path, out: Path, req: Path | None = None):
    cmd = [sys.executable, str(code / "main.py"), "--dataset", str(data), "--out", str(out),
           "--trace-dir", str(out.parent / "traces"), "--cache-dir", str(out.parent / "cache")]
    if req is not None:
        cmd += ["--requests", str(req)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode not in (0, 1) or not out.exists():
        raise RuntimeError(f"{cmd}\n{r.stdout}\n{r.stderr}")


def load(path: Path) -> dict:
    return {r["case_id"]: (r["deletion_status"], r["steps_json"]) for r in csv.DictReader(open(path, encoding="utf-8"))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--alone", type=int, default=25)
    a = ap.parse_args()
    code, out = Path(a.code).resolve(), Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = out / "data"
    if data.exists():
        shutil.rmtree(data)
    shutil.copytree(DATASET, data, ignore=shutil.ignore_patterns("output.csv"))
    reqs = list(csv.DictReader(open(data / "deletion_requests.csv", encoding="utf-8")))
    rnd = random.Random(2026)
    _run(code, data, out / "full.csv")
    _run(code, data, out / "samples.csv", data / "sample_deletion_requests.csv")
    shuffled = rnd.sample(reqs, len(reqs))
    _write(out / "req_shuffled.csv", shuffled)
    orig_req = (data / "deletion_requests.csv").read_bytes()
    # variations that change what the dataset contains are run on a temporary rewrite, then restored
    _write(data / "deletion_requests.csv", shuffled)
    _run(code, data, out / "shuffled.csv")
    half = set(c["case_id"] for c in rnd.sample(reqs, len(reqs) // 2))
    for name, keep in (("half_a", lambda r: r["case_id"] in half), ("half_b", lambda r: r["case_id"] not in half)):
        _write(data / "deletion_requests.csv", [r for r in reqs if keep(r)])
        _run(code, data, out / f"{name}.csv")
    noise = []
    for i in range(40):
        noise.append({"case_id": f"case_{9000 + i}", "email": f"unrelated.person{i}@nowhere.test",
                      "requested_at": "2026-09-01T10:00:00Z", "reported_status": "COMPLETE",
                      "reported_at": "2026-09-02T12:00:00Z", "audit_at": "2026-09-15T12:00:00Z",
                      "request_text": "Please delete my account and all personal data."})
    _write(data / "deletion_requests.csv", reqs + noise)
    _run(code, data, out / "plus_noise.csv")
    alone_ids = sorted(c["case_id"] for c in rnd.sample(reqs, a.alone))
    for cid in alone_ids:
        _write(data / "deletion_requests.csv", [r for r in reqs if r["case_id"] == cid])
        _run(code, data, out / f"alone_{cid}.csv")
    (data / "deletion_requests.csv").write_bytes(orig_req)
    smp = data / "sample_deletion_requests.csv"
    smp_bytes, gold_bytes = smp.read_bytes(), (data / "sample_output.csv").read_bytes()
    smp.unlink()
    (data / "sample_output.csv").unlink()
    _run(code, data, out / "no_sample.csv")
    smp.write_bytes(smp_bytes)
    (data / "sample_output.csv").write_bytes(gold_bytes)

    base = load(out / "full.csv")
    report = {}
    for f in sorted(out.glob("*.csv")):
        if f.name in ("full.csv", "samples.csv") or f.name.startswith("req_"):
            continue
        p = load(f)
        common = [c for c in p if c in base]
        diff = [c for c in common if p[c] != base[c]]
        report[f.stem] = {"compared": len(common), "changed": len(diff), "changed_cases": diff[:20]}
    agg = {"variations": len(report),
           "alone_runs": len(alone_ids),
           "total_compared": sum(v["compared"] for v in report.values()),
           "total_changed": sum(v["changed"] for v in report.values()),
           "by_variation": {k: v for k, v in report.items() if not k.startswith("alone_")},
           "alone_changed": sorted(k[6:] for k, v in report.items() if k.startswith("alone_") and v["changed"])}
    (out / "invariance.json").write_text(json.dumps(agg, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in agg.items() if k != "by_variation"}),
          {k: v["changed"] for k, v in agg["by_variation"].items()})


if __name__ == "__main__":
    main()
