"""Ghost Data Still Exists -- deletion-audit agent entry point.

Usage (from the repository root):
    python3 code/main.py                       # audit dataset/deletion_requests.csv -> ./output.csv
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv
    python3 code/main.py --no-cache            # force re-extraction of every evidence file

Writes alongside the CSV a run manifest (inputs' SHA-256, code revision, parser version,
model usage) and a JSONL decision trace per case under code/runs/ (git-ignored, not zipped).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ghost_audit import parsers  # noqa: E402
from ghost_audit.llm import USAGE  # noqa: E402
from ghost_audit.pipeline import Engine, read_requests, write_output  # noqa: E402
from ghost_audit.util import code_fingerprint, sha256_file  # noqa: E402


def repo_root() -> Path:
    return HERE.parent


def git_revision(root: Path) -> str:
    try:
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True,
                             timeout=10).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "code"], cwd=root, capture_output=True,
                               text=True, timeout=10).stdout.strip()
        return (rev or "unknown") + ("+local-changes" if dirty else "")
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def main(argv=None) -> int:
    root = repo_root()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=str(root / "dataset"))
    ap.add_argument("--requests", default=None, help="requests CSV (default: <dataset>/deletion_requests.csv)")
    ap.add_argument("--out", default=str(root / "output.csv"))
    ap.add_argument("--cache-dir", default=str(HERE / ".cache"))
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--trace-dir", default=str(HERE / "runs"))
    args = ap.parse_args(argv)

    dataset = Path(args.dataset)
    req_path = Path(args.requests) if args.requests else dataset / "deletion_requests.csv"
    t0 = time.time()
    engine = Engine(dataset, None if args.no_cache else Path(args.cache_dir))
    requests = read_requests(req_path)
    results = engine.run(requests)
    issues = write_output(results, Path(args.out), [r["case_id"] for r in requests])
    errors = [e for e in issues if "WARNING:" not in e]
    warnings = [e for e in issues if "WARNING:" in e]
    elapsed = time.time() - t0

    trace_dir = Path(args.trace_dir)
    trace_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(args.out).stem
    with open(trace_dir / f"{stem}.trace.jsonl", "w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps({"case_id": r.case_id, "status": r.status, "internal_status": r.internal_status,
                                 "unresolved": r.unresolved, "trace": r.trace}, default=str) + "\n")
    status_counts = {}
    for r in results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1
    manifest = {
        "code_revision": git_revision(root),
        "code_fingerprint": code_fingerprint(HERE),
        "parser_version": parsers.PARSER_VERSION,
        "requests_file": str(req_path.relative_to(root)) if req_path.is_relative_to(root) else str(req_path),
        "requests_sha256": sha256_file(req_path),
        "inputs_sha256": {p.name: sha256_file(p) for p in sorted(dataset.glob("*.csv"))},
        "evidence_files": {fid: {"sha256": ef.sha256, "status": ef.status, "observations": ef.n_observations,
                                 "facts": len(ef.facts), "warnings": ef.warnings, "error": ef.error}
                           for fid, ef in engine.store.files.items()},
        "extraction_failures": engine.store.failures,
        "file_types": {fid: ef.path.suffix.lower() for fid, ef in engine.store.files.items()},
        "investigation": {k: v for k, v in __import__("ghost_audit.investigate", fromlist=["summary"])
                          .summary(engine.investigation).items() if k != "outcomes"},
        "cache": {"hits": engine.store.cache_hits, "misses": engine.store.cache_misses,
                  "enabled": not args.no_cache},
        "n_requests": len(results),
        "status_counts": status_counts,
        "validation_errors": errors,
        "validation_warnings": warnings,
        "seconds_total": round(elapsed, 2),
        "seconds_loading": round(engine.load_seconds, 2),
        "model_usage": USAGE.summary(),
        "internal_status_counts": dict(sorted(
            {k: sum(1 for r in results if r.internal_status == k) for k in {r.internal_status for r in results}}.items())),
        "cases_with_unresolved_items": sum(1 for r in results if r.unresolved),
        "intent_decisions": {f"{src}:{lab}": n for (src, lab), n in sorted(
            __import__("collections").Counter((r.trace["intent"]["source"], r.trace["intent"]["label"])
                                              for r in results).items())},
    }
    (trace_dir / f"{stem}.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"wrote {args.out}: {len(results)} rows {status_counts}; validation errors: {len(errors)}; "
          f"warnings: {len(warnings)}; {elapsed:.1f}s; cache hits {engine.store.cache_hits}/{len(engine.store.files)}; "
          f"model calls {USAGE.summary()['calls']}")
    for e in errors[:20]:
        print("  VALIDATION:", e)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
