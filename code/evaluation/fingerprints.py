"""Fingerprint of the evaluation code that produces results (the gate and its self-tests are excluded:
they judge results and do not produce them)."""
from __future__ import annotations

import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
JUDGING_ONLY = {"acceptance.py", "gate_tests.py"}


def evaluation_fingerprint(eval_dir: Path = HERE) -> str:
    h = hashlib.sha256()
    files = sorted(p for p in Path(eval_dir).glob("*.py") if p.name not in JUDGING_ONLY and not p.name.startswith("_"))
    files += [Path(eval_dir) / "known_exceptions.json", Path(eval_dir) / "test_registry.json"]
    for p in files:
        if p.is_file():
            h.update(p.name.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()
