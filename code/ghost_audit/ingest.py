"""Manifest-driven evidence ingestion with a content-hash cache."""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import parsers
from .models import Observation
from .util import sha256_file


@dataclass
class EvidenceFile:
    file_id: str
    path: Path
    origin: str
    captured_at: str
    sha256: str = ""
    status: str = "pending"
    error: str = ""
    n_observations: int = 0
    text: str = ""  # extracted text for PDFs / OCR (kept for audit and identifier search)
    facts: list = field(default_factory=list)  # structured facts without resource ids (e.g. legal register rows)
    warnings: list = field(default_factory=list)


@dataclass
class EvidenceStore:
    files: dict = field(default_factory=dict)          # file_id -> EvidenceFile
    observations: list = field(default_factory=list)   # all Observations
    failures: list = field(default_factory=list)       # (file_id, error)
    cache_hits: int = 0
    cache_misses: int = 0


def _dispatch(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".json":
        return parsers.parse_json, False
    if suffix == ".sql":
        return parsers.parse_sql, False
    if suffix == ".log":
        return parsers.parse_log, False
    if suffix == ".txt":
        return parsers.parse_text, False
    if suffix == ".pdf":
        return parsers.parse_pdf, True
    if suffix in {".png", ".jpg", ".jpeg"}:
        return parsers.parse_image, True
    return None, False


def load_evidence(dataset_dir: Path, cache_dir: Path | None = None) -> EvidenceStore:
    store = EvidenceStore()
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
    with open(dataset_dir / "evidence_files.csv", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        ef = EvidenceFile(row["file_id"], dataset_dir / row["file_path"], row["origin"], row["captured_at"])
        store.files[ef.file_id] = ef
        if not ef.path.exists():
            ef.status, ef.error = "missing", "file listed in manifest not found"
            store.failures.append((ef.file_id, ef.error))
            continue
        ef.sha256 = sha256_file(ef.path)
        fn, returns_text = _dispatch(ef.path)
        if fn is None:
            ef.status, ef.error = "unsupported", f"no parser for {ef.path.suffix}"
            store.failures.append((ef.file_id, ef.error))
            continue
        # cache key: content hash + parser version + file identity (ids/captured_at feed the observations)
        key = f"{ef.sha256[:24]}_{parsers.PARSER_VERSION}_{ef.file_id}_{ef.captured_at.replace(':', '')}"
        cpath = cache_dir / f"{key}.json" if cache_dir else None
        if cpath and cpath.exists():
            payload = json.loads(cpath.read_text(encoding="utf-8"))
            obs = [Observation.from_dict(d) for d in payload["observations"]]
            ef.text = payload.get("text", "")
            ef.warnings = payload.get("warnings", [])
            store.cache_hits += 1
        else:
            try:
                result = fn(ef.path, ef.file_id, ef.captured_at)
                if returns_text:
                    obs, ef.text = result
                else:
                    obs = result
            except Exception as exc:  # record, never silently drop
                ef.status, ef.error = "error", f"{type(exc).__name__}: {exc}"
                store.failures.append((ef.file_id, ef.error))
                continue
            store.cache_misses += 1
            ef.warnings = parsers.WARNINGS.pop(ef.file_id, [])
            if cpath:
                cpath.write_text(json.dumps({"observations": [o.to_dict() for o in obs], "text": ef.text,
                                             "warnings": ef.warnings}), encoding="utf-8")
        if ef.text:
            ef.facts = parsers.legal_facts(ef.text)
        if ef.warnings:
            store.failures.append((ef.file_id, "partial extraction: " + "; ".join(ef.warnings[:3])))
        if obs:
            ef.status = "ok"
        elif ef.facts:
            ef.status = "facts-only"     # extracted, but the facts name no resource id
        elif ef.text:
            ef.status = "no-direct-facts"  # text extracted; usable only via catalog aliases found in it
        else:
            ef.status = "empty"
            store.failures.append((ef.file_id, "no text or observations extracted"))
        ef.n_observations = len(obs)
        store.observations.extend(obs)
    return store
