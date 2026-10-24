"""End-to-end pipeline: load inputs once, audit requests, serialise + validate output."""
from __future__ import annotations

import csv
import os
import json
import time
from pathlib import Path

from .activity import ActivityStream
from .audit import Auditor
from .identity import IdentityIndex
from .ingest import load_evidence
from .intent import classify
from .policy import Policy
from .validate import case_key, validate_rows


def read_requests(path: Path) -> list:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


class Engine:
    def __init__(self, dataset_dir: Path, cache_dir: Path | None = None):
        t0 = time.time()
        self.dataset_dir = dataset_dir
        self.store = load_evidence(dataset_dir, cache_dir)
        self.identity = IdentityIndex(dataset_dir)
        self.activity = ActivityStream(dataset_dir)
        self.policy = Policy(dataset_dir)
        self.auditor = Auditor(self.store, self.identity, self.activity, self.policy)
        self.load_seconds = time.time() - t0
        self._assigned = False

    def prepare(self, request_sets: list):
        """Account correlation must see every request in the dataset at once (global uniqueness).
        Only request fields are used -- never any answer file."""
        allq = []
        for reqs in request_sets:
            for q in reqs:
                q = dict(q)
                q["_deletion"] = classify(q["request_text"]).is_deletion
                uids = self.identity.resolve_email(q["email"])
                q["_user"] = uids[0] if uids else None
                allq.append(q)
        self.auditor.assign_accounts(allq)
        self._assigned = True

    def run(self, requests: list) -> list:
        assert self._assigned, "call prepare() first"
        return [self.auditor.audit(q) for q in sorted(requests, key=lambda r: case_key(r["case_id"]))]


def write_output(results: list, path: Path, expected_ids: list):
    rows = [{"case_id": r.case_id, "deletion_status": r.status,
             "steps_json": json.dumps(r.steps, separators=(",", ":"), ensure_ascii=False)} for r in results]
    rows.sort(key=lambda r: case_key(r["case_id"]))
    errors = validate_rows(rows, expected_ids)
    # write atomically: an interrupted run never leaves a truncated output.csv behind
    tmp = path.with_name(path.name + ".partial")
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"])
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)
    return errors
