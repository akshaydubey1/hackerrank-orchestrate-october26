"""Global activity stream: parsed claims, explicit identity links and repopulation events.

Activity rows are *claims*. They are used for three things only:
  1. explicit data-catalog identity links (LINK_RESOURCE_IDENTITY),
  2. dependency edges (a connector / restore job that repopulated a downstream resource),
  3. correlating a request's workflow report (reported_at/reported_status) with the
     deletion-worker submission it summarises, to recover the primary account id when no
     evidence file names it.
They never establish that a record is absent.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from .util import EMAIL_RE, USER_REF_RE, parse_ts


@dataclass
class Activity:
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str

    @property
    def ts(self):
        return parse_ts(self.event_time)


class ActivityStream:
    def __init__(self, dataset_dir: Path):
        with open(dataset_dir / "system_activity.csv", newline="", encoding="utf-8") as fh:
            self.rows = [Activity(**r) for r in csv.DictReader(fh)]
        self.by_resource: dict = {}
        for a in self.rows:
            self.by_resource.setdefault(a.resource_id, []).append(a)
        self.links = []          # (activity, resource_id, alias, [identifiers], exclusive)
        self.repopulations = []  # (activity, source_resource, downstream_resource)
        for a in self.rows:
            if a.event_type == "LINK_RESOURCE_IDENTITY":
                m = re.search(r"(?:linked|confirmed)\s+(\S+)\s+\(([^)]*)\)", a.details)
                alias = m.group(2) if m else ""
                idents = EMAIL_RE.findall(a.details) + USER_REF_RE.findall(a.details)
                exclusive = "belongs only to" in a.details or "no other subject" in a.details
                self.links.append((a, a.resource_id, alias, idents, exclusive))
            m = re.search(r"repopulated downstream resource\s+(\S+?)\.?$", a.details)
            if m:
                self.repopulations.append((a, a.resource_id, m.group(1)))

    def account_submissions(self):
        return [a for a in self.rows if a.event_type == "DELETE_RECORD" and a.source_system == "deletion_worker"
                and a.target_system == "account_service"]

    def non_deletion_classifications(self):
        return [a for a in self.rows if a.event_type == "CLASSIFY_REQUEST"]
