"""Normalised evidence observation model shared by all parsers."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Observation:
    """One grounded statement about one resource, taken from one evidence file.

    exists:          True = record observed present, False = positively observed absent
                     (404 / NOT_FOUND / absent from a complete-scope snapshot), None = unknown.
    pii:             True = direct identifiers (name/email/phone/hash) still exposed,
                     False = record observed without direct identifiers, None = not stated.
    flow_enabled:    integration data-flow state.
    restore_allowed: backup restore state.
    """

    evidence_id: str
    location: str
    captured_at: str
    observed_at: str
    system: str
    resource_id: str
    replica: str = "primary"
    exists: Optional[bool] = None
    pii: Optional[bool] = None
    flow_enabled: Optional[bool] = None
    restore_allowed: Optional[bool] = None
    retention_until: Optional[str] = None
    expires_at: Optional[str] = None   # scheduled expiry stated by the source (e.g. export download links)
    record_type: Optional[str] = None  # explicit policy category if the source states one
    kind: Optional[str] = None         # sub-type hint: attachment, message, contact_index, hash_only ...
    shared_context: Optional[bool] = None
    identifiers: list = field(default_factory=list)  # every identifier value tied to the record
    exposed: list = field(default_factory=list)      # identifier values visibly exposed in the record
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Observation":
        return Observation(**d)
