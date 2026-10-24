"""deletion_rules.csv evaluation: category inference + explicit condition checks."""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .util import parse_ts

# Required final state for each policy action.
TARGET = {"DELETE": "ABSENT", "REDACT": "REDACTED", "ANONYMIZE": "ANONYMIZED", "RETAIN": "PRESENT"}


@dataclass
class Rule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


class Policy:
    def __init__(self, dataset_dir: Path):
        with open(dataset_dir / "deletion_rules.csv", newline="", encoding="utf-8") as fh:
            self.rules = {r["data_category"]: Rule(**r) for r in csv.DictReader(fh)}

    # ------------------------------------------------------------------
    @staticmethod
    def categorize(system: str, kind: Optional[str], record_type: Optional[str]) -> str:
        if record_type in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "USER_PROFILE", "SEARCH_INDEX_ENTRY",
                           "ANALYTICS_PROFILE", "USER_EXPORT", "MARKETING_PROFILE", "SECURITY_AUDIT_LOG",
                           "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE", "CACHE_ENTRY",
                           "EMAIL_DELIVERY_LOG", "PRODUCT_TELEMETRY", "SECONDARY_IDENTIFIER"}:
            return record_type
        if record_type == "DATA_FLOW" or system == "integration_service":
            return "DATA_FLOW"
        return {
            "account_service": "USER_PROFILE",
            "search_service": "SEARCH_INDEX_ENTRY",
            "cache_service": "CACHE_ENTRY",
            "analytics_platform": "SECONDARY_IDENTIFIER" if kind == "hash_only" else "ANALYTICS_PROFILE",
            "telemetry_service": "PRODUCT_TELEMETRY",
            "export_service": "USER_EXPORT",
            "object_storage": "USER_EXPORT",
            "marketing_platform": "MARKETING_PROFILE",
            "email_delivery_service": "EMAIL_DELIVERY_LOG",
            "security_service": "SECURITY_AUDIT_LOG",
            "legal_service": "LEGAL_HOLD_RECORD",
            "backup_service": "BACKUP_ARCHIVE",
            "identity_service": "ACCOUNT_TOMBSTONE",
            "support_platform": {"attachment": "SUPPORT_ATTACHMENT",
                                 "contact_index": "SECONDARY_IDENTIFIER"}.get(kind or "", "SUPPORT_MESSAGE"),
        }.get(system, "UNKNOWN")

    # ------------------------------------------------------------------
    def decide(self, category: str, *, audit_at, retention_until: Optional[str] = None,
               shared_context: Optional[bool] = None, attributable: Optional[bool] = None,
               account_deleted: bool = True, attachment_exclusive: Optional[bool] = True) -> tuple:
        """Return (action, rule_id, explanation). action in DELETE/REDACT/ANONYMIZE/RETAIN/DISABLE/NONE."""
        if category == "DATA_FLOW":
            return "DISABLE", "-", "active sync/import paths must not recreate deleted data"
        rule = self.rules.get(category)
        if rule is None:
            return "NONE", "-", f"no rule for {category}"
        action = rule.required_action
        if category == "SECURITY_AUDIT_LOG":
            until = parse_ts(retention_until)
            if until is not None and until < audit_at:
                return "DELETE", rule.rule_id, "retention period expired"
            return "RETAIN", rule.rule_id, rule.condition
        if category == "LEGAL_HOLD_RECORD":
            until = parse_ts(retention_until)
            if until is not None and until < audit_at:
                return "DELETE", rule.rule_id, "legal hold no longer active"
            return "RETAIN", rule.rule_id, rule.condition
        if category == "SUPPORT_MESSAGE":
            if shared_context is False:
                return "DELETE", rule.rule_id, "no shared context to retain"
            return "REDACT", rule.rule_id, rule.condition
        if category == "SUPPORT_ATTACHMENT":
            if attachment_exclusive is False:
                return "REDACT", rule.rule_id, "attachment shared with another subject"
            return "DELETE", rule.rule_id, rule.condition
        if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            return "ANONYMIZE", rule.rule_id, rule.condition
        if category == "ACCOUNT_TOMBSTONE":
            return ("REDACT" if account_deleted else "DELETE"), rule.rule_id, rule.condition
        if category == "BACKUP_ARCHIVE":
            return "RETAIN", rule.rule_id, rule.condition
        return action, rule.rule_id, rule.condition
