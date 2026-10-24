"""Turn per-resource treatments into the canonical, ordered step list."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                      "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
STATE_OF = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
PHASE_OF = {**{o: "FINDING" for o in FINDING_ORDER}, **{o: "REMEDIATION" for o in REMEDIATION_ORDER},
            **{o: "VERIFICATION" for o in VERIFICATION_ORDER}}
ORDER = {o: i for i, o in enumerate(FINDING_ORDER + REMEDIATION_ORDER + VERIFICATION_ORDER)}


@dataclass
class Treatment:
    system: str
    resource_id: str
    category: str
    action: str                 # DELETE / REDACT / ANONYMIZE / RETAIN / DISABLE / NONE
    exists: Optional[bool]
    pii: Optional[bool]
    flow_enabled: Optional[bool]
    restore_allowed: Optional[bool]
    evidence_id: str
    late_only: bool = False


def plan_one(t: Treatment) -> tuple:
    """Return (finding_op|None, remediation_op|None, verification_op|None, note)."""
    if t.category == "DATA_FLOW":
        if t.flow_enabled:
            return "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED", ""
        if t.flow_enabled is False or t.exists is False:
            return None, None, "VERIFY_DATA_FLOW_DISABLED", ""
        return None, None, None, "flow state unknown"
    if t.category == "BACKUP_ARCHIVE":
        if t.restore_allowed:
            return "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED", ""
        if t.restore_allowed is False:
            return None, None, "VERIFY_RESTORE_BLOCKED", ""
        return None, None, None, "restore state unknown"
    if t.action == "DELETE":
        if t.exists:
            return "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT", ""
        if t.exists is False:
            return None, None, "VERIFY_RECORD_ABSENT", ""
        if t.category == "USER_PROFILE" and t.exists is None:
            # primary account named by the workflow but never observed: absence is the
            # required final state, only provable later (dropped from COMPLETE if unsupported)
            return None, None, "VERIFY_RECORD_ABSENT", "account state unproven"
        return None, None, None, "presence unknown at audit_at"
    if t.action == "REDACT":
        if t.exists is False:
            return None, None, None, "record not present"
        if t.pii:
            return "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", ""
        if t.pii is False:
            return None, None, "VERIFY_RECORD_REDACTED", ""
        return None, None, None, "redaction state unknown"
    if t.action == "ANONYMIZE":
        if t.exists is False:
            return None, None, "VERIFY_RECORD_ABSENT", ""
        if t.pii:
            return "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED", ""
        if t.pii is False:
            return None, None, "VERIFY_RECORD_ANONYMIZED", ""
        return None, None, None, "anonymisation state unknown"
    if t.action == "RETAIN":
        if t.exists or (t.exists is None and t.late_only):
            return None, None, "VERIFY_RECORD_PRESENT", ""
        if t.exists is False:
            # required retained record missing: no allowed operation restores it; the plan still
            # states the required final state and the case can never be COMPLETE
            return None, None, "VERIFY_RECORD_PRESENT", "RETENTION_VIOLATION: required retained record observed absent"
        return None, None, None, "retained record not observed at audit_at"
    return None, None, None, f"no action for {t.category}"


def build_steps(treatments: list) -> tuple:
    findings, remediation, verification, notes = [], [], [], []
    for t in treatments:
        f, r, v, note = plan_one(t)
        if note:
            notes.append(f"{t.resource_id}: {note}")
        if f:
            findings.append((f, t))
        if r:
            remediation.append((r, t))
        if v:
            verification.append((v, t))
    status = "INCOMPLETE" if findings else "COMPLETE"
    if status == "COMPLETE" and not any(t.evidence_id for _, t in verification):
        # nothing in the audit window proves any required state: never certify COMPLETE
        status = "INCOMPLETE"
        notes.append("UNCERTIFIED: no in-window evidence proves any required final state")
    if status == "COMPLETE":
        # every verification must be backed by evidence proving the state at audit_at
        unsupported = [t.resource_id for _, t in verification if not t.evidence_id]
        if unsupported:
            notes.append("unsupported verification dropped: " + ",".join(unsupported))
            verification = [(v, t) for v, t in verification if t.evidence_id]

    def key(item):
        op, t = item
        return (ORDER[op], t.system, t.resource_id)

    steps = []
    for phase_items, cite in ((findings, True), (remediation, False), (verification, status == "COMPLETE")):
        for op, t in sorted(phase_items, key=key):
            steps.append({"step_no": len(steps) + 1, "phase": PHASE_OF[op], "system_id": t.system,
                          "resource_id": t.resource_id, "operation": op, "state": STATE_OF[op],
                          "evidence_id": t.evidence_id if cite else ""})
    return status, steps, notes
