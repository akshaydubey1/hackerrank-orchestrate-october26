"""Turn per-resource treatments into the canonical, ordered step list.

Every resource whose required final state cannot be established from admissible evidence is
recorded as an UNRESOLVED item. Unresolved items are never converted into steps, never
silently dropped, and are returned to the caller so the case result carries them.
"""
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
    unknown_reason: str = ""    # why the state could not be established (empty when it could)


def plan_one(t: Treatment) -> tuple:
    """Return (finding_op|None, remediation_op|None, verification_op|None, unresolved_reason)."""
    why = t.unknown_reason or "state not established by admissible evidence"
    if t.category == "DATA_FLOW":
        if t.flow_enabled:
            return "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED", ""
        if t.flow_enabled is False or t.exists is False:
            return None, None, "VERIFY_DATA_FLOW_DISABLED", ""
        return None, None, None, f"flow state unknown: {why}"
    if t.category == "BACKUP_ARCHIVE":
        if t.restore_allowed:
            return "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED", ""
        if t.restore_allowed is False:
            return None, None, "VERIFY_RESTORE_BLOCKED", ""
        return None, None, None, f"restore capability unknown: {why}"
    if t.action == "DELETE":
        if t.exists:
            return "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT", ""
        if t.exists is False:
            return None, None, "VERIFY_RECORD_ABSENT", ""
        if t.category == "USER_PROFILE":
            # the primary account always has a required final state; it is planned as future work
            # in an INCOMPLETE case, and stays unresolved (never cited) otherwise
            return None, None, "VERIFY_RECORD_ABSENT", f"account absence unproven: {why}"
        return None, None, None, f"presence unknown: {why}"
    if t.action == "REDACT":
        if t.exists is False:
            return None, None, None, "record to retain-and-redact observed absent"
        if t.pii:
            return "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", ""
        if t.pii is False:
            return None, None, "VERIFY_RECORD_REDACTED", ""
        return None, None, None, f"redaction state unknown: {why}"
    if t.action == "ANONYMIZE":
        if t.exists is False:
            return None, None, "VERIFY_RECORD_ABSENT", ""
        if t.pii:
            return "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED", ""
        if t.pii is False:
            return None, None, "VERIFY_RECORD_ANONYMIZED", ""
        return None, None, None, f"anonymisation state unknown: {why}"
    if t.action == "RETAIN":
        if t.exists:
            return None, None, "VERIFY_RECORD_PRESENT", ""
        if t.exists is False:
            return None, None, "VERIFY_RECORD_PRESENT", "RETENTION_VIOLATION: required retained record observed absent"
        return None, None, None, f"retained record not observed: {why}"
    return None, None, None, f"no action for {t.category}"


def build_steps(treatments: list, force_uncertified: bool = False) -> tuple:
    """Return (status, steps, unresolved). status is COMPLETE, INCOMPLETE or UNCERTIFIED.

    UNCERTIFIED means: no violation was found, but at least one required final state is not proven
    by admissible evidence (or nothing is proven at all). It is an internal state; the caller
    serialises it as INCOMPLETE carrying only the future verification checks (empty evidence_id,
    no fabricated findings) and reports every unresolved item.
    """
    findings, remediation, verification, unresolved = [], [], [], []
    for t in treatments:
        f, r, v, note = plan_one(t)
        if note:
            unresolved.append({"resource_id": t.resource_id, "system_id": t.system, "category": t.category,
                               "reason": note})
        if f:
            findings.append((f, t))
        if r:
            remediation.append((r, t))
        if v:
            verification.append((v, t))
    if findings:
        status = "INCOMPLETE"
    elif force_uncertified:
        status = "UNCERTIFIED"
    elif any(u["reason"].startswith("RETENTION_VIOLATION") for u in unresolved):
        status = "UNCERTIFIED"  # a missing retained record rules out COMPLETE; no finding op exists for it
    elif unresolved:
        status = "UNCERTIFIED"  # some required final state is not proven
    elif any(t.evidence_id and t.exists is not None or t.evidence_id and (t.flow_enabled is not None or
             t.restore_allowed is not None) for _, t in verification):
        status = "COMPLETE"
    else:
        status = "UNCERTIFIED"
    if status == "COMPLETE":
        # COMPLETE may only carry evidence-backed verification; everything else is already in
        # `unresolved` (each unproven item produced a reason above)
        verification = [(v, t) for v, t in verification if t.evidence_id and not t.unknown_reason
                         and (t.exists is not None or t.flow_enabled is not None or t.restore_allowed is not None)]

    def key(item):
        op, t = item
        return (ORDER[op], t.system, t.resource_id)

    steps = []
    for phase_items, cite in ((findings, True), (remediation, False), (verification, status == "COMPLETE")):
        for op, t in sorted(phase_items, key=key):
            steps.append({"step_no": len(steps) + 1, "phase": PHASE_OF[op], "system_id": t.system,
                          "resource_id": t.resource_id, "operation": op, "state": STATE_OF[op],
                          "evidence_id": t.evidence_id if cite else ""})
    return status, steps, unresolved
