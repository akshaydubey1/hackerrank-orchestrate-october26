# Walkthrough — one case end to end (case_37)

Values below are copied from `output.csv` and `code/runs/output.trace.jsonl`, both produced by
`python3 code/main.py`.

**Request.** `case_37`, email `abena.o189491@zoho.com`, requested 2026-09-06T12:00:00Z, reported
`COMPLETE` at 2026-09-09T12:00:00Z, audit_at **2026-10-01T12:00:00Z**. Text: "I want to close this account
and have its associated personal data deleted…"

| Stage | What happens | Where (file → function) | case_37 values |
|---|---|---|---|
| 1. Authorization | Rule classifier with target-aware patterns and negation; non-deletion intents give `NOT_APPLICABLE` and `[]` | `ghost_audit/intent.py` → `classify`, `classify_rules` | `DELETION`, reason `full-scope deletion phrase: /\bclose (my\|this\|the) account\b/` |
| 2. Historical identity | The request email is resolved against current **and** historical identifiers; every email, phone and hash the subject ever had becomes a search key | `ghost_audit/identity.py` → `IdentityIndex.__init__`, `resolve_email`, `Person.identifier_keys` | the request email is the *oldest* address: `user_audit_log.csv` audit_179 (changed 2026-02-03), audit_305 (changed 2026-06-03); current `abena.o1894@zoho.com`. Resolved to `user_35` with 3 emails, 1 phone, 3 hashes |
| 3. Admissible evidence | An observation counts only if the file's capture time **and** the line's own time are ≤ audit_at | `ghost_audit/audit.py` → `Auditor.admissible`, `Auditor.view` | `evidence_03` (`records/customer_account_handover_20261001.txt`, captured 2026-10-01T12:00:00Z = audit_at) is admissible; lines 13, 22, 28 name the historical email and line 32 names `user_35` |
| 4. Resource state | The state at audit_at is rebuilt per resource from admissible observations; activity rows are claims, not proof | `Auditor.correlate_account`, `Auditor.state_at` | `account_5193` NOT_FOUND (line 13, and absent from the complete failover capture evidence_54); `search_1934` FOUND (line 28) even though `activity_3740` reports the deletion; `data_flow_2528` ACTIVE (line 22), and `activity_3755` (2026-09-09T12:53:51Z) "repopulated downstream resource search_1934"; `audit_record_2019` FOUND (line 32) |
| 5. Policy | Category → rule from `deletion_rules.csv` | `ghost_audit/policy.py`; `Auditor.audit` builds one `Treatment` per resource | USER_PROFILE rule_01 DELETE; SEARCH_INDEX_ENTRY rule_03 DELETE; SECURITY_AUDIT_LOG rule_12 RETAIN; DATA_FLOW: active paths must be disabled |
| 6. Ordered plan | Findings, then remediation, then verification. Within remediation, flows are disabled and restores blocked before records change. Findings cite evidence; future work has an empty `evidence_id` | `ghost_audit/planner.py` → `plan_one`, `build_steps` (`ORDER` key) | 1 REPORT_REMAINING_RECORD search_1934 [evidence_03]; 2 REPORT_ACTIVE_DATA_FLOW data_flow_2528 [evidence_03]; 3 DISABLE_DATA_FLOW data_flow_2528; 4 DELETE_RECORD search_1934 |
| 7. Verification | Every required final state gets a check, including the records already compliant (the account absent, the audit record retained) | `build_steps` (verification phase) | 5 VERIFY_RECORD_ABSENT account_5193; 6 VERIFY_RECORD_ABSENT search_1934; 7 VERIFY_RECORD_PRESENT audit_record_2019; 8 VERIFY_DATA_FLOW_DISABLED data_flow_2528 — status **INCOMPLETE** |

Why the status is not COMPLETE: a search entry that rule_03 requires deleted is still present at audit_at,
and an active connector has already recreated it once. The workflow's own `COMPLETE` claim is contradicted
by evidence_03.

## Questions put to the owner and the actual answers (2026-10-24T23:00:50Z, in-app question)

Question text exactly as asked; option labels exactly as selected:

| Question (verbatim) | Owner's selection (verbatim) |
|---|---|
| "The release gate will stay BLOCKED. The 71 uncertified cases are documented exceptions, and you chose to keep them strict. Development and structure checks pass. How do you want this submission treated?" | "Decide later" |
| "Only an account-level claude.ai data export covers 13:09–17:35 UTC and the end of this final turn. Will you take that export after this turn and submit it alongside log.txt?" | "Yes, I'll export it" |
| "In case_37 the remediation disables data_flow_2528 before deleting search_1934, because activity_3755 shows that flow repopulated the index after the request. Is this the ordering rule you want applied everywhere?" | "Yes, flows first always" |

Correction (2026-10-24T23:59:44Z): the agent wrote the second question's premise ("Only an account-level … export covers …") before any export had been inspected. Its coverage is unverified (`docs/transcript_audit.md` §5). The owner's answer is recorded as given.

The ordering question offered the current rule and an alternative; the owner chose the current rule. The
other two answers are the owner's own plans; the agent can act on neither.
