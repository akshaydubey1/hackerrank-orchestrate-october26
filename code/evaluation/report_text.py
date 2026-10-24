"""Hand-written narrative for evaluation_report.md (numbers are inserted by main.py)."""

NARRATIVE = {
    "sample_discrepancies": """**Why each remaining sample step is missed (none are extra steps):**

* **Unattributable anonymised analytics (case_03, 25, 26, 27, 28).** These records carry no identifier
  in any file; the only link is a deletion-worker `ANONYMIZE_RECORD` activity. Every one of them sits in
  a batch where 2–3 requests were processed in the same hour with the same reporting style, so the
  activity stream cannot say which request owns which record. The gold order matches case-number order,
  which we deliberately do not use. We emit the step only when exactly one request can own the record
  (this resolves case_21 here and {run_linked} attributions across the full dataset) and otherwise record the ambiguity in the trace.
* **Security records that appear in no participant file (case_18 `audit_record_6645`,
  case_20 `audit_record_5569`).** A full-text search of every file, OCR output and PDF text finds neither id.
* **case_04 (showcase case).** No admissible evidence names the subject's account or analytics record
  (`account_004` never appears in the activity stream; the analytics report is not linked to the subject).
  With nothing proving any required state, the planner refuses to certify COMPLETE and returns an
  uncertified INCOMPLETE. This is the only status error, and it is the deliberate cost of never turning
  "no evidence" into COMPLETE.
""",
    "fixture_modes": {
        "fx_extraction_failures_recorded": "unreadable JSON + manifest file missing on disk",
        "fx_backup_risk": "backup with restore allowed (SQL inventory)",
        "fx_claim": "worker reports SUCCESS, later observation shows record present",
        "fx_decoy": "same-name user + `.jr` look-alike + substring e-mail decoys",
        "fx_exact_audit": "observation exactly at audit_at is admissible",
        "fx_future": "file captured after audit_at must be ignored",
        "fx_hist_email": "request uses historical e-mail; record keyed only by sha256 of old e-mail",
        "fx_intent_access": "access request -> NOT_APPLICABLE",
        "fx_intent_correct": "correction request -> NOT_APPLICABLE",
        "fx_intent_es": "Spanish deletion request (no evidence -> uncertified, never COMPLETE)",
        "fx_intent_export": "export request -> NOT_APPLICABLE",
        "fx_intent_ja": "Japanese deletion request",
        "fx_intent_ko": "Korean deletion request",
        "fx_intent_mkt": "marketing-only opt-out containing the word 'remove' -> NOT_APPLICABLE",
        "fx_intent_neg": "mixed request with explicit 'do not delete' -> NOT_APPLICABLE",
        "fx_miss": "search miss is not absence; duplicate observations give one step",
        "fx_pdf_pii": "PII only inside a PDF attachment",
        "fx_png_pii": "PII only inside a screenshot (Tesseract OCR)",
        "fx_replica": "primary deleted, failover replica still holds the profile",
        "fx_resync": "deleted, then an active connector repopulates search",
        "fx_retained_ok": "active legal hold + disabled flow + blocked backup -> COMPLETE",
        "fx_tomb_clean": "tombstone with only the stable user_id -> VERIFY_RECORD_REDACTED",
        "fx_tomb_pii": "tombstone still holding name+email (REDACT, never DELETE) and a security "
                       "record whose retention expired (DELETE)",
    },
    "mutation_notes": """Every injected fault listed above is caught by at least one independent check. The weakest detection is
"ignore request window": only the sample guard notices it, because the fixtures do not contain
pre-request evidence. Surviving-mutant analysis therefore points at one gap to close next: a
fixture where a record seen only *before* the request must not be reported.""",
    "verifier_intro": """`code/evaluation/verifier.py` imports none of the predictor's decision code. It rebuilds
identifier sets from the CSVs, reads the raw cited file (its own pdftotext/Tesseract calls), finds the
record context by plain text search (log line + its trace, enclosing JSON object, SQL row), and checks
with its own token rules that the cited context supports the claimed state, that the citation was
captured by audit_at, that every finding has a matching remediation and verification, that recreation
paths are remediated before record treatment, that retained records are never deleted unless an
expired retention date is cited, and — for COMPLETE answers — sweeps all admissible logs for a positive
presence marker next to the subject that the answer does not account for (possible false COMPLETE).
Shared assumptions with the predictor: sha256(lower(email)) hashing, resource-id prefixes naming the
system, the same Tesseract binary, and deletion_rules.csv. Running it on the gold sample answers is the
false-alarm check (it must report 0 issues there).

`cited_without_subject_identifier` counts cited steps whose record context does not itself print the
subject (e.g. a `404` account lookup, or an anonymised analytics row); those links come from the
workflow correlation / deletion-run attribution described in the README and are the weakest links in
the output.""",
    "failures_and_improvements": """## Failures found and improvements made (chronological)

| # | Failure observed | Root cause (layer) | Fix | Regression guard |
|---|---|---|---|---|
| 1 | Sample status 29/32; 9/32 exact | intent lexicon missed "verify my profile is gone" requests (intent); bundle absence overrode direct 404s (temporal) | added deletion-verification phrases; prefer direct observations over capture absence | samples, `fx_future` |
| 2 | Security records reported absent although they exist | JSON bundles with several targeted captures treated as complete (temporal) | capture absence only from single-capture collections that cover the subject | samples |
| 3 | Connector screen linked a flow to the wrong customer | OCR identifiers taken from the whole page (ingestion) | screens: same-line identifiers only; PDFs: whole document | `fx_png_pii`, `fx_decoy` |
| 4 | `connector_heartbeat` flows ignored | unknown log event (ingestion) | generic `enabled=` / `restore_allowed=` handling | `fx_resync` |
| 5 | Stale pre-request records (object_19, tombstone_17) reported | no request window (temporal) | state only from observations inside [requested_at, audit_at] | mutation "ignore request window" |
| 6 | Wrong account attributed (case_23/28/29) | greedy nearest-time matching (identity) | candidate sets + constraint propagation; queue-order tie-break by evidence-linked follow-up actions; otherwise leave ambiguous | samples |
| 7 | Anonymised analytics given to the wrong request | last-in-first-out guess (identity) | accept only uniquely forced attributions; batch reporting style filter | samples (0 FP) |
| 8 | 34 "retention violations" | SQL inventory `snapshot_scope` treated as complete (temporal) | inventories never prove absence; the contradiction count is now 0 | verifier `retention_violation` |
| 9 | COMPLETE with no evidence at all | planner certified empty plans (planning) | COMPLETE needs at least one evidence-backed verification, else uncertified INCOMPLETE | `fx_intent_es/ja/ko` |
| 10 | Metamorphic "future evidence" changed 131 cases | never-observed resources declared absent from older captures (temporal) | capture absence needs the resource to be known before the capture | metamorphic test C6 |
| 11 | Metamorphic "paraphrase" changed 163 statuses | lexicon matched `eliminar` but not `eliminen`; Spanish "no de eliminación" negation missed (intent) | stem-based multilingual patterns + cross-language negation | metamorphic test C7 |
| 12 | Capture absence contradicted by a later event | full-table dump treated as complete even when a later in-window event shows the record (temporal) | such absences are withdrawn (late exports are used to withdraw a proof, never to make one) | trace flag |
| 13 | Mutation harness corrupted static methods on restore | test tooling | restore raw class attribute | mutation suite clean run |
""",
    "limitations": """## Remaining limitations (honest list)

* **Account attribution.** {amb} of {deletions} deletion requests have no account step because several requests
  share the same workflow report time and status and nothing else separates their accounts; {tb} more
  rely on the queue-order tie-break (validated on 3 sample groups only). Of the {complete} COMPLETE answers,
  {complete_no_acct} do not contain an account-absence citation; they are COMPLETE because no evidence shows
  remaining data, not because absence of the account was proven. The trace marks every such case.
* **Anonymised analytics** in ambiguous deletion batches are left out ({amb_analytics} activities).
* **Late-captured files** (exported after audit_at, describing events inside the window) are used only to
  name retained records in the future-work plan and to withdraw a capture-based absence proof. They are
  never cited and never make a finding. This is a deliberate reading of the contract and changes 3 sample steps.
* **Absence proofs** come from explicit 404/NOT_FOUND observations, single-capture JSON collections that
  cover the subject, and replica dumps; SQL inventories are excluded because the data refutes their
  completeness. If the hidden key treats inventories as complete, some account verifications are missed.
* **OCR** is Tesseract only. It is good enough here because every screen's facts are cross-checked with an
  exact join (identifier or data-catalog link); fuzzy matching is used only to decide whether an already
  linked owner's identifier is printed, never to create a link.
* **No model calls were made.** The rule-based classifier decided all 550 requests; the model fallback is
  implemented and fault-tested (Section C) but needs `ANTHROPIC_API_KEY`, which this environment does not have.
""",
}
