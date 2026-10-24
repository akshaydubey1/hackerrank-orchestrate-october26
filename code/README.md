# Ghost Data Still Exists — deletion-audit agent

Deterministic, evidence-first auditor. For each request it decides whether deletion was authorised,
resolves the subject's current and historical identifiers, reconstructs every linked resource's state
at `audit_at` from the evidence files, applies `deletion_rules.csv`, and emits the canonical
FINDING → REMEDIATION → VERIFICATION plan. Every decision is traced.

## Setup

```bash
# Python 3.10+ (tested on 3.13). System tools: tesseract (OCR) and pdftotext (poppler-utils).
#   macOS:  brew install tesseract poppler      Debian/Ubuntu: apt-get install tesseract-ocr poppler-utils
python3 -m pip install -r code/requirements.txt   # only pypdf is used at run time (PDF fallback)
```

No API key is required. Optionally `export ANTHROPIC_API_KEY=...` enables the model fallback for
requests the rule-based intent classifier cannot decide (see `prompts/intent_fallback.md`).

## Run (from the repository root, with `dataset/` present)

```bash
python3 code/main.py                       # -> ./output.csv (518 rows), code/runs/output.{manifest.json,trace.jsonl}
python3 code/main.py --no-cache            # force fresh OCR/PDF/SQL extraction
python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv
python3 code/evaluation/main.py            # full evaluation -> code/evaluation/evaluation_report.md (~1.5 min)
python3 code/evaluation/main.py --quick    # samples + fixtures + verifier only
python3 code/evaluation/make_usage_report.py   # usage_report.md from the last run's manifest
```

The run manifest records the code revision, parser version, SHA-256 of every input CSV and evidence file,
extraction failures, cache hits/misses, timings, validation results and model usage.

## Architecture

```
code/
  main.py                    CLI, run manifest, decision traces
  ghost_audit/
    ingest.py                manifest-driven loading; cache keyed by content hash + parser version + file id/capture time
    parsers.py               JSON (bundles, exports, ledgers), SQL (isolated in-memory SQLite, per replica table),
                             6 log dialects (trace-grouped), handover text, PDF (pdftotext), PNG (Tesseract)
                             -> normalised Observation(evidence_id, location, captured_at, observed_at, system,
                                replica, resource_id, exists, pii, flow_enabled, restore_allowed, retention, kind, identifiers)
    identity.py              current snapshot + dated audit log -> emails, phones (digits), sha256 hashes, user refs
    activity.py              activity stream as *claims*: catalog links, repopulation edges, workflow submissions
    intent.py / llm.py       multilingual, negation-aware intent rules; optional validated model fallback
    audit.py                 resource linking, per-replica state at audit_at, deletion-run attribution
    policy.py                deletion_rules.csv -> category -> required treatment (explicit condition checks)
    planner.py               treatment -> findings / remediation / verification, canonical ordering
    validate.py              output contract checks (fields, phase/op/state, ordering, citations, round trip)
  evaluation/
    main.py                  sample metrics, fixtures, metamorphic, semantic, operational, mutation tests
    verifier.py              independent checker (does not import the predictor's decision code)
    fixtures.py              synthetic world with hand-written expectations
  prompts/intent_fallback.md
```

### How a case is decided

1. **Authorisation.** Rules over multilingual stems (EN/ES/PT/FR/DE/IT/NL/JA/KO/ZH) with explicit-negation and
   marketing-only patterns. Undecided text never authorises deletion (model fallback only if a key is set).
2. **Identity.** The request e-mail resolves to a `user_id` through current *or* historical e-mails. Join keys are
   exact: lower-cased e-mail, sha256 of every current/historical e-mail, digit-normalised phones, `user_NN`
   references. Names are never a join key (the data contains same-name and `.jr` look-alike decoys).
3. **Linking.** A resource belongs to the subject if any observation of it carries one of those keys (record
   fields, trace lookup keys, correlation keys, nested JSON, SQL JSON blobs, document text), if the data catalog
   links it, or if it is a downstream copy (search doc → source account, connector/restore → repopulated resource).
   Two weaker, explicitly traced links exist for ids that no file ties to a person:
   * *workflow correlation* — the deletion-worker account submission summarised by the request's
     `reported_at`/`reported_status` (candidate sets + constraint propagation; queue-order tie-break; otherwise ambiguous);
   * *deletion-run attribution* — a policy action on an otherwise unlinked record, accepted only when exactly one
     request can own it.
4. **State at `audit_at`.** Only observations captured by `audit_at` and observed inside
   `[requested_at, audit_at]`. State is kept per replica and aggregated (a copy in any replica is present).
   Absence needs positive proof: 404/NOT_FOUND, or a later complete capture that covers the subject.
   Activity results are claims; a connector/restore that *repopulated* a resource after its last observation
   re-creates it. Missing search results, misses, partial logs and inventories never prove absence.
5. **Policy.** Category from system + record kind (attachment vs conversation, hash-only contact, tombstone…),
   then `deletion_rules.csv` with explicit condition checks (retention/hold expiry, shared support context).
6. **Plan.** Recreation paths first (disable flows, block restores), then delete/redact/anonymise, then the
   required final state of every relevant resource including retained ones. Ordering: phase → operation table
   order → `system_id` → `resource_id`. COMPLETE requires at least one evidence-backed verification and contains
   only cited verification steps; anything unproven is dropped and recorded in the trace.

### Tradeoffs

* **Rules over LLM calls.** The evidence is structured enough that deterministic parsing is exact, reproducible,
  free, and auditable; the model is reserved for genuinely ambiguous request text.
* **Precision over recall on weak links.** Ambiguous account/analytics attributions are left out rather than
  guessed (0 extra steps on the samples), at the cost of recall.
* **Late exports.** Files exported after `audit_at` that describe in-window events may name retained records in the
  future-work plan and may withdraw a capture-based absence proof; they are never cited and never create a finding.

Evidence is treated as untrusted data: nothing read from a file is executed or followed as an instruction;
free text is only scanned for identifiers. The pipeline never modifies `dataset/`.
