# Ghost Data Still Exists — deletion-audit agent

Author and maintainer: Akshay Awadh Dubey. Built for HackerRank Orchestrate (October 2026) with an AI coding
agent; the development transcript is the repository's `log.txt` and AI/model usage is reported in
`evaluation/usage_report.md`.

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
python3 code/main.py --no-cache            # force fresh OCR/PDF/SQL extraction (the submitted run uses this)
python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv
python3 code/evaluation/main.py --quick    # samples + synthetic cases + verifier (~30 s)
python3 code/evaluation/main.py            # + metamorphic, operational and mutation tests (several minutes)
python3 code/evaluation/make_usage_report.py   # usage_report.md from the last code/main.py run's manifest
```

Regenerate every artifact in one go (predictions with fresh extraction, request-batch invariance, the
before/after comparison against a previous git revision, fail-first evidence, both reports):

```bash
python3 code/evaluation/reproduce.py --baseline f280a63 --previous 3be6cb1   # needs a git checkout
python3 code/evaluation/reproduce.py                      # from an extracted code.zip (baseline sections NOT RUN)
```

`code/evaluation/main.py` reads `code/runs/invariance/invariance.json`, `code/runs/compare_{base,prev}.json` and
`code/runs/failfirst/*.json` when they exist; a section whose input is missing is reported as NOT RUN.
`code/evaluation/acceptance.py` turns the results into `acceptance_report.md` (PASS / FAIL / EXCEPTION / NOT RUN
per check, verdicts per area; exit status 1 on any FAIL); recorded exceptions with rationale and exact case
lists live in `code/evaluation/known_exceptions.json`. `code/evaluation/investigate_cases.py` writes the case-level
evidence matrix and conflict reproductions to `case_investigation.md`. CI (`.github/workflows/checks.yml`) runs the
execution job, the full reproduction and the acceptance gate.

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
    investigate.py           bounded OCR re-extraction with verbatim validation (policy: ladder or model)
    audit.py                 strict cut-off view, per-request workflow correlation, prior-state reconstruction,
                             per-replica state at audit_at, unresolved-item tracking
    policy.py                deletion_rules.csv -> category -> required treatment (explicit condition checks)
    planner.py               treatment -> findings / remediation / verification, canonical ordering
    validate.py              output contract checks (fields, phase/op/state, ordering, citations, round trip)
  evaluation/
    main.py                  sample metrics, fixtures, metamorphic, semantic, operational, mutation tests
    verifier.py              independent checker (does not import the predictor's decision code)
    verifier_defects.py      labelled defects injected into gold answers (verifier must flag each)
    fixtures.py              synthetic world with hand-written expectations
    invariance.py            reruns main.py on different request batches; every row must be unchanged
    compare.py               before/after metrics and per-case root cause between two code versions
    failfirst.py             runs today's synthetic cases against any code tree (fail-first evidence)
    report.py                renders evaluation_report.md from the results of evaluation/main.py
    reproduce.py             regenerates predictions, invariance, comparisons, fail-first and all reports
    unit_tests.py            certification and investigation unit checks (runnable against any code tree)
    agent_eval.py            labelled evaluation of the investigation step vs the deterministic baseline
    investigate_cases.py     case-level evidence matrix and specification-conflict reproductions
    acceptance.py            correctness gate (PASS / FAIL / EXCEPTION / NOT RUN) -> acceptance_report.md
  prompts/intent_fallback.md
```

### How a case is decided

1. **Authorisation.** Target-aware rules over multilingual stems (EN/ES/PT/FR/DE/IT/NL/JA/KO/ZH): negation first,
   then full-scope phrases, then a deletion verb with the nearest scope noun in the same sentence (account /
   profile / personal data authorise erasure; newsletter, old phone, address, card do not). Text the rules cannot
   decide is UNDECIDED: it does not authorise deletion and is recorded as unresolved (model fallback only if a
   key is set; that path is untested against a real provider).
2. **Identity.** The request e-mail resolves to a `user_id` through current *or* historical e-mails. Join keys are
   exact: lower-cased e-mail, sha256 of every current/historical e-mail, digit-normalised phones, `user_NN`
   references. Names are never a join key (the data contains same-name and look-alike decoys). OCR text is used
   raw (no substitution table) and nothing fuzzy is accepted: a near-miss only triggers the bounded re-extraction
   in step 7.
3. **Linking.** A resource belongs to the subject if any observation of it carries one of those keys (record
   fields, trace lookup keys, correlation keys, nested JSON, SQL JSON blobs, document text), if the data catalog
   links it, or if it is a downstream copy (search doc → source account, connector/restore → repopulated resource).
   Two weaker, explicitly traced links exist for ids that no file ties to a person. Both use **only this
   request's fields and activity at or before `audit_at`** — never other requests, queue order or the sample file:
   * *workflow correlation* — the deletion-worker account submission in [reported_at − 3 h, reported_at + 20 min]:
     an evidence-linked one wins, else a unique unowned one with the matching result, else the only one; otherwise
     the account is recorded as unresolved;
   * *deletion-run attribution* — a policy action on an otherwise unlinked record, accepted only when every rival
     run in the preceding hour provably belongs to another subject.
4. **State at `audit_at` (strict cut-off).** An observation is admissible only if its file was captured by
   `audit_at` **and** its embedded event time is at or before `audit_at`; catalog aliases count only after their
   link time. The same view drives linking, ownership, state, policy and planning. Pre-request history carries
   forward unless a later deletion run for the subject, a later success claim, or a stated expiry supersedes it
   (then the state is *unknown*, not absent). State is kept per replica and aggregated (a copy in any replica is
   present). Absence needs positive proof: 404/NOT_FOUND, or a later complete capture that covers the subject.
   Restore capability needs an affirmative statement about the specific archive (on a line naming it); another
   archive's completed restore is not evidence about it.
   Activity results are claims; a connector/restore that *repopulated* a resource after its last observation
   re-creates it. Missing search results, misses, partial logs and inventories never prove absence.
5. **Policy.** Category from system + record kind (attachment vs conversation, hash-only contact, tombstone…),
   then `deletion_rules.csv` with explicit condition checks (retention/hold expiry, shared support context).
6. **Plan and certification.** Recreation paths first (disable flows, block restores), then delete/redact/anonymise,
   then the required final state of every relevant resource including retained ones. Ordering: phase → operation
   table order → `system_id` → `resource_id`. Before any status is chosen, every required verification must be backed
   by a cited admissible observation of its state; an unsupported one is an unresolved item, never dropped.
   **COMPLETE requires every required final state proven, including the subject's primary account**, which must be
   identified (identifier in admissible evidence, or the unique workflow submission for this request alone) and
   observed. A missing account id is not proof of absence; absent candidates in an ambiguous window are not proof
   about the subject. Otherwise the case is UNCERTIFIED and serialised as `INCOMPLETE` with only the future
   verification checks (empty `evidence_id`, no invented findings); every blocking reason is in the trace.
7. **Bounded investigation (`ghost_audit/investigate.py`).** When a screenshot's OCR token is a near-miss of exactly
   one known identifier, a policy chooses deterministic re-extractions (re-OCR at ×2/×3, other page-segmentation
   modes, binarisation) within a budget; the identifier counts only if read verbatim. The default policy is a fixed
   ladder; a model policy (`GHOST_AUDIT_INVESTIGATOR=model` plus `ANTHROPIC_API_KEY`) chooses the next tool, but it has
   not been run against a real provider. Policies cannot accept or edit facts, read other files, or change temporal
   filtering, policy rules or serialisation.

### Tradeoffs

* **Rules over LLM calls.** The evidence is structured enough that deterministic parsing is exact, reproducible,
  free, and auditable; the model is reserved for genuinely ambiguous request text.
* **Precision over recall on weak links.** Ambiguous account/analytics attributions are left out rather than
  guessed (0 extra steps on the samples), at the cost of recall.
* **Strict cut-off.** Files captured after `audit_at` are not used at all, even when their embedded events are
  earlier. Some sample answers rely on such files (see the organizer question in the evaluation report); the
  strict reading is kept until the organizers clarify.

Evidence is treated as untrusted data: nothing read from a file is executed or followed as an instruction;
free text is only scanned for identifiers. The pipeline never modifies `dataset/`.
