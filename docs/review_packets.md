# Review packets — three highest-impact unresolved issues

Baseline: commit `62eb25d` (prediction-code fingerprint `173e1b82…`, 518 output sha256 `c6cc2f64…`).
Counts below are from that baseline's `code/runs/evaluation_results.json`. Each packet ends with the decision
that needs the repository owner's judgement; the decision actually taken is recorded in the "Decision" line
only after it is made.

---

## Packet 1 — Accounts in ambiguous workflow windows

* **Cases.** 63 of the 71 uncertified cases (518 output). Of these, 27 have *every* candidate account proven
  absent; 36 have a candidate that is present or of unknown state. Samples: case_25, case_26, case_28,
  case_31 (all gold COMPLETE).
* **Example.** case_25 (`s.yoon04@gmail.com`, user_25): the report window holds unowned submissions
  `account_3136` and `account_5684` (`system_activity.csv` rows activity_3597, activity_3600, both FAILED,
  matching NOT_STARTED); both are 404 in evidence_92 (`records/service_resource_export_20260915_114455.json`).
  Gold: `VERIFY_RECORD_ABSENT account_3136 [evidence_92]`.
* **Code.** `ghost_audit/audit.py` — `Auditor.correlate_account` (candidate window), the
  `cand_states` block in `Auditor.audit` (marks the case unresolved), `planner.build_steps` (UNCERTIFIED).
* **Expected vs actual.** Gold certifies COMPLETE and names one account; we output INCOMPLETE with future
  checks only and name no account.
* **Root-cause hypothesis.** The generator assigns submissions to requests by queue order; nothing
  participant-visible encodes that assignment.
  **Competing explanation.** A participant-visible link exists that we have not found (raw review of
  evidence_92 and the activity stream found none: collections are sorted by id, no shared trace ids,
  timestamps do not align — `code/evaluation/case_reviews.md` §A).
* **Approach A (current).** Unresolved unless an identifier ties a candidate to the subject.
  + never attributes another person's account; batch-invariant.
  − 63 cases uncertified; 4 sample statuses differ from gold.
* **Approach B.** When *every* candidate in the window is proven absent, treat the subject's account as
  absent (COMPLETE possible), emitting no account step because its id is unknown.
  + 27 of the 63 become certifiable; the 4 samples match gold status (31/32 instead of 27/32).
  − relies on the window being exhaustive and containing the subject's account, which no evidence states;
  the account step still differs from gold (no id).
* **Recommendation.** Keep A until the organisers answer question 3(c) in `case_reviews.md`; B is the fallback
  if they confirm the window is meant to be exhaustive.
* **Acceptance criterion.** Under any approach: 0 of 2,097 batch-invariance changes, no case attributes an
  account owned by another subject (verifier `context_names_other_subject` = 0), and every certified account
  claim cites admissible evidence.
* **Decision (2026-10-24T22:46:37Z, repository owner, via the in-app question):** selected "Keep strict (Recommended)". Effect, as described by the agent: no account is attributed, and the 27 all-absent cases stay uncertified. This was the option the agent recommended; the owner selected it. No implementation change follows.

---

## Packet 2 — File capture time vs. line time

* **Cases.** Samples case_09/23/24/29/30 (5 gold retained-record steps); in the 518 output, 17 workflow
  candidates whose only subject link is in a file captured after audit_at (`case_investigation.md` §1).
* **Example.** case_09: `audit_record_4902` appears only in evidence_06
  (`logs/structured_service_events_eu_west_20260918.log`, captured 2026-09-18T11:55:24Z); the line is dated
  2026-09-16T08:52:59Z; audit_at 2026-09-16T09:00:00Z.
* **Code.** `ghost_audit/audit.py` — `Auditor.admissible` (capture time **and** line time must be ≤ audit_at).
* **Expected vs actual.** Gold includes an uncited `VERIFY_RECORD_PRESENT audit_record_4902`; we omit it.
* **Root-cause hypothesis.** The gold answers treat "information available" as event time.
  **Competing explanation.** Gold uses these files only to name future-work steps, never to change a status.
* **Approach A (current).** Capture time and line time both gate admissibility everywhere.
  + literal reading of "Evidence created later must not change the answer"; metamorphic tests enforce it.
  − 5 sample steps missed.
* **Approach B.** Admit lines dated ≤ audit_at from later files, but only to *name* uncited future-work steps
  (never to cite, link identity, or change a status).
  + recovers the 5 sample steps without changing any status; contained blast radius.
  − still uses information that did not exist at audit_at; needs new tests for the "name only" boundary.
* **Measured.** The unrestricted event-time reading (analysis only, at a3633c9) gave 29/32 statuses but 29 extra
  and 46 missing steps, so neither reading reproduces gold; B is narrower and has not been measured.
* **Recommendation.** Keep A pending organiser question 1; B is a contained option if confirmed.
* **Acceptance criterion.** Any change must keep the metamorphic tests "add evidence captured after every
  audit_at" and "add activity dated after each audit_at" at 0 changed cases, and change no status.
* **Decision (2026-10-24T22:46:37Z, repository owner, via the in-app question):** selected "Strict capture time (Recommended)". Effect, as described by the agent: files captured after audit_at are not used. This was the option the agent recommended; the owner selected it. No implementation change follows.

---

## Packet 3 — Output for "not proven either way"

* **Cases.** All 71 uncertified rows (518 output); samples case_04, case_25, case_26, case_28, case_31 — gold
  COMPLETE for all five.
* **Example.** case_58: no supported violation; candidate accounts `account_5715`, `account_9862` both absent;
  retained `audit_record_8465` verified present. Output: INCOMPLETE with two uncited future checks.
* **Code.** `ghost_audit/planner.py` — `build_steps` (status UNCERTIFIED); `Auditor.audit` serialises it as
  INCOMPLETE.
* **Expected vs actual.** The contract defines COMPLETE as fully proven and INCOMPLETE as findings +
  remediation + verification; an uncertified case fits neither.
* **Root-cause hypothesis.** The contract assumes every relevant record is identifiable; the sample answers
  certify COMPLETE when no violation is shown.
  **Competing explanation.** The samples certify because the gold generator knows the hidden assignment
  (Packet 1), not because "no violation shown" is meant to imply COMPLETE.
* **Approach A (current).** INCOMPLETE with only future checks (empty evidence_id), no invented findings.
  + never certifies an unproven state; honest about uncertainty.
  − contradicts the contract's description of INCOMPLETE (no findings); 5 sample statuses differ.
* **Approach B.** COMPLETE carrying only the cited verifications that *are* proven, uncertainty kept in the
  trace.
  + matches gold status on all 5 uncertified samples.
  − certifies completion without proving the account's state, which the contract's COMPLETE definition forbids.
* **Recommendation.** Keep A pending organiser question 2.
* **Acceptance criterion.** Whatever the serialisation, the internal UNCERTIFIED state and its reasons stay in
  the trace and in `known_exceptions.json`, and the release gate stays BLOCKED while any exist.
* **Decision (2026-10-24T22:46:37Z, repository owner, via the in-app question):** selected "INCOMPLETE, future checks (Recommended)". Effect, as described by the agent: the current serialisation is kept. This was the option the agent recommended; the owner selected it. No implementation change follows.

---

Organiser clarification message: the owner selected "I'll send it myself" (2026-10-24T22:46:37Z); the agent keeps it as a draft
in `code/evaluation/case_reviews.md` and has not sent it.

No explanation of these decisions was given by the owner; none is attributed. (Note added 2026-10-24T23:59:44Z.)
