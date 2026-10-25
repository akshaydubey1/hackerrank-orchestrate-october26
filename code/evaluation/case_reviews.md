# Raw-evidence case reviews

Six unresolved cases were reopened from the original files, not from the predictor's or the
verifier's extracted text. Screenshots and PDF pages were viewed as images, re-read with five
re-extraction settings, and PDFs rasterised and re-OCRed; JSON was walked in full, logs read line
by line with their trace ids, SQL searched raw, and the activity stream read around each event.
Ownership was never inferred from numeric id patterns, request order or time proximity.

| # | Case | Problem type | Outcome |
|---|---|---|---|
| A | case_25 (sample) | ambiguous account | unresolved — no admissible link |
| B | case_03 (sample) | anonymised analytics record | unresolved — proximity would pick the wrong record |
| C | case_45 | media-only identity link | **extraction omission found and fixed**; case still uncertified (account unknown) |
| D | case_18 / case_20 (samples) | retained record | unresolved — ids occur nowhere, also not in re-reads |
| E | case_55 | unknown restore path | unresolved — no statement about this archive; the only "drill" date predates the archive |
| F | case_04 (sample) | sample / specification conflict | unresolved — the subject occurs in no evidence file |

## A. case_25 — ambiguous account (gold: `VERIFY_RECORD_ABSENT account_3136 [evidence_92]`)

* **Examined.** evidence_92 (`records/service_resource_export_20260915_114455.json`, captured 2026-09-15T11:44:55Z)
  in full: every collection (`profile_lookups`, `profiles`, `restore_entries`, `connectors`, `audit_records`,
  `tickets`, `index_queries`) is sorted by `resource_id`; `account_3136` is a 404 lookup with `profile: null`
  at 09:31:40Z. `audit_record_451` (`subject_reference: user_25`, 10:07:33Z) is the only record naming the
  subject. Activity rows 3597–3607: the 2026-09-02 deletion run submits `account_3136` (FAILED), `account_4842`,
  `account_5334`, `account_5684` (FAILED), `account_7225`, then anonymises `analytics_1895` and `analytics_4566`.
* **Supported.** `account_3136` and `account_5684` are absent at 2026-09-15; both are FAILED submissions,
  matching the NOT_STARTED reports of case_25 *and* case_26 (same `reported_at`).
* **Rejected alternatives.** Position in the export (sorted by id, no grouping); timestamps (no consistent
  proximity); run order (3136 before 5684 matches the gold assignment, but that is request/queue order).
* **Remaining uncertainty.** Which of the two accounts is user_25's. Not derivable from this request's evidence.

## B. case_03 — anonymised analytics record (gold: `VERIFY_RECORD_ANONYMIZED analytics_9406 [evidence_94]`)

* **Examined.** evidence_94 (`logs/resource_lookup_trace_20260926_103856.log`, a 28-query readback, captured
  2026-09-26T10:38:56Z, admissible for case_03 audit_at 11:00Z) line by line: each query is a
  `*_started` line with `lookup_key=` and a `*_completed` line, joined by `trace_id=rb-HHMMSS-NNN`.
  Line 18: `account_7566` lookup with `lookup_key=l.fontaine46@yahoo.com` (the subject). Line 20, one second
  later: `analytics_5589` with `lookup_key=null`. Line 42: `analytics_9406` with `lookup_key=null`, an hour
  later. Activity 3849–3853: accounts `2064` (PARTIAL), `6523`, `7566` submitted, then `analytics_9406` and
  `analytics_5589` anonymised 15 s apart.
* **Supported.** Both analytics records are anonymised (all identifier fields null) at the readback.
* **Rejected alternatives.** Readback proximity points at `analytics_5589` — the gold answer says `9406`, so
  proximity is not just unproven but wrong here. Trace ids are per query, not per subject.
* **Remaining uncertainty.** Two anonymised records, three candidate subjects; nothing names any of them.

## C. case_45 — media-only identity link (evidence_37, `images/security_audit_explorer_20260905.png`)

* **Examined.** The screenshot (viewed as an image): "Account events · Subject filter: user_03 ·
  6 signed events", a table of six rows, each `user_03 … Valid audit_record_00N`.
* **Found.** The default OCR pass (Tesseract `--psm 3`) drops row 2 (`25 Aug 03:21 Session revoked … user_03 …
  audit_record_002`). The verifier uses the same default pass, so both missed it — a shared assumption.
  All five re-extraction settings read the row verbatim.
* **Mechanism and fix.** The screen states its own count ("6 records"); 5 row ids were extracted. The bounded
  investigation step now treats "declared count > extracted ids" as a problem, re-extracts with the tool
  ladder, and accepts the new rows **only if** the total then equals the declared count exactly; accepted
  rows go through the ordinary document parser (their own line names `user_03`). Fail-first tests:
  `fx_ocr_row_gap` (a synthetic screen where the old code returned COMPLETE while missing a retained record),
  unit tests U9–U11 (acceptance, over-read rejection, observation from the row's own line).
* **Effect.** case_45 gains `VERIFY_RECORD_PRESENT security_service audit_record_002` (future check). Its status
  is unchanged: no account record is known for user_03 by audit_at, so it remains uncertified.

## D. case_18 / case_20 — retained records (gold: `audit_record_6645`, `audit_record_5569`)

* **Examined.** All 11 screenshots re-read at ×2/psm 6 and ×3/psm 11; all 4 PDFs rasterised at 200 dpi and
  OCRed; `pdfimages -list` (no embedded images); raw SQL, JSON, logs and text searched for the full ids and
  for their numeric suffixes.
* **Result.** Neither id occurs anywhere. The suffixes occur only inside other identifiers: `account_6645`
  (a 404 lookup in `application_trace_eu_north_20260302.log`), `support_5569` and ticket `CS-5569`.
* **Remaining uncertainty.** We cannot find participant-visible evidence for these gold steps.

## E. case_55 — unknown restore path (`backup_9287`, evidence_32 `images/backup_restore_console_20260429.png`)

* **Examined.** The screenshot as an image: archive row `backup_9287 · areed1433@gmail.com · eu-west-1 ·
  26 Apr 02:00 · Archive`; detail panel: Created 26 Apr 2026, Checksum Verified, **Last drill 29 Mar 2026**,
  Retention end 26 Jul 2026; activity panel: `backup_9286 restored · Completed`, `backup_9281 restored ·
  Completed`; page metric "Restore success 99.6%". Activity: `activity_4006` (2026-04-29) catalogs the backup
  to the subject; `activity_3387` (`RESTORE_BACKUP … backup_9287`, 2026-08-22) is after audit_at (2026-04-30).
* **Supported.** The archive holds the subject's data; no block or hold is shown.
* **Rejected alternatives.** Other archives' completed restores (not this archive); the page-wide success rate;
  "Last drill 29 Mar 2026" — it predates the archive's creation (26 Apr), so it cannot be a restore of this
  archive; `activity_3387` (after audit_at).
* **Remaining uncertainty.** Whether an archive with the subject's data and no visible block counts as an active
  restore path without an explicit statement (organiser question 2 below).

## F. case_04 — sample / specification conflict

* **Examined.** The subject (`user_04`, `thandiwe.n@gmail.com`, its sha256, phone digits `…716845928`, name
  "Thandiwe Ndlovu"; no identity history) searched in every evidence file — raw bytes, extracted OCR/PDF text and
  ×2 re-reads of every screenshot — and in the activity stream.
* **Result.** **The subject occurs in no evidence file and no activity row.** `account_004` occurs nowhere;
  evidence_54 (7-row failover dump) does not contain it; `analytics_901` is a fully anonymised row in evidence_56
  and one `ANONYMIZE_RECORD` activity naming no person.
* **Remaining uncertainty.** How the gold answer links either resource to user_04.

## Ready-to-send clarification message (not sent)

> Subject: Ghost Data Still Exists — three clarification questions with minimal examples
>
> Hello, we would appreciate guidance on three points. In each case we searched every participant file (raw
> JSON/SQL/logs/text, OCR of every screenshot at several settings, rasterised OCR of every PDF page) and the
> activity stream, and may simply be missing the intended evidence — could you tell us where it is?
>
> 1. **Capture time vs. event time.** case_09 (audit_at 2026-09-16T09:00:00Z): the sample answer verifies
>    `audit_record_4902`, which appears only in `logs/structured_service_events_eu_west_20260918.log`
>    (evidence_06, `captured_at` 2026-09-18T11:55:24Z); the line itself is dated 2026-09-16T08:52:59Z.
>    Should a file captured after audit_at be used for lines dated before audit_at (for uncited future-work
>    steps, for identity links, or not at all)? Same pattern: case_23/24/29/30 via evidence_02.
> 2. **No proof either way.** When no violation is supported but a required final state is not proven — e.g.
>    case_55: `backup_9287` (evidence_32) holds the subject's data with no block shown, and the screen's only
>    restore statements concern other archives — what is the expected status, and which steps should it carry?
>    Does such an archive count as an active restore path without an explicit statement about it?
> 3. **Resource/identity links we cannot locate.** (a) case_04: where is `account_004` or `analytics_901` linked
>    to user_04? We find no occurrence of the subject in any evidence file. (b) case_18 `audit_record_6645`,
>    case_20 `audit_record_5569`: which file contains these ids? (c) case_25/case_26 share report time and
>    status; the window holds two unowned submissions (`account_3136`, `account_5684`). Which evidence assigns
>    each to its request, or is the expected answer meant to depend on the other requests in the file?
>
> Thank you.
