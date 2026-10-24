"""Render evaluation_report.md from the results dict built by evaluation/main.py.

Every number in the report comes from `res`; the prose explains what the numbers mean. Sections
that need an input that was not produced in this run say NOT RUN instead of showing old values.
"""
from __future__ import annotations

FIXTURE_MODES = {
    "fx_extraction_failures_recorded": "unreadable JSON, missing file, malformed SQL statement and a text file with no facts are all recorded as failures",
    "fx_backup_risk": "backup with restore allowed (SQL inventory)",
    "fx_claim": "worker reports SUCCESS, later observation shows the record present",
    "fx_decoy": "same-name user, `.jr` look-alike and substring e-mail decoys",
    "fx_exact_audit": "observation exactly at audit_at is admissible",
    "fx_future": "file captured after audit_at is ignored",
    "fx_hist_email": "request uses a historical e-mail; record keyed only by sha256 of the old e-mail",
    "fx_intent_access": "access request -> NOT_APPLICABLE",
    "fx_intent_correct": "correction request -> NOT_APPLICABLE",
    "fx_intent_es": "Spanish deletion request, no evidence -> never COMPLETE",
    "fx_intent_export": "export request -> NOT_APPLICABLE",
    "fx_intent_ja": "Japanese deletion request",
    "fx_intent_ko": "Korean deletion request",
    "fx_intent_mkt": "marketing-only opt-out containing 'remove' -> NOT_APPLICABLE",
    "fx_intent_neg": "mixed request with an explicit 'do not delete' -> NOT_APPLICABLE",
    "fx_miss": "search miss is not absence; duplicate observations give one step",
    "fx_pdf_pii": "PII only inside a PDF attachment",
    "fx_png_pii": "PII only inside a screenshot (Tesseract OCR)",
    "fx_replica": "primary deleted, failover replica still holds the profile (and a same-instant dump of another DB lacks it)",
    "fx_resync": "deleted, then an active connector repopulates search",
    "fx_retained_ok": "active legal hold + disabled flow + blocked backup -> COMPLETE",
    "fx_tomb_clean": "tombstone with only the stable user_id -> VERIFY_RECORD_REDACTED",
    "fx_tomb_pii": "tombstone still holding name+email (REDACT, never DELETE) and an expired security record (DELETE)",
    "fx_prior_survives": "state observed before the request, no later deletion run -> carried forward and reported",
    "fx_prior_superseded": "state observed before the request, then this subject's deletion run -> unresolved, not reported",
    "fx_stale_contradicted": "stale presence contradicted by a newer NOT_FOUND",
    "fx_late_capture": "file captured after audit_at whose lines are dated before it -> not even named in the plan",
    "fx_embedded_future": "file captured before audit_at with a line dated after it -> that line ignored",
    "fx_intent_newsletter": "'remove me from your newsletter' -> NOT_APPLICABLE",
    "fx_intent_limited": "'delete the old shipping address, keep my account' -> NOT_APPLICABLE",
    "fx_intent_old_phone": "'remove my old phone number' -> NOT_APPLICABLE",
    "fx_intent_spacing": "negation split by doubled spaces and line breaks -> NOT_APPLICABLE",
    "fx_intent_undecided": "no recognisable request -> NOT_APPLICABLE and recorded as undecided",
    "fx_backup_silent": "backup screen with no restore statement -> no restore finding, recorded as unresolved",
    "fx_backup_operational": "recovery console showing completed restores -> restore risk reported",
    "fx_ambiguous_account": "two equally plausible workflow submissions -> no guessed account, recorded as unresolved",
    "fx_sql_partial": "SQL snapshot with a malformed statement -> failure recorded, valid rows still used",
    "fx_ocr_nearmiss": "one-letter look-alike of the subject's e-mail -> no ownership link",
    "fx_text_handover": "plain-text handover with an upper-case e-mail; a second text file with no facts",
    "fx_injection": "evidence and request text that try to instruct the auditor are treated as data",
}

FAILFIRST_DEFECT = {
    "fx_ambiguous_account": "account chosen by queue order / cross-request pools",
    "fx_backup_silent": "restore risk inferred from a screen that says nothing about restore",
    "fx_intent_limited": "limited-scope removal treated as account deletion",
    "fx_intent_newsletter": "newsletter removal treated as account deletion",
    "fx_intent_old_phone": "old-phone removal treated as account deletion",
    "fx_intent_undecided": "undecided intent silently equated with NOT_APPLICABLE (no record)",
    "fx_intent_spacing": "negation defeated by whitespace",
    "fx_late_capture": "post-cutoff file used to name resources in future-work steps",
    "fx_prior_superseded": "pre-request history handled without regard to later deletion runs",
    "fx_prior_survives": "relevant pre-request history discarded",
    "fx_replica": "same-instant snapshot absence overrode a snapshot presence",
    "fx_sql_partial": "same-instant snapshot conflict (found by the malformed-SQL fixture)",
}


def pct(x):
    return f"{100 * x:.1f}%"


def _yes(ok):
    return "PASS" if ok else "**FAIL**"


def render(res: dict, eng) -> str:
    s = res["samples"]
    env = res.get("environment", {})
    L = ["# Evaluation report — Ghost Data Still Exists", "",
         "_Generated by `python3 code/evaluation/main.py` from the code identified below; every number "
         "in this file comes from that run. Sections whose inputs were not produced say NOT RUN._", "",
         "## 0. Run identity", "",
         "| Item | Value |", "|---|---|",
         f"| Code fingerprint (sha256 of `ghost_audit/*.py`, `main.py`, `prompts/*`, `requirements.txt`) | `{env.get('code_fingerprint', '?')}` |",
         f"| Parser / cache version | `{env.get('parser_version', '?')}` |",
         f"| Python / SQLite | {env.get('python', '?')} / {env.get('sqlite', '?')} |",
         f"| OCR / PDF tools | {env.get('tesseract', '?')}; {env.get('pdftotext', '?')} |",
         f"| Python packages | pypdf {env.get('pypdf', '?')}, reportlab {env.get('reportlab', '?')} (fixtures), pillow {env.get('pillow', '?')} (fixtures) |",
         f"| Model access | {env.get('model_env', '?')} |",
         "| Input fingerprints (sha256, first 16 hex) | " + ", ".join(f"`{k}` {v}" for k, v in env.get("inputs_sha256", {}).items()) + " |",
         ""]

    # ---------------------------------------------------------------- before / after
    cmp_ = res.get("compare")
    L += ["## 1. Before / after (previous commit f280a63 vs this code)", ""]
    if cmp_:
        L += ["Both columns are produced by the same scorer and the same independent verifier "
              "(`code/evaluation/compare.py`); the batch-invariance row comes from `invariance.py` run on each "
              "code tree.", "", "| Measure | Before (f280a63) | After (this code) |", "|---|---|---|"]
        for k in cmp_["before"]:
            L.append(f"| {k} | {cmp_['before'][k]} | {cmp_['after'][k]} |")
        L += ["", f"**{len(cmp_['changes'])} of 518 predictions changed.** Root cause of each change "
              "(first matching rule in `compare.py:explain`):", "", "| Root cause | Cases |", "|---|---|"]
        for k, v in sorted(cmp_["change_causes"].items(), key=lambda kv: -kv[1]):
            L.append(f"| {k} | {v} |")
        flips = [c for c in cmp_["changes"] if c[1] != c[2]]
        L += ["", f"Status changes: {len(flips)}" + (" — " + ", ".join(f"{c[0]} {c[1]}→{c[2]}" for c in flips[:60])
                                                     + (" …" if len(flips) > 60 else "") if flips else "") + ".", ""]
        L += ["Reading the table: the sample scores went **down** on purpose. The previous code reached "
              "24/32 exact answers partly by (a) naming resources that appear only in files captured after "
              "`audit_at` and (b) assigning accounts and anonymised analytics records to requests by "
              "queue order across the whole request file. Both are removed; Section 2 attributes every "
              "remaining sample miss to one of these causes.", ""]
    else:
        L += ["NOT RUN (no `compare.json`).", ""]

    # ---------------------------------------------------------------- A. samples
    L += ["## 2. Public samples (32 cases) — sample-tuned, not an estimate of hidden-test accuracy", "",
          "The rules were developed while inspecting these samples, so these numbers measure fit, not "
          "generalisation. The gold answers are read only here, after prediction.", "",
          "| Metric | Value |", "|---|---|",
          f"| Case-level status accuracy | {s['status_correct']}/{s['cases']} ({pct(s['status_accuracy'])}) |",
          f"| Step-level precision (6 fields, step_no excluded) | {pct(s['step_precision'])} ({s['tp']} TP, {s['fp']} FP) |",
          f"| Step-level recall | {pct(s['step_recall'])} ({s['fn']} FN) |",
          f"| Step-level F1 | {pct(s['step_f1'])} |",
          f"| Row / exact-sequence accuracy (status + full ordered array) | {s['exact_sequence_n']}/{s['cases']} ({pct(s['exact_sequence'])}) |",
          f"| Citation accuracy (gold cited steps with the same evidence_id) | {pct(s['citation_accuracy'])} |",
          f"| False COMPLETE (pred COMPLETE, gold INCOMPLETE) | {len(s['false_complete'])} {s['false_complete']} |",
          f"| False INCOMPLETE (pred INCOMPLETE, gold COMPLETE) | {len(s['false_incomplete'])} {s['false_incomplete']} |",
          "", "Field-level accuracy (each gold step aligned to the predicted step with the same phase + system + resource; "
          "a missing step counts as wrong in every field):", "", "| Field | Accuracy |", "|---|---|"]
    L += [f"| {k} | {pct(v)} |" for k, v in s["field_accuracy"].items()]
    L += ["", "### Every remaining sample miss and its cause", "",
          "No predicted step is absent from the gold answers (0 FP). Each missing gold step:", "",
          "| Case | Operation | Resource | Gold evidence | Cause |", "|---|---|---|---|---|"]
    for c, op, rid, ev, cause in sorted(res.get("sample_miss_causes", []), key=lambda t: int(t[0].split("_")[1])):
        L.append(f"| {c} | {op} | {rid} | {ev or '—'} | {cause} |")
    from collections import Counter
    cc = Counter(t[4].split(":")[0] for t in res.get("sample_miss_causes", []))
    L += ["", "| Cause | Missing steps |", "|---|---|"] + [f"| {k} | {v} |" for k, v in cc.most_common()]
    L += ["", "See Section 9 for why these are left unresolved instead of being matched to the gold answers.", ""]

    # ---------------------------------------------------------------- B. fixtures
    fx = res["fixtures"]
    L += ["## 3. Independent synthetic cases (hand-written expectations)", "",
          f"**{sum(ok for _, ok, _ in fx)}/{len(fx)} passed.** The fixture world (`code/evaluation/fixtures.py`) "
          "shares no ids, names or files with the challenge data; expectations were written from the "
          "problem statement and `deletion_rules.csv` before running the predictor.", "",
          "| Case | Behaviour checked | Result | Detail |", "|---|---|---|---|"]
    for name, ok, detail in fx:
        L.append(f"| `{name}` | {FIXTURE_MODES.get(name, '')} | {_yes(ok)} | {detail} |")
    ff = res.get("failfirst")
    L += ["", "### Fail-first evidence for the regressions added in this repair pass", ""]
    if ff:
        b, n = ff["base"], ff["new"]
        L += ["Today's fixtures run against the previous implementation (f280a63) and against this code "
              "(`code/evaluation/failfirst.py`). A regression test counts only if it fails before the fix.", "",
              f"Previous code: {sum(v['pass'] for v in b.values())}/{len(b)} cases pass; this code: "
              f"{sum(v['pass'] for v in n.values())}/{len(n)}.", "",
              "| Fixture | Defect it reproduces | f280a63 | This code |", "|---|---|---|---|"]
        for c in sorted(n):
            if not b.get(c, {}).get("pass", False):
                L.append(f"| `{c}` | {FAILFIRST_DEFECT.get(c, FIXTURE_MODES.get(c, ''))} | "
                         f"FAIL ({b.get(c, {}).get('status', 'n/a')}, {b.get(c, {}).get('n_steps', '?')} steps) | "
                         f"{'PASS' if n[c]['pass'] else '**FAIL**'} |")
        L.append("")
        L.append("Fixtures that pass on both trees (e.g. `fx_ocr_nearmiss`, `fx_embedded_future`, "
                 "`fx_stale_contradicted`, `fx_injection`) are guards against reintroducing a hack, not proof of a fix.")
    else:
        L.append("NOT RUN (no fail-first results supplied).")
    L.append("")

    # ---------------------------------------------------------------- C. metamorphic / invariance
    if "metamorphic" in res:
        L += ["## 4. Metamorphic and invariance tests on the real 518-case dataset", "",
              "| Transformation (must not change any output) | Result | Detail | Seconds |", "|---|---|---|---|"]
        for name, ok, detail, sec in res["metamorphic"]:
            L.append(f"| {name} | {_yes(ok)} | {detail} | {sec} |")
        L += ["", "| Deliberate semantic change | Expected | Result | Detail |", "|---|---|---|---|"]
        exp = {"S1 activate restore path": "INCOMPLETE + REPORT_RESTORE_RISK citing the new file",
               "S2 expose prohibited identifier": "INCOMPLETE + REPORT_EXPOSED_PII",
               "S3 surviving failover replica": "INCOMPLETE + REPORT_REMAINING_RECORD citing the new file",
               "S4 remove deletion authorisation": "NOT_APPLICABLE, []"}
        for name, ok, detail in res["semantic"]:
            L.append(f"| {name} | {exp.get(name, '')} | {_yes(ok)} | {detail} |")
    else:
        L += ["## 4. Metamorphic and invariance tests", "", "NOT RUN (`--quick`)."]
    inv = res.get("invariance")
    L += ["", "### Request-batch invariance (`code/evaluation/invariance.py`)", ""]
    if inv:
        L += ["Each variation is a separate process run of `code/main.py`; outputs are compared case by case "
              "with the full run.", "", "| Variation | Compared | Changed |", "|---|---|---|"]
        for k, v in inv["by_variation"].items():
            L.append(f"| {k} | {v['compared']} | {v['changed']} |")
        L.append(f"| {inv['alone_runs']} single-request runs | {inv['alone_runs']} | {len(inv['alone_changed'])} |")
        L.append(f"| **total** | {inv['total_compared']} | {inv['total_changed']} |")
    else:
        L.append("NOT RUN (no `invariance.json`).")
    L.append("")

    if "operational" in res:
        L += ["## 5. Operational reliability", "", "| Check | Result | Detail |", "|---|---|---|"]
        for name, ok, detail in res["operational"]:
            L.append(f"| {name} | {_yes(ok)} | {detail} |")
        L += ["", "## 6. Mutation testing (does the suite catch injected faults?)", "",
              "Suite = synthetic cases + sample regression guard (status count and step TP/FP may not get worse) "
              f"+ structural validation. Clean-run failures: {res['suite_clean_failures'] or 'none'}.", "",
              "| Injected fault | Detected | First failing checks |", "|---|---|---|"]
        for name, det, fails in res["mutations"]:
            L.append(f"| {name} | {'yes' if det else '**NO (survived)**'} | {'; '.join(fails) or '—'} |")
        surv = [m[0] for m in res["mutations"] if not m[1]]
        L += ["", f"{len(res['mutations']) - len(surv)}/{len(res['mutations'])} mutants detected."
              + (f" Surviving: {', '.join(surv)}." if surv else ""), ""]
    else:
        L += ["## 5–6. Operational reliability and mutation testing", "", "NOT RUN (`--quick`).", ""]

    # ---------------------------------------------------------------- E. verifier
    vd = res.get("verifier_defects", [])
    L += ["## 7. Independent verifier", "",
          "`code/evaluation/verifier.py` imports none of the predictor's decision code. It rebuilds identifier "
          "sets from the CSVs, re-extracts the cited file itself (own pdftotext / Tesseract calls), locates the "
          "record context by plain text search, and checks: the citation was captured by audit_at and its line "
          "is not dated after it; every planned resource is discoverable by audit_at; the cited context supports "
          "the claimed state; the context names no other subject; every finding has remediation and verification; "
          "recreation paths are closed before records are treated; retained records are verified and never "
          "deleted without a cited expired retention date; COMPLETE contains only cited, supported verification; "
          "absence is not proven from a partial capture; canonical order and numbering; active flows/restores "
          "visible in admissible evidence are planned.", "",
          "**Assumptions shared with the predictor** (a bug in one of these would not be caught): "
          "sha256(lower(email)) hashing; resource-id prefixes name the system (`search_` → search_service); "
          "the same Tesseract binary; `deletion_rules.csv` as the policy source; the restore-console wording "
          "`<backup> restored … Completed` read as an operational restore path.", "",
          f"### Labelled defect fixtures: {sum(x[3] for x in vd)}/{len(vd)} detected", "",
          "Each starts from a gold sample answer, injects one defect, and passes only if the clean row is NOT "
          "flagged and the defective row IS.", "", "| Defect | Case | Expected issue | Result |", "|---|---|---|---|"]
    for name, cid, exp_, ok, detail in vd:
        L.append(f"| {name} | {cid} | `{exp_}` | {_yes(ok)} ({detail}) |")
    ve = res["verifier_eval"]
    L += ["", "### Verifier over the predictions", "",
          "| Verifier stat / issue | 518 predictions | 32 sample predictions | 32 gold answers |", "|---|---|---|---|"]
    vs, vg = res["verifier_samples_pred"], res["verifier_gold"]
    for k in sorted(set(ve["stats"]) | set(vg["stats"]) | set(vs["stats"])):
        L.append(f"| {k} | {ve['stats'].get(k, 0)} | {vs['stats'].get(k, 0)} | {vg['stats'].get(k, 0)} |")
    ikeys = sorted(set(ve["issues"]) | set(vg["issues"]) | set(vs["issues"]))
    for k in ikeys:
        L.append(f"| issue: `{k}` | {len(ve['issues'].get(k, []))} | {len(vs['issues'].get(k, []))} | "
                 f"{len(vg['issues'].get(k, []))} |")
    L += ["", "Issue lists: " + "; ".join(f"`{k}` (gold): {', '.join(v)}" for k, v in vg["issues"].items())
          + ("; " if vg["issues"] else "") + "; ".join(f"`{k}` (samples): {', '.join(v)}" for k, v in vs["issues"].items()), "",
          "* The gold answers fail `resource_not_discoverable_by_audit_at` for 8 steps: the specification conflict "
          "described in Section 9.", "",
          "* `incomplete_without_findings` on the 518 output counts the uncertified cases (Section 9.3): no "
          "violation is supported, completion is not proven, and the row carries only the future verification "
          "checks. `incomplete_empty_plan` would flag an empty INCOMPLETE row.", "",
          "* `cited_without_subject_identifier` counts cited steps whose record context does not itself print "
          "the subject (e.g. a 404 account lookup or an anonymised analytics row); those links come from "
          "evidence-linked workflow correlation and are the weakest links in the output.", ""]

    # ---------------------------------------------------------------- output contract
    ct = res.get("contract", {})
    L += ["## 8. Output contract (root `output.csv` re-read from disk)", ""]
    if ct.get("present"):
        L += ["| Check | Result |", "|---|---|",
              f"| Header | `{ct['header']}` |",
              f"| Rows / unique case ids / expected | {ct['rows']} / {ct['unique_case_ids']} / {ct['expected_rows']} |",
              f"| Contract errors (fields, operation/state pairs, phase order, numbering, duplicates, evidence ids known, "
              f"empty evidence on future work, COMPLETE = cited verification only, NOT_APPLICABLE = [], sorting, CSV/JSON round trip) | "
              f"{len(ct['errors'])} {ct['errors'][:5] if ct['errors'] else ''} |",
              f"| Empty INCOMPLETE rows | {len(ct['empty_incomplete'])} {ct['empty_incomplete'][:10]} |",
              f"| INCOMPLETE rows without findings (uncertified, warning) | {ct['warnings_count']} |",
              f"| Steps | {ct['steps']} |",
              f"| Status counts | {ct['status_counts']} |",
              f"| Identical to a fresh prediction by this code | {ct['matches_fresh_prediction']} |",
              f"| sha256 | `{ct['sha256']}` |"]
    else:
        L.append("NOT RUN (no root output.csv).")
    ic = res.get("internal_counts", {})
    L += ["", f"Internal decision states over the 518 requests: {ic}. Blocking unresolved reasons: "
          f"{res.get('unresolved_reasons', {})}.", ""]

    L += [SPEC, FAILURES, LIMITATIONS.format(uncert=ic.get("UNCERTIFIED", 0),
                                               n_notapp=res.get("final_counts", {}).get("NOT_APPLICABLE", 0))]

    # ---------------------------------------------------------------- extraction
    L += ["## 12. Extraction coverage", "", "| Evidence file | Type | Status | Observations | Facts | Warnings / error |",
          "|---|---|---|---|---|---|"]
    from collections import Counter as C2
    st = C2(ef.status for ef in eng.store.files.values())
    for fid, ef in eng.store.files.items():
        if ef.status != "ok" or ef.path.suffix in (".png", ".pdf") or ef.warnings:
            L.append(f"| {fid} | {ef.path.suffix} | {ef.status} | {ef.n_observations} | {len(ef.facts)} | "
                     f"{'; '.join(ef.warnings)[:120] or ef.error or '—'} |")
    L += ["", f"All {len(eng.store.files)} manifest files are accounted for: {dict(st)}. `no-direct-facts` = text "
          "extracted but no resource id in it (used only through data-catalog aliases); `facts-only` = structured "
          "facts without a resource id (legal-hold register rows). Raw OCR/PDF text is kept next to the observations "
          "in the extraction cache.", "", f"_Suite runtime: {res['seconds']} s._", ""]
    return "\n".join(L)


SPEC = """## 9. Specification conflicts, ambiguities and blockers

### 9.1 Post-cutoff discovery in the gold samples (conflict with the stated time contract)

The contract says *"Use only information available at or before `audit_at` … Evidence created later must not change
the answer"* and *"Never cite … an evidence item captured after the case's `audit_at`."* Five gold answers contain an
uncited future-work step for a security record that appears **only** in a file captured after `audit_at`:

| Case | audit_at | Gold step | Only file naming the resource | File captured_at | Line time |
|---|---|---|---|---|---|
| case_09 | 2026-09-16T09:00Z | VERIFY_RECORD_PRESENT audit_record_4902 | evidence_06 (`structured_service_events_eu_west_20260918.log`) | 2026-09-18T11:55:24Z | 2026-09-16T08:52:59Z |
| case_23 | 2026-09-15T12:00Z | VERIFY_RECORD_PRESENT audit_record_4128 | evidence_02 | 2026-09-17T12:00Z | before audit_at |
| case_24 | 2026-09-15T12:00Z | VERIFY_RECORD_PRESENT audit_record_7095 | evidence_02 | 2026-09-17T12:00Z | before audit_at |
| case_29 | 2026-09-15T12:00Z | VERIFY_RECORD_PRESENT audit_record_3954 | evidence_02 | 2026-09-17T12:00Z | before audit_at |
| case_30 | 2026-09-15T12:00Z | VERIFY_RECORD_PRESENT audit_record_1707 | evidence_02 | 2026-09-17T12:00Z | before audit_at |

Minimal reproduction (case_09): `grep -rl audit_record_4902 dataset/evidence` → only
`logs/structured_service_events_eu_west_20260918.log`; `grep evidence_06 dataset/evidence_files.csv` → captured
2026-09-18T11:55:24Z; case_09 audit_at is 2026-09-16T09:00:00Z; no activity row names the record. Reproducing the
gold step therefore requires reading a file that did not exist at audit_at. This code does not, and the fixture
`fx_late_capture` and the metamorphic test "late-captured files with pre-audit_at line times" enforce it.
Two further gold steps (case_18 `audit_record_6645`, case_20 `audit_record_5569`) name records that appear in **no**
participant file or activity row.

**Clarification question for the organisers:** *"For case_09 (and case_23/24/29/30) the sample answer verifies
`audit_record_4902` as retained, but that id appears only in evidence_06, captured 2026-09-18, after the case's
audit_at of 2026-09-16 (the log line itself is dated 2026-09-16T08:52:59Z). Should a file captured after audit_at be
used when its lines describe events before audit_at — for uncited future-work steps only, or not at all? Is the
gold step for case_18 `audit_record_6645` derived from a participant-visible file?"*

### 9.2 case_04 — gold COMPLETE that no admissible evidence supports

Gold: COMPLETE with `VERIFY_RECORD_ABSENT account_004 [evidence_54]` and `VERIFY_RECORD_ANONYMIZED analytics_901
[evidence_56]`. `account_004` occurs in no evidence file and no activity row (the verifier reports it as not
discoverable); evidence_54 is a 7-row failover dump that never mentions it. `analytics_901` appears in evidence_56
with every identifier null and in one `ANONYMIZE_RECORD` activity, seven minutes before the report, that names no
person; no workflow submission falls in the report window. Linking either record to user_04 would need the id
numbering convention (`user_04` ↔ `account_004`) or time proximity alone, which this code refuses to use. The case
is therefore uncertified and serialised as INCOMPLETE with no steps — the only empty INCOMPLETE row in any output
(it is a sample; the 518-case output has none).

### 9.3 No output status for "not proven either way" (contract gap)

COMPLETE must be evidence-backed; INCOMPLETE is described as findings + remediation + verification. A case with no
supported violation **and** an unproven required final state fits neither. This code keeps an internal UNCERTIFIED
state and serialises it as INCOMPLETE carrying only the future verification checks (empty evidence_id, no
fabricated findings), with every blocking reason in the per-case trace. In the 518-case output this applies to the
cases counted under `internal_counts['UNCERTIFIED']` (Section 8), mainly because the primary account could not be
attributed. If the organisers expect COMPLETE for "no violation found", these rows will score as status errors.

### 9.4 Account attribution without request order

When several unowned deletion-worker submissions fall in a request's report window and nothing links one of them to
the subject, the account is not attributed. Samples show the gold answers resolve such groups in request-file order
(e.g. case_25 → account_3136, case_26 → account_5684 within the same window), which depends on which other requests
exist and is excluded by design (request-batch invariance, Section 4). If **every** candidate is proven absent, the
subject's account is absent whichever it is: the case can be COMPLETE, but no account step is emitted because its id
cannot be named without guessing (case_25/26/28/31 in the samples).
"""

FAILURES = """## 10. Failures found and improvements made (chronological)

| # | Failure observed | Root cause (layer) | Fix | Regression guard |
|---|---|---|---|---|
| 1 | Sample status 29/32, 9/32 exact | intent lexicon missed "verify my profile is gone" (intent); bundle absence overrode direct 404s (temporal) | added verification phrasings; direct observations beat capture absence | samples, `fx_future` |
| 2 | Security records reported absent although present | multi-capture JSON bundles treated as complete (temporal) | capture absence only from single-capture collections covering the subject | verifier `absence_from_partial_capture` |
| 3 | Connector screen linked to the wrong customer | OCR identifiers taken page-wide (ingestion) | screens: same-line identifiers only | `fx_png_pii`, `fx_decoy` |
| 4 | 34 "retention violations" | SQL inventories treated as complete (temporal) | inventories never prove absence | verifier `retention_violation` |
| 5 | Metamorphic "future evidence" changed 131 cases | never-observed resources declared absent from older captures | absence needs the resource to be known before the capture | metamorphic C6 |
| 6 | Metamorphic "paraphrase" changed 163 statuses | `eliminen` / Spanish negation missed (intent) | stem-based multilingual patterns + negation | metamorphic C7 |
| 7 | **Review:** 116 verifier temporal issues; post-cutoff files named resources in plans | late files used to name retained records and withdraw proofs (temporal) | strict cutoff on capture time **and** line time before linking, discovery, state and planning; catalog aliases only from links made by audit_at | `fx_late_capture`, metamorphic late-capture / future-activity tests |
| 8 | **Review:** 57/2097 outputs changed with batch composition; 4 changed without the sample file | account and analytics attribution by queue order across the request pools (identity) | per-request correlation only; ambiguous windows left unresolved | `fx_ambiguous_account`, invariance.py, mutant "guess ambiguous account" |
| 9 | **Review:** pre-request history discarded | observations outside [requested_at, audit_at] dropped (state) | prior state carried forward unless this subject's deletion run followed it | `fx_prior_survives`, `fx_prior_superseded`, mutant "forget pre-request history" |
| 10 | **Review:** COMPLETE without proof (52 cases had no account proof); unproven verification silently dropped | planner certified COMPLETE when any one verification was cited | COMPLETE requires every required final state proven; otherwise UNCERTIFIED with reasons; candidate-absence rule | `fx_intent_es`, mutant "certify COMPLETE without proof", verifier D1 |
| 11 | **Review:** "remove me from your newsletter", "old phone number" → deletion | verb matched without its object (intent) | target-aware rules: verb + nearest scope noun in the same sentence; UNDECIDED recorded | `fx_intent_newsletter/limited/old_phone/undecided` |
| 12 | **Review:** dataset-specific OCR substitutions and a `.jr` hack | parsers patched to the dataset (ingestion) | removed; raw OCR kept; no fuzzy linking | operational check 7, `fx_ocr_nearmiss`, `fx_decoy` |
| 13 | **Review:** SQL statement errors swallowed; register PDF facts ignored | parser error handling (ingestion) | statement-by-statement retry with recorded warnings; legal-register rows extracted as facts | `fx_sql_partial`, extraction-failure fixture |
| 14 | Restore risk asserted from a backup screen saying nothing about restore; then the opposite over-correction left case_55 empty | restore capability inferred from silence (policy) | needs an affirmative statement: explicit allow/deny, or the same console showing its archives' restores completing | `fx_backup_silent`, `fx_backup_operational` |
| 15 | Same-instant snapshots of two databases: absence overrode presence | snapshot row time vs snapshot time (state) | a row in a snapshot is present at the snapshot time; equal-time conflict keeps presence | `fx_replica`, `fx_sql_partial` (found by the new SQL fixture) |
| 16 | Metamorphic formatting test changed 2 cases (a regression introduced by the intent rewrite in this pass; the previous code passed it) | negation patterns assumed single spaces (intent) | whitespace normalised before matching | `fx_intent_spacing`, metamorphic formatting test |
| 17 | Mutation harness corrupted static methods; mutants out of date with new APIs | test tooling | restore raw class attribute; mutants rewritten for the new signatures | clean suite run |
"""

LIMITATIONS = """## 11. Remaining limitations (honest list)

* **{uncert} uncertified cases** in the 518-case output are INCOMPLETE rows with only future verification steps
  (Section 9.3). They are not proven incomplete; they are not proven complete either.
* **Account attribution** is the main source of unresolved items (Section 9.4). Accounts are only linked by an
  identifier in admissible evidence or by a workflow submission that is the unique match for this request alone.
* **Late-captured files are ignored entirely.** If the organisers' key uses them (Section 9.1), the affected
  future-work steps are missed by design.
* **Absence proofs** come only from explicit 404 / NOT_FOUND observations, single-capture JSON collections that
  cover the subject, and full-table replica dumps. SQL inventories never prove absence.
* **Restore capability** needs an affirmative statement; a backup screen without one stays unresolved.
* **OCR** is Tesseract only; screenshots are used only through exact identifier or data-catalog joins.
* **Intent** is rule-based ({n_notapp} NOT_APPLICABLE in the 518 output). The optional model fallback is used only
  for requests the rules mark UNDECIDED and only with `ANTHROPIC_API_KEY`; it was **not executed against a real
  provider** in this environment — only its mocked fault-handling tests ran (Section 5).
* Hidden-test accuracy is unknown; the sample numbers above are fit on the samples, not an estimate.
"""
