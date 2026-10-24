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
    "fx_backup_other_archive": "another archive's completed restore on the same console -> no risk for this archive, unresolved",
    "fx_backup_row_restorable": "the archive's own row says 'Restore available' -> restore risk reported",
    "fx_account_unknown": "no account record known for the subject -> never COMPLETE, unresolved",
    "fx_account_candidates_absent": "every unowned candidate in the window absent -> not proof for the subject, never COMPLETE",
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
    "fx_account_unknown": "missing account id treated as non-blocking -> COMPLETE without account proof",
    "fx_account_candidates_absent": "absent ambiguous candidates treated as proof of the subject's account",
    "fx_backup_other_archive": "restore capability inferred from another archive's restore",
    "U1": "uncited verification silently dropped after COMPLETE was chosen",
    "U3": "unproven account allowed COMPLETE",
    "U4": "(new module) look-alike re-read must not be accepted",
    "U5": "(new module) verbatim re-read accepted, stops early",
    "U6": "(new module) hypothesis inside a longer token rejected",
    "U7": "(new module) policy action outside the tool list refused",
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
    def cmp_section(cmp_, label):
        out = []
        if not cmp_:
            return out + [f"NOT RUN (no comparison against {label}).", ""]
        out += [f"| Measure | {label} | This code |", "|---|---|---|"]
        for k in cmp_["before"]:
            out.append(f"| {k} | {cmp_['before'][k]} | {cmp_['after'][k]} |")
        out += ["", f"**{len(cmp_['changes'])} of 518 predictions changed.** Root cause of each change "
                "(first matching rule in `compare.py:explain`):", "", "| Root cause | Cases |", "|---|---|"]
        for k, v in sorted(cmp_["change_causes"].items(), key=lambda kv: -kv[1]):
            out.append(f"| {k} | {v} |")
        flips = [c for c in cmp_["changes"] if c[1] != c[2]]
        out += ["", f"Status changes: {len(flips)}" + (" — " + ", ".join(f"{c[0]} {c[1]}→{c[2]}" for c in flips[:80])
                                                       + (" …" if len(flips) > 80 else "") if flips else "") + ".", ""]
        return out
    L += ["## 1. Before / after", "",
          "Every column is produced by the same scorer and the same independent verifier (`code/evaluation/compare.py`); "
          "batch invariance comes from `invariance.py` run on each code tree.", "",
          "### 1a. Original implementation (f280a63) vs this code", ""]
    L += cmp_section(res.get("compare"), "f280a63")
    L += ["### 1b. Last reviewed revision (3be6cb1, PR #1 head before this pass) vs this code", ""]
    L += cmp_section(res.get("compare_prev"), "3be6cb1")
    L += ["Reading the tables: sample agreement went **down** on purpose, twice. f280a63 reached 24/32 exact answers "
          "partly by naming resources visible only in files captured after `audit_at` and by assigning accounts by "
          "queue order. 3be6cb1 still certified COMPLETE when the subject's account was unidentified, or when every "
          "candidate in an ambiguous workflow window was absent, although neither proves the subject's account "
          "absent. Section 2 and `case_investigation.md` classify every remaining sample difference.", ""]

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
          f"Extra predicted steps: {s['fp']} (all are future checks with empty evidence_id in uncertified cases, "
          "where the gold answer certifies COMPLETE with a citation). Each missing gold step:", "",
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
    L += ["", "### Fail-first evidence", ""]
    if ff:
        n = ff["new"]
        tags = [t for t in ("base", "prev") if t in ff]
        L += ["Today's synthetic cases and unit tests run against earlier revisions and against this code "
              "(`code/evaluation/failfirst.py`). A regression test counts only if it fails before the fix.", "",
              " ; ".join(f"{ff[t + '_rev']}: {sum(v['pass'] for v in ff[t].values())}/{len(ff[t])} pass" for t in tags)
              + f" ; this code: {sum(v['pass'] for v in n.values())}/{len(n)} pass.", "",
              "| Test | Defect it reproduces | " + " | ".join(ff[t + "_rev"] for t in tags) + " | This code |",
              "|---|---|" + "---|" * len(tags) + "---|"]
        for c in sorted(n):
            if any(not ff[t].get(c, {}).get("pass", False) for t in tags):
                cells = []
                for t in tags:
                    x = ff[t].get(c, {})
                    cells.append("PASS" if x.get("pass") else (f"FAIL ({x.get('status', 'n/a')}"
                                                                + (f", {x['n_steps']} steps)" if x.get("status") != "unit" else ")")))
                L.append(f"| `{c}` | {FAILFIRST_DEFECT.get(c, FIXTURE_MODES.get(c, ''))} | " + " | ".join(cells)
                         + f" | {'PASS' if n[c]['pass'] else '**FAIL**'} |")
        L.append("")
        L.append("Tests that pass on every tree (e.g. `fx_ocr_nearmiss`, `fx_embedded_future`, `fx_injection`, "
                 "`fx_backup_row_restorable`) guard against reintroducing a defect; they are not proof of a fix.")
    else:
        L.append("NOT RUN (no fail-first results supplied).")
    L.append("")

    ut = res.get("unit_tests", [])
    L += ["", f"### Unit tests: {sum(1 for x in ut if x[1])}/{len(ut)} passed", "",
          "| Test | Result | Detail |", "|---|---|---|"] + [f"| {n_} | {_yes(ok)} | {d} |" for n_, ok, d in ut]
    L += [""]
    # ---------------------------------------------------------------- agent capability
    invs = res.get("investigation", {})
    L += ["## 3b. Bounded investigation step (agent capability)", "",
          "**Problem.** Screenshot OCR sometimes misreads an identifier (dataset: evidence_32 reads `areed1433@gmail.com` "
          "as `areedi433` / `areedt433`). The previous code accepted a one-edit look-alike as exposure (fuzzy). That rule "
          "is removed. Instead, when an OCR token is a near-miss of exactly one known identifier, a policy chooses which "
          "deterministic re-extraction to run (re-OCR at ×2/×3 with different page segmentation, optional binarisation) "
          "under a budget of 3 per problem and 60 per run; a hypothesis is accepted **only** if a re-extraction reads it "
          "verbatim as a whole token. Policies cannot read other files, accept or edit facts, or touch temporal "
          "filtering, policy rules or serialisation (unit tests U4–U7, mutant 'accept investigation hypothesis without "
          "verbatim read').", "",
          f"**On the challenge data** (policy `{', '.join(invs.get('policy', []))}`): {invs.get('problems', 0)} problems, "
          f"{invs.get('verified', 0)} verified, {invs.get('actions_run', 0)} re-extractions, {invs.get('model_calls', 0)} model calls.", "",
          "| File | OCR read | Hypothesis | Actions | Verified |", "|---|---|---|---|---|"]
    for o in invs.get("outcomes", []):
        L.append(f"| {o['problem']['file_id']} | `{o['problem']['observed']}` | `{o['problem']['hypothesis']}` | "
                 f"{', '.join(a['action'] for a in o['attempts']) or '—'} | {o['verified']} |")
    abl = res.get("investigation_ablation_changed")
    L += ["", f"Ablation (same run without verified reads): {len(abl) if abl is not None else 'NOT RUN'} of 518 predictions "
          "change. On this dataset the step replaces an unsafe rule without changing any answer; its value is shown "
          "on the labelled set below.", ""]
    ae = res.get("agent_eval")
    if ae:
        L += ["**Labelled evaluation** (`code/evaluation/agent_eval.py`, 60 seeded console-row images, label = the "
              "address actually drawn; 40 show a known identifier, 20 show a look-alike decoy that must NOT be accepted; "
              "same images, tools and budgets for every strategy):", "",
              "| Strategy | Status | Problems found | True identifiers verified (of 40) | Decoys wrongly accepted (of 20) | Re-extractions |",
              "|---|---|---|---|---|---|"]
        for r in ae:
            if r["status"] == "RUN":
                L.append(f"| {r['strategy']} | RUN | {r['problems_found']} | {r['true_verified']} | "
                         f"{r['decoys_wrongly_verified']} | {r['re_extractions']} |")
            else:
                L.append(f"| {r['strategy']} | {r['status']} | — | — | — | — |")
        L += ["", "The model policy is implemented (`ModelPolicy`, prompt `prompts/investigation_policy.md`, schema-checked "
              "JSON, timeout, retries, call budget, usage accounting) and tested only with **mock** transports "
              "(Section 5). It has **not** been executed against a real provider, so no claim is made that it improves "
              "on the deterministic ladder. Most misreads are not even recognised as near-misses (problem detection, "
              "not re-extraction, is the bottleneck).", ""]
    else:
        L += ["Labelled evaluation: NOT RUN (`--quick`).", ""]

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

The full case-level evidence matrix (every uncertified case, every sample mismatch, every workflow candidate and
where it occurs in any evidence format) and minimal reproductions are in `code/evaluation/case_investigation.md`.
Summary of the classification there:

| Conflict | Classification | Effect |
|---|---|---|
| C1 gold steps for records visible only in files captured after `audit_at` (case_09/23/24/29/30); subject↔account links for 17 candidates exist only in such files | ambiguous specification (capture time vs line time) | strict reading kept; the alternative was measured (analysis only) and does not reproduce the gold answers either |
| C2 gold steps for ids that occur in no evidence (case_18 `audit_record_6645`, case_20 `audit_record_5569`) | genuinely unsupported sample answer | not reproducible |
| C3 case_04 (`account_004` nowhere; `analytics_901` anonymised, no link) | genuinely unsupported by admissible evidence | uncertified |
| C4 ambiguous workflow windows (e.g. case_25/26 share report time; candidates `account_3136`, `account_5684`) | would need an unsupported implementation assumption (cross-request order) | account unresolved; case uncertified |
| C5 finance retention register (evidence_27) | ambiguous specification (is it a "supplied legal hold"?) | context only; not taken as proof of retention |
| C6 archive restore capability inferred from another archive's restore (case_55) | ambiguous specification | restore state unresolved; case uncertified |
| No public status for "not proven either way" | contract gap | uncertified cases serialised as INCOMPLETE with future checks only |

Six draft organiser questions (not sent) are at the end of `case_investigation.md`.

### 9.1 What "uncertified" means in the output

COMPLETE requires every required final state to be proven by a cited admissible observation **before** the status
is chosen, including the subject's primary account. An account is proven only when it is identified (an identifier
in admissible evidence, or the unique workflow submission for this request alone) and its state is observed. A
missing account id is not proof of absence, and a set of absent candidates is not proof about the subject unless
evidence shows the set is exhaustive and contains the subject's account (a report-time window shows neither).
Cases with no supported violation but an unproven required state are UNCERTIFIED and serialised as INCOMPLETE with
only the future verification checks (empty evidence_id, no invented findings). If the organisers expect COMPLETE for
these, they score as status errors; if they expect the account to be attributed by request order, the gold answers
depend on information this design deliberately excludes.
"""

FAILURES = """## 10. Failures found and improvements made (chronological)

| # | Failure observed | Root cause (layer) | Fix | Regression guard |
|---|---|---|---|---|
| 1 | Sample status 29/32, 9/32 exact | intent lexicon gaps; bundle absence overrode direct 404s | verification phrasings; direct observations beat capture absence | samples, `fx_future` |
| 2 | Security records reported absent although present | multi-capture JSON bundles treated as complete | capture absence only from single-capture collections covering the subject | verifier `absence_from_partial_capture` |
| 3 | Connector screen linked to the wrong customer | OCR identifiers taken page-wide | screens: same-line identifiers only | `fx_png_pii`, `fx_decoy` |
| 4 | 34 "retention violations" | SQL inventories treated as complete | inventories never prove absence | verifier `retention_violation` |
| 5 | Metamorphic "future evidence" changed 131 cases | never-observed resources declared absent | absence needs the resource known before the capture | metamorphic test |
| 6 | Metamorphic "paraphrase" changed 163 statuses | Spanish stems / negation missed | stem-based multilingual patterns + negation | metamorphic test |
| 7 | Review of f280a63: 116 temporal verifier issues | late files named resources in plans | strict cut-off on capture **and** line time before linking, discovery, state, planning | `fx_late_capture`, late-capture and future-activity metamorphic tests |
| 8 | Review of f280a63: 57/2097 batch-dependent outputs | attribution by queue order / request pools | per-request correlation only | `fx_ambiguous_account`, invariance.py, mutant "guess ambiguous account" |
| 9 | Review of f280a63: pre-request history discarded | observations before requested_at dropped | prior state carried forward unless this subject's deletion run followed | `fx_prior_survives`, `fx_prior_superseded` |
| 10 | Review of f280a63: intent over-triggered | verb matched without its object | target-aware rules; UNDECIDED recorded | `fx_intent_newsletter/limited/old_phone/undecided` |
| 11 | Review of f280a63: OCR substitution table, `.jr` hack, swallowed SQL errors | dataset-specific patches | removed; SQL statement warnings recorded; register PDF facts extracted | operational check, `fx_sql_partial` |
| 12 | Same-instant snapshots: absence overrode presence | row time vs snapshot time | presence at snapshot time wins on equal time | `fx_replica`, `fx_sql_partial` |
| 13 | Negation broken by doubled whitespace (introduced by the intent rewrite in this effort; f280a63 passed) | patterns assumed single spaces | whitespace normalised | `fx_intent_spacing`, formatting metamorphic test |
| 14 | **Review of 3be6cb1:** COMPLETE allowed with no account known, or with all ambiguous candidates absent | missing proof marked non-blocking | both are blocking; COMPLETE needs the identified account proven | `fx_account_unknown`, `fx_account_candidates_absent`, unit U3 |
| 15 | **Review of 3be6cb1:** unsupported verification dropped after COMPLETE was chosen | planner filtered steps after the status decision | each verification checked for a supporting citation before status selection; COMPLETE asserts it | unit U1, U2, mutant "certify COMPLETE without proof" |
| 16 | **Review of 3be6cb1:** register row described as "retained per the register" | existence of a register row taken as availability | recorded as context only, never as proof of retention; organiser question | C5 |
| 17 | **Review of 3be6cb1:** restore capability inferred from other archives' completed restores | page-wide restore wording | restore wording must be on a line naming this archive | `fx_backup_other_archive`, `fx_backup_row_restorable` |
| 18 | **Review of 3be6cb1:** one-edit fuzzy OCR "corroboration" | fuzzy rule in exposure check | replaced by the bounded investigation step with verbatim validation | unit U4–U7, mutant "accept investigation hypothesis without verbatim read", agent_eval decoys |
| 19 | Report said a fixture had unexplained provenance | the author (this agent) did not check the trace | the session trace shows it was written by this session at 2026-10-24T19:49:41Z; its expectation was re-checked (per-archive `ACTIVE` restore statement, NOT_FOUND account) | `fx_text_handover` |
| 20 | Mutation harness corrupted static methods; mutants stale after API changes | test tooling | restore raw attribute; mutants rewritten | clean suite run |
"""

LIMITATIONS = """## 11. Remaining limitations (honest list)

* **{uncert} uncertified cases** in the 518-case output (Section 9.1): not proven incomplete, not proven complete.
* **Account attribution** is the dominant blocker; the only admissible way to identify an account is an identifier in
  admissible evidence or the unique workflow submission for the request alone.
* **Late-captured files are ignored entirely** (C1); if the key uses them, the affected steps are missed by design.
* **Absence proofs** come only from explicit 404 / NOT_FOUND observations, single-capture JSON collections covering
  the subject and full-table replica dumps; SQL inventories never prove absence.
* **Restore capability** needs a statement about the specific archive.
* **OCR** is Tesseract only; most misreads are not recognised as near-misses, so the investigation step resolves few.
* **Intent** is rule-based ({n_notapp} NOT_APPLICABLE in the 518 output). The model fallbacks (intent, investigation
  policy) were **not executed against a real provider**; only mock-transport tests ran.
* Hidden-test accuracy is unknown; the sample numbers above are fit on the samples, not an estimate.
"""
