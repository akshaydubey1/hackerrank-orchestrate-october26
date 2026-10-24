"""Case-level evidence matrix and specification-conflict reproductions.

    python3 code/evaluation/investigate_cases.py      # -> code/evaluation/case_investigation.md

Covers (1) every uncertified case in the 518-case run, (2) every COMPLETE case without an account
step, and (3) every public-sample mismatch. For each it records the subject's admissible
identifiers, linked resources, the workflow candidate set and each candidate's state, every place
(any evidence format, any capture time, any activity row) that names a candidate or a missing gold
resource, and the exact blocking reason. Search uses the independent verifier's own extraction
(raw text, JSON, SQL text, pdftotext, Tesseract), not the predictor's parsers, and it also searches
the bare numeric suffix of each id so that OCR or formatting variants are not missed.

Nothing here changes predictions; the gold sample answers are read only to list mismatches.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
ROOT = CODE.parent
sys.path.insert(0, str(CODE))

from evaluation.verifier import Verifier  # noqa: E402
from ghost_audit.pipeline import Engine, read_requests  # noqa: E402
from ghost_audit.util import parse_ts  # noqa: E402

DATASET = ROOT / "dataset"
KEY = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%MZ") if dt else "—"


class Finder:
    def __init__(self, ver: Verifier):
        self.ver = ver
        self.occ = ver.occurrences()
        self.texts = {fid: ver.text(fid) for fid in ver.files}
        self.acts = ver.acts

    def places(self, rid: str, cut, uid: str) -> list:
        """Every occurrence of rid with capture time, line time, admissibility and named subjects."""
        out = []
        for fid, cap, rt, ctx in self.occ.get(rid, []):
            named = sorted(self.ver.users_named(ctx))
            adm = cap is not None and cap <= cut and (rt is None or rt <= cut)
            out.append({"where": fid, "captured": cap, "line_time": rt, "admissible": adm,
                        "names_subject": uid in named, "names_others": [u for u in named if u != uid][:3]})
        return out

    def suffix_hits(self, rid: str) -> tuple:
        """Where the id's numeric suffix occurs without the id: (tokens carrying it, untyped places).

        A token such as `account_6645` or `CS-6645` is a different identifier; a bare number next to
        no prefix could be an OCR / formatting variant and is listed separately for manual review."""
        num = rid.rsplit("_", 1)[-1]
        if len(num) < 3:
            return [], []
        typed, bare = set(), []
        corpus = list(self.texts.items()) + [(a, row["resource_id"] + " " + row["details"]) for a, row in self.acts.items()]
        for fid, t in corpus:
            for m in re.finditer(rf"(?<![\d.]){re.escape(num)}(?![\d.])", t):
                tok = re.search(rf"([A-Za-z0-9_\-]*[A-Za-z][A-Za-z0-9_\-]*[_\-]){re.escape(num)}$", t[max(0, m.start() - 30):m.end()])
                if tok and tok.group(0) != rid:
                    typed.add(tok.group(0))
                elif not tok:
                    bare.append(fid)
        return sorted(typed), sorted(set(bare))


def fmt_places(pl: list) -> str:
    if not pl:
        return "nowhere"
    parts = []
    for p in pl[:6]:
        flag = "adm" if p["admissible"] else "NOT adm"
        who = "names subject" if p["names_subject"] else (f"names {','.join(p['names_others'])}" if p["names_others"]
                                                          else "names nobody")
        parts.append(f"{p['where']} (cap {iso(p['captured'])}, line {iso(p['line_time'])}, {flag}, {who})")
    return "; ".join(parts) + (f"; +{len(pl) - 6} more" if len(pl) > 6 else "")


def classify_candidate(pl: list) -> str:
    if any(p["admissible"] and p["names_subject"] for p in pl):
        return "ADMISSIBLE LINK MISSED (parser/retrieval omission)"
    if any(p["names_subject"] for p in pl):
        return "subject link only in evidence not admissible at audit_at"
    if any(p["names_others"] for p in pl):
        return "linked to another subject"
    return "no identifier links it to anyone"


def run():
    ver = Verifier(DATASET, CODE / ".cache" / "verifier")
    fd = Finder(ver)
    eng = Engine(DATASET, CODE / ".cache")
    gold = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
            for r in csv.DictReader(open(DATASET / "sample_output.csv", encoding="utf-8"))}
    sample_reqs = read_requests(DATASET / "sample_deletion_requests.csv")
    eval_reqs = read_requests(DATASET / "deletion_requests.csv")
    s_res = {r.case_id: r for r in eng.run(sample_reqs)}
    e_res = {r.case_id: r for r in eng.run(eval_reqs)}
    reqs = {q["case_id"]: q for q in sample_reqs + eval_reqs}

    def row(r, q):
        t = r.trace
        uid = (t.get("identity") or {}).get("user_ids", [None])[0] or "—"
        idn = t.get("identity") or {}
        cut = parse_ts(q["audit_at"])
        ac = t.get("account_correlation") or {}
        cands = ac.get("candidates", []) or []
        cstates = t.get("account_candidate_states", {}) or {}
        cand_txt, cand_cls = [], []
        for c in cands:
            pl = fd.places(c, cut, uid)
            cls = classify_candidate(pl)
            cand_cls.append(cls)
            st = {True: "present", False: "absent", None: "unknown"}[cstates.get(c)]
            cand_txt.append(f"`{c}` {st}; {cls}")
        linked = [f"{x['resource']}" + ("" if not x.get("unknown") else " (state unknown)")
                  for x in t.get("resources", []) if "category" in x]
        blocking = [u["reason"] for u in r.unresolved if u.get("blocking", True)]
        return {"case": r.case_id, "status": r.status, "internal": r.internal_status, "uid": uid,
                "ids": f"{idn.get('n_emails', 0)}e/{idn.get('n_phones', 0)}p/{idn.get('n_hashes', 0)}h",
                "linked": linked, "basis": ac.get("basis", "—"), "acct": ac.get("account"),
                "cands": cand_txt, "cand_cls": cand_cls, "blocking": blocking}

    uncertified = [row(r, reqs[c]) for c, r in sorted(e_res.items(), key=lambda kv: int(kv[0].split("_")[1]))
                   if r.internal_status == "UNCERTIFIED"]
    complete_no_acct = [row(r, reqs[c]) for c, r in sorted(e_res.items(), key=lambda kv: int(kv[0].split("_")[1]))
                        if r.status == "COMPLETE" and not any(s["system_id"] == "account_service" for s in r.steps)]

    # ---------------------------------------------------------------- sample mismatches
    tup = lambda s: tuple(s[k] for k in KEY)
    mism = []
    for cid in sorted(gold, key=lambda c: int(c.split("_")[1])):
        r, (gs, gsteps) = s_res[cid], gold[cid]
        P, G = {tup(s) for s in r.steps}, {tup(s) for s in gsteps}
        if r.status == gs and P == G and [tup(s) for s in r.steps] == [tup(s) for s in gsteps]:
            continue
        q = reqs[cid]
        cut = parse_ts(q["audit_at"])
        uid = (r.trace.get("identity") or {}).get("user_ids", [None])[0]
        miss = []
        for s in gsteps:
            if tup(s) in P:
                continue
            rid = s["resource_id"]
            pl = fd.places(rid, cut, uid)
            own_pred = [p for p in r.steps if p["resource_id"] == rid]
            if own_pred:
                kind = ("implementation choice: same resource, different serialisation "
                        f"(pred {own_pred[0]['operation']} [{own_pred[0]['evidence_id'] or '—'}])")
            elif not pl:
                typed, bare = fd.suffix_hits(rid)
                kind = ("genuinely unsupported sample answer: the id occurs in no extracted text, JSON, SQL, OCR, "
                        "PDF or activity row" +
                        (f"; its numeric suffix occurs only inside other identifiers ({', '.join(typed[:5])})" if typed else "") +
                        (f"; bare-number occurrences to review: {', '.join(bare[:5])}" if bare else ""))
            elif not any(p["admissible"] for p in pl):
                kind = "ambiguous specification: the id appears only in evidence captured after audit_at"
            elif any(p["admissible"] and p["names_subject"] for p in pl):
                kind = "PARSER/RETRIEVAL OMISSION: an admissible occurrence names the subject"
            elif rid.startswith("account_"):
                kind = ("unsupported implementation assumption would be needed: the id is admissible but no admissible "
                        "evidence ties it to this subject (workflow window ambiguous)")
            else:
                kind = ("unsupported implementation assumption would be needed: admissible occurrences name nobody "
                        "(anonymised record; attribution would need other requests or time proximity alone)")
            miss.append((s, pl, kind))
        extra = [s for s in r.steps if tup(s) not in G]
        mism.append({"case": cid, "pred": r.status, "gold": gs, "internal": r.internal_status, "q": q,
                     "miss": miss, "extra": extra, "blocking": [u["reason"] for u in r.unresolved
                                                                if u.get("blocking", True)]})
    return uncertified, complete_no_acct, mism, ver


def render(uncertified, complete_no_acct, mism) -> str:
    L = ["# Case investigation — evidence matrix and specification conflicts", "",
         "_Generated by `python3 code/evaluation/investigate_cases.py`. Searches use the independent verifier's "
         "extraction of every evidence format (text, JSON, SQL, pdftotext, Tesseract) and the activity stream, "
         "at every capture time, and also the numeric suffix of each id. `adm` = captured by audit_at and line "
         "time by audit_at._", ""]
    reason_counts = Counter()
    for r in uncertified:
        for b in r["blocking"]:
            reason_counts[b.split(":")[0].split(" (")[0]] += 1
    cls_counts = Counter(c for r in uncertified for c in r["cand_cls"])
    L += ["## 1. Uncertified cases in the 518-case output", "",
          f"**{len(uncertified)} cases** have no supported violation and at least one unproven required state; each is "
          "serialised as INCOMPLETE carrying only future verification checks.", "",
          "| Blocking reason | Cases |", "|---|---|"] + [f"| {k} | {v} |" for k, v in reason_counts.most_common()]
    L += ["", "Every workflow candidate account of these cases, classified by searching all evidence:", "",
          "| Candidate classification | Candidates |", "|---|---|"] + [f"| {k} | {v} |" for k, v in cls_counts.most_common()]
    L += ["", "| Case | Subject | Identifiers | Linked resources | Account basis | Candidates (state; where linked) | Blocking reason |",
          "|---|---|---|---|---|---|---|"]
    for r in uncertified:
        L.append(f"| {r['case']} | {r['uid']} | {r['ids']} | {', '.join(r['linked']) or '—'} | {r['basis']} | "
                 f"{'<br>'.join(r['cands']) or '—'} | {'<br>'.join(r['blocking'])[:400]} |")
    L += ["", "## 2. COMPLETE cases without an account step", "",
          f"**{len(complete_no_acct)} cases.**" + (" Each is listed with why COMPLETE was still allowed." if complete_no_acct
                                                    else " Under the current rules COMPLETE requires the subject's "
                                                         "account to be identified and its required state proven."), ""]
    if complete_no_acct:
        L += ["| Case | Account basis | Linked resources |", "|---|---|---|"]
        for r in complete_no_acct:
            L.append(f"| {r['case']} | {r['basis']} | {', '.join(r['linked'])} |")
    kinds = Counter()
    for m in mism:
        for _, _, k in m["miss"]:
            kinds[k.split(":")[0]] += 1
    L += ["", "## 3. Every public-sample mismatch", "",
          f"{len(mism)} of 32 sample cases differ from the gold answer in status or steps.", "",
          "| Classification of each missing gold step | Steps |", "|---|---|"] + \
         [f"| {k} | {v} |" for k, v in kinds.most_common()]
    L += ["", "| Case | Pred / gold status | Missing gold step | Where the resource occurs | Classification |",
          "|---|---|---|---|---|"]
    for m in mism:
        for s, pl, k in m["miss"]:
            L.append(f"| {m['case']} | {m['pred']} / {m['gold']} | {s['operation']} `{s['resource_id']}` "
                     f"[{s['evidence_id'] or '—'}] | {fmt_places(pl)} | {k} |")
        for s in m["extra"]:
            L.append(f"| {m['case']} | {m['pred']} / {m['gold']} | (extra predicted) {s['operation']} "
                     f"`{s['resource_id']}` [{s['evidence_id'] or '—'}] | — | "
                     f"{'uncertified case: future check with empty evidence_id (gold certifies with a citation)' if m['internal'] == 'UNCERTIFIED' else 'see trace'} |")
        if m["pred"] != m["gold"]:
            L.append(f"| {m['case']} | {m['pred']} / {m['gold']} | (status) | — | internal {m['internal']}; blocking: "
                     f"{'; '.join(m['blocking'])[:300] or '—'} |")
    L += ["", CONFLICTS]
    return "\n".join(L) + "\n"


CONFLICTS = """## 4. Minimal reproductions of the specification conflicts

Governing rules (AGENTS.md §6.2 / §6.6): *"Use only information available at or before `audit_at` … Evidence
created later must not change the answer"*; *"Never cite organizer-only truth or an evidence item captured after the
case's `audit_at`"*; §6.5 *"A deletion is COMPLETE only when every relevant copy has the required treatment"*.

**C1 — resource known only from a file captured after `audit_at` (ambiguous specification).**
case_09: `grep -rl audit_record_4902 dataset/evidence` → `evidence/logs/structured_service_events_eu_west_20260918.log`
only; `dataset/evidence_files.csv` line `evidence_06,…,2026-09-18T11:55:24Z`; the line itself is dated
`2026-09-16T08:52:59Z`; case_09 `audit_at` = `2026-09-16T09:00:00Z`. Expected (gold): `VERIFY_RECORD_PRESENT
security_service audit_record_4902 ""`. Actual: not emitted (the file did not exist at audit_at). Same pattern:
case_23/24/29/30 via evidence_02 (captured 2026-09-17, audit_at 2026-09-15). Section 1 shows the same pattern for the
uncertified cases: the only files that tie a candidate account to its subject were captured after audit_at.
Measured alternative (analysis only, not shipped): admitting such lines by their own timestamp gives 29/32 sample
statuses but 29 extra and 46 missing steps (strict: 27/32, 11 extra, 35 missing), so neither reading reproduces the
gold answers.

**C2 — gold step for an id that occurs nowhere (genuinely unsupported sample answer).** case_18
`audit_record_6645`, case_20 `audit_record_5569`: no occurrence in any extracted text, JSON, SQL, OCR or PDF text or
activity row (Section 3 also reports whether the numeric suffix appears anywhere).

**C3 — case_04 (genuinely unsupported by admissible evidence).** Gold `VERIFY_RECORD_ABSENT account_004
[evidence_54]` — `account_004` occurs nowhere; evidence_54 is a 7-row failover dump that does not contain it.
Gold `VERIFY_RECORD_ANONYMIZED analytics_901 [evidence_56]` — evidence_56 lists `analytics_901` with every identifier
null; `activity_3463` anonymised it 7 minutes before the report but names no person; no workflow submission falls in
the report window. Deriving either link needs the id-numbering pattern (`user_04` ↔ `account_004`) or time proximity.

**C4 — account attribution in ambiguous workflow windows (unsupported implementation assumption needed).** e.g.
case_25 and case_26 share `reported_at` 2026-09-02T12:00Z and reported status; the window holds unowned submissions
`account_3136` and `account_5684` (both later absent). Gold gives `account_3136` to case_25 and `account_5684` to
case_26. Nothing admissible ties either id to either subject; picking one requires another request's existence or
order. A set of absent candidates also does not prove the subject's account absent: the window is a heuristic and is
not shown to be exhaustive or to contain that account.

**C5 — finance retention register (ambiguous specification).** evidence_27 ("Disputed orders and tax records
register") lists `ORD-… | user_NN | reason | amount | Retain until …`. It names no system resource and does not call
itself a legal hold; the dataset's legal holds are separate `legal_hold_NNN` records. The register is recorded as
context only: it is not treated as proof that any record is retained.

**C6 — restore capability of a specific archive (ambiguous specification).** case_55: evidence_32 shows
`backup_9287` (the subject's archive, retention end 26 Jul 2026, no block shown); the only restore wording on the
screen concerns *other* archives (`backup_9286 restored · Completed`). A completed restore of another archive does not
establish this archive's restore path, so the restore state is unresolved (not reported as a risk, not certified).

### Draft questions for the organisers (not sent)

1. *Cut-off:* For case_09 (and 23/24/29/30) the sample answer verifies `audit_record_4902`, which appears only in
   evidence_06 (captured 2026-09-18; line dated 2026-09-16T08:52:59Z; audit_at 2026-09-16T09:00Z). Should a file
   captured after `audit_at` be used for lines dated before it — for uncited future-work steps, for identity links,
   or not at all?
2. *Unsupported ids:* Is the gold `audit_record_6645` (case_18) / `audit_record_5569` (case_20) derived from a
   participant-visible file? We find no occurrence in any evidence file or activity row.
3. *case_04:* Which participant-visible evidence links `account_004` and `analytics_901` to user_04 by audit_at?
4. *Ambiguous workflow windows:* When several unowned account submissions fall in a request's report window
   (e.g. case_25/case_26), is the expected answer derivable from a single request's evidence, or does it depend on
   the other requests in the file?
5. *No proof either way:* When no violation is supported but a required final state (e.g. the primary account) is
   not proven, should the status be INCOMPLETE (and with which steps) or COMPLETE?
6. *Registers and archives:* Is a finance retention register row (evidence_27) a "supplied legal hold" under
   rule_13? Does an archive that holds the subject's data, with no block shown, count as an active restore path
   (REPORT_RESTORE_RISK) without an explicit restore statement about that archive?
"""


if __name__ == "__main__":
    u, c, m, _ = run()
    out = HERE / "case_investigation.md"
    out.write_text(render(u, c, m), encoding="utf-8")
    print(f"wrote {out}: {len(u)} uncertified, {len(c)} COMPLETE without account step, {len(m)} sample mismatches")
