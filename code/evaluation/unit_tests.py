"""Unit-level checks of certification and investigation rules that fixtures cannot isolate.

    python3 code/evaluation/unit_tests.py [code_dir]   # runs against any code tree (fail-first)
Each test returns (name, passed, detail); a test that raises (e.g. the module does not exist in
an older tree) is reported as failed with the error.
"""
from __future__ import annotations

import sys
from pathlib import Path


def _planner_cases():
    from ghost_audit import planner
    T = planner.Treatment
    out = []
    ts = [T("account_service", "account_1", "USER_PROFILE", "DELETE", False, None, None, None, "evidence_1"),
          T("support_platform", "support_1", "SUPPORT_MESSAGE", "REDACT", None, False, None, None, "")]
    st, steps, unresolved = planner.build_steps(ts)
    out.append(("U1 uncited verification blocks COMPLETE", st != "COMPLETE",
                f"status={st}, steps={[s['resource_id'] for s in steps]}, unresolved={len(unresolved)}"))
    ts = [T("account_service", "account_2", "USER_PROFILE", "DELETE", False, None, None, None, "evidence_2"),
          T("search_service", "search_2", "SEARCH_INDEX_ENTRY", "DELETE", False, None, None, None, "evidence_3")]
    st, steps, _ = planner.build_steps(ts)
    out.append(("U2 COMPLETE carries only cited verification", st == "COMPLETE" and all(s["evidence_id"] for s in steps),
                f"status={st}, steps={len(steps)}"))
    ts = [T("account_service", "account_3", "USER_PROFILE", "DELETE", None, None, None, None, ""),
          T("search_service", "search_3", "SEARCH_INDEX_ENTRY", "DELETE", False, None, None, None, "evidence_4")]
    st, steps, _ = planner.build_steps(ts)
    out.append(("U3 unproven account blocks COMPLETE", st != "COMPLETE", f"status={st}"))
    # U8 an unknown required state still yields its future check (no empty INCOMPLETE plan)
    ts = [T("backup_service", "backup_8", "BACKUP_ARCHIVE", "RETAIN", True, None, None, None, "")]
    st, steps, _ = planner.build_steps(ts)
    out.append(("U8 unknown restore state keeps its required future check", st != "COMPLETE" and
                [s["operation"] for s in steps] == ["VERIFY_RESTORE_BLOCKED"] and steps[0]["evidence_id"] == "",
                f"status={st}, steps={[s['operation'] for s in steps]}"))
    return out


def _investigation_cases():
    from ghost_audit import investigate as inv
    out = []
    pb = inv.Problem("f1", "unused.png", "lena.kach@example.org", "lena.koch@example.org",
                     "analytics_1 lena.kach@example.org")
    saved = inv._reextract
    try:
        inv._reextract = lambda path, action, cache: ("analytics_1  lena.kach@example.org", True)
        o1 = inv.investigate([pb], inv.FixedLadder())[0]
        inv._reextract = lambda path, action, cache: ("analytics_1  lena.koch@example.org", True)
        o2 = inv.investigate([pb], inv.FixedLadder())[0]
        inv._reextract = lambda path, action, cache: ("xlena.koch@example.org.evil", True)
        o3 = inv.investigate([pb], inv.FixedLadder())[0]
    finally:
        inv._reextract = saved
    out.append(("U4 investigation: re-read of the look-alike is not accepted", not o1.verified and len(o1.attempts) == 3,
                f"verified={o1.verified}, attempts={len(o1.attempts)} (per-problem budget 3)"))
    out.append(("U5 investigation: verbatim re-read is accepted and stops", o2.verified and len(o2.attempts) == 1,
                f"verified={o2.verified}, attempts={len(o2.attempts)}"))
    out.append(("U6 investigation: hypothesis embedded in a longer token is not accepted", not o3.verified,
                f"verified={o3.verified}"))

    class Rogue:
        name, calls = "rogue", 0

        def next_action(self, problem, tried):
            return "read_other_file"
    o4 = inv.investigate([pb], Rogue())[0]
    out.append(("U7 investigation: disallowed policy action is refused", not o4.verified and not o4.attempts
                and "disallowed" in o4.stop_reason, o4.stop_reason))
    return out


def _row_gap_cases():
    """Row-gap acceptance. Each case states the screen text the default OCR produced (`base`) and what a
    re-extraction returned (`reread`); the expectation follows from the screen alone."""
    from types import SimpleNamespace
    from ghost_audit import investigate as inv
    out = []

    def screen(base):
        return SimpleNamespace(files={"img": SimpleNamespace(path=Path("x.png"), text=base, captured_at="2026-01-01T00:00:00Z",
                                                             verified_identifiers=set(), investigations=[],
                                                             n_observations=0)}, observations=[])

    def attempt(base, reread):
        st = screen(base)
        gaps = inv.find_row_gaps(st)
        saved = inv._reextract
        try:
            inv._reextract = lambda p, a, c: (reread, True)
            outs = inv.investigate(gaps, inv.FixedLadder())
        finally:
            inv._reextract = saved
        return st, gaps, outs

    head = "events  updated moments ago - 3 records\n"
    r1, r2, r3 = ("user_9 valid audit_record_1", "user_9 valid audit_record_2", "user_9 valid audit_record_3")
    full = head + "\n".join([r1, r2, r3]) + "\n"
    base = head + r1 + "\n" + r3 + "\n"
    st, gaps, outs = attempt(base, full)
    out.append(("U9 row gap: complete re-read restating the count is accepted",
                len(gaps) == 1 and outs[0].verified and outs[0].new_ids == ["audit_record_2"], f"gaps={len(gaps)}"))
    _, _, o = attempt(base, full + "user_9 valid audit_record_7\n")
    out.append(("U10 row gap: re-read exceeding the declared count is rejected", o and not o[0].verified,
                o[0].attempts[-1].get("reason", "") if o else "no problem"))
    inv.apply(st, outs)
    obs = [x for x in st.observations if x.resource_id == "audit_record_2"]
    out.append(("U11 row gap: accepted row becomes an ordinary observation from its own line",
                len(obs) == 1 and "user_9" in obs[0].identifiers and obs[0].location.startswith("re-extraction"),
                f"{[(x.resource_id, x.identifiers) for x in obs]}"))
    # U12 two tables (two different counts) -> the count is not bound to one table -> no problem opened
    two = "orders - 2 records\nuser_9 order_1\nevents - 3 records\n" + r1 + "\n" + r3 + "\n"
    out.append(("U12 two count statements (two tables): no gap is opened", not inv.find_row_gaps(screen(two)), ""))
    # U13 ids of another type elsewhere on the page are not counted, and cannot complete the count
    base13 = base + "backup_5 restore policy panel\n"
    _, g13, o13 = attempt(base13, head + r1 + "\n" + r3 + "\nbackup_5 user_9 panel\nbackup_6 user_9 panel\n")
    out.append(("U13 unrelated id types neither count nor complete the table",
                len(g13) == 1 and getattr(g13[0], "table_type", None) == "audit_record" and not o13[0].verified,
                o13[0].attempts[-1].get("reason", "") if o13 else "no problem"))
    # U14 pagination: the count is a total, not the rows on screen
    pag = "events - showing 1-2 of 3 records\n" + r1 + "\n" + r3 + "\n"
    out.append(("U14 paginated count: no gap is opened", not inv.find_row_gaps(screen(pag)), ""))
    # U15 a row repeated in a detail panel counts once
    dup = base + "audit_record_1 - raw event\n"
    g15 = inv.find_row_gaps(screen(dup))
    out.append(("U15 duplicate id (detail panel) counts once", len(g15) == 1 and len(g15[0].known_ids) == 2,
                f"{g15[0].known_ids if g15 else None}"))
    # U16 the re-read reads a different count -> the count is not confirmed
    _, _, o16 = attempt(base, full.replace("3 records", "4 records"))
    out.append(("U16 re-read with a different count is rejected", o16 and not o16[0].verified,
                o16[0].attempts[-1].get("reason", "") if o16 else ""))
    # U17 the re-read drops an original row, yet the union would reach the count
    _, _, o17 = attempt(base, head + r1 + "\n" + r2 + "\nuser_9 valid audit_record_4\n")
    out.append(("U17 re-read dropping an original row is rejected", o17 and not o17[0].verified,
                o17[0].attempts[-1].get("reason", "") if o17 else ""))
    # U18 replacement: an original id misread as another id plus one new row exactly meets the count
    _, _, o18 = attempt(base, head + r1 + "\nuser_9 valid audit_record_8\n" + r2 + "\n")
    out.append(("U18 replacement id that happens to satisfy the count is rejected", o18 and not o18[0].verified,
                o18[0].attempts[-1].get("reason", "") if o18 else ""))
    # U19 a recovered row with no owner on its own line is not accepted
    _, _, o19 = attempt(base, head + r1 + "\nvalid audit_record_2\n" + r3 + "\n")
    out.append(("U19 recovered row without an owner identifier is rejected", o19 and not o19[0].verified,
                o19[0].attempts[-1].get("reason", "") if o19 else ""))
    # U20 completion adds presence only, with the file's capture time; nothing is inferred absent
    st20, _, o20 = attempt(base, full)
    inv.apply(st20, o20)
    out.append(("U20 count completion adds presence only, stamped with the file's capture time",
                st20.observations and all(x.exists is not False and x.captured_at == "2026-01-01T00:00:00Z"
                                          for x in st20.observations),
                f"{[(x.resource_id, x.exists, x.captured_at) for x in st20.observations]}"))
    return out


GROUPS = [("U1 U2 U3 U8", _planner_cases, 4), ("U4 U5 U6 U7", _investigation_cases, 4), ("U9 U10 U11 U12 U13 U14 U15 U16 U17 U18 U19 U20", _row_gap_cases, 12)]


def run(code_dir=None) -> list:
    code_dir = Path(code_dir) if code_dir is not None else Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(code_dir.resolve()))
    out = []
    for label, fn, n in GROUPS:
        try:
            out += fn()
        except Exception as exc:  # an older tree may lack the module or behave differently
            out += [(f"{t} (group errored)", False, f"{type(exc).__name__}: {exc}") for t in label.split()]
    return out


if __name__ == "__main__":
    res = run(sys.argv[1] if len(sys.argv) > 1 else None)
    for r in res:
        print(("PASS" if r[1] else "FAIL"), r[0], "-", r[2])
    sys.exit(0 if all(r[1] for r in res) else 1)
