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


GROUPS = [("U1 U2 U3 U8", _planner_cases, 4), ("U4 U5 U6 U7", _investigation_cases, 4)]


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
