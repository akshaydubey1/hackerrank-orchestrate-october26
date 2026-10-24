"""Fail-first evidence: run the CURRENT regression fixtures against any code tree.

    git archive f280a63 code | tar -x -C /tmp/base            # the pre-repair implementation
    cp code/evaluation/fixtures.py /tmp/base/code/evaluation/  # today's fixtures, old predictor
    python3 code/evaluation/failfirst.py /tmp/base/code /tmp/fx_base > base.json
    python3 code/evaluation/failfirst.py code /tmp/fx_new > new.json

A fixture added for a defect must FAIL on the old tree and PASS on the new one.
"""
import sys, json
from pathlib import Path
code = Path(sys.argv[1]).resolve(); sys.path.insert(0, str(code))
from evaluation.fixtures import build
from ghost_audit.pipeline import Engine, read_requests
import ghost_audit
assert str(code) in ghost_audit.__file__, ghost_audit.__file__
root = Path(sys.argv[2]); root.mkdir(parents=True, exist_ok=True); exp = build(root)
e = Engine(root, None); R = read_requests(root / 'deletion_requests.csv')
if hasattr(e, 'prepare'):
    try: e.prepare([R])
    except TypeError: e.prepare()
exp.pop('__extraction_failures__')
out = {}
for r in e.run(R):
    x = exp[r.case_id]; k = lambda s: (s['phase'], s['system_id'], s['resource_id'], s['operation'], s['evidence_id'])
    ok = ('status' not in x or r.status == x['status']) and r.status in x.get('status_in', [r.status])
    if 'steps' in x: ok = ok and [k(s) for s in r.steps] == [k(s) for s in x['steps']]
    for m in x.get('must_include', []): ok = ok and k(m) in {k(s) for s in r.steps}
    for a, b, c in x.get('must_exclude_ops', []): ok = ok and not any(s['system_id'] == a and s['resource_id'] == b and s['operation'] == c for s in r.steps)
    for rid in x.get('must_exclude_resources', []): ok = ok and not any(s['resource_id'] == rid for s in r.steps)
    for rid in x.get('must_not_cite', []): ok = ok and not any(s['resource_id'] == rid and s['evidence_id'] for s in r.steps)
    if x.get('must_have_unresolved'): ok = ok and any(x['must_have_unresolved'] in json.dumps(u) for u in getattr(r, 'unresolved', []))
    out[r.case_id] = {"pass": ok, "status": r.status, "n_steps": len(r.steps), "kind": "behaviour"}
# unit-level tests (today's file) against the same tree; an error counts as a failure
import importlib.util
spec = importlib.util.spec_from_file_location("unit_tests_today", Path(__file__).resolve().parent / "unit_tests.py")
ut = importlib.util.module_from_spec(spec); spec.loader.exec_module(ut)
for name, ok, detail in ut.run(code):
    incompatible = "(group errored)" in name and any(
        e in detail for e in ("AttributeError", "ImportError", "ModuleNotFoundError", "TypeError"))
    out[name.split()[0]] = {"pass": ok, "status": "unit", "n_steps": 0, "detail": detail,
                            "kind": "harness-incompatible" if incompatible else "behaviour"}
print(json.dumps(out))
