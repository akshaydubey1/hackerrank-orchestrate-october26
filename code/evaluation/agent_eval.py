"""Evaluate the bounded investigation step against the deterministic baseline on labelled images.

    python3 code/evaluation/agent_eval.py [--n 60]   # -> prints JSON; evaluation/main.py embeds it

Labelled set (seeded, generated here, independent of the challenge data): each image is one console
row "backup_NNNN  <address>  eu-west-1  Archive" rendered small. The label is the address actually
drawn. Two kinds:
  true   the drawn address IS a known identifier        -> correct outcome: verified
  decoy  the drawn address is a different address within two edits of a known identifier
         (and is not itself known)                       -> correct outcome: NOT verified
Strategies, all under the same images, tools and budgets:
  baseline        no investigation (only an exact read in the default OCR pass counts)
  ladder_b3       FixedLadder, at most 3 re-extractions per problem
  ladder_b5       FixedLadder, at most 5 re-extractions per problem
  model           ModelPolicy — runs only with ANTHROPIC_API_KEY; otherwise reported NOT RUN
A second labelled set covers row-gap screens (see build_rows). Every strategy uses its own cache so
re-extraction cost is comparable; latency, model calls, tokens and estimated cost are recorded.

Running the model comparison (credentials are read from the environment only; never put them in a file
or a chat):
    export ANTHROPIC_API_KEY=...            # in your own shell
    export GHOST_AUDIT_MODEL=claude-haiku-5-5   # optional; default shown
    python3 code/evaluation/agent_eval.py --n 60
"""
from __future__ import annotations

import argparse
import json
import random
import string
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from ghost_audit import investigate as inv  # noqa: E402
from ghost_audit.parsers import ocr_text  # noqa: E402

FONT_CANDIDATES = ["/usr/share/fonts/opentype/inter/Inter-Regular.otf",
                   "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "DejaVuSans.ttf"]
NAMES = ["areed", "lilly", "milli", "ilya", "olli", "tilda", "kai", "lio", "nils", "ivo", "lina", "emil"]


def _font(size):
    from PIL import ImageFont
    for f in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(f, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _render(text: str, size: int, path: Path):
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (900, 40 + int(size * 2.2)), "white")
    ImageDraw.Draw(img).text((20, 20), text, fill=(40, 40, 40), font=_font(size))
    img.save(path)


def _mutate(rnd, email: str) -> str:
    loc, dom = email.split("@")
    for _ in range(20):
        i = rnd.randrange(len(loc))
        c = rnd.choice(string.ascii_lowercase + string.digits)
        cand = loc[:i] + c + loc[i + 1:]
        if cand != loc:
            return cand + "@" + dom
    return "x" + email


def build(root: Path, n: int, seed: int = 11) -> list:
    rnd = random.Random(seed)
    cases = []
    for i in range(n):
        known = f"{rnd.choice(NAMES)}{rnd.choice(['1', 'l', 'i', ''])}{rnd.randint(100, 999)}{rnd.choice(['1', 'l', ''])}@gmail.com"
        kind = "true" if i % 3 else "decoy"
        drawn = known if kind == "true" else _mutate(rnd, known)
        size = rnd.choice([11, 12, 13, 14])
        p = root / f"case_{i:03d}.png"
        _render(f"backup_{9000 + i}   {drawn}   eu-west-1   Archive", size, p)
        cases.append({"id": i, "path": str(p), "known": known, "drawn": drawn, "kind": kind, "size": size})
    return cases



def build_rows(root: Path, n: int, seed: int = 17) -> list:
    """Row-gap screens. label = rows actually drawn.
    gap    declared count == rows drawn; one row is small/low-contrast -> correct: recovered
    decoy  declared count  > rows drawn (a row is genuinely absent)   -> correct: nothing accepted"""
    from evaluation.fixtures import _png_rows
    rnd = random.Random(seed)
    cases = []
    for i in range(n):
        kind = "gap" if i % 3 else "decoy"
        base = 9500 + 10 * i
        big = rnd.choice([14, 15, 16, 18])   # realistic UI sizes; one row small and low-contrast
        rows = [(f"1  Password changed   user_{base}   Valid   audit_record_{base + 1}", big, (0, 0, 0)),
                (f"2  Session revoked   user_{base}   Valid   audit_record_{base + 2}", rnd.choice([9, 10, 11]), (90, 90, 90)),
                (f"3  Login new device   user_{base}   Valid   audit_record_{base + 3}", big, (0, 0, 0))]
        drawn = [f"audit_record_{base + k}" for k in (1, 2, 3)]
        declared = 3 if kind == "gap" else 4
        p = root / f"rows_{i:03d}.png"
        p.write_bytes(_png_rows([(f"Security events   Updated moments ago - {declared} records", big, (0, 0, 0))] + rows))
        cases.append({"id": i, "path": str(p), "kind": kind, "drawn": drawn, "declared": declared})
    return cases


def evaluate_rows(cases: list, strategy: str, cache: Path) -> dict:
    import time
    from ghost_audit import llm
    files = {f"rows_{c['id']}": SimpleNamespace(path=Path(c["path"]), text=ocr_text(Path(c["path"])), captured_at="",
                                                verified_identifiers=set(), investigations=[], n_observations=0)
             for c in cases}
    store = SimpleNamespace(files=files, observations=[])
    res = {"strategy": strategy, "set": "row_gap", "cases": len(cases),
           "gap_cases": sum(c["kind"] == "gap" for c in cases), "decoy_cases": sum(c["kind"] == "decoy" for c in cases)}
    if strategy == "model" and not inv.ModelPolicy.available():
        return {**res, "status": "NOT RUN (no ANTHROPIC_API_KEY; no real provider call was made)"}
    t0, u0 = time.time(), llm.USAGE.summary()
    recovered, false_rows, actions, problems = 0, 0, 0, 0
    if strategy != "baseline":
        policy = inv.ModelPolicy() if strategy == "model" else inv.FixedLadder()
        probs = inv.find_row_gaps(store)
        problems = len(probs)
        outs = inv.investigate(probs, policy, cache, per_problem=5 if strategy == "ladder_b5" else 3, per_run=10_000)
        actions = sum(len(o.attempts) for o in outs)
        for o in outs:
            c = next(x for x in cases if f"rows_{x['id']}" == o.problem.file_id)
            if o.verified:
                good = [r for r in o.new_ids if r in c["drawn"]]
                recovered += len(good)
                false_rows += len(o.new_ids) - len(good)
    u1 = llm.USAGE.summary()
    # rows (not screens) that the default OCR pass missed on screens whose count can be completed;
    # same unit as rows_recovered
    missed_base = sum(1 for c in cases if c["kind"] == "gap"
                      for r in c["drawn"] if r not in files[f"rows_{c['id']}"].text.lower())
    return {**res, "status": "RUN", "problems_found": problems, "rows_missed_by_default_ocr": missed_base,
            "rows_recovered": recovered, "false_rows_accepted": false_rows, "re_extractions": actions,
            "seconds": round(time.time() - t0, 1), "model_calls": u1["calls"] - u0["calls"],
            "tokens": (u1["input_tokens"] + u1["output_tokens"]) - (u0["input_tokens"] + u0["output_tokens"]),
            "cost_usd": round(u1["estimated_cost_usd"] - u0["estimated_cost_usd"], 6)}


def evaluate(cases: list, strategy: str, cache: Path) -> dict:
    files = {}
    for c in cases:
        files[f"img_{c['id']}"] = SimpleNamespace(path=Path(c["path"]), text=ocr_text(Path(c["path"])),
                                                  verified_identifiers=set(), investigations=[])
    store = SimpleNamespace(files=files)
    known = {c["known"] for c in cases}
    # decoys must not be known identifiers themselves
    known -= {c["drawn"] for c in cases if c["kind"] == "decoy"}
    base_exact = {fid for fid, ef in files.items() if any(inv.verbatim(k, ef.text) for k in known)}
    res = {"strategy": strategy, "cases": len(cases), "true_cases": sum(c["kind"] == "true" for c in cases),
           "decoy_cases": sum(c["kind"] == "decoy" for c in cases)}
    tp = fp = actions = problems = 0
    if strategy == "baseline":
        for c in cases:
            fid = f"img_{c['id']}"
            hit = fid in base_exact and inv.verbatim(c["known"], files[fid].text)
            tp += hit and c["kind"] == "true"
            fp += hit and c["kind"] == "decoy"
    else:
        if strategy == "model" and not inv.ModelPolicy.available():
            return {**res, "status": "NOT RUN (no ANTHROPIC_API_KEY; no real provider call was made)"}
        policy = inv.ModelPolicy() if strategy == "model" else inv.FixedLadder()
        budget = 5 if strategy == "ladder_b5" else 3
        probs = inv.find_problems(store, known)
        problems = len(probs)
        outs = inv.investigate(probs, policy, cache, per_problem=budget, per_run=10_000)
        verified = {(o.problem.file_id, o.problem.hypothesis) for o in outs if o.verified}
        actions = sum(len(o.attempts) for o in outs)
        for c in cases:
            fid = f"img_{c['id']}"
            hit = (fid in base_exact and inv.verbatim(c["known"], files[fid].text)) or (fid, c["known"]) in verified
            tp += hit and c["kind"] == "true"
            fp += hit and c["kind"] == "decoy"
    return {**res, "status": "RUN", "problems_found": problems, "true_verified": int(tp),
            "decoys_wrongly_verified": int(fp), "re_extractions": actions,
            "base_exact_reads_of_true": sum(1 for c in cases if c["kind"] == "true"
                                            and inv.verbatim(c["known"], files[f"img_{c['id']}"].text))}


def run(n: int = 60, n_rows: int = 18) -> list:
    import time
    from ghost_audit import llm
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cases = build(root, n)
        rows = build_rows(root, n_rows)
        out = []
        for s_ in ("baseline", "ladder_b3", "ladder_b5", "model"):
            cache = root / f"cache_{s_}"   # separate caches: every strategy pays for its own re-extractions
            t0, u0 = time.time(), llm.USAGE.summary()
            r = evaluate(cases, s_, cache)
            u1 = llm.USAGE.summary()
            if r.get("status") == "RUN":
                r.update(seconds=round(time.time() - t0, 1), model_calls=u1["calls"] - u0["calls"],
                         tokens=(u1["input_tokens"] + u1["output_tokens"]) - (u0["input_tokens"] + u0["output_tokens"]),
                         cost_usd=round(u1["estimated_cost_usd"] - u0["estimated_cost_usd"], 6))
            out.append(r)
            out.append(evaluate_rows(rows, s_, root / f"cache_rows_{s_}"))
        return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60)
    print(json.dumps(run(ap.parse_args().n), indent=2))
