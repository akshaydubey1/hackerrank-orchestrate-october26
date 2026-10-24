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


def run(n: int = 60) -> list:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cases = build(root, n)
        cache = root / "cache"
        return [evaluate(cases, s, cache) for s in ("baseline", "ladder_b3", "ladder_b5", "model")]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60)
    print(json.dumps(run(ap.parse_args().n), indent=2))
