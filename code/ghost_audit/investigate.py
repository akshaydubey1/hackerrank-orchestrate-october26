"""Bounded evidence investigation for one concrete extraction problem: an identifier misread by OCR.

Problem. A screenshot's OCR text contains an e-mail token that is not any known identifier but is
a near-miss (domain within two edits, local part within three, unique) of exactly one known
identifier. This window only proposes what to look for; it never accepts anything.
The page may show that person's address, or it may show a different, similar address (a decoy).

Decision. Which re-extraction to run next, if any: the policy chooses among a fixed set of
deterministic tools (re-OCR at a higher scale and a different page-segmentation mode, optional
binarisation) under a per-problem and a per-run action budget, and may stop early.

Validation (deterministic, independent of the policy). A hypothesis is accepted only if a
re-extraction contains it verbatim as a whole token. The accepted string is then an ordinary exact
identifier; nothing fuzzy reaches linking or exposure. A policy can only spend budget: it cannot
create, edit or accept a fact, read files other than the problem's image, or change temporal
filtering, policy rules or serialisation.

Policies.
  FixedLadder  deterministic baseline: tries the tools in a fixed order.
  ModelPolicy  asks a model to choose the next tool from the allowed list (JSON schema, timeout,
               retries, call and cost budget, every call counted in llm.USAGE). It runs only when
               ANTHROPIC_API_KEY is set; otherwise it reports NOT RUN and the caller falls back to
               the deterministic ladder. It has not been executed against a real provider.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .util import EMAIL_RE

ACTIONS = {
    # name: (scale, tesseract psm, binarise)
    "ocr_x2_psm6": (2, 6, False),
    "ocr_x3_psm6": (3, 6, False),
    "ocr_x2_psm4": (2, 4, False),
    "ocr_x3_psm11": (3, 11, False),
    "ocr_x2_bin_psm6": (2, 6, True),
}
LADDER = ["ocr_x2_psm6", "ocr_x3_psm6", "ocr_x2_psm4", "ocr_x3_psm11", "ocr_x2_bin_psm6"]
MAX_ACTIONS_PER_PROBLEM = 3
MAX_ACTIONS_PER_RUN = 60
VERSION = "investigate-v3"


def _edit(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@dataclass
class Problem:
    file_id: str
    path: str
    observed: str          # identifier_misread: token as OCR read it; row_gap: "<n> row ids"
    hypothesis: str        # identifier_misread: the single known identifier; row_gap: declared count
    context: str           # the OCR line it was read on (the count line for row_gap)
    kind: str = "identifier_misread"
    known_ids: list = field(default_factory=list)   # row_gap: the table's row ids already extracted
    table_type: str = ""                             # row_gap: resource-id prefix of the table's rows


@dataclass
class Outcome:
    problem: Problem
    policy: str
    attempts: list = field(default_factory=list)   # [{"action", "verbatim", "cached"}]
    verified: bool = False
    stop_reason: str = ""
    model_calls: int = 0
    new_ids: list = field(default_factory=list)     # row_gap: ids recovered by the accepted re-read
    accepted_text: str = ""                          # row_gap: the accepted re-extraction (kept for audit)

    def to_dict(self):
        d = asdict(self)
        d["problem"] = asdict(self.problem)
        return d


def find_problems(store, known_emails: set) -> list:
    by_dom = {}
    for e in known_emails:
        by_dom.setdefault(e.split("@", 1)[1], []).append(e)
    out = []
    for fid, ef in store.files.items():
        if ef.path.suffix.lower() not in (".png", ".jpg", ".jpeg") or not ef.text:
            continue
        seen = set()
        for line in ef.text.lower().splitlines():
            for tok in EMAIL_RE.findall(line):
                tok = tok.lower()
                if tok in known_emails or tok in seen or "@" not in tok:
                    continue
                loc, dom = tok.split("@", 1)
                # hypothesis generation only (acceptance is verbatim): local part within 3 edits,
                # domain within 2 edits (OCR often breaks ".com" or the domain's letters too)
                near = [e for d, es in by_dom.items() if _edit(d, dom) <= 2
                        for e in es if _edit(e.split("@", 1)[0], loc) <= 3]
                if len(near) == 1:
                    seen.add(tok)
                    out.append(Problem(fid, str(ef.path), tok, near[0], line.strip()[:160]))
    return sorted(out, key=lambda p: (p.file_id, p.observed))


COUNT_RE = re.compile(r"\b(\d{1,4})\s+records?\b")
PAGINATION_RE = re.compile(r"\b(showing|page \d+|of \d+ records?|next page|previous page)\b|\d+\s*[-\u2013]\s*\d+\s+of\s+\d+")
OWNER_RE = re.compile(r"\buser_\d+\b|[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}|\b[0-9a-f]{64}\b")


def _prefix(rid: str) -> str:
    return rid.rsplit("_", 1)[0]


def _table_ids(low: str, table_type: str) -> set:
    from .util import RESOURCE_RE
    return {m.group(0) for m in RESOURCE_RE.finditer(low) if _prefix(m.group(0)) == table_type}


def find_row_gaps(store) -> list:
    """Screens whose single, non-paginated record count exceeds the distinct row ids of the table's type.

    The count is bound to one table: a page with several distinct counts (several tables) or with
    pagination wording ("showing 1-25 of 132", "page 2") is skipped, because the count would not describe
    the rows on screen. Only ids of the table's resource type are counted, so ids of other types on the
    page (detail panels, navigation) cannot fill the count. Duplicates (a row repeated in a detail
    panel) count once."""
    from .util import RESOURCE_RE
    out = []
    for fid, ef in store.files.items():
        if ef.path.suffix.lower() not in (".png", ".jpg", ".jpeg") or not ef.text:
            continue
        low = ef.text.lower()
        counts = {int(m.group(1)) for m in COUNT_RE.finditer(low)}
        if len(counts) != 1 or PAGINATION_RE.search(low):
            continue
        declared = counts.pop()
        prefixes = {}
        for m in RESOURCE_RE.finditer(low):
            prefixes.setdefault(_prefix(m.group(0)), set()).add(m.group(0))
        if not prefixes:
            continue
        table_type, ids = max(prefixes.items(), key=lambda kv: (len(kv[1]), kv[0]))
        if 0 < len(ids) < declared:
            line = next((ln.strip() for ln in low.splitlines() if COUNT_RE.search(ln)), "")
            out.append(Problem(fid, str(ef.path), f"{len(ids)} {table_type} row ids", str(declared), line[:160],
                               kind="row_gap", known_ids=sorted(ids), table_type=table_type))
    return out


def _accept(pb: Problem, text: str) -> tuple:
    """Deterministic validation. Returns (accepted, new_ids, reason)."""
    if pb.kind != "row_gap":
        ok = verbatim(pb.hypothesis, text)
        return ok, [], "verbatim" if ok else "hypothesis not read verbatim"
    low = text.lower()
    declared = int(pb.hypothesis)
    counts = {int(m.group(1)) for m in COUNT_RE.finditer(low)}
    if counts != {declared}:
        return False, [], f"count not confirmed by the re-read ({sorted(counts) or 'none'})"
    ids = _table_ids(low, pb.table_type)
    dropped = sorted(set(pb.known_ids) - ids)
    if dropped:
        return False, [], f"re-read drops original rows {dropped[:3]} (cannot be reconciled with the first reading)"
    new = sorted(ids - set(pb.known_ids))
    if not new or len(ids) != declared:
        return False, [], f"{len(ids)} {pb.table_type} ids read, {declared} declared"
    lines = low.splitlines()
    ungrounded = [r for r in new if not any(r in ln and OWNER_RE.search(ln.replace(r, "")) for ln in lines)]
    if ungrounded:
        return False, [], f"recovered rows without an owner identifier on their own line: {ungrounded}"
    return True, new, "declared count completed by a complete re-read"


def _reextract(path: str, action: str, cache_dir: Path | None) -> tuple:
    scale, psm, binarise = ACTIONS[action]
    key = hashlib.sha256(Path(path).read_bytes()).hexdigest()[:24] + f"_{action}_{VERSION}"
    cpath = cache_dir / f"reocr_{key}.txt" if cache_dir else None
    if cpath and cpath.exists():
        return cpath.read_text(encoding="utf-8"), True
    from PIL import Image
    im = Image.open(path).convert("L")
    im = im.resize((im.width * scale, im.height * scale), Image.LANCZOS)
    if binarise:
        im = im.point(lambda v: 255 if v > 160 else 0)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "img.png"
        im.save(p)
        try:
            text = subprocess.run(["tesseract", str(p), "-", "--psm", str(psm)], capture_output=True, text=True,
                                  timeout=120).stdout
        except (OSError, subprocess.SubprocessError):
            text = ""
    if cpath:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cpath.write_text(text, encoding="utf-8")
    return text, False


def verbatim(hypothesis: str, text: str) -> bool:
    return bool(re.search(rf"(?<![\w.%+\-]){re.escape(hypothesis)}(?![\w\-])", text.lower()))


class FixedLadder:
    name = "fixed_ladder"

    def next_action(self, problem: Problem, tried: list):
        for a in LADDER:
            if a not in tried:
                return a
        return None


class ModelPolicy:
    """Model chooses the next tool. Returns None (stop) on any failure; never sees file bytes."""
    name = "model"

    def __init__(self, max_calls: int = 30):
        self.max_calls = max_calls
        self.calls = 0

    @staticmethod
    def available() -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def next_action(self, problem: Problem, tried: list):
        if not self.available() or self.calls >= self.max_calls:
            return None
        from . import llm
        self.calls += 1
        return llm.choose_investigation_action(
            {"problem_kind": problem.kind, "observed": problem.observed, "hypothesis": problem.hypothesis,
             "ocr_line": problem.context, "already_tried": tried}, [a for a in LADDER if a not in tried])


def policy_from_env():
    choice = os.environ.get("GHOST_AUDIT_INVESTIGATOR", "fixed_ladder")
    if choice == "model" and ModelPolicy.available():
        return ModelPolicy()
    return FixedLadder()


def investigate(problems: list, policy, cache_dir: Path | None = None,
                per_problem: int = MAX_ACTIONS_PER_PROBLEM, per_run: int = MAX_ACTIONS_PER_RUN) -> list:
    spent = 0
    outcomes = []
    for pb in problems:
        oc = Outcome(pb, policy.name)
        tried = []
        while True:
            if len(tried) >= per_problem:
                oc.stop_reason = "per-problem action budget reached"
                break
            if spent >= per_run:
                oc.stop_reason = "per-run action budget reached"
                break
            before = getattr(policy, "calls", 0)
            action = policy.next_action(pb, tried)
            oc.model_calls += getattr(policy, "calls", 0) - before
            if action is None:
                oc.stop_reason = "policy stopped"
                break
            if action not in ACTIONS or action in tried:
                oc.stop_reason = f"policy proposed a disallowed action {action!r}"
                break
            text, cached = _reextract(pb.path, action, cache_dir)
            spent += 0 if cached else 1
            ok, new, why = _accept(pb, text)
            tried.append(action)
            oc.attempts.append({"action": action, "verbatim": ok, "cached": cached, "new_ids": new, "reason": why})
            if ok:
                oc.verified = True
                oc.new_ids = new
                oc.accepted_text = text if pb.kind == "row_gap" else ""
                oc.stop_reason = ("declared record count completed" if pb.kind == "row_gap"
                                  else "hypothesis read verbatim")
                break
        outcomes.append(oc)
    return outcomes


def apply(store, outcomes: list):
    """Record verified reads on the evidence file; raw OCR text is left untouched.

    identifier_misread -> the exact identifier is added to the file's verified identifiers.
    row_gap            -> the accepted re-extraction is parsed by the ordinary document parser and only
                          the recovered rows' observations are added (labelled with the action used)."""
    from .parsers import document_facts
    for oc in outcomes:
        ef = store.files[oc.problem.file_id]
        ef.investigations.append(oc.to_dict())
        if not oc.verified:
            continue
        if oc.problem.kind == "row_gap":
            action = oc.attempts[-1]["action"]
            obs = [o for o in document_facts(oc.accepted_text, oc.problem.file_id, ef.captured_at, "ocr")
                   if o.resource_id in oc.new_ids]
            for o in obs:
                o.location = f"re-extraction {action}: {o.location}"
            store.observations.extend(obs)
            ef.n_observations += len(obs)
        else:
            ef.verified_identifiers.add(oc.problem.hypothesis)


def summary(outcomes: list) -> dict:
    return {"version": VERSION, "problems": len(outcomes), "verified": sum(o.verified for o in outcomes),
            "actions_run": sum(len(o.attempts) for o in outcomes),
            "policy": sorted({o.policy for o in outcomes}) or ["fixed_ladder"],
            "model_calls": sum(o.model_calls for o in outcomes),
            "outcomes": [o.to_dict() for o in outcomes]}


def describe() -> str:
    return json.dumps({"actions": ACTIONS, "ladder": LADDER, "per_problem": MAX_ACTIONS_PER_PROBLEM,
                       "per_run": MAX_ACTIONS_PER_RUN})
