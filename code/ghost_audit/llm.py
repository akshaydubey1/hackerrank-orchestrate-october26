"""Optional LLM fallback with strict accounting.

The production pipeline is deterministic. A model is consulted only when the rule-based
intent classifier returns UNDECIDED and ANTHROPIC_API_KEY is set. The model sees only the
request text (treated as untrusted data inside a delimited block), must answer with a JSON
object validated against a fixed schema, and is called with a timeout and bounded retries.
Every call is counted in USAGE; nothing is estimated or invented.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "intent_fallback.md"
DEFAULT_MODEL = os.environ.get("GHOST_AUDIT_MODEL", "claude-haiku-5-5")
# USD per million tokens, used only to estimate cost of calls that were actually made.
PRICE_PER_MTOK = {"input": float(os.environ.get("GHOST_AUDIT_PRICE_IN", "1.0")),
                  "output": float(os.environ.get("GHOST_AUDIT_PRICE_OUT", "5.0"))}


@dataclass
class Usage:
    calls: int = 0
    failures: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_hits: int = 0
    by_model: dict = field(default_factory=dict)

    def record(self, model: str, inp: int, out: int):
        self.calls += 1
        self.input_tokens += inp
        self.output_tokens += out
        m = self.by_model.setdefault(model, {"calls": 0, "input_tokens": 0, "output_tokens": 0})
        m["calls"] += 1
        m["input_tokens"] += inp
        m["output_tokens"] += out

    def summary(self) -> dict:
        cost = (self.input_tokens * PRICE_PER_MTOK["input"] + self.output_tokens * PRICE_PER_MTOK["output"]) / 1e6
        return {"provider": "anthropic" if self.calls else "none", "calls": self.calls, "failures": self.failures,
                "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cache_hits": self.cache_hits, "by_model": self.by_model, "estimated_cost_usd": round(cost, 6)}


USAGE = Usage()
_CACHE: dict = {}


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def classify_intent(text: str, *, timeout: float = 20.0, retries: int = 2) -> dict | None:
    """Return {"is_deletion": bool, "label": str} or None on any failure (caller keeps the safe default)."""
    if not available():
        return None
    if text in _CACHE:
        USAGE.cache_hits += 1
        return _CACHE[text]
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    body = {"model": DEFAULT_MODEL, "max_tokens": 64, "temperature": 0,
            "system": prompt,
            "messages": [{"role": "user", "content": f"<request_text>\n{text}\n</request_text>"}]}
    req = urllib.request.Request(
        os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/") + "/v1/messages",
        data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", "anthropic-version": "2023-06-01",
                 "x-api-key": os.environ["ANTHROPIC_API_KEY"]})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read())
            usage = payload.get("usage", {})
            USAGE.record(payload.get("model", DEFAULT_MODEL), int(usage.get("input_tokens", 0)),
                         int(usage.get("output_tokens", 0)))
            out = json.loads("".join(b.get("text", "") for b in payload.get("content", [])))
            if not isinstance(out, dict) or not isinstance(out.get("is_deletion"), bool) \
                    or out.get("label") not in {"DELETION", "ACCESS_OR_EXPORT", "CORRECTION",
                                                "MARKETING_OPT_OUT", "OTHER"}:
                raise ValueError("schema violation")
            _CACHE[text] = out
            return out
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, KeyError):
            USAGE.failures += 1
            time.sleep(min(2 ** attempt, 4))
    return None
