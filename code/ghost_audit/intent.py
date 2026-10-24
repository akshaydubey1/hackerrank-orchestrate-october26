"""Request-intent classification (deletion vs. non-deletion), multilingual, negation-aware.

Deterministic lexicon rules run first. If they cannot decide (no deletion term and no
non-deletion term) and an LLM client is configured, the optional model fallback in
llm.py is consulted; otherwise the request is treated as NOT authorising deletion
(the safe default: never destroy data without an explicit request).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

DELETION_TERMS = [
    r"\bdelet(e|ed|ing|ion)\b", r"\berase(d)?\b", r"\berasure\b", r"\bremov(e|ed|al)\b",
    r"\bclose (my|this|the) account\b", r"\bclosed my account\b", r"\bclose (it|the account) completely\b",
    r"\bwould like it closed\b", r"\bclose this account\b", r"\bwant to close\b", r"\bpermanently\b",
    r"\bforget me\b", r"\b(profile|account) (is|was) gone\b", r"\bcannot identify me\b",
    r"\bfully removed\b", r"\bno longer (exists?|be linked)\b",
    r"\bwipe (out )?(my|this|the)\b", r"\bpurge\b", r"\bget rid of (my|this) (account|data)\b",
    # es / pt / fr / de / it / nl (stems cover conjugations: eliminen, borre, supprimez, löschen ...)
    r"\belimin(ar|en|e|a|ad|ación|acion|ação|acao|ate|are)\w*", r"\bborr(ar|en|e|ad)\w*",
    r"\bexclu(ir|am|a|são|sao)\b", r"exclusão", r"\bapag(ar|uem|ue)\b",
    r"\bsuppr(ession|imer|imez|ime|imé)\w*", r"\beffac(er|ez|é)\w*", r"\bl[öo]sch(en|ung|e|t)\w*",
    r"\bcancell(are|azione|ate)\b", r"\bverwijder\w*",
    # ja / ko / zh
    "削除", "삭제", "删除", "注销",
]
NEGATION_PATTERNS = [
    r"not a request to (erase|delete|remove)", r"(don'?t|do not|please don't|never) (delete|erase|remove|close)",
    r"without deleting", r"no (borrar|eliminar)", r"ne (pas )?supprimer", r"nicht l[öo]schen",
    r"not (a|an) (deletion|erasure|removal)( request)?", r"not (asking|requesting) (you )?to (delete|erase|remove)",
    r"\bno (de |una |es una )?(eliminaci[oó]n|borrado)", r"pas (une|de) (demande de )?suppression",
    r"keine l[öo]schung", r"n[ãa]o (é )?(um pedido de )?(exclus[ãa]o|apagar)",
    "削除しないで", "삭제하지 마",
]
NON_DELETION_ONLY = [
    r"marketing (lists?|emails?) only", r"(from|off) marketing( lists?)? only", r"only .*marketing",
    r"stop (the )?(promotional|marketing) (emails|messages)", r"unsubscribe",
]
NON_DELETION_HINTS = [
    r"\bcopy of\b", r"\bdownload\b", r"\bportable format\b", r"\bexport\b", r"what personal information",
    r"\bmisspelled\b", r"\bcorrect(ion)?\b", r"\bupdate\b", r"\bout of date\b", r"\bchange the email\b",
    r"\breset", r"\binvoices?\b", r"\baccess my\b", r"information request",
]


@dataclass
class IntentResult:
    is_deletion: bool
    label: str      # DELETION | ACCESS_OR_EXPORT | CORRECTION | MARKETING_OPT_OUT | OTHER | UNDECIDED
    reason: str
    source: str = "rules"


def classify(text: str) -> IntentResult:
    t = (text or "").strip()
    low = t.lower()
    for p in NEGATION_PATTERNS:
        if re.search(p, low):
            return IntentResult(False, "ACCESS_OR_EXPORT", f"explicit negation: /{p}/")
    for p in NON_DELETION_ONLY:
        if re.search(p, low):
            return IntentResult(False, "MARKETING_OPT_OUT", f"marketing-only request: /{p}/")
    deletion_hits = [p for p in DELETION_TERMS if re.search(p, low)]
    # "download your data link still works ... delete that export" is still deletion, so hints
    # only win when no deletion term is present.
    if deletion_hits:
        return IntentResult(True, "DELETION", f"deletion term: /{deletion_hits[0]}/")
    for p in NON_DELETION_HINTS:
        if re.search(p, low):
            label = "ACCESS_OR_EXPORT" if re.search(r"copy|download|export|information|invoice", p) else "CORRECTION"
            return IntentResult(False, label, f"non-deletion action: /{p}/")
    from . import llm  # optional model fallback, only for requests the rules cannot decide
    out = llm.classify_intent(t)
    if out is not None:
        return IntentResult(out["is_deletion"], out["label"], "model fallback", source="llm")
    return IntentResult(False, "UNDECIDED", "no deletion authorisation found (safe default: no deletion)")
