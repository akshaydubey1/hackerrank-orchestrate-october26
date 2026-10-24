"""Request-intent classification: does the text authorise deleting the account / personal data?

Target-aware rules: a deletion verb only authorises deletion when the thing it targets is the
account, the profile, or the person's data as a whole. Removing a newsletter subscription, an old
phone number or a shipping address is a narrower action (opt-out / correction), not erasure.

Order of decisions
  1. explicit negation ("do not delete", "not a request to erase", ...)       -> not deletion
  2. a full-scope deletion statement anywhere in the text                      -> DELETION
  3. deletion verbs that only target a limited item, or marketing-only wording -> not deletion
  4. other recognised non-deletion actions (access, export, correction, ...)   -> not deletion
  5. anything else                                                              -> UNDECIDED
UNDECIDED is never silently equated with NOT_APPLICABLE: the caller records it as an unresolved
item. If ANTHROPIC_API_KEY is set, the optional model fallback (llm.py) is consulted first.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

DELETION_VERBS = [
    r"\bdelet(e|ed|es|ing|ion)\b", r"\berase(d|s)?\b", r"\berasure\b", r"\berasing\b", r"\bremov(e|ed|es|al|ing)\b",
    r"\bwipe(d)?\b", r"\bpurge(d)?\b", r"\bforget\b", r"\bclose(d)?\b", r"\bclosure\b",
    r"\belimin(ar|en|e|a|ad|ación|acion|ação|acao|ate|are|ato|azione)\w*", r"\bborr(ar|en|e|ad|ado)\w*",
    r"\bexclu(ir|am|a|são|sao)\b", r"exclusão", r"\bapag(ar|uem|ue|ado)\b",
    r"\bsuppr(ession|imer|imez|ime|imé)\w*", r"\beffac(er|ez|é)\w*", r"\bl[öo]sch(en|ung|e|t)\w*",
    r"\bcancell(are|azione|ate)\b", r"\bverwijder\w*", r"\bfermer\b", r"\bcerrar\b", r"\bencerrar\b",
    "削除", "삭제", "删除", "注销", "退会",
]
FULL_TARGETS = [
    r"\baccounts?\b", r"\bprofiles?\b", r"\bpersonal (data|information|details|info)\b", r"\bmy data\b",
    r"\b(all|any|every) (of )?(my )?(data|information|records|copies|copy|traces)\b", r"\beverything\b",
    r"\brecords?\b", r"\bcop(y|ies)\b", r"\btraces\b", r"\bcontact details\b", r"\bmy name\b", r"\bidentifiable\b",
    r"\bconta\b", r"\bcuenta\b", r"\bcompte\b", r"\bkonto\b", r"\bconto\b", r"\baccount-deletion\b",
    r"\bdatos( personales)?\b", r"\bdonn[ée]es\b", r"\bdaten\b", r"\bdados\b",
    "アカウント", "계정", "账户", "账号", "個人データ", "개인 정보", "개인정보",
]
LIMITED_TARGETS = [
    r"\bnewsletters?\b", r"\bmarketing\b", r"\bpromotion(al|s)?\b", r"\bmailing( list)?s?\b", r"\b(email|sms) list\b",
    r"\b(shipping|delivery|billing|home|old|previous|second) address(es)?\b",
    r"\b(old|previous|outdated|second|work) (phone|mobile|number|e-?mail)\b", r"\bpayment (method|card)\b",
    r"\b(saved )?cards?\b", r"\bphotos?\b", r"\b(my|product) reviews?\b", r"\bwish ?list\b", r"\bcart\b",
    r"\bsearch history\b", r"\bcookies?\b",
]
FULL_PHRASES = [
    r"\bclose (my|this|the) account\b", r"\bclosed (my|this|the) account\b", r"\b(account|profile)( page)? (is|was) gone\b",
    r"\bforget me\b", r"\b(erase|delete|remove) me\b(?! from)", r"\b(profile|account) (was|is|has been) (fully )?(deleted|removed|erased)\b",
    r"\bcannot identify me\b", r"\bpermanent account[- ]deletion\b",
]
NEGATION_PATTERNS = [
    r"not a request to (erase|delete|remove)", r"(don'?t|do not|please don't|never) (delete|erase|remove|close)",
    r"\bwithout (deleting|removing|erasing|closing)\b", r"\bkeep (my|the|this) account\b",
    r"\bnot asking (you )?for (a |any )?(deletion|erasure|removal)\b", r"\bleave (my|the|this) (account|profile)\b",
    r"\bi still (need|use|want) (it|the account|my account|this account)\b", r"\bcontinue using\b", r"no (borrar|eliminar)", r"ne (pas )?supprimer",
    r"nicht l[öo]schen", r"not (a|an) (deletion|erasure|removal)( request)?",
    r"not (asking|requesting) (you )?to (delete|erase|remove)",
    r"\bno (de |una |es una )?(eliminaci[oó]n|borrado)", r"pas (une|de) (demande de )?suppression",
    r"keine l[öo]schung", r"n[ãa]o (é )?(um pedido de )?(exclus[ãa]o|apagar)", "削除しないで", "삭제하지 마",
]
MARKETING_ONLY = [
    r"marketing (lists?|emails?|messages?) only", r"(from|off) marketing( lists?)? only", r"\bonly\b.*\bmarketing\b",
    r"stop (the )?(promotional|marketing) (emails|messages)", r"\bunsubscribe\b", r"\bopt[- ]?out\b",
]
NON_DELETION_HINTS = [
    (r"\bcopy of\b|\bdownload\b|\bportable format\b|\bexport (my|the)\b|what (personal )?(information|data)|\binvoices?\b",
     "ACCESS_OR_EXPORT"),
    (r"\bmisspelled\b|\bcorrect(ion)?\b|\bupdate\b|\bout of date\b|\bchange (my|the)\b", "CORRECTION"),
    (r"\breset\b|\bcan'?t access\b|\blog ?in\b", "OTHER"),
    (r"\bdeactivat\w*|\bpause\b|\bsuspend\b", "OTHER"),
]


@dataclass
class IntentResult:
    is_deletion: bool
    label: str      # DELETION | ACCESS_OR_EXPORT | CORRECTION | MARKETING_OPT_OUT | OTHER | UNDECIDED
    reason: str
    source: str = "rules"


def _first(patterns, text):
    for p in patterns:
        m = re.search(p, text)
        if m:
            return p, m
    return None, None


def _nearest_target(text: str, start: int, end: int):
    """Nearest scope noun to a deletion verb: forward within 70 chars (same sentence), else backward within 60."""
    # stay inside the verb's own sentence: a scope noun in the next sentence is not its object
    fwd = re.split(r"[.!?。！？]", text[end:end + 70], maxsplit=1)[0]
    back = re.split(r"[.!?。！？]", text[max(0, start - 60):start])[-1]
    best = None
    for kind, pats in (("full", FULL_TARGETS), ("limited", LIMITED_TARGETS)):
        for p in pats:
            for m in re.finditer(p, fwd):
                d = m.start()
                if best is None or d < best[0]:
                    best = (d, kind, m.group(0))
    if best:
        return best[1], best[2]
    for kind, pats in (("full", FULL_TARGETS), ("limited", LIMITED_TARGETS)):
        for p in pats:
            for m in re.finditer(p, back):
                d = len(back) - m.end()
                if best is None or d < best[0]:
                    best = (d, kind, m.group(0))
    return (best[1], best[2]) if best else (None, None)


def classify_rules(text: str) -> IntentResult:
    # whitespace and line breaks carry no meaning: collapse them so "do  not\n close" is "do not close"
    low = re.sub(r"\s+", " ", (text or "")).strip().lower()
    p, _ = _first(NEGATION_PATTERNS, low)
    if p:
        label = next((lab for pat, lab in NON_DELETION_HINTS if re.search(pat, low)), "OTHER")
        return IntentResult(False, label, f"explicit negation: /{p}/")
    p, _ = _first(FULL_PHRASES, low)
    if p:
        return IntentResult(True, "DELETION", f"full-scope deletion phrase: /{p}/")
    limited = []
    for vp in DELETION_VERBS:
        for m in re.finditer(vp, low):
            kind, tgt = _nearest_target(low, m.start(), m.end())
            if kind == "full":
                return IntentResult(True, "DELETION", f"'{m.group(0)}' targets '{tgt}'")
            if kind == "limited":
                limited.append(f"'{m.group(0)}' targets '{tgt}'")
    p, _ = _first(MARKETING_ONLY, low)
    if p or limited:
        mk = p or any(re.search(r"newsletter|marketing|promotion|mailing|list", x) for x in limited)
        return IntentResult(False, "MARKETING_OPT_OUT" if mk else "CORRECTION",
                            "limited-scope request: " + (f"/{p}/" if p else "; ".join(limited)))
    for pat, label in NON_DELETION_HINTS:
        if re.search(pat, low):
            return IntentResult(False, label, f"non-deletion action: /{pat}/")
    return IntentResult(False, "UNDECIDED", "no deletion authorisation found")


def classify(text: str) -> IntentResult:
    r = classify_rules(text)
    if r.label != "UNDECIDED":
        return r
    from . import llm  # optional model fallback, only for requests the rules cannot decide
    out = llm.classify_intent((text or "").strip())
    if out is not None:
        return IntentResult(out["is_deletion"], out["label"], "model fallback", source="llm")
    return r
