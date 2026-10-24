"""Small shared helpers: time parsing, identifier normalisation, hashing."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Optional

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_REF_RE = re.compile(r"\buser_\d+\b")
HEX64_RE = re.compile(r"\b[0-9a-f]{64}\b")
RESOURCE_RE = re.compile(
    r"\b(account|search|support|analytics|export|backup|data_flow|audit_record|tombstone|"
    r"legal_hold|marketing|cache|email_delivery|object|telemetry)_\d+\b"
)

NULL_TOKENS = {"", "null", "none", "nil", "n/a", "-"}


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO-8601 'Z' timestamps; returns aware UTC datetime or None."""
    if not value:
        return None
    v = value.strip()
    if v.lower() in NULL_TOKENS:
        return None
    try:
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def iso(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def clean(value) -> Optional[str]:
    """Return a stripped string, or None for null-like tokens."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    s = str(value).strip()
    if s.lower() in NULL_TOKENS:
        return None
    return s


def norm_email(value: Optional[str]) -> Optional[str]:
    v = clean(value)
    return v.lower() if v and "@" in v else None


def norm_phone(value: Optional[str]) -> Optional[str]:
    v = clean(value)
    if not v:
        return None
    digits = re.sub(r"\D", "", v)
    return digits if len(digits) >= 7 else None


def email_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def truthy(value) -> Optional[bool]:
    v = clean(value)
    if v is None:
        return None
    lv = v.lower()
    if lv in {"1", "true", "yes", "y", "enabled", "allowed", "active"}:
        return True
    if lv in {"0", "false", "no", "n", "disabled", "denied", "blocked", "stopped"}:
        return False
    return None


def code_fingerprint(code_dir) -> str:
    """sha256 over the predictor's source, prompts and requirements (sorted relative paths + bytes).

    Evaluation reports, caches and run outputs are excluded, so the same value is obtained from
    the git checkout and from an extracted code.zip of the same revision."""
    from pathlib import Path
    code_dir = Path(code_dir)
    h = hashlib.sha256()
    files = sorted(list(code_dir.glob("ghost_audit/*.py")) + list(code_dir.glob("prompts/*"))
                   + [code_dir / "main.py", code_dir / "requirements.txt"])
    for p in files:
        if p.is_file():
            h.update(p.relative_to(code_dir).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def dataset_digest(dataset_dir) -> str:
    """sha256 over every participant file (relative path + bytes), excluding the blank output template."""
    from pathlib import Path
    dataset_dir = Path(dataset_dir)
    h = hashlib.sha256()
    for p in sorted(x for x in dataset_dir.rglob("*") if x.is_file() and x.name != "output.csv"):
        h.update(p.relative_to(dataset_dir).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


CONFIG_VARS = ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "GHOST_AUDIT_MODEL", "GHOST_AUDIT_INVESTIGATOR",
               "GHOST_AUDIT_PRICE_IN", "GHOST_AUDIT_PRICE_OUT")


def config_fingerprint() -> dict:
    """Run-affecting configuration. Secrets and endpoints are recorded only as set/unset."""
    import os
    out = {}
    for k in CONFIG_VARS:
        v = os.environ.get(k)
        out[k] = ("set" if v else "unset") if k in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL") else (v or "default")
    return out
