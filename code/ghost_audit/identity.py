"""Identity reconstruction: current snapshot + dated audit history -> identifier sets."""
from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .util import USER_REF_RE, clean, email_hash, norm_email, norm_phone, parse_ts


@dataclass
class Person:
    user_id: str
    name: str = ""
    emails: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    email_history: list = field(default_factory=list)  # (email, valid_from, valid_to)

    def identifier_keys(self) -> set:
        keys = {("user", self.user_id)}
        keys |= {("email", e) for e in self.emails}
        keys |= {("phone", p) for p in self.phones}
        keys |= {("hash", h) for h in self.hashes}
        return keys


def identifier_key(value: str) -> Optional[tuple]:
    """Normalise a raw identifier value to an (kind, value) join key."""
    v = clean(value)
    if not v:
        return None
    if USER_REF_RE.fullmatch(v):
        return ("user", v)
    if "@" in v:
        return ("email", norm_email(v))
    lv = v.lower()
    if len(lv) == 64 and all(c in "0123456789abcdef" for c in lv):
        return ("hash", lv)
    if v.startswith("sha256:"):
        return None
    p = norm_phone(v)
    if p and sum(c.isdigit() for c in v) >= 7 and not any(c.isalpha() for c in v):
        return ("phone", p)
    return None


class IdentityIndex:
    def __init__(self, dataset_dir: Path):
        self.people: dict = {}
        self.index: dict = defaultdict(set)  # (kind,value) -> {user_id}
        with open(dataset_dir / "user_identities.csv", newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                p = Person(r["user_id"], r["name"])
                e = norm_email(r["email"])
                if e:
                    p.emails.add(e)
                    p.hashes.add(email_hash(e))
                    p.email_history.append((e, None, None))
                ph = norm_phone(r["phone"])
                if ph:
                    p.phones.add(ph)
                if clean(r.get("email_hash")):
                    p.hashes.add(r["email_hash"].lower())
                self.people[p.user_id] = p
        audit_path = dataset_dir / "user_audit_log.csv"
        if audit_path.exists():
            with open(audit_path, newline="", encoding="utf-8") as fh:
                for r in csv.DictReader(fh):
                    p = self.people.setdefault(r["user_id"], Person(r["user_id"]))
                    f = r["field_name"]
                    for val in (r["old_value"], r["new_value"]):
                        if f == "email":
                            e = norm_email(val)
                            if e:
                                p.emails.add(e)
                                p.hashes.add(email_hash(e))
                        elif f == "phone":
                            ph = norm_phone(val)
                            if ph:
                                p.phones.add(ph)
                        elif f == "email_hash" and clean(val):
                            p.hashes.add(val.lower())
                        elif f in ("name", "full_name") and clean(val):
                            pass  # names are never used as a sole join key
                    if f == "email":
                        t = parse_ts(r["event_time"])
                        p.email_history.append((norm_email(r["old_value"]), None, t))
        for p in self.people.values():
            for k in p.identifier_keys():
                self.index[k].add(p.user_id)

    def owners_of(self, raw_values) -> set:
        owners = set()
        for v in raw_values:
            k = identifier_key(v)
            if k:
                owners |= self.index.get(k, set())
        return owners

    def resolve_email(self, email: str) -> list:
        e = norm_email(email)
        return sorted(self.index.get(("email", e), set()))
