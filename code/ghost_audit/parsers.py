"""Format-specific evidence parsers producing normalised Observations.

Every parser treats file contents strictly as data. Nothing read from evidence is
ever executed or interpreted as an instruction; free text is only scanned for
identifiers with regular expressions.
"""
from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from .models import Observation
from .util import (EMAIL_RE, HEX64_RE, RESOURCE_RE, USER_REF_RE, clean,
                   truthy)

PARSER_VERSION = "parsers-v10"

# ---------------------------------------------------------------------------
# Resource-id helpers
# ---------------------------------------------------------------------------
PREFIX_SYSTEM = OrderedDict([
    ("audit_record_", "security_service"),
    ("data_flow_", "integration_service"),
    ("legal_hold_", "legal_service"),
    ("email_delivery_", "email_delivery_service"),
    ("account_", "account_service"),
    ("search_", "search_service"),
    ("support_", "support_platform"),
    ("analytics_", "analytics_platform"),
    ("export_", "export_service"),
    ("backup_", "backup_service"),
    ("tombstone_", "identity_service"),
    ("marketing_", "marketing_platform"),
    ("cache_", "cache_service"),
    ("object_", "object_storage"),
    ("telemetry_", "telemetry_service"),
])


def system_for(resource_id: str, fallback: Optional[str] = None) -> Optional[str]:
    for prefix, system in PREFIX_SYSTEM.items():
        if resource_id.startswith(prefix):
            return system
    return fallback


ID_FIELDS_EMAIL = ("email", "owner_email", "customer_email", "requester_email", "uploaded_by",
                   "subject_selector", "lookup_value", "lookup_key", "match_key", "subject_key",
                   "scan_key", "owner_key", "matched_value", "correlation_key", "query",
                   "subject_reference", "customer_reference", "subject_ref", "user_id")
NAME_FIELDS = ("full_name", "name", "display_name", "requester_name")
PHONE_FIELDS = ("phone", "owner_phone", "requester_phone")
HASH_FIELDS = ("email_hash",)
# Fields whose presence (non-null) means a direct identifier is still exposed.
DIRECT_FIELDS = ("email", "owner_email", "customer_email", "requester_email", "uploaded_by",
                 "full_name", "name", "display_name", "requester_name", "phone", "owner_phone",
                 "requester_phone", "email_hash")


def _ids_from_text(text: str) -> list:
    out = []
    out += EMAIL_RE.findall(text)
    out += USER_REF_RE.findall(text)
    out += HEX64_RE.findall(text)
    for m in re.findall(r"\+\d[\d ()\-]{6,}\d", text):
        out.append(m)
    return out


def interpret_record(rec: dict, *, system: str, evidence_id: str, captured_at: str,
                     observed_at: str, location: str, replica: str = "primary",
                     collection: str = "") -> Optional[Observation]:
    """Turn a structured record (JSON or SQL row) into an Observation."""
    rec = dict(rec)
    doc = rec.pop("document", None)
    if isinstance(doc, dict):
        for k, v in doc.items():
            rec.setdefault(k, v)
    rid = clean(rec.get("resource_id"))
    if not rid:
        return None
    system = system_for(rid, system) if system in (None, "", "unknown") else system
    obs = Observation(evidence_id=evidence_id, location=location, captured_at=captured_at,
                      observed_at=observed_at or captured_at, system=system, resource_id=rid,
                      replica=replica, exists=True)
    idents, exposed = [], []
    for f in ID_FIELDS_EMAIL + NAME_FIELDS + PHONE_FIELDS + HASH_FIELDS:
        v = clean(rec.get(f))
        if v is None or isinstance(rec.get(f), (dict, list)):
            continue
        idents.append(v)
    for f in DIRECT_FIELDS:
        v = clean(rec.get(f))
        if v is not None and not isinstance(rec.get(f), (dict, list)):
            exposed.append(v)
    text = clean(rec.get("message_text")) or clean(rec.get("message_excerpt")) or ""
    if text and text.upper() != "[REDACTED]":
        found = _ids_from_text(text)
        idents += found
        exposed += [x for x in found if not USER_REF_RE.fullmatch(x)]
    obs.identifiers = idents
    obs.exposed = exposed

    coll = collection.lower()
    if system == "analytics_platform":
        attributable = exposed or clean(rec.get("user_id")) or clean(rec.get("customer_reference"))
        obs.pii = bool(attributable)
    elif system == "identity_service":
        obs.kind = "tombstone"
        obs.pii = bool(exposed)
    else:
        obs.pii = bool(exposed)

    if system == "support_platform":
        if "attachment" in coll or rec.get("file_name") or rec.get("storage_class") == "ticket_attachment":
            obs.kind = "attachment"
        else:
            obs.kind = "message"
            # order / ticket context marks a shared conversation that must be retained (rule_05)
            obs.shared_context = bool(re.search(r"order|delivery|ticket|agent", text, re.I)) or bool(rec.get("ticket_id"))
    if system == "integration_service":
        obs.flow_enabled = truthy(rec.get("enabled"))
    if system == "backup_service":
        obs.restore_allowed = truthy(rec.get("restore_allowed"))
    if system == "security_service":
        obs.retention_until = clean(rec.get("retention_until"))
    if system == "legal_service":
        obs.retention_until = clean(rec.get("retained_until")) or clean(rec.get("retention_until"))
        obs.kind = "legal_hold"
    if system == "account_service":
        status = (clean(rec.get("account_status")) or "").upper()
        if status in {"DELETED", "PURGED"}:
            obs.exists = False
        obs.note = status
    if system == "export_service" and rec.get("download_available") is not None:
        obs.note = "download_available=%s" % rec.get("download_available")
    return obs


# ---------------------------------------------------------------------------
# Explicit "record_lookup" style lines (handover text, manifests, diagnostics)
# ---------------------------------------------------------------------------
RESULT_MAP = {
    "FOUND": dict(exists=True),
    "NOT_FOUND": dict(exists=False),
    "IDENTIFIABLE": dict(exists=True, pii=True),
    "ANONYMIZED": dict(exists=True, pii=False),
    "REDACTED": dict(exists=True, pii=False),
    "ACTIVE": dict(exists=True),
    "DISABLED": dict(exists=True),
    "BLOCKED": dict(exists=True),
}


def lookup_observation(*, system, resource_id, record_type, result, subject, evidence_id,
                       captured_at, observed_at, location) -> Observation:
    rt = (record_type or "").upper()
    res = (result or "").upper()
    obs = Observation(evidence_id=evidence_id, location=location, captured_at=captured_at,
                      observed_at=observed_at or captured_at,
                      system=system or system_for(resource_id, "unknown"),
                      resource_id=resource_id, record_type=rt or None)
    for k, v in RESULT_MAP.get(res, {}).items():
        setattr(obs, k, v)
    subj = clean(subject)
    if subj and subj.lower() not in {"no direct identifier"}:
        obs.identifiers = [subj]
        if res == "IDENTIFIABLE" or (rt in {"USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT",
                                            "SUPPORT_ATTACHMENT", "MARKETING_PROFILE"} and res == "FOUND"):
            if not USER_REF_RE.fullmatch(subj):
                obs.exposed = [subj]
    if rt == "DATA_FLOW":
        obs.flow_enabled = res == "ACTIVE"
    if rt == "BACKUP_ARCHIVE":
        obs.restore_allowed = res == "ACTIVE"
    if rt == "SUPPORT_ATTACHMENT":
        obs.kind = "attachment"
    if rt == "SUPPORT_MESSAGE":
        obs.kind = "message"
        obs.shared_context = True
    if rt == "ACCOUNT_TOMBSTONE":
        obs.kind = "tombstone"
    if rt == "LEGAL_HOLD_RECORD":
        obs.kind = "legal_hold"
    if res == "IDENTIFIABLE":
        obs.pii = True
    return obs


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def parse_json(path: Path, evidence_id: str, captured_at: str) -> list:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list = []
    if "service_exports" in data:
        for system, groups in data["service_exports"].items():
            for group, records in groups.items():
                for i, r in enumerate(records):
                    loc = f"service_exports.{system}.{group}[{i}]"
                    obs_at = clean(r.get("observed_at")) or captured_at
                    if system == "account_service" and "status_code" in r:
                        prof = r.get("profile") or {}
                        if r.get("status_code") == 404 or not prof:
                            out.append(Observation(evidence_id, loc, captured_at, obs_at, system,
                                                   r["resource_id"], exists=False))
                            continue
                        rec = dict(prof, resource_id=r["resource_id"])
                    elif system == "search_service" and "hits" in r:
                        docs = (r.get("hits") or {}).get("documents") or []
                        if not docs:
                            # a zero-hit query is not proof the resource is gone
                            continue
                        for d in docs:
                            o = interpret_record(dict(d), system=system, evidence_id=evidence_id,
                                                 captured_at=captured_at, observed_at=obs_at,
                                                 location=loc)
                            if o:
                                q = clean(r.get("query"))
                                if q:
                                    o.identifiers.append(q)
                                out.append(o)
                        continue
                    else:
                        rec = r
                    o = interpret_record(rec, system=system, evidence_id=evidence_id,
                                         captured_at=captured_at, observed_at=obs_at, location=loc)
                    if o:
                        out.append(o)
        return out
    if "snapshots" in data:
        for si, snap in enumerate(data["snapshots"]):
            store = snap.get("data_store")
            coll = snap.get("collection", "")
            snap_at = clean(snap.get("captured_at")) or captured_at
            for i, r in enumerate(snap.get("records") or []):
                loc = f"snapshots[{si}].{store}.{coll}[{i}]"
                if "record_type" in r and "result" in r:
                    out.append(lookup_observation(system=r.get("system"), resource_id=r["resource_id"],
                                                  record_type=r.get("record_type"), result=r.get("result"),
                                                  subject=r.get("lookup_value") or r.get("subject_reference"),
                                                  evidence_id=evidence_id, captured_at=captured_at,
                                                  observed_at=clean(r.get("recorded_at")) or snap_at,
                                                  location=loc))
                    continue
                o = interpret_record(r, system=store, evidence_id=evidence_id, captured_at=captured_at,
                                     observed_at=snap_at, location=loc, collection=coll)
                if o:
                    out.append(o)
            # complete-collection marker so absence can be reasoned about per data store
            out.append(Observation(evidence_id, f"snapshots[{si}].{store}.{coll}", captured_at, snap_at,
                                   store, "__collection__:" + coll, note="snapshot_scope"))
        return out
    if "records" in data:
        coll = data.get("collection", "")
        src_at = clean(data.get("captured_at")) or captured_at
        system_hint = {"customer_export_jobs": "export_service",
                       "customer_analytics_reports": "analytics_platform"}.get(coll)
        for i, r in enumerate(data["records"]):
            loc = f"records[{i}]"
            if "record_type" in r and "result" in r:
                out.append(lookup_observation(system=r.get("system"), resource_id=r["resource_id"],
                                              record_type=r.get("record_type"), result=r.get("result"),
                                              subject=r.get("subject_reference") or r.get("lookup_value"),
                                              evidence_id=evidence_id, captured_at=captured_at,
                                              observed_at=clean(r.get("recorded_at")) or src_at,
                                              location=loc))
                continue
            o = interpret_record(r, system=system_hint or system_for(r.get("resource_id", ""), "unknown"),
                                 evidence_id=evidence_id, captured_at=captured_at, observed_at=src_at,
                                 location=loc, collection=coll)
            if o:
                out.append(o)
        return out
    return out


# ---------------------------------------------------------------------------
# SQL snapshots -> isolated in-memory SQLite
# ---------------------------------------------------------------------------
def parse_sql(path: Path, evidence_id: str, captured_at: str) -> list:
    sql = path.read_text(encoding="utf-8")
    m = re.search(r"Captured at:\s*(\S+)", sql) or re.search(r"snapshot_completed_at=(\S+)", sql)
    snap_at = m.group(1) if m else captured_at
    con = sqlite3.connect(":memory:")  # isolated; never touches disk or other snapshots
    con.row_factory = sqlite3.Row
    try:
        con.executescript(sql)
    except sqlite3.Error:
        # retry statement by statement so one malformed row does not lose the file
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        for stmt in sql.split(";\n"):
            try:
                con.execute(stmt)
            except sqlite3.Error:
                pass
    out: list = []
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        scope = {r[0]: r[1] for r in con.execute("SELECT origin_system, captured_at FROM snapshot_scope")}
    table_system = {
        "customer_profiles": "account_service", "customer_search_documents": "search_service",
        "customer_analytics_profiles": "analytics_platform", "support_records": "support_platform",
        "customer_exports": "export_service", "connector_subscriptions": "integration_service",
        "backup_restore_entries": "backup_service", "security_audit_records": "security_service",
        "search_documents_primary": "search_service",
    }
    for t in tables:
        if t == "snapshot_scope":
            continue
        replica = "primary"
        if t.startswith("customer_data_") or t.startswith("customer_profiles_"):
            replica = t.split("customer_data_")[-1] if t.startswith("customer_data_") else t.split("customer_profiles_")[-1]
        for i, row in enumerate(con.execute(f'SELECT * FROM "{t}"')):
            d = dict(row)
            loc = f"{t}:{d.get('resource_id')}"
            if "record_json" in d:
                rec = json.loads(d["record_json"])
                system = d.get("origin_system")
                o = interpret_record(rec, system=system, evidence_id=evidence_id, captured_at=captured_at,
                                     observed_at=snap_at, location=loc, replica=replica,
                                     collection=d.get("collection_name", ""))
            else:
                system = table_system.get(t) or system_for(d.get("resource_id", ""), "unknown")
                rec = dict(d)
                if "user_id" in rec and system == "account_service":
                    rec["customer_reference"] = rec.pop("user_id")
                if "source_resource_id" in rec:
                    rec["linked_resource"] = rec.pop("source_resource_id")
                o = interpret_record(rec, system=system, evidence_id=evidence_id, captured_at=captured_at,
                                     observed_at=clean(d.get("updated_at")) or snap_at, location=loc,
                                     replica=replica, collection=t)
                if o and rec.get("linked_resource"):
                    o.note = "source=" + rec["linked_resource"]
            if o:
                out.append(o)
        # complete-scope marker for each table (absence reasoning)
        sys_for_table = table_system.get(t)
        if t.startswith("customer_profiles_"):
            sys_for_table = "account_service"
        full_table = "Database topology" in sql and not scope
        if sys_for_table and (not scope or sys_for_table in scope):
            out.append(Observation(evidence_id, t, captured_at, scope.get(sys_for_table, snap_at),
                                   sys_for_table, "__collection__:" + t, replica=replica,
                                   note="full_table" if full_table else "snapshot_scope"))
        elif t.startswith("customer_data_"):
            out.append(Observation(evidence_id, t, captured_at, snap_at, "*", "__collection__:" + t,
                                   replica=replica, note="replica_dump"))
    con.close()
    return out


# ---------------------------------------------------------------------------
# Logs: six dialects -> key/value events, grouped by trace
# ---------------------------------------------------------------------------
KV_RE = re.compile(r'([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\S+)')
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(.*)$")


def _kv(text: str) -> dict:
    d = {}
    for k, v in KV_RE.findall(text):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"')
        d[k] = v
    return d


def parse_log_line(line: str) -> Optional[dict]:
    m = TS_RE.match(line.strip())
    if not m:
        return None
    ts, rest = m.groups()
    ev: dict = {"ts": ts}
    if rest.startswith("{"):
        try:
            ev.update(json.loads(rest))
        except json.JSONDecodeError:
            return None
        ev.setdefault("service", ev.get("logger"))
        return ev
    if rest.startswith("["):  # [LEVEL] [service] [trace] event: k="v"
        mm = re.match(r"\[(\w+)\]\s+\[([\w-]+)\]\s+\[([\w-]+)\]\s+([\w]+):\s*(.*)$", rest)
        if mm:
            ev.update(level=mm.group(1), service=mm.group(2), trace_id=mm.group(3), event=mm.group(4))
            ev.update(_kv(mm.group(5)))
            return ev
    if " | " in rest:  # LEVEL | service | trace | event | kv
        parts = [p.strip() for p in rest.split(" | ")]
        if len(parts) >= 5:
            ev.update(level=parts[0], service=parts[1], trace_id=parts[2], event=parts[3])
            ev.update(_kv(" | ".join(parts[4:])))
            return ev
    if rest.startswith("<"):  # syslog: <pri>1 host service trace - - kv
        mm = re.match(r"<\d+>\d+\s+\S+\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)$", rest)
        if mm:
            ev.update(service=mm.group(1), trace_id=mm.group(2))
            ev.update(_kv(mm.group(3)))
            return ev
    kv = _kv(rest)
    if "message" in kv and "function" in kv:  # cloud runtime: nested escaped message
        inner = _kv(kv.pop("message"))
        ev.update(kv)
        ev.update(inner)
        ev["service"] = kv.get("function")
        ev["trace_id"] = kv.get("requestId")
        return ev
    ev.update(kv)
    if "requestId" in ev:
        ev["trace_id"] = ev["requestId"]
    return ev


LOOKUP_KEYS = ("lookup_key", "match_key", "subject_key", "scan_key", "owner_key", "subject_ref",
               "correlation_key", "matched_value", "subject_reference", "customer_reference",
               "customer_email", "requester_email", "email", "query")


def _event_to_obs(ev: dict, keys: list, evidence_id: str, captured_at: str, loc: str) -> Optional[Observation]:
    rid = clean(ev.get("resource_id"))
    if not rid:
        return None
    event = ev.get("event", "")
    service = ev.get("service") or ""
    if event == "record_lookup":
        return lookup_observation(system=ev.get("system"), resource_id=rid, record_type=ev.get("record_type"),
                                  result=ev.get("result"), subject=ev.get("subject_reference"),
                                  evidence_id=evidence_id, captured_at=captured_at, observed_at=ev["ts"],
                                  location=loc)
    system = system_for(rid, service)
    if service in {"profile_service"}:
        system = "profile_service"  # a different system than account_service; kept separate
    obs = Observation(evidence_id=evidence_id, location=loc, captured_at=captured_at, observed_at=ev["ts"],
                      system=system, resource_id=rid, identifiers=list(keys))
    exposed = []
    for f in DIRECT_FIELDS:
        v = clean(ev.get(f))
        if v:
            exposed.append(v)
    rows = clean(ev.get("rows"))
    status = clean(ev.get("http_status"))
    if event == "profile_lookup_completed":
        obs.exists = not (rows == "0" or status == "404")
        obs.pii = bool(exposed) if obs.exists else None
    elif event == "index_query_completed":
        res = (clean(ev.get("result")) or "").lower()
        if res == "hit":
            obs.exists = True
            obs.pii = True
        elif res == "miss":
            return None  # a miss is not proof of absence
    elif event in {"audit_record_read_completed"}:
        obs.exists = rows != "0"
        obs.retention_until = clean(ev.get("retention_until"))
    elif event == "connector_config_read_completed":
        obs.exists = True
        obs.flow_enabled = truthy(ev.get("enabled"))
    elif event == "restore_policy_read_completed":
        obs.exists = truthy(ev.get("archive_present")) is not False
        obs.restore_allowed = truthy(ev.get("restore_allowed"))
    elif event == "restore_candidate_evaluated":
        obs.exists = True
        elig = truthy(ev.get("eligible"))
        block = truthy(ev.get("deletion_block"))
        obs.restore_allowed = bool(elig) and not bool(block)
    elif event == "restore_authorization_completed":
        obs.exists = True
        obs.restore_allowed = (clean(ev.get("decision")) or "").lower() == "allow"
    elif event == "support_ticket_read_completed":
        obs.exists = True
        obs.kind = "message"
        obs.shared_context = True
        obs.pii = bool(exposed)
    elif event in {"message_pii_scan"}:
        obs.exists, obs.kind, obs.pii, obs.shared_context = True, "message", True, True
        exposed.append(clean(ev.get("matched_value")) or "")
    elif event == "message_read":
        obs.exists, obs.kind, obs.shared_context = True, "message", True
        obs.pii = (clean(ev.get("message_text")) or "").upper() != "[REDACTED]"
    elif event == "attachment_pii_scan":
        obs.exists, obs.kind, obs.pii = True, "attachment", True
        exposed.append(clean(ev.get("matched_value")) or "")
    elif event in {"analytics_profile_read_completed", "analytics_profile_read"}:
        obs.exists = True
        di = clean(ev.get("direct_identifiers"))
        ref = clean(ev.get("customer_reference"))
        obs.pii = bool(exposed) or bool(ref) or (di not in (None, "0"))
    elif event == "analytics_identity_scan":
        obs.exists = True
        obs.pii = True
        exposed.append(clean(ev.get("matched_value")) or "")
    elif event == "contact_lookup_completed":
        obs.exists = rows != "0"
        obs.kind = "hash_only"
        obs.pii = True
    elif event in {"export_download_check_completed"}:
        obs.exists = truthy(ev.get("available")) is not False
    elif event in {"export_metadata_read_completed"}:
        obs.exists = rows != "0" if rows else True
        obs.pii = bool(exposed)
    elif event == "contact_query_completed":
        obs.exists = rows != "0"
        obs.kind = "contact_index"
        obs.pii = True
    elif event == "deletion_marker_check":
        if truthy(ev.get("marker_found")) is False:
            obs.exists = True
            obs.kind = "contact_index"
            obs.pii = True
        else:
            obs.exists = False
    elif ev.get("enabled") is not None and system == "integration_service":
        obs.exists = True
        obs.flow_enabled = truthy(ev.get("enabled"))
    elif ev.get("restore_allowed") is not None and system == "backup_service":
        obs.exists = True
        obs.restore_allowed = truthy(ev.get("restore_allowed"))
    elif event.endswith("_completed") or event.endswith("_read"):
        obs.exists = rows != "0" if rows else None
    else:
        return None
    obs.exposed = [e for e in exposed if e]
    obs.identifiers = list(dict.fromkeys(obs.identifiers + obs.exposed))
    obs.note = event
    return obs


def parse_log(path: Path, evidence_id: str, captured_at: str) -> list:
    traces: "OrderedDict[str, list]" = OrderedDict()
    loose: list = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        ev = parse_log_line(line)
        if not ev:
            continue
        ev["_line"] = n
        tid = clean(ev.get("trace_id"))
        if tid and tid.startswith(("tr-", "rb-")):
            traces.setdefault(tid, []).append(ev)
        else:
            loose.append(ev)
    out = []
    for tid, events in traces.items():
        keys = []
        for ev in events:
            for k in LOOKUP_KEYS:
                v = clean(ev.get(k))
                if v and not RESOURCE_RE.fullmatch(v):
                    keys.append(v)
        for ev in events:
            o = _event_to_obs(ev, keys, evidence_id, captured_at, f"line {ev['_line']} ({tid})")
            if o:
                out.append(o)
    for ev in loose:
        keys = [clean(ev.get(k)) for k in LOOKUP_KEYS if clean(ev.get(k))]
        o = _event_to_obs(ev, keys, evidence_id, captured_at, f"line {ev['_line']}")
        if o:
            out.append(o)
    return out


# ---------------------------------------------------------------------------
# Plain text handover
# ---------------------------------------------------------------------------
HANDOVER_RE = re.compile(
    r"^\s*-\s*(\S+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(.+?)\s*$")


def parse_text(path: Path, evidence_id: str, captured_at: str) -> list:
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = HANDOVER_RE.match(line)
        if m:
            ts, system, rid, rtype, result, subj = m.groups()
            out.append(lookup_observation(system=system, resource_id=rid, record_type=rtype, result=result,
                                          subject=subj, evidence_id=evidence_id, captured_at=captured_at,
                                          observed_at=ts, location=f"line {n}"))
    return out


# ---------------------------------------------------------------------------
# PDFs and images: extract text, then pull grounded facts with patterns
# ---------------------------------------------------------------------------
def pdf_text(path: Path) -> str:
    try:
        return subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True,
                              text=True, timeout=60).stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        from pypdf import PdfReader  # fallback parser
        return "\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)


def ocr_text(path: Path) -> str:
    try:
        return subprocess.run(["tesseract", str(path), "-", "--psm", "3"], capture_output=True,
                              text=True, timeout=120).stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return ""


OCR_FIXES = [(re.compile(r"(?<=[a-z])t(?=\d{3})"), "1")]  # areedt433 -> areed1433 style slips


def document_facts(text: str, evidence_id: str, captured_at: str, kind: str) -> list:
    """Extract (resource, identifiers) co-occurrence facts from document/screen text.

    Screens and documents rarely state a deletion verdict, so only presence facts are
    emitted: a resource id printed next to the subject's identifiers proves the record
    (and its identifiers) existed at capture time.
    """
    out = []
    lines = text.splitlines()
    ids_all = _ids_from_text(text)
    for n, line in enumerate(lines, 1):
        for rid in sorted(set(m.group(0) for m in RESOURCE_RE.finditer(line))):
            # documents describe one subject; screens put unrelated rows side by side
            near = ids_all if kind == "pdf" else _ids_from_text(line)
            obs = Observation(evidence_id=evidence_id, location=f"{kind} line {n}", captured_at=captured_at,
                              observed_at=captured_at, system=system_for(rid, "unknown"), resource_id=rid,
                              exists=True, identifiers=list(dict.fromkeys(near)), note=kind)
            obs.exposed = [x for x in obs.identifiers if "@" in x]
            if obs.system == "support_platform":
                obs.kind = "attachment" if re.search(r"\.pdf|attachment|upload", text, re.I) else "message"
            out.append(obs)
    return out


def parse_pdf(path: Path, evidence_id: str, captured_at: str) -> tuple:
    text = pdf_text(path)
    return document_facts(text, evidence_id, captured_at, "pdf"), text


def parse_image(path: Path, evidence_id: str, captured_at: str) -> tuple:
    text = ocr_text(path)
    for rx, rep in OCR_FIXES:
        text = rx.sub(rep, text)
    return document_facts(text, evidence_id, captured_at, "ocr"), text
