"""Per-case deletion audit: identity -> linked resources -> state at audit_at -> policy -> plan."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from .activity import ActivityStream
from .identity import IdentityIndex
from .ingest import EvidenceStore
from .intent import classify
from .models import Observation
from .planner import Treatment, build_steps
from .policy import Policy
from .util import parse_ts

def _action_style(a) -> str:
    d = a.details
    if d.startswith("Policy action completed"):
        return "policy"
    if "received the final result" in d:
        return "result"
    return "other"


def _fuzzy_token(target: str, low_text: str, max_edits: int = 2) -> bool:
    """True if some e-mail-like token in the OCR text is within max_edits of target."""
    for tok in re.findall(r"[\w.,%+\-]+@[\w.\-]+", low_text):
        if abs(len(tok) - len(target)) > max_edits:
            continue
        prev = list(range(len(target) + 1))
        for i, ca in enumerate(tok, 1):
            cur = [i]
            for j, cb in enumerate(target, 1):
                cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            prev = cur
        if prev[-1] <= max_edits and tok.split("@")[0].replace(",", ".") != target.split("@")[0] + ".jr":
            if not tok.split("@")[0].endswith(("jr", ".jr", ",jr")):
                return True
    return False


# Collections that represent a complete capture of one record kind for one system.
COLLECTION_KIND = {
    "customer_profiles": ("account_service", None),
    "customer_search_documents": ("search_service", None),
    "customer_analytics_reports": ("analytics_platform", None),
    "customer_analytics_profiles": ("analytics_platform", None),
    "customer_export_jobs": ("export_service", None),
    "customer_exports": ("export_service", None),
    "connector_configurations": ("integration_service", None),
    "connector_subscriptions": ("integration_service", None),
    "security_audit_events": ("security_service", None),
    "security_audit_records": ("security_service", None),
    "backup_catalog": ("backup_service", None),
    "backup_restore_entries": ("backup_service", None),
    "deleted_customer_references": ("identity_service", None),
    "support_conversations": ("support_platform", "message"),
    "support_records": ("support_platform", "message"),
    "ticket_attachments": ("support_platform", "attachment"),
    "retained_order_records": ("legal_service", None),
    "customer_profiles_primary": ("account_service", None),
    "customer_profiles_failover_replica": ("account_service", None),
    "search_documents_primary": ("search_service", None),
}

ACCOUNT_MATCH_BEFORE = timedelta(hours=3)
ACCOUNT_MATCH_AFTER = timedelta(minutes=20)
RUN_WINDOW = timedelta(hours=4)
STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


@dataclass
class ResourceState:
    system: str
    resource_id: str
    exists: Optional[bool] = None
    pii: Optional[bool] = None
    flow_enabled: Optional[bool] = None
    restore_allowed: Optional[bool] = None
    retention_until: Optional[str] = None
    kind: Optional[str] = None
    record_type: Optional[str] = None
    shared_context: Optional[bool] = None
    evidence_id: str = ""
    observed_at: str = ""
    basis: list = field(default_factory=list)  # human-readable trace of how the state was derived
    late_only: bool = False
    link: str = ""


@dataclass
class CaseResult:
    case_id: str
    status: str
    steps: list
    trace: dict


class Auditor:
    def __init__(self, store: EvidenceStore, identity: IdentityIndex, activity: ActivityStream, policy: Policy):
        self.store, self.identity, self.activity, self.policy = store, identity, activity, policy
        self.obs_by_resource = defaultdict(list)
        self.markers = []
        self.present_by_file = defaultdict(set)
        self._index_observations()
        self.owners = defaultdict(set)        # resource_id -> {user_id} (time-invariant ownership)
        self.owner_evidence = defaultdict(list)
        self._link_owners()
        self._enrich_documents()
        self.account_claims = {}              # case_id -> account submission activity (assign_accounts)
        self.account_ambiguous = {}           # case_id -> candidate account ids left unresolved
        self.account_tiebreak = {}            # case_id -> candidates resolved by queue order
        self.run_links = {}                   # case_id -> [(resource_id, activity)]
        self.run_ambiguous = []

    # ------------------------------------------------------------------ indexing
    def _index_observations(self):
        snap_counts = defaultdict(int)
        for o in self.store.observations:
            if o.resource_id.startswith("__collection__:") and o.location.startswith("snapshots["):
                coll = o.resource_id.split(":", 1)[1]
                snap_counts[(o.evidence_id, o.system, coll)] += 1
        for o in self.store.observations:
            if o.resource_id.startswith("__collection__:"):
                coll = o.resource_id.split(":", 1)[1]
                if o.location.startswith("snapshots[") and snap_counts[(o.evidence_id, o.system, coll)] != 1:
                    continue  # several targeted captures of one collection: not a complete scope
                if coll in COLLECTION_KIND or coll.startswith("customer_data_"):
                    self.markers.append(o)
                continue
            self.obs_by_resource[o.resource_id].append(o)
            if o.exists:
                self.present_by_file[o.evidence_id].add(o.resource_id)
        # documents/screens: resolve aliases published by the data catalog (statement numbers,
        # file names, references) into presence facts grounded in the document text itself
        for act, rid, alias, idents, exclusive in self.activity.links:
            if not alias or alias == rid:
                continue
            for ef in self.store.files.values():
                if ef.text and alias.lower() in ef.text.lower():
                    text = ef.text
                    found = [i for i in idents if i.lower() in text.lower()]
                    o = Observation(evidence_id=ef.file_id, location=f"text alias '{alias}'",
                                    captured_at=ef.captured_at, observed_at=ef.captured_at,
                                    system=act.target_system,
                                    resource_id=rid, exists=True, identifiers=found,
                                    exposed=[i for i in found if "@" in i], note="document-alias")
                    if o.system == "identity_service":
                        o.kind = "tombstone"  # exposure decided in _enrich_documents
                    self.obs_by_resource[rid].append(o)
                    self.present_by_file[ef.file_id].add(rid)

    def _link_owners(self):
        for rid, obs in self.obs_by_resource.items():
            for o in obs:
                for u in self.identity.owners_of(o.identifiers):
                    self.owners[rid].add(u)
                    self.owner_evidence[(rid, u)].append(o.evidence_id)
                if o.note.startswith("source="):
                    self.owner_evidence[(rid, "source")].append(o.note[7:])
        for act, rid, alias, idents, exclusive in self.activity.links:
            for u in self.identity.owners_of(idents):
                self.owners[rid].add(u)
                self.owner_evidence[(rid, u)].append(act.activity_id)
        # downstream copies inherit their source's owner (search doc -> account; connector -> target)
        for rid, obs in list(self.obs_by_resource.items()):
            for o in obs:
                if o.note.startswith("source="):
                    for u in self.owners.get(o.note[7:], set()):
                        self.owners[rid].add(u)
        for act, src, dst in self.activity.repopulations:
            for u in set(self.owners.get(src, set())):
                self.owners[dst].add(u)
                self.owner_evidence[(dst, u)].append(act.activity_id)
            for u in set(self.owners.get(dst, set())):
                self.owners[src].add(u)

    def _enrich_documents(self):
        """Screens and documents: decide exposure and process state from the extracted text.

        Exposure is judged only for resources already linked to an owner by an exact join
        (identifier or data-catalog link). OCR noise is tolerated when checking whether that
        owner's email/phone/name is printed (edit distance <= 2 on email tokens), but fuzzy
        matching is never used to create a link -- '.jr' look-alike decoys stay separate.
        """
        for rid, obs in self.obs_by_resource.items():
            for o in obs:
                if o.note not in ("ocr", "pdf", "document-alias"):
                    continue
                ef = self.store.files.get(o.evidence_id)
                text = (ef.text if ef else "") or ""
                low = text.lower()
                hits = []
                for u in self.owners.get(rid, set()):
                    p = self.identity.people.get(u)
                    if not p:
                        continue
                    for e in p.emails:
                        if e in low or _fuzzy_token(e, low):
                            hits.append(e)
                    if p.name and p.name.lower() in low:
                        hits.append(p.name)
                    digits = re.sub(r"\D", "", text)
                    for ph in p.phones:
                        if len(ph) >= 8 and ph in digits:
                            hits.append("phone")
                o.exposed = sorted(set(hits))
                if o.system == "identity_service":
                    o.kind = "tombstone"
                if o.system in ("account_service", "search_service", "export_service", "object_storage",
                                "marketing_platform", "support_platform", "analytics_platform", "identity_service"):
                    o.pii = bool(hits)
                if o.system == "support_platform" and o.note == "ocr":
                    o.kind = None  # a screen does not say whether it is an attachment; other evidence decides
                    o.shared_context = bool(re.search(r"agent|assigned|order|delivery", low))
                if o.system == "integration_service":
                    if re.search(r"\b(disabled|paused|stopped|inactive)\b", low):
                        o.flow_enabled = False
                    elif re.search(r"\b(continuous|healthy|delivered|running|active)\b", low):
                        o.flow_enabled = True
                if o.system == "backup_service":
                    if re.search(r"restore (blocked|denied|disabled)|deletion block|legal hold", low):
                        o.restore_allowed = False
                    else:
                        # archive holding the subject with no restore block recorded: restorable
                        o.restore_allowed = True if hits else None
                if o.system == "security_service":
                    o.pii = None

    # ------------------------------------------------------------------ account correlation
    def assign_accounts(self, requests: list):
        """Correlate each deletion request's workflow report with the deletion-worker submission
        it summarises (time window around reported_at, result consistent with reported_status).
        Used only to recover an account id that no evidence file names; uniqueness is enforced
        globally so one submission is never attributed to two requests."""
        subs = self.activity.account_submissions()
        cand = {}
        for q in requests:
            if not q.get("_deletion"):
                continue
            rep, req, uid = parse_ts(q["reported_at"]), parse_ts(q["requested_at"]), q.get("_user")
            inwin = [a for a in subs if a.ts and a.ts >= req
                     and rep - ACCOUNT_MATCH_BEFORE <= a.ts <= rep + ACCOUNT_MATCH_AFTER]
            own = [a for a in inwin if uid in self.owners.get(a.resource_id, set())]
            if own:  # the account is linked to this subject by evidence: take the closest
                cand[q["case_id"]] = {min(own, key=lambda a: abs((a.ts - rep).total_seconds())).activity_id}
                continue
            free = [a for a in inwin if not self.owners.get(a.resource_id)]
            strict = [a for a in free if STATUS_RESULT.get(q["reported_status"]) == a.reported_result]
            pool = strict or free
            if pool:
                cand[q["case_id"]] = {a.activity_id for a in pool}
        by_id = {a.activity_id: a for a in subs}
        self.account_ambiguous = {}
        changed = True
        while changed:
            changed = False
            for cid, ids in list(cand.items()):
                if len(ids) == 1:
                    aid = next(iter(ids))
                    self.account_claims[cid] = by_id[aid]
                    del cand[cid]
                    for other in cand.values():
                        if aid in other:
                            other.discard(aid)
                            changed = True
                    changed = True
            for cid in [c for c, ids in cand.items() if not ids]:
                del cand[cid]
        # Tie-break for still-ambiguous requests: the deletion worker processes a run as a queue,
        # so the request whose own (evidence-linked) follow-up actions start first is matched to
        # the earliest remaining submission of the same result class. Requests without any
        # linked follow-up action stay ambiguous (no account step rather than a guess).
        uid_of = {q["case_id"]: q.get("_user") for q in requests}
        dw = [a for a in self.activity.rows if a.source_system == "deletion_worker"
              and a.target_system != "account_service" and a.ts]
        def first_followup(cid, ids):
            lo = min(by_id[i].ts for i in ids)
            hi = lo + timedelta(hours=6)
            ts = [a.ts for a in dw if lo <= a.ts <= hi and uid_of.get(cid) in self.owners.get(a.resource_id, set())]
            return min(ts) if ts else None
        self.account_tiebreak = {}
        pending = {cid: ids for cid, ids in cand.items() if ids}
        order = sorted(((first_followup(cid, ids), cid) for cid, ids in pending.items() if first_followup(cid, ids)),
                       key=lambda x: (x[0], x[1]))
        used = {a.activity_id for a in self.account_claims.values()}
        for t, cid in order:
            ids = [i for i in pending[cid] if i not in used]
            if not ids:
                continue
            aid = min(ids, key=lambda i: (by_id[i].ts, i))
            self.account_claims[cid] = by_id[aid]
            self.account_tiebreak[cid] = sorted(by_id[i].resource_id for i in pending[cid])
            used.add(aid)
        for cid, ids in cand.items():
            if cid not in self.account_claims and ids:
                self.account_ambiguous[cid] = sorted(by_id[i].resource_id for i in ids)
        # Deletion-run attribution for policy actions on resources no identifier links to anyone
        # (typically already-anonymised analytics). Accepted only when exactly one request in the
        # run window could own it: the request's own account was submitted in the hour before the
        # action, and the subject has no other resource of that system. Otherwise ambiguous -> skipped.
        user_of = {q["case_id"]: q.get("_user") for q in requests}
        actions = [a for a in self.activity.rows if a.source_system == "deletion_worker"
                   and a.target_system not in ("account_service",) and not self.owners.get(a.resource_id)]
        owned_systems = defaultdict(set)
        for rid, us in self.owners.items():
            sysname = self._system_guess(rid)
            for u in us:
                owned_systems[u].add(sysname)
        self.run_ambiguous = []
        req_by_case = {q["case_id"]: q for q in requests}
        cand = {}
        for act in sorted(actions, key=lambda a: (a.ts, a.activity_id)):
            elig = set()
            for cid, q in req_by_case.items():
                if not q.get("_deletion"):
                    continue
                sub = self.account_claims.get(cid)
                if sub is not None:
                    if not (sub.ts <= act.ts <= sub.ts + timedelta(hours=1)):
                        continue
                elif cid in self.account_ambiguous:
                    continue
                else:  # no account submission at all: anchor the run on the workflow report time
                    rep = parse_ts(q["reported_at"])
                    if not (rep - ACCOUNT_MATCH_BEFORE <= act.ts <= rep + ACCOUNT_MATCH_AFTER):
                        continue
                uid = user_of.get(cid)
                if act.target_system in owned_systems.get(uid, set()):
                    continue
                # a run's follow-ups share one reporting style; a request whose own linked
                # follow-ups in this run use a different style belongs to a different batch
                style = _action_style(act)
                own = [b for b in self.activity.rows if b.source_system == "deletion_worker" and b.ts
                       and abs((b.ts - act.ts).total_seconds()) <= 3 * 3600
                       and b.target_system != "account_service" and uid in self.owners.get(b.resource_id, set())]
                if own and all(_action_style(b) != style for b in own):
                    continue
                # the resource must be visible in a capture that is admissible for this request
                # and that covers this subject
                audit_at, start = parse_ts(q["audit_at"]), parse_ts(q["requested_at"])
                if not any(self._admissible(o, audit_at, start) and uid in self._file_subjects(o.evidence_id)
                           for o in self.obs_by_resource.get(act.resource_id, [])):
                    continue
                elig.add(cid)
            if elig:
                cand[(act.activity_id, act.resource_id, act.target_system)] = (act, elig)
        # constraint propagation: one resource per system per request; accept only forced pairs
        changed = True
        while changed:
            changed = False
            for key, (act, elig) in list(cand.items()):
                if len(elig) == 1:
                    cid = next(iter(elig))
                    self.run_links.setdefault(cid, []).append((act.resource_id, act))
                    del cand[key]
                    for k2, (a2, e2) in cand.items():
                        if k2[2] == key[2] and cid in e2:
                            e2.discard(cid)
                    changed = True
            for key in [k for k, (a, e) in cand.items() if not e]:
                del cand[key]
        for key, (act, elig) in cand.items():
            self.run_ambiguous.append((act.activity_id, act.resource_id, sorted(elig)))

    # ------------------------------------------------------------------ state
    @staticmethod
    def _admissible(o: Observation, audit_at, window_start=None) -> bool:
        """Usable for state: file captured by audit_at and the observation itself inside
        [requested_at, audit_at]. Pre-request observations are stale for an audit of the
        post-request state (they still count for identity linking)."""
        cap, obs_at = parse_ts(o.captured_at), parse_ts(o.observed_at)
        if cap is None or cap > audit_at:
            return False
        if obs_at is not None and obs_at > audit_at:
            return False
        if window_start is not None and obs_at is not None and obs_at < window_start:
            return False
        return True

    @staticmethod
    def _late(o: Observation, audit_at, window_start=None) -> bool:
        """Captured after audit_at but describing an event inside the audit window: may name a
        resource that must appear in the future-work plan, never proves state, never cited."""
        cap, obs_at = parse_ts(o.captured_at), parse_ts(o.observed_at)
        return (cap is not None and cap > audit_at and obs_at is not None and obs_at <= audit_at
                and (window_start is None or obs_at >= window_start))

    def _file_subjects(self, evidence_id: str) -> set:
        if not hasattr(self, "_fs"):
            self._fs = defaultdict(set)
            for rid, obs in self.obs_by_resource.items():
                for o in obs:
                    for u in self.identity.owners_of(o.identifiers):
                        self._fs[o.evidence_id].add(u)
        return self._fs.get(evidence_id, set())

    @staticmethod
    def _informative(o: Observation) -> bool:
        return not (o.exists is None and o.pii is None and o.flow_enabled is None and o.restore_allowed is None)

    def state_at(self, rid: str, audit_at, uid: Optional[str] = None, system_hint: Optional[str] = None,
                 window_start=None, known_since=None) -> Optional[ResourceState]:
        """Reconstruct one resource's state at audit_at.

        * only observations whose file capture time AND embedded observation time are <= audit_at
        * state is kept per replica, then aggregated: a copy present in any replica is present
        * absence needs positive proof: an explicit 404/NOT_FOUND, or a later complete-scope
          capture of the same replica that covers this subject but no longer holds the record
        * sync/restore repopulation after the last observation re-creates the record
        """
        allobs = self.obs_by_resource.get(rid, [])
        obs = [o for o in allobs if self._admissible(o, audit_at, window_start)]
        late = [o for o in allobs if self._late(o, audit_at, window_start)]
        stale = [o for o in allobs if self._admissible(o, audit_at) and not self._admissible(o, audit_at, window_start)]
        obs.sort(key=lambda o: (o.observed_at, o.captured_at, o.evidence_id, o.location))
        known = late + stale
        system = obs[-1].system if obs else (known[0].system if known else (system_hint or self._system_guess(rid)))
        st = ResourceState(system=system, resource_id=rid)
        # descriptive attributes (what kind of record it is) are time-invariant: take them from
        # every capture available by audit_at; an attachment finding is never downgraded
        for o in sorted(stale + obs, key=lambda o: (o.observed_at, o.evidence_id)):
            for attr in ("record_type", "retention_until"):
                if getattr(o, attr):
                    setattr(st, attr, getattr(o, attr))
            if o.kind and st.kind != "attachment":
                st.kind = o.kind
            if o.shared_context:
                st.shared_context = True
        informative = [o for o in obs if self._informative(o)]
        per_replica = {}
        for o in informative:
            if o.exists is not None or o.replica not in per_replica:
                per_replica[o.replica] = o
        # complete-scope captures (per replica, subject-scoped)
        absent_by_marker = {}
        for m in sorted(self.markers, key=lambda m: (m.observed_at, m.evidence_id)):
            coll = m.resource_id.split(":", 1)[1]
            msys, mkind = COLLECTION_KIND.get(coll, ("*", None))
            if msys not in ("*", system) or (mkind and st.kind and mkind != st.kind):
                continue
            if not self._admissible(m, audit_at, window_start):
                continue
            if m.note == "snapshot_scope" and not m.location.startswith("snapshots["):
                # SQL inventories declare origin-system scope but are subject-targeted extracts:
                # treating them as complete produced 34 contradictions with retained security
                # records seen elsewhere, so they never prove absence
                continue
            full_table = m.note == "full_table"
            if not full_table and (uid is None or uid not in self._file_subjects(m.evidence_id)):
                continue  # targeted capture that does not cover this subject proves nothing
            if rid in self.present_by_file.get(m.evidence_id, set()):
                continue
            cur = per_replica.get(m.replica)
            if cur is not None and (cur.observed_at >= m.observed_at or cur.exists is False):
                continue
            if not obs:
                # a resource never observed in the window may only be declared absent from a capture
                # if it was already known (workflow/run activity) before that capture was taken
                if known_since is None or parse_ts(m.observed_at) < known_since:
                    continue
            # a capture-based absence is withdrawn if a later in-window event (even one only exported
            # after audit_at, which is never cited) shows the record present: the capture was not complete
            if any(o.exists and o.observed_at > m.observed_at for o in late):
                st.basis.append(f"{m.evidence_id}: capture absence contradicted by later in-window event "
                                f"(late export); not used as proof")
                continue
            absent_by_marker[m.replica] = m
            per_replica[m.replica] = Observation(m.evidence_id, m.location, m.captured_at, m.observed_at, system,
                                                 rid, replica=m.replica, exists=False,
                                                 note="absent from complete capture")
        if not per_replica:
            if not obs and not late and not stale:
                return None
            if not obs:
                st.late_only = True  # known to exist only from outside the audit window
                for o in late + stale:
                    for attr in ("kind", "record_type", "retention_until"):
                        if getattr(o, attr):
                            setattr(st, attr, getattr(o, attr))
                st.basis.append("no in-window observation; known from late/pre-request captures: "
                                + ",".join(sorted({o.evidence_id for o in late + stale})))
            return st
        present = [o for o in per_replica.values() if o.exists]
        if present:
            chosen = max(present, key=lambda o: (o.observed_at, o.captured_at, o.evidence_id))
            st.exists = True
            vals = [o.pii for o in present if o.pii is not None]
            st.pii = any(vals) if vals else None
            if st.pii is None:
                for o in reversed(informative):
                    if o.pii is not None:
                        st.pii = o.pii
                        break
        else:
            states = [o for o in per_replica.values() if o.exists is False]
            # prefer a direct observation of the resource (404 / NOT_FOUND) over absence inferred
            # from a complete capture; then the most recent
            chosen = max(states or list(per_replica.values()),
                         key=lambda o: (o.note != "absent from complete capture", o.observed_at, o.captured_at,
                                        o.evidence_id))
            st.exists = chosen.exists
            st.pii = chosen.pii
        st.evidence_id, st.observed_at = chosen.evidence_id, chosen.observed_at
        for o in reversed(informative):
            if o.flow_enabled is not None:
                st.flow_enabled = o.flow_enabled
                if system == "integration_service":
                    st.evidence_id, st.observed_at = o.evidence_id, o.observed_at
                break
        for o in reversed(informative):
            if o.restore_allowed is not None:
                st.restore_allowed = o.restore_allowed
                if system == "backup_service":
                    st.evidence_id, st.observed_at = o.evidence_id, o.observed_at
                break
        for rep, o in sorted(per_replica.items()):
            st.basis.append(f"[{rep}] {o.evidence_id} {o.location} @ {o.observed_at}: exists={o.exists} "
                            f"pii={o.pii} flow={o.flow_enabled} restore={o.restore_allowed} ({o.note})")
        # repopulation by an active connector / restore job after the last observation
        for act, src, dst in self.activity.repopulations:
            if dst == rid and act.ts and act.ts <= audit_at and act.event_time > st.observed_at and st.exists is False:
                st.exists, st.pii = True, True
                st.evidence_id, st.observed_at = act.activity_id, act.event_time
                st.basis.append(f"{act.activity_id}: repopulated by {src} after last observation")
        return st

    @staticmethod
    def _system_guess(rid: str) -> str:
        from .parsers import system_for
        return system_for(rid, "unknown")

    # ------------------------------------------------------------------ case
    def resources_for(self, uid: str, audit_at) -> dict:
        out = {}
        for rid, owners in self.owners.items():
            if uid in owners:
                out[rid] = "identifier match: " + ",".join(sorted(set(self.owner_evidence.get((rid, uid), []))))
        return out

    def audit(self, q: dict) -> CaseResult:
        trace = {"case_id": q["case_id"], "request_email": q["email"], "audit_at": q["audit_at"]}
        intent = classify(q["request_text"])
        trace["intent"] = {"is_deletion": intent.is_deletion, "label": intent.label, "reason": intent.reason}
        if not intent.is_deletion:
            return CaseResult(q["case_id"], "NOT_APPLICABLE", [], trace)
        audit_at = parse_ts(q["audit_at"])
        window_start = parse_ts(q["requested_at"])
        uids = self.identity.resolve_email(q["email"])
        trace["identity"] = {"user_ids": uids}
        if not uids:
            trace["limitation"] = "request email not found in identity snapshot or history"
            return CaseResult(q["case_id"], "INCOMPLETE", [], trace)
        uid = uids[0]
        person = self.identity.people[uid]
        trace["identity"].update(emails=sorted(person.emails), n_phones=len(person.phones),
                                 n_hashes=len(person.hashes))
        linked = self.resources_for(uid, audit_at)
        acct = self.account_claims.get(q["case_id"])
        if q["case_id"] in self.account_ambiguous:
            trace["account_ambiguity"] = self.account_ambiguous[q["case_id"]]
        if q["case_id"] in self.account_tiebreak:
            trace["account_tiebreak"] = {"candidates": self.account_tiebreak[q["case_id"]],
                                         "rule": "queue order of evidence-linked follow-up actions"}
        if acct:
            linked.setdefault(acct.resource_id, f"workflow correlation {acct.activity_id}")
        for rid, act in self.run_links.get(q["case_id"], []):
            linked.setdefault(rid, f"deletion run {act.activity_id}")
        # a user may hold several accounts over time: keep the one this request concerns
        accounts = [r for r in linked if r.startswith("account_")]
        if len(accounts) > 1 and acct and acct.resource_id in accounts:
            for r in accounts:
                if r != acct.resource_id:
                    linked.pop(r)
        treatments = []
        res_trace = []
        for rid in sorted(linked):
            known_since = None
            if acct and acct.resource_id == rid:
                known_since = acct.ts
            for r2, a2 in self.run_links.get(q["case_id"], []):
                if r2 == rid:
                    known_since = a2.ts
            st = self.state_at(rid, audit_at, uid, window_start=window_start, known_since=known_since)
            if st is None:
                if rid.startswith("account_") and acct and acct.resource_id == rid:
                    st = ResourceState(system="account_service", resource_id=rid)
                    st.basis.append("no admissible observation; id from workflow correlation; state unproven")
                else:
                    res_trace.append({"resource": rid, "skipped": "no admissible observation at audit_at",
                                      "link": linked[rid]})
                    continue
            if st.system in ("profile_service", "unknown"):
                continue
            category = self.policy.categorize(st.system, st.kind, st.record_type)
            action, rule_id, why = self.policy.decide(category, audit_at=audit_at, retention_until=st.retention_until,
                                                      shared_context=st.shared_context)
            treatments.append(Treatment(system=st.system, resource_id=rid, category=category, action=action,
                                        exists=st.exists, pii=st.pii, flow_enabled=st.flow_enabled,
                                        restore_allowed=st.restore_allowed, evidence_id=st.evidence_id,
                                        late_only=st.late_only))
            res_trace.append({"resource": rid, "system": st.system, "link": linked[rid], "category": category,
                              "rule": rule_id, "action": action, "why": why, "state_basis": st.basis})
        status, steps, notes = build_steps(treatments)
        trace["resources"] = res_trace
        trace["planner_notes"] = notes
        return CaseResult(q["case_id"], status, steps, trace)
