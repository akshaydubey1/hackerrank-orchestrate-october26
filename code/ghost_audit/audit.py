"""Per-case deletion audit at a strict information cutoff.

For a request audited at T = audit_at, only information available at or before T is used --
for identity linking, ownership, resource discovery, state, policy and planning alike:

  * an evidence file is usable only if its capture time <= T, and each observation in it only
    if its own embedded time <= T;
  * an activity row is usable only if its event time <= T;
  * a data-catalog alias found in a document is usable only if the catalog link itself is <= T.

Nothing about one request depends on which other requests are being processed.
"""
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
RETAINED = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}
DOC_NOTES = ("ocr", "pdf", "document-alias")

ACCOUNT_MATCH_BEFORE = timedelta(hours=3)
ACCOUNT_MATCH_AFTER = timedelta(minutes=20)
RUN_ACTION_WINDOW = timedelta(hours=1)
STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


def _action_style(a) -> str:
    d = a.details
    if d.startswith("Policy action completed"):
        return "policy"
    if "received the final result" in d:
        return "result"
    return "other"


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


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
    basis: list = field(default_factory=list)
    unknown_reason: str = ""


@dataclass
class CaseResult:
    case_id: str
    status: str             # serialised status
    steps: list
    trace: dict
    internal_status: str = ""
    unresolved: list = field(default_factory=list)


@dataclass
class CutoffView:
    """Everything known at one cutoff time: ownership links and which subjects each file covers."""
    owners: dict
    owner_evidence: dict
    file_subjects: dict


class Auditor:
    def __init__(self, store: EvidenceStore, identity: IdentityIndex, activity: ActivityStream, policy: Policy):
        self.store, self.identity, self.activity, self.policy = store, identity, activity, policy
        self.obs_by_resource = defaultdict(list)
        self.markers = []
        self.present_by_file = defaultdict(set)
        self.alias_link_time = {}
        self._index_observations()
        self._describe_documents()
        self._views = {}
        self.account_subs = [a for a in activity.account_submissions() if a.ts]
        self.dw_actions = [a for a in activity.rows if a.source_system == "deletion_worker"
                           and a.target_system != "account_service" and a.ts]

    # ------------------------------------------------------------------ indexing (time-free)
    def _index_observations(self):
        snap_counts = defaultdict(int)
        for o in self.store.observations:
            if o.resource_id.startswith("__collection__:") and o.location.startswith("snapshots["):
                snap_counts[(o.evidence_id, o.system, o.resource_id)] += 1
        for o in self.store.observations:
            if o.resource_id.startswith("__collection__:"):
                coll = o.resource_id.split(":", 1)[1]
                if o.location.startswith("snapshots[") and snap_counts[(o.evidence_id, o.system, o.resource_id)] != 1:
                    continue  # several targeted captures of one collection: never a complete scope
                if coll in COLLECTION_KIND or coll.startswith("customer_data_"):
                    self.markers.append(o)
                continue
            self.obs_by_resource[o.resource_id].append(o)
            if o.exists:
                self.present_by_file[o.evidence_id].add(o.resource_id)
        # documents/screens that print a business reference (statement number, file name,
        # customer key) published by the data catalog become presence facts for that resource
        for act, rid, alias, idents, exclusive in self.activity.links:
            if not alias or alias == rid:
                continue
            for ef in self.store.files.values():
                if ef.text and alias.lower() in ef.text.lower():
                    found = [i for i in idents if i.lower() in ef.text.lower()]
                    o = Observation(evidence_id=ef.file_id, location=f"text alias '{alias}' (catalog {act.activity_id})",
                                    captured_at=ef.captured_at, observed_at=ef.captured_at,
                                    system=act.target_system, resource_id=rid, exists=True, identifiers=found,
                                    note="document-alias")
                    if o.system == "identity_service":
                        o.kind = "tombstone"
                    self.alias_link_time[(rid, ef.file_id)] = act.ts
                    self.obs_by_resource[rid].append(o)
                    self.present_by_file[ef.file_id].add(rid)

    def _describe_documents(self):
        """Owner-independent facts read from screens/documents: process state words and kind."""
        for obs in self.obs_by_resource.values():
            for o in obs:
                if o.note not in DOC_NOTES:
                    continue
                ef = self.store.files.get(o.evidence_id)
                low = ((ef.text if ef else "") or "").lower()
                if o.system == "identity_service":
                    o.kind = "tombstone"
                if o.system == "support_platform" and o.note == "ocr":
                    o.kind = None  # a screen does not say whether it is an attachment
                    o.shared_context = bool(re.search(r"\b(agent|assigned|order|delivery)\b", low))
                if o.system == "integration_service":
                    if re.search(r"\b(disabled|paused|stopped|inactive)\b", low):
                        o.flow_enabled = False
                    elif re.search(r"\b(continuous|delivered|running|active)\b", low):
                        o.flow_enabled = True
                if o.system in ("export_service", "object_storage"):
                    m = re.search(r"expires\s+(\d{1,2} \w{3} \d{4})", low)
                    if m:
                        from datetime import datetime
                        try:
                            o.expires_at = datetime.strptime(m.group(1).title(), "%d %b %Y").strftime("%Y-%m-%dT%H:%M:%SZ")
                        except ValueError:
                            pass
                if o.system == "backup_service":
                    # restore capability needs an affirmative statement ABOUT THIS ARCHIVE: wording on a
                    # line that names this backup id. Page-wide text (other archives' restores, banners)
                    # is not evidence about it; silence is not evidence either.
                    own = "\n".join(ln for ln in low.splitlines() if o.resource_id in ln)
                    if re.search(r"restore (blocked|denied|disabled)|deletion block|legal hold", own):
                        o.restore_allowed = False
                    elif re.search(r"restore (allowed|available|enabled)|restorable|eligible for restore", own):
                        o.restore_allowed = True
                    else:
                        o.restore_allowed = None

    # ------------------------------------------------------------------ admissibility
    def admissible(self, o: Observation, cut) -> bool:
        cap, at = parse_ts(o.captured_at), parse_ts(o.observed_at)
        if cap is None or cap > cut or (at is not None and at > cut):
            return False
        lt = self.alias_link_time.get((o.resource_id, o.evidence_id)) if o.note == "document-alias" else None
        return lt is None or lt <= cut

    def view(self, cut) -> CutoffView:
        key = cut.isoformat()
        if key in self._views:
            return self._views[key]
        owners, ev = defaultdict(set), defaultdict(list)
        file_subjects = defaultdict(set)
        sources = []
        for rid, obs in self.obs_by_resource.items():
            for o in obs:
                if not self.admissible(o, cut):
                    continue
                for u in self.identity.owners_of(o.identifiers):
                    owners[rid].add(u)
                    ev[(rid, u)].append(o.evidence_id)
                    file_subjects[o.evidence_id].add(u)
                if o.note.startswith("source="):
                    sources.append((rid, o.note[7:]))
        for act, rid, alias, idents, exclusive in self.activity.links:
            if act.ts and act.ts <= cut:
                for u in self.identity.owners_of(idents):
                    owners[rid].add(u)
                    ev[(rid, u)].append(act.activity_id)
        for rid, src in sources:
            for u in set(owners.get(src, ())):
                owners[rid].add(u)
                ev[(rid, u)].append("source " + src)
        for act, src, dst in self.activity.repopulations:
            if act.ts and act.ts <= cut:
                for u in set(owners.get(src, ())):
                    owners[dst].add(u)
                    ev[(dst, u)].append(act.activity_id)
                for u in set(owners.get(dst, ())):
                    owners[src].add(u)
        v = CutoffView(owners=owners, owner_evidence=ev, file_subjects=file_subjects)
        self._views[key] = v
        return v

    # ------------------------------------------------------------------ workflow correlation
    def correlate_account(self, q: dict, uid: str, cut, v: CutoffView) -> tuple:
        """The deletion-worker submission that this request's own workflow report summarises.
        Uses only this request's fields and activity rows <= audit_at; no other request."""
        rep, req = parse_ts(q["reported_at"]), parse_ts(q["requested_at"])
        inwin = [a for a in self.account_subs if req <= a.ts <= cut
                 and rep - ACCOUNT_MATCH_BEFORE <= a.ts <= rep + ACCOUNT_MATCH_AFTER]
        own = [a for a in inwin if uid in v.owners.get(a.resource_id, ())]
        if own:
            return min(own, key=lambda a: (abs((a.ts - rep).total_seconds()), a.activity_id)), "evidence-linked", []
        unowned = [a for a in inwin if not v.owners.get(a.resource_id)]
        free = [a for a in unowned if STATUS_RESULT.get(q["reported_status"]) == a.reported_result]
        if len(free) == 1:
            return free[0], "unique workflow submission", []
        if not free and len(unowned) == 1:
            # the only submission summarised by this report, although its result wording differs
            return unowned[0], "only workflow submission in the report window (result differs)", []
        pool = free or unowned
        return None, ("ambiguous" if pool else "no submission in the report window"), sorted(a.resource_id for a in pool)

    def attribute_runs(self, uid: str, acct, cut, v: CutoffView) -> tuple:
        """Policy actions on records that no identifier links to anyone (typically anonymised
        analytics). Attributed to this request only when every other account submitted in the hour
        before the action is provably someone else's run that cannot own it."""
        if acct is None:
            return [], []
        systems_of = {}

        def owned_systems(u):
            if u not in systems_of:
                systems_of[u] = {self._system_guess(r) for r, us in v.owners.items() if u in us}
            return systems_of[u]

        by_system, ambiguous = defaultdict(list), []
        for x in self.dw_actions:
            if x.ts > cut or v.owners.get(x.resource_id) or not (acct.ts <= x.ts <= acct.ts + RUN_ACTION_WINDOW):
                continue
            if x.target_system in owned_systems(uid):
                continue
            rivals = [s for s in self.account_subs if s is not acct and x.ts - RUN_ACTION_WINDOW <= s.ts <= x.ts]
            blocked = False
            for s in rivals:
                rowners = v.owners.get(s.resource_id, set())
                if not rowners:
                    blocked = True  # an unidentified rival run could own it
                    break
                ro = sorted(rowners)[0]
                if x.target_system in owned_systems(ro):
                    continue  # the rival subject already has its own record of this kind
                rival_follow = [b for b in self.dw_actions if b.ts <= cut and abs((b.ts - x.ts).total_seconds()) <= 10800
                                and ro in v.owners.get(b.resource_id, ())]
                if rival_follow and all(_action_style(b) != _action_style(x) for b in rival_follow):
                    continue  # the rival's run reports in a different batch style
                blocked = True
                break
            (ambiguous if blocked else by_system[x.target_system]).append(x)
        links = []
        for sysname, xs in by_system.items():
            if len(xs) == 1:
                links.append((xs[0].resource_id, xs[0]))
            else:
                ambiguous += xs
        return links, [(x.activity_id, x.resource_id) for x in ambiguous]

    # ------------------------------------------------------------------ state
    def _subject_runs(self, uid: str, acct, cut, v: CutoffView) -> list:
        """Times at which a deletion run for this subject touched anything (activity <= cut)."""
        ts = [a.ts for a in self.dw_actions if a.ts <= cut and uid in v.owners.get(a.resource_id, ())]
        ts += [a.ts for a in self.account_subs if a.ts <= cut and uid in v.owners.get(a.resource_id, ())]
        if acct is not None:
            ts.append(acct.ts)
        return sorted(ts)

    def _doc_exposure(self, o: Observation, rid: str, v: CutoffView) -> list:
        ef = self.store.files.get(o.evidence_id)
        text = (ef.text if ef else "") or ""
        low = text.lower()
        digits = re.sub(r"\D", "", text)
        hits = []
        for u in v.owners.get(rid, set()):
            p = self.identity.people.get(u)
            if not p:
                continue
            for e in p.emails:
                if e in low or (ef is not None and e in ef.verified_identifiers):
                    hits.append(e)
            if p.name and p.name.lower() in low:
                hits.append("name")
            for ph in p.phones:
                if len(ph) >= 8 and ph in digits:
                    hits.append("phone")
        return sorted(set(hits))

    def state_at(self, rid: str, cut, uid: str, v: CutoffView, request_at, runs: list,
                 known_since=None) -> Optional[ResourceState]:
        obs = [o for o in self.obs_by_resource.get(rid, []) if self.admissible(o, cut)]
        obs.sort(key=lambda o: (o.observed_at, o.captured_at, o.evidence_id, o.location))
        system = obs[-1].system if obs else self._system_guess(rid)
        st = ResourceState(system=system, resource_id=rid)
        for o in obs:  # descriptive, time-invariant attributes
            for attr in ("record_type", "retention_until"):
                if getattr(o, attr):
                    setattr(st, attr, getattr(o, attr))
            if o.kind and st.kind != "attachment":
                st.kind = o.kind
            if o.shared_context:
                st.shared_context = True
        view_obs = []
        for o in obs:
            if o.note in DOC_NOTES:
                o = Observation(**o.to_dict())
                o.exposed = self._doc_exposure(o, rid, v)
                if o.system in ("account_service", "search_service", "export_service", "object_storage",
                                "marketing_platform", "support_platform", "analytics_platform", "identity_service"):
                    o.pii = bool(o.exposed)
            view_obs.append(o)
        informative = [o for o in view_obs if not (o.exists is None and o.pii is None and o.flow_enabled is None
                                                   and o.restore_allowed is None)]
        per_replica = {}
        for o in informative:
            if o.exists is not None or o.replica not in per_replica:
                per_replica[o.replica] = o
        # absence from a later complete capture of the same replica that covers this subject.
        # A row inside a snapshot is present *at the snapshot time*, not only at its updated_at, so a
        # presence and an absence from snapshots taken at the same instant conflict -> presence stands.
        snap_time = {}
        for m in self.markers:
            if self.admissible(m, cut):
                k = (m.evidence_id, m.replica)
                snap_time[k] = max(snap_time.get(k, ""), m.observed_at)
        for m in sorted(self.markers, key=lambda m: (m.observed_at, m.evidence_id)):
            if not self.admissible(m, cut):
                continue
            coll = m.resource_id.split(":", 1)[1]
            msys, mkind = COLLECTION_KIND.get(coll, ("*", None))
            if msys not in ("*", system) or (mkind and st.kind and mkind != st.kind):
                continue
            if m.note == "snapshot_scope" and not m.location.startswith("snapshots["):
                continue  # SQL inventories list origin systems but hold subject-targeted rows
            if m.note != "full_table" and uid not in v.file_subjects.get(m.evidence_id, set()):
                continue
            if rid in self.present_by_file.get(m.evidence_id, set()):
                continue
            cur = per_replica.get(m.replica)
            if cur is not None and (cur.observed_at >= m.observed_at or cur.exists is False
                                    or (cur.exists and snap_time.get((cur.evidence_id, cur.replica), "") >= m.observed_at)):
                continue
            if not obs and (known_since is None or parse_ts(m.observed_at) < known_since):
                continue  # never observed: absence is meaningful only once the record is known
            per_replica[m.replica] = Observation(m.evidence_id, m.location, m.captured_at, m.observed_at, system, rid,
                                                 replica=m.replica, exists=False, note="absent from complete capture")
        if not per_replica:
            if not obs:
                return None
            st.unknown_reason = "observations carry no state"
            return st
        present = [o for o in per_replica.values() if o.exists]
        if present:
            chosen = max(present, key=lambda o: (o.observed_at, o.captured_at, o.evidence_id))
            st.exists = True
            vals = [o.pii for o in present if o.pii is not None]
            st.pii = any(vals) if vals else next((o.pii for o in reversed(informative) if o.pii is not None), None)
        else:
            states = [o for o in per_replica.values() if o.exists is False]
            chosen = max(states or list(per_replica.values()),
                         key=lambda o: (o.note != "absent from complete capture", o.observed_at, o.captured_at,
                                        o.evidence_id))
            st.exists, st.pii = chosen.exists, chosen.pii
        st.evidence_id, st.observed_at = chosen.evidence_id, chosen.observed_at
        for attr in ("flow_enabled", "restore_allowed"):
            for o in reversed(informative):
                if getattr(o, attr) is not None:
                    setattr(st, attr, getattr(o, attr))
                    if system in ("integration_service", "backup_service"):
                        st.evidence_id, st.observed_at = o.evidence_id, o.observed_at
                    break
        for rep, o in sorted(per_replica.items()):
            st.basis.append(f"[{rep}] {o.evidence_id} {o.location} @ {o.observed_at}: exists={o.exists} pii={o.pii} "
                            f"flow={o.flow_enabled} restore={o.restore_allowed} ({o.note})")
        # a later successful deletion-worker claim on this very record makes an older presence uncertain
        claim = [a for a in self.activity.by_resource.get(rid, []) if a.source_system == "deletion_worker"
                 and a.ts and st.observed_at < a.event_time and a.ts <= cut and a.reported_result == "SUCCESS"]
        obs_t = parse_ts(st.observed_at)
        expiry = next((parse_ts(o.expires_at) for o in reversed(obs) if o.expires_at), None)
        if st.exists and expiry and obs_t and obs_t < expiry <= cut:
            st.unknown_reason = (f"present at {st.observed_at} with a stated expiry {expiry.strftime('%Y-%m-%d')} "
                                 "before audit_at; state after expiry not observed")
        elif claim and st.exists:
            st.unknown_reason = f"present at {st.observed_at}, then {claim[-1].activity_id} claims treatment; no newer observation"
        # prior state observed before the request: carried forward unless this subject's deletion
        # run happened afterwards (the run may have changed it; a claim is not proof either way)
        elif obs_t and obs_t < request_at:
            later_runs = [t for t in runs if obs_t < t <= cut]
            if later_runs:
                st.unknown_reason = (f"last observed {st.observed_at} before the request; a deletion run for this "
                                     f"subject followed at {later_runs[0].strftime('%Y-%m-%dT%H:%M:%SZ')}")
            else:
                st.basis.append("prior state carried forward: no later run or observation")
        # repopulation by an active connector / restore job after the last observation
        for act, src, dst in self.activity.repopulations:
            if dst == rid and act.ts and act.ts <= cut and act.event_time > st.observed_at and st.exists is False:
                st.exists, st.pii, st.unknown_reason = True, True, ""
                st.evidence_id, st.observed_at = act.activity_id, act.event_time
                st.basis.append(f"{act.activity_id}: repopulated by {src} after last observation")
        return st

    @staticmethod
    def _system_guess(rid: str) -> str:
        from .parsers import system_for
        return system_for(rid, "unknown")

    # ------------------------------------------------------------------ case
    def audit(self, q: dict) -> CaseResult:
        cid = q["case_id"]
        trace = {"case_id": cid, "request_email": q["email"], "audit_at": q["audit_at"]}
        intent = classify(q["request_text"])
        trace["intent"] = {"is_deletion": intent.is_deletion, "label": intent.label, "reason": intent.reason,
                           "source": intent.source}
        if not intent.is_deletion:
            unresolved = [{"reason": "intent undecided: treated as not authorising deletion"}] \
                if intent.label == "UNDECIDED" else []
            return CaseResult(cid, "NOT_APPLICABLE", [], trace,
                              internal_status="UNDECIDED_INTENT" if unresolved else "NOT_APPLICABLE",
                              unresolved=unresolved)
        cut = parse_ts(q["audit_at"])
        request_at = parse_ts(q["requested_at"])
        uids = self.identity.resolve_email(q["email"])
        trace["identity"] = {"user_ids": uids}
        if not uids:
            return CaseResult(cid, "INCOMPLETE", [], trace, internal_status="UNCERTIFIED",
                              unresolved=[{"reason": "request e-mail not found in identity snapshot or history"}])
        uid = uids[0]
        person = self.identity.people[uid]
        trace["identity"].update(n_emails=len(person.emails), n_phones=len(person.phones), n_hashes=len(person.hashes))
        v = self.view(cut)
        linked = {rid: "identifier match: " + ",".join(sorted(set(v.owner_evidence.get((rid, uid), []))))
                  for rid, us in v.owners.items() if uid in us}
        acct, how, cands = self.correlate_account(q, uid, cut, v)
        trace["account_correlation"] = {"account": acct.resource_id if acct else None, "basis": how,
                                        "activity": acct.activity_id if acct else None, "candidates": cands}
        if acct:
            linked.setdefault(acct.resource_id, f"workflow correlation {acct.activity_id}")
        run_links, run_amb = self.attribute_runs(uid, acct, cut, v)
        trace["run_attribution"] = {"linked": [(r, a.activity_id) for r, a in run_links], "ambiguous": run_amb}
        for rid, act in run_links:
            linked.setdefault(rid, f"deletion run {act.activity_id}")
        accounts = [r for r in linked if r.startswith("account_")]
        if len(accounts) > 1 and acct and acct.resource_id in accounts:
            for r in accounts:
                if r != acct.resource_id:
                    trace.setdefault("superseded_accounts", []).append(r)
                    linked.pop(r)
        runs = self._subject_runs(uid, acct, cut, v)
        treatments, res_trace = [], []
        for rid in sorted(linked):
            known_since = acct.ts if acct and acct.resource_id == rid else None
            for r2, a2 in run_links:
                if r2 == rid:
                    known_since = a2.ts
            st = self.state_at(rid, cut, uid, v, request_at, runs, known_since)
            if st is None:
                if acct and acct.resource_id == rid:
                    st = ResourceState(system="account_service", resource_id=rid,
                                       unknown_reason="named by the workflow, never observed by audit_at")
                else:
                    res_trace.append({"resource": rid, "skipped": "no admissible observation", "link": linked[rid]})
                    continue
            if st.system in ("profile_service", "unknown"):
                continue
            category = self.policy.categorize(st.system, st.kind, st.record_type)
            action, rule_id, why = self.policy.decide(category, audit_at=cut, retention_until=st.retention_until,
                                                      shared_context=st.shared_context)
            exists, pii = st.exists, st.pii
            flow, restore = st.flow_enabled, st.restore_allowed
            retained = category in RETAINED
            if st.unknown_reason and not retained:
                exists = pii = flow = restore = None
            cite = st.evidence_id if (exists is not None or flow is not None or restore is not None) else ""
            treatments.append(Treatment(system=st.system, resource_id=rid, category=category, action=action,
                                        exists=exists, pii=pii, flow_enabled=flow, restore_allowed=restore,
                                        evidence_id=cite, unknown_reason="" if retained else st.unknown_reason))
            res_trace.append({"resource": rid, "system": st.system, "link": linked[rid], "category": category,
                              "rule": rule_id, "action": action, "why": why, "state_basis": st.basis,
                              "unknown": st.unknown_reason})
        # retention/legal-hold registers that name this subject but no resource id: the retained
        # record must survive, yet no step can name it -> recorded, never silently ignored
        for ef in self.store.files.values():
            cap = parse_ts(ef.captured_at)
            for f in ef.facts:
                if cap and cap <= cut and f["subject_reference"] == uid:
                    active = f["retain_until"] is None or parse_ts(f["retain_until"]) > cut
                    trace.setdefault("register_facts", []).append({**f, "evidence_id": ef.file_id, "active": active})
                    if active:
                        # A finance retention register row (order, subject, retain-until). It is not a
                        # supplied legal hold on a system resource and names no resource id, so no policy
                        # rule or step applies. It is recorded as context; it is NOT taken as proof that
                        # any record is (or is not) still available.
                        trace.setdefault("register_unresolved", []).append({
                            "reason": f"finance retention register {ef.file_id} lists order {f['order_reference']} "
                                      f"for the subject until {f['retain_until'] or 'unspecified'}; no system "
                                      "resource is named, availability not verified (context only)",
                            "blocking": False})
        pre, info = [], []
        if acct is None and not any(r.startswith("account_") for r in linked):
            # The subject's account is one of the workflow submissions in the report window, but
            # nothing says which. If every candidate is proven absent, the subject's account is
            # absent whichever it is; the step cannot name it without guessing, so none is emitted.
            cand_states = {}
            for c in cands:
                ks = min((a.ts for a in self.account_subs if a.resource_id == c and a.ts <= cut), default=None)
                cs = self.state_at(c, cut, uid, v, request_at, runs, ks)
                cand_states[c] = None if cs is None or cs.unknown_reason else cs.exists
            trace["account_candidate_states"] = cand_states
            if not cands:
                # no workflow submission and no account linked by any admissible evidence. A missing
                # identifier is not proof of absence: the account's required state is unproven.
                pre.append({"reason": f"primary account not identified: no account record known for the "
                                      f"subject by audit_at ({how})", "candidates": []})
            else:
                # Candidates absent does not prove the subject's account absent unless evidence shows the
                # set is exhaustive and contains that account; a report-time window shows neither.
                pre.append({"reason": f"primary account not identified ({how}); candidate states "
                                      f"{dict(sorted(cand_states.items()))} do not prove the subject's account "
                                      "absent (set not shown to be exhaustive or to contain it)",
                            "candidates": cands})
        internal, steps, unresolved = build_steps(treatments)
        unresolved = pre + trace.get("register_unresolved", []) + unresolved
        if internal == "COMPLETE" and any(u.get("blocking", True) for u in unresolved):
            # COMPLETE needs every relevant record's required state proven; anything unresolved
            # (unidentified or unproven account, unverifiable hold) blocks certification
            internal, steps, _ = build_steps(treatments, force_uncertified=True)
        unresolved = unresolved + info
        trace["resources"] = res_trace
        trace["unresolved"] = unresolved
        status = internal if internal != "UNCERTIFIED" else "INCOMPLETE"
        return CaseResult(cid, status, steps, trace, internal_status=internal, unresolved=unresolved)
