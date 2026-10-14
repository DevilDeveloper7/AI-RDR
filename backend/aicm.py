"""
AICM - AI Incident Case Manager (task 4.6; planning/aicm-spec.md).

Closes `backend/actions.py`'s `notify_and_open_case()` stub and
`backend/arm.py`'s trailing `AICM.update_case(case, actions_taken)` seam -
see both modules' own docstrings for the exact stub language this replaces.

**Real documentation gap (disclosed in the spec, not invented here)**: AICM
has a full page in the SDD (S6.4.2 - Table 6.4.2a's case model, Table
6.4.2b's lifecycle, and real pseudocode for the recommendation engine), but
the SRS never names AICM at all - no requirement ID, unlike PathPredict/Risk
Fusion/ARM. Followed anyway, since the SDD's own tables/pseudocode are
concrete enough to build against directly.

**Judgment calls disclosed here (the SDD is silent on all of these - see
each one's own docstring/comment below for the reasoning)**:
  - Which lifecycle transitions are automatic vs. analyst-driven
    (`_VALID_TRANSITIONS`, `update_case()`'s auto Triaged->Contained rule).
  - The correlation window (`CORRELATION_WINDOW_SECONDS`, 24h default).
  - The recommendation rule table (`_rules_match()`) - the SDD gives only
    three example actions, no exhaustive table.
  - `score_from_history()`'s cold-start prior (`COLD_START_CONFIDENCE`,
    0.5) - same cold-start pattern `IncidentConfidenceTracker`
    (backend/pathpredict.py) and `CachedThreatIntelClient`
    (backend/risk_fusion.py) already use elsewhere in this codebase.
  - Fields beyond Table 6.4.2a's literal list, each added because the
    literal table doesn't give the mechanism enough to actually work:
    `context` (a free-form enrichment bag `enrich()` reads - `user_id`,
    `dashboard_signals`, `fusion_line`, etc.), `recommendation_history`
    (an append-only log `score_from_history()` queries - `recommendations`
    itself gets overwritten on every `recommend()` re-run, so it alone
    can't hold durable accept/reject history), `last_playbook_id` (stands
    in for the PDL pseudocode's undocumented `case.type`), and the five
    per-transition timestamp fields (`triaged_at`.../`closed_at`) that
    make the table's plural "timestamps" real instead of a single opaque
    field.

Layout mirrors `backend/risk_fusion.py`'s `ThreatIntelCache` pattern most
closely (one ABC, one in-memory fake, one real OpenSearch implementation,
never-raise discipline built in from the start - not retrofitted the way
task 4.3b had to fix `OpenSearchThreatIntelCache` after shipping it broken)
and `backend/arm.py`'s `ActionStore` for the get/put/all shape.

**Integration points this module fills (see each site's own comment)**:
  1. `backend/actions.py`'s `notify_and_open_case()` calls
     `open_or_update_case()` for real and returns the real `case_id`.
  2. `backend/arm.py`'s `_execute()` calls `update_case()` after building
     `results`; `approve()` calls `_execute()` (already, before this task),
     so both go through the exact same call site - no duplicated logic.

**Process-wide default store (disclosed judgment call)**: `actions.py`'s
`notify_and_open_case()` is called from inside playbook-step closures built
by `backend/playbooks.py`, whose step definitions are explicitly out of
scope for this task to edit - so there is no constructor/call-site to thread
a shared `CaseStore` instance through from `ARM` down into
`notify_and_open_case()`. `get_default_store()`/`set_default_store()` give
both integration points a single shared instance without that plumbing:
`actions.py` and `arm.py` both call AICM's functions with no explicit
`store=` argument, so both resolve to the same process-wide default unless a
caller overrides it (every test that needs isolation does, via
`set_default_store()` - see `backend/tests/conftest.py`'s autouse fixture).
"""

from __future__ import annotations

import datetime
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Lifecycle - Table 6.4.2b, plus the disclosed transition-automation rules
# from planning/aicm-spec.md's "Case lifecycle" section.
# ---------------------------------------------------------------------------


class CaseState(Enum):
    NEW = "New"
    TRIAGED = "Triaged"
    CONTAINED = "Contained"
    RECOVERED = "Recovered"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


# New -> Triaged: automatic (open_or_update_case(), immediately on creation).
# Triaged -> Contained: automatic (update_case(), on a successful non-notify
#   action). Contained -> Recovered -> Resolved -> Closed: each an explicit,
#   analyst-driven call (mark_recovered()/resolve()/close()) - no skipping a
#   state, per the spec's own "a state machine, not a free-form field".
_VALID_TRANSITIONS: Dict[CaseState, frozenset] = {
    CaseState.NEW: frozenset({CaseState.TRIAGED}),
    CaseState.TRIAGED: frozenset({CaseState.CONTAINED}),
    CaseState.CONTAINED: frozenset({CaseState.RECOVERED}),
    CaseState.RECOVERED: frozenset({CaseState.RESOLVED}),
    CaseState.RESOLVED: frozenset({CaseState.CLOSED}),
    CaseState.CLOSED: frozenset(),
}

_OPEN_STATES = frozenset(
    {CaseState.NEW, CaseState.TRIAGED, CaseState.CONTAINED, CaseState.RECOVERED}
)

_STATE_TIMESTAMP_FIELD = {
    CaseState.TRIAGED: "triaged_at",
    CaseState.CONTAINED: "contained_at",
    CaseState.RECOVERED: "recovered_at",
    CaseState.RESOLVED: "resolved_at",
    CaseState.CLOSED: "closed_at",
}


class InvalidCaseTransition(Exception):
    """Raised when a caller asks for a state jump `_VALID_TRANSITIONS`
    doesn't allow (e.g. `Closed -> New`, or `New -> Closed` directly) -
    rejected rather than silently allowed, per the spec's explicit
    "a state machine, not a free-form field" requirement."""


class CaseNotFoundError(KeyError):
    """Raised by the lifecycle/recommendation functions below when
    `case_id` doesn't resolve to a stored `Case` - a caller bug (every real
    `case_id` passed to these functions is expected to have come from
    `open_or_update_case()`'s own return value), not an ordinary/expected
    outcome, so this is allowed to raise (unlike `CaseStore.get()` itself,
    whose own never-raise contract only covers backend I/O failures, not
    "no such id was ever created")."""


def is_valid_transition(frm: CaseState, to: CaseState) -> bool:
    return to in _VALID_TRANSITIONS.get(frm, frozenset())


def validate_transition(frm: CaseState, to: CaseState) -> None:
    if not is_valid_transition(frm, to):
        raise InvalidCaseTransition(f"cannot transition a case from {frm.value!r} to {to.value!r}")


def is_open(state: CaseState) -> bool:
    """True for New/Triaged/Contained/Recovered - the correlation window
    (`open_or_update_case()`) only ever folds a new trigger into a case that
    is still open; Resolved/Closed cases always start a fresh case instead,
    matching the spec's own "an existing open (not Resolved/Closed) case"
    wording."""
    return state in _OPEN_STATES


# ---------------------------------------------------------------------------
# Case data model - Table 6.4.2a, verbatim fields first, disclosed additions
# after (see module docstring for why each addition exists).
# ---------------------------------------------------------------------------


@dataclass
class Case:
    case_id: str
    entity: str
    host: str
    risk_score: float
    severity: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    attack_techniques: List[str] = field(default_factory=list)
    predicted_targets: List[Dict[str, Any]] = field(default_factory=list)
    actions_taken: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    state: CaseState = CaseState.NEW
    owner: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""

    # --- disclosed additions beyond Table 6.4.2a's literal field list ---
    triaged_at: Optional[str] = None
    contained_at: Optional[str] = None
    recovered_at: Optional[str] = None
    resolved_at: Optional[str] = None
    closed_at: Optional[str] = None
    resolution_notes: Optional[str] = None
    last_playbook_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    recommendation_history: List[Dict[str, Any]] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _parse_iso(ts: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _transition(case: Case, to_state: CaseState, now: Optional[str] = None) -> None:
    validate_transition(case.state, to_state)
    now = now or _now_iso()
    case.state = to_state
    case.updated_at = now
    field_name = _STATE_TIMESTAMP_FIELD.get(to_state)
    if field_name:
        setattr(case, field_name, now)


# ---------------------------------------------------------------------------
# CaseStore - mirrors ActionStore's get/put/all shape (backend/arm.py) and
# ThreatIntelCache's never-raise discipline (backend/risk_fusion.py).
# ---------------------------------------------------------------------------


class CaseStore(ABC):
    """Abstract store for `Case` records, keyed by `case_id`.

    **Never-raise contract (load-bearing, not advisory - same wording as
    `ThreatIntelCache`/`IncidentTrackerStore`'s own docstrings, applied here
    from the start rather than retrofitted the way task 4.3b had to fix
    `OpenSearchThreatIntelCache` after shipping it broken)**: `get()`,
    `put()`, and `all()` must never raise for an ordinary backend failure -
    connection error, timeout, a non-2xx/404 response, or an unparseable
    body. `get()` must return `None` and `all()` must return `[]` in those
    cases, identical to "nothing found"; `put()` must silently no-op - a
    lost case write is not low-stakes the way a lost cache/tracker write is
    (see `OpenSearchCaseStore`'s own docstring), but it must still never be
    allowed to propagate and take down a caller's whole playbook execution."""

    @abstractmethod
    def get(self, case_id: str) -> Optional[Case]:
        """Return the stored `Case` for `case_id`, or `None` on a miss -
        including an ordinary backend failure (see class docstring)."""

    @abstractmethod
    def put(self, case: Case) -> None:
        """Persist `case`, overwriting whatever was stored under the same
        `case_id` before. Must silently no-op (not raise) on an ordinary
        backend failure."""

    @abstractmethod
    def all(self) -> List[Case]:
        """Return every stored `Case` - `open_or_update_case()`'s
        correlation query and `score_from_history()`'s history query both
        scan this. Must return `[]` (not raise) on an ordinary backend
        failure."""


class InMemoryCaseStore(CaseStore):
    """Default store for tests - no filesystem/network access, state lives
    only as long as the Python object does. Mirrors `InMemoryActionStore`
    exactly (dict-backed, nothing fancier needed at this scale)."""

    def __init__(self) -> None:
        self._cases: Dict[str, Case] = {}

    def get(self, case_id: str) -> Optional[Case]:
        return self._cases.get(case_id)

    def put(self, case: Case) -> None:
        self._cases[case.case_id] = case

    def all(self) -> List[Case]:
        return list(self._cases.values())


def _case_to_doc(case: Case) -> Dict[str, Any]:
    doc = dict(case.__dict__)
    doc["state"] = case.state.value
    return doc


def _doc_to_case(doc: Dict[str, Any]) -> Case:
    kwargs = dict(doc)
    kwargs["state"] = CaseState(kwargs.get("state", CaseState.NEW.value))
    # Tolerate a doc missing any disclosed-addition field (e.g. written by
    # an older schema version) - Case's own dataclass defaults cover it.
    known_fields = {f for f in Case.__dataclass_fields__}
    kwargs = {k: v for k, v in kwargs.items() if k in known_fields}
    return Case(**kwargs)


class OpenSearchCaseStore(CaseStore):
    """Real implementation, backed by the SDD's own named index
    (`ai-rdr-incident-cases-*` - S6.4.2's case model already has a given
    name and primary-fields list, unlike ARM's action-state/PathPredict's
    prediction indices, which had to invent their own).

    **Disclosed deviation from the literal `-*` glob, for the same reason
    `OpenSearchThreatIntelCache`/`OpenSearchIncidentTrackerStore` each
    already disclosed**: a get/put-by-`_id` call needs one concrete index
    name, not a wildcard pattern (OpenSearch/Elasticsearch's single-document
    `_doc/{id}` GET/PUT endpoints don't accept one) - so this uses one
    concrete, non-rotating index (`ai-rdr-incident-cases` by default) rather
    than literally trying to PUT/GET against `ai-rdr-incident-cases-*`. Same
    judgment call, same reasoning, applied here for the same technical
    requirement, not a new invention.

    Never exercised against live OpenSearch in this phase - constructing
    this class opens no network connection, only `get()`/`put()`/`all()`
    need a reachable indexer. Never-raise discipline built in from the
    start (see `CaseStore`'s own docstring) - mirrors
    `OpenSearchThreatIntelCache`'s now-fixed `get()`/`put()` exactly: no
    `raise_for_status()`, explicit `Timeout`/`RequestException` handling,
    explicit non-2xx/404 handling, explicit unparseable-body handling."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 9200,
        index: str = "ai-rdr-incident-cases",
        verify_ssl: bool = False,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.index = index
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"https://{self.host}:{self.port}/{path}"

    def get(self, case_id: str) -> Optional[Case]:
        import requests  # lazy import - see RealXForceClient's own convention

        try:
            resp = requests.get(
                self._url(f"{self.index}/_doc/{case_id}"),
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            return None  # degraded mode - treat exactly like a miss
        except requests.exceptions.RequestException:
            return None

        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            # Any other non-2xx response (403, 500, etc.) - a backend
            # failure, not a crash. No raise_for_status() here.
            return None

        try:
            return _doc_to_case(resp.json()["_source"])
        except (ValueError, KeyError, TypeError):
            # 2xx but an unparseable/unexpected body shape - still a
            # failure, not a crash.
            return None

    def put(self, case: Case) -> None:
        import requests  # lazy import - see RealXForceClient's own convention

        try:
            resp = requests.put(
                self._url(f"{self.index}/_doc/{case.case_id}"),
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                json=_case_to_doc(case),
            )
        except requests.exceptions.Timeout:
            return  # silently no-op - never-raise contract (see CaseStore)
        except requests.exceptions.RequestException:
            return

        if resp.status_code >= 400:
            return

    def all(self) -> List[Case]:
        import requests  # lazy import - see RealXForceClient's own convention

        try:
            resp = requests.post(
                self._url(f"{self.index}/_search"),
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                json={"size": 10000, "query": {"match_all": {}}},
            )
        except requests.exceptions.Timeout:
            return []
        except requests.exceptions.RequestException:
            return []

        if resp.status_code >= 400:
            return []

        try:
            hits = resp.json()["hits"]["hits"]
            return [_doc_to_case(hit["_source"]) for hit in hits]
        except (ValueError, KeyError, TypeError):
            return []


# ---------------------------------------------------------------------------
# Process-wide default store - see module docstring's "Process-wide default
# store" section for why this exists.
# ---------------------------------------------------------------------------

_default_store: Optional[CaseStore] = None


def get_default_store() -> CaseStore:
    global _default_store
    if _default_store is None:
        _default_store = InMemoryCaseStore()
    return _default_store


def set_default_store(store: CaseStore) -> None:
    """Test/ops seam: replace the process-wide default `CaseStore` - every
    test that touches AICM (directly or via `actions.notify_and_open_case`/
    `arm.ARM._execute`) resets this first for isolation (see
    `backend/tests/conftest.py`'s autouse fixture). Also how Phase B would
    swap in `OpenSearchCaseStore` for the live deployment, when that's
    wired up - not done in this phase (see module docstring)."""
    global _default_store
    _default_store = store


def _require_case(store: CaseStore, case_id: str) -> Case:
    case = store.get(case_id)
    if case is None:
        raise CaseNotFoundError(f"no case found for case_id={case_id!r}")
    return case


# ---------------------------------------------------------------------------
# Severity/risk_score - read from the trigger payload per the spec
# ("risk_score/severity ... no new computation, just read it at
# case-creation time"). Real gap, disclosed: neither `fuse()`'s output nor
# ARM's trigger payload currently carries a *numeric* risk_score field
# (only the string `risk_tier`) - the mapping below is this module's own
# disclosed stand-in until a real numeric fused score exists upstream, used
# only when a caller doesn't supply `risk_score` explicitly.
# ---------------------------------------------------------------------------

_SEVERITY_ALIASES = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_RISK_SCORE_BY_SEVERITY = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}


def _severity_from_trigger(trigger: Dict[str, Any]) -> str:
    raw = trigger.get("risk_tier") or trigger.get("priority") or trigger.get("severity") or "low"
    return _SEVERITY_ALIASES.get(str(raw).strip().lower(), "LOW")


# ---------------------------------------------------------------------------
# Correlation - "group by (entity, host) within a configurable time window"
# (planning/aicm-spec.md's "Correlation" section).
# ---------------------------------------------------------------------------

CORRELATION_WINDOW_SECONDS = 24 * 60 * 60.0
"""Disclosed judgment call, no number given in the SDD - start generous
(this project's own real incidents so far have spanned minutes, not days;
see the spec's own reasoning for why a too-wide window just means more
correlation, not less)."""


def _find_correlatable_case(
    store: CaseStore, entity: str, host: str, now: str, window_seconds: float
) -> Optional[Case]:
    now_dt = _parse_iso(now)
    matches: List[Case] = []
    for case in store.all():
        if case.entity != entity or case.host != host:
            continue
        if not is_open(case.state):
            continue
        try:
            delta = abs((now_dt - _parse_iso(case.updated_at)).total_seconds())
        except (ValueError, TypeError):
            continue
        if delta <= window_seconds:
            matches.append(case)
    if not matches:
        return None
    return max(matches, key=lambda c: c.updated_at)


def open_or_update_case(
    entity: str,
    host: str,
    trigger: Dict[str, Any],
    playbook_id: Optional[str] = None,
    risk_score: Optional[float] = None,
    attack_techniques: Optional[Sequence[str]] = None,
    predicted_targets: Optional[Sequence[Dict[str, Any]]] = None,
    context: Optional[Dict[str, Any]] = None,
    store: Optional[CaseStore] = None,
    now: Optional[str] = None,
    correlation_window_seconds: float = CORRELATION_WINDOW_SECONDS,
) -> Case:
    """The SDD's own `case := AICM.open_or_update_case(entity, score,
    playbook)` pseudocode line, for real. First looks for an existing open
    case for the same `(entity, host)` updated within
    `correlation_window_seconds` of `now` - if found, merges into it
    (attack techniques, latest predicted targets, a severity bump if this
    trigger is worse than what the case already has, re-run `recommend()`);
    otherwise creates a new `New`-state case and immediately auto-advances
    it to `Triaged` (per the spec's disclosed judgment call - severity is
    already known at creation time, so there's no real waiting period that
    would justify a separate manual step for this one transition).

    `attack_techniques`/`predicted_targets` are accepted as already-
    collected inputs (the distinct non-null `RawEvent.mitre_technique`
    values for this incident; `pathpredict.build_prediction()`'s own
    `targets` list) - this function does no new MITRE mapping or PathPredict
    computation of its own, per the spec's own "nothing new to build for
    these inputs" note. Both default to empty when a caller doesn't have
    them yet (e.g. PathPredict hasn't run for this entity) - not an error.
    """
    store = store or get_default_store()
    now = now or _now_iso()
    severity = _severity_from_trigger(trigger)
    score = risk_score if risk_score is not None else trigger.get("risk_score")
    if score is None:
        score = _RISK_SCORE_BY_SEVERITY[severity]
    techniques = list(dict.fromkeys(attack_techniques or []))
    targets = list(predicted_targets or [])
    extra_context = dict(context or {})

    existing = _find_correlatable_case(store, entity, host, now, correlation_window_seconds)
    if existing is not None:
        for technique in techniques:
            if technique not in existing.attack_techniques:
                existing.attack_techniques.append(technique)
        if targets:
            existing.predicted_targets = targets
        existing.context.update(extra_context)
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[existing.severity]:
            existing.severity = severity
            existing.risk_score = score
        if playbook_id:
            existing.last_playbook_id = playbook_id
        existing.updated_at = now
        recommend(existing, playbook_id, store=store)
        store.put(existing)
        return existing

    case = Case(
        case_id=str(uuid.uuid4()),
        entity=entity,
        host=host,
        risk_score=score,
        severity=severity,
        attack_techniques=techniques,
        predicted_targets=targets,
        state=CaseState.NEW,
        created_at=now,
        updated_at=now,
        last_playbook_id=playbook_id,
        context=extra_context,
    )
    store.put(case)
    _transition(case, CaseState.TRIAGED, now)  # automatic - see docstring
    recommend(case, playbook_id, store=store)
    store.put(case)
    return case


# ---------------------------------------------------------------------------
# Lifecycle transitions - update_case()/mark_recovered()/resolve()/close().
# ---------------------------------------------------------------------------

# Any action name other than "notify_and_open_case" itself counts as a
# qualifying containment action when it succeeded - matches the spec's
# literal wording ("at least one successfully-executed containment action
# ... not just notify_and_open_case itself") without inventing a finer
# disruptive/non-disruptive split the spec doesn't give.
def _has_qualifying_containment_action(actions_taken: Sequence[Dict[str, Any]]) -> bool:
    return any(
        a.get("action") != "notify_and_open_case" and a.get("status") == "success"
        for a in actions_taken
    )


def update_case(
    case_id: str, actions_taken: Sequence[Dict[str, Any]], store: Optional[CaseStore] = None
) -> Case:
    """The SDD pseudocode's trailing `AICM.update_case(case, actions_taken)`
    line. Appends `actions_taken` (ARM's own `record["results"]` shape -
    `[{action, target, status, timestamp, reversible, detail}, ...]`) to
    the case, then auto-transitions `Triaged -> Contained` the moment at
    least one non-notify action in this batch succeeded (per the spec's
    disclosed judgment call - mirrors "ARM actions applied; spread halted"
    exactly). A no-op transition-wise if the case is already past Triaged
    (e.g. a second playbook run against an already-Contained case) - still
    appends the new actions either way."""
    store = store or get_default_store()
    case = _require_case(store, case_id)
    case.actions_taken = list(case.actions_taken) + list(actions_taken)
    case.updated_at = _now_iso()
    if case.state == CaseState.TRIAGED and _has_qualifying_containment_action(actions_taken):
        _transition(case, CaseState.CONTAINED)
    store.put(case)
    return case


def mark_recovered(case_id: str, store: Optional[CaseStore] = None) -> Case:
    """Explicit analyst/operator call - "targets restored; threat
    eradicated" is a real-world claim this system cannot verify on its own
    (a successful snapshot/backup proves a copy exists, not that recovery
    actually happened), so this is never inferred from action results,
    unlike `update_case()`'s own Contained auto-transition."""
    store = store or get_default_store()
    case = _require_case(store, case_id)
    _transition(case, CaseState.RECOVERED)
    store.put(case)
    return case


def resolve(case_id: str, notes: Optional[str] = None, store: Optional[CaseStore] = None) -> Case:
    """Explicit analyst call - "Analyst confirms closure; lessons
    recorded" (Table 6.4.2b). `notes` is stored on `resolution_notes` (a
    disclosed addition - the table's own "lessons recorded" language implies
    somewhere to put them)."""
    store = store or get_default_store()
    case = _require_case(store, case_id)
    _transition(case, CaseState.RESOLVED)
    if notes:
        case.resolution_notes = notes
    store.put(case)
    return case


def close(case_id: str, store: Optional[CaseStore] = None) -> Case:
    """Explicit analyst call - "Archived for audit and learning" (Table
    6.4.2b). Only valid from Resolved - no skipping straight from an earlier
    state (`validate_transition()` enforces this)."""
    store = store or get_default_store()
    case = _require_case(store, case_id)
    _transition(case, CaseState.CLOSED)
    store.put(case)
    return case


# ---------------------------------------------------------------------------
# Recommendation engine - the PDL from planning/aicm-spec.md's
# "Recommendation engine" section, implemented for real.
# ---------------------------------------------------------------------------

COLD_START_CONFIDENCE = 0.5
"""Disclosed constant - same cold-start pattern `IncidentConfidenceTracker`
(backend/pathpredict.py) and `CachedThreatIntelClient`'s wrapped lookups
(backend/risk_fusion.py) already use elsewhere in this codebase. Used by
`score_from_history()` whenever no real accept/reject history exists yet
for a given candidate action."""

# Duplicated from backend/playbooks.py's own Playbook.name values on
# purpose, NOT imported from there: playbooks.py imports backend/actions.py,
# and actions.py imports this module for the real open_or_update_case()/
# update_case() calls (see module docstring's "Integration points") - an
# `from .playbooks import PLAYBOOKS` here would complete a cycle
# (aicm -> playbooks -> actions -> aicm).
_PLAYBOOK_NAMES = {
    "PB-01": "Ransomware Containment",
    "PB-02": "Suspicious Behaviour",
    "PB-03": "Known-Bad Indicator",
    "PB-04": "Honey-File Trigger",
}


def enrich(case: Case) -> Dict[str, Any]:
    """`AICM_recommend`'s `enrich(case)` step: assembles exactly the fields
    already available on `case` - risk/severity, `attack_techniques`,
    `predicted_targets`, plus whatever free-form `context` the case was
    opened/updated with (e.g. `user_id`, `fuse()`'s own `dashboard_signals`/
    `fusion_line` if a caller passed them through). No new enrichment logic,
    per the spec's own "no new enrichment logic, just collection" note."""
    data: Dict[str, Any] = {
        "risk_score": case.risk_score,
        "severity": case.severity,
        "attack_techniques": list(case.attack_techniques),
        "predicted_targets": list(case.predicted_targets),
    }
    data.update(case.context)
    return data


def _justification(case: Case, playbook_id: Optional[str], extra: str) -> str:
    """Templated, no LLM call - same "Verdict-sentence generator"
    convention `fuse()`'s own `fusion_line` already established
    (backend/risk_fusion.py)."""
    name = _PLAYBOOK_NAMES.get(playbook_id, playbook_id or "an unknown playbook")
    base = (
        f"Recommended because {name} triggered with risk_tier={case.severity} "
        f"and {len(case.actions_taken)} action(s) already executed."
    )
    return f"{base} {extra}".strip()


def _rules_match(
    playbook_id: Optional[str], case: Case, context: Dict[str, Any]
) -> List[Tuple[str, str]]:
    """`rules.match(case.type, case.state, context)` - the small, disclosed
    rule table from planning/aicm-spec.md's "Recommendation engine" section
    (`case.type` read as `playbook_id`/`case.last_playbook_id`, the closest
    real stand-in this codebase has for the PDL's undocumented field - see
    module docstring). Returns `(action, justification)` pairs; an unknown/
    missing `playbook_id` returns no candidates - an honest "nothing to
    recommend yet" rather than guessing a rule bucket."""
    successful = {a.get("action") for a in case.actions_taken if a.get("status") == "success"}
    candidates: List[Tuple[str, str]] = []

    if playbook_id == "PB-01":
        if "snapshot_target" in successful or "backup_file" in successful:
            candidates.append(
                (
                    "Restore from snapshot",
                    _justification(case, playbook_id, "A snapshot/backup action already succeeded."),
                )
            )
        if context.get("user_id"):
            candidates.append(
                (
                    "Reset credentials for affected user",
                    _justification(
                        case, playbook_id, f"Affected user {context['user_id']} is known."
                    ),
                )
            )
        if case.predicted_targets:
            candidates.append(
                (
                    "Review predicted-target directories for residual risk",
                    _justification(
                        case, playbook_id, "PathPredict flagged residual-risk directories."
                    ),
                )
            )
    elif playbook_id == "PB-02":
        candidates.append(
            (
                "Confirm or dismiss as false positive",
                _justification(case, playbook_id, "Awaiting analyst confirmation of the ML anomaly."),
            )
        )
        candidates.append(
            (
                "Escalate to PB-01 if encryption confirmed",
                _justification(case, playbook_id, "Escalation path if encryption is confirmed."),
            )
        )
    elif playbook_id == "PB-03":
        candidates.append(
            (
                "Block the matched indicator at the network perimeter",
                _justification(
                    case,
                    playbook_id,
                    "Outside ARM's own block_ip_hash scope (perimeter firewall rules this project "
                    "doesn't control).",
                ),
            )
        )
        candidates.append(
            (
                "Investigate related cases for the same indicator",
                _justification(
                    case,
                    playbook_id,
                    "Cross-case correlation is display-only in this phase (URSE's job later, not built here).",
                ),
            )
        )
    elif playbook_id == "PB-04":
        candidates.append(
            (
                "Treat as confirmed malicious - escalate to full containment if not already at Critical",
                _justification(
                    case, playbook_id, "Honey-file access is deterministic, high-confidence evidence."
                ),
            )
        )
        candidates.append(
            (
                "Review host for lateral movement",
                _justification(case, playbook_id, "Check for related activity elsewhere on this host."),
            )
        )
    return candidates


def score_from_history(
    action: str, store: Optional[CaseStore] = None, cold_start: float = COLD_START_CONFIDENCE
) -> float:
    """`score_from_history(rec, past_cases)` - a real `CaseStore` query over
    every past case's `recommendation_history` for entries recommending this
    exact `action`, weighted by how often an analyst accepted vs. rejected
    it (`accepted / (accepted + rejected)`). Returns `cold_start` only when
    no history exists yet for this action - a fixed prior, not an arbitrary/
    random number, per the spec's own disclosed requirement. Genuinely
    changes once `record_feedback()` writes real accept/reject history (see
    `backend/tests/test_aicm.py`'s test proving this), not a permanently-
    fake stub."""
    store = store or get_default_store()
    accepted = 0
    rejected = 0
    for case in store.all():
        for rec in case.recommendation_history:
            if rec.get("action") != action:
                continue
            if rec.get("accepted") is True:
                accepted += 1
            elif rec.get("accepted") is False:
                rejected += 1
    total = accepted + rejected
    if total == 0:
        return cold_start
    return accepted / total


def recommend(
    case: Case,
    playbook_id: Optional[str] = None,
    store: Optional[CaseStore] = None,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """`AICM_recommend(case)`'s full PDL, for real: `enrich()` -> match
    candidate rules -> score each by `score_from_history()` -> sort
    descending -> top `top_k`. Mutates `case.recommendations` (the current
    ranked view - Table 6.4.2a's field) and appends the same ranked entries
    to `case.recommendation_history` (the durable log `score_from_history()`
    reads - `recommendations` alone gets overwritten on every re-run, so it
    can't hold feedback history across repeated correlation updates to the
    same case). Callers (`open_or_update_case()`) persist `case` via `store`
    afterwards; this function only mutates the in-memory object.

    `playbook_id` defaults to `case.last_playbook_id` when omitted, matching
    the PDL's own single-argument `AICM_recommend(case)` signature."""
    store = store or get_default_store()
    playbook_id = playbook_id or case.last_playbook_id
    context = enrich(case)
    candidates = _rules_match(playbook_id, case, context)

    recs: List[Dict[str, Any]] = []
    for action, justification in candidates:
        recs.append(
            {
                "recommendation_id": str(uuid.uuid4()),
                "case_id": case.case_id,
                "action": action,
                "justification": justification,
                "confidence": score_from_history(action, store),
                "accepted": None,
            }
        )

    ranked = sorted(recs, key=lambda r: r["confidence"], reverse=True)[:top_k]
    case.recommendation_history.extend(ranked)
    case.recommendations = ranked
    return ranked


def record_feedback(
    case_id: str, recommendation_id: str, accepted: bool, store: Optional[CaseStore] = None
) -> Case:
    """The analyst-feedback seam `score_from_history()` reads from - the
    dashboard (task 5, not built here) would call this when an analyst
    accepts/rejects a recommendation. Raises `KeyError` if `recommendation_id`
    doesn't match anything ever recommended on this case - a caller bug, not
    an ordinary/expected outcome."""
    store = store or get_default_store()
    case = _require_case(store, case_id)
    found = False
    for rec in case.recommendation_history:
        if rec.get("recommendation_id") == recommendation_id:
            rec["accepted"] = accepted
            found = True
    for rec in case.recommendations:
        if rec.get("recommendation_id") == recommendation_id:
            rec["accepted"] = accepted
            found = True
    if not found:
        raise KeyError(f"no recommendation {recommendation_id!r} found on case {case_id!r}")
    case.updated_at = _now_iso()
    store.put(case)
    return case
