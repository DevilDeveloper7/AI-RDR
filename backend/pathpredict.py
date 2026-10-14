"""
PathPredict - pre-emptive-protection prediction layer (task 3.4;
planning/pathpredict-spec.md).

This is Phase A only: the real ranking/confidence/ETA algorithm, fully
importable and locally testable against `backend.tests.fakes.FakeHostController`
- no live SSH access is assumed or required. It is NOT wired into
ARM's automated backup action here; per the spec's S7, that must wait until
the Linux-traversal-order validation gap below is closed. Until then this
module's output is display-only.

**Empirical grounding (spec S3)**: the core within-directory mechanism
(rank remaining directory entries alphabetically) is grounded in a real
measurement - median Spearman rho 0.991 between file-touch order and
alphabetical filename order, on 740,475 real EN2025 ransomware
file-modify events (200 largest (sample, process, parent_directory) groups).
That's real signal, not an assumption.

**Open validation gap (spec S7), NOT resolved by this module**: the S3
measurement is from EN2025, a *Windows* sandbox dataset (NTFS
FindFirstFile/FindNextFile enumeration). This project's actual Linux
production target uses ext4, whose default htree directory indexing returns
readdir() entries in hash-bucket order once a directory is large enough -
NOT lexicographic order. Whether the alphabetical-touch-order pattern holds
at all on the real Linux target is unverified; re-running S3's rho check
against real Linux/ext4 data (via testing/mock_ransomware_behavior.py) is
explicitly future work, not done here. Nothing in this module should be
wired into a real automated ARM action until that check is done - see S5/S7.

This is a heuristic, not a trained model (spec S4/S6): no labeled "correct
next N targets" dataset exists to fit a sequence model against, and a
heuristic traceable to a measured population statistic is more defensible
at a diploma defense than an opaque model with no ground truth to validate
it against.
"""

from __future__ import annotations

import fnmatch
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .arm import DEFAULT_ALLOW_LIST_PATH, load_allow_list
from .host_controller import HostController

# ---------------------------------------------------------------------------
# Tunables (spec S4.3/S4.4 - explicitly "e.g."/"tunable" values, not precisely
# fitted; see the spec for why: no real incident data exists yet to tune
# against, only the population-level S3 measurement).
# ---------------------------------------------------------------------------

DEFAULT_DECAY = 0.85
"""conf(k) = running_hit_rate * DECAY**k (spec S4.3). The spec explicitly
flags 0.85 as a starting point "to tune once real incident data exists, not
guessed precisely here" - this constant carries that same caveat forward."""

COLD_START_PRIOR = 0.5
"""Confidence prior used before an incident's live tracker has accumulated
any same-incident evidence (spec S4.3's "standard cold-start handling for
any online estimator")."""

CROSS_DIRECTORY_CONFIDENCE_CEILING = 0.3
"""Hard cap on confidence for any cross-directory frontier prediction (spec
S4.4), regardless of running_hit_rate/decay - this fallback has NO empirical
validation behind it (S3's rho check only covered within-directory order),
so it must never be reported as trustworthy as an in-directory guess."""


# ---------------------------------------------------------------------------
# Critical-asset exclusion - reuses ARM's existing allow-list mechanism
# (backend/critical_assets.yml's `paths` key, already reserved for exactly
# this per that file's own comment) rather than reinventing one.
# ---------------------------------------------------------------------------


def is_critical_asset(path: str, allow_list_path: Optional[Path] = None) -> bool:
    """True if `path` matches one of critical_assets.yml's `paths` globs.
    PathPredict must never predict-and-act on a critical-asset path as if it
    were a normal target (spec S4.2 step 2) - this is the same allow-list
    ARM's own critical-asset gating uses (backend/arm.py's
    host_is_allow_listed, mirrored here for paths instead of hosts), reused
    rather than reinvented."""
    allow_list = load_allow_list(Path(allow_list_path) if allow_list_path else DEFAULT_ALLOW_LIST_PATH)
    return any(fnmatch.fnmatch(path, pattern) for pattern in allow_list.get("paths", []))


# ---------------------------------------------------------------------------
# S4.2: within-directory ranking (primary mechanism)
# ---------------------------------------------------------------------------


def _parent_directory(path: str) -> str:
    return str(PurePosixPath(path).parent)


def rank_within_directory(
    directory_listing: Sequence[str],
    touched: Sequence[str],
    allow_list_path: Optional[Path] = None,
) -> List[str]:
    """Spec S4.2 steps 1-3: sort the not-yet-touched, non-critical-asset
    entries of `directory_listing` alphabetically. `directory_listing` and
    `touched` must use the same representation (both bare filenames, or both
    full paths) for the touched-exclusion check to work - `build_prediction`
    below always passes full paths for both.
    """
    touched_set = set(touched)
    remaining = [
        entry
        for entry in directory_listing
        if entry not in touched_set and not is_critical_asset(entry, allow_list_path)
    ]
    return sorted(remaining)


# ---------------------------------------------------------------------------
# S4.2 point 4: live per-incident confidence tracker
# ---------------------------------------------------------------------------


class IncidentConfidenceTracker:
    """Live per-incident hit-rate tracker (spec S4.2's "live confidence per
    incident"). One instance per flagged entity/incident - deliberately NOT
    shared/global across incidents, since the spec's whole point is that
    this estimates *this* incident's own rho live, rather than trusting the
    S3 population average for every incident equally. An incident whose
    first few predictions miss degrades its own confidence in real time.
    """

    def __init__(self, cold_start_prior: float = COLD_START_PRIOR) -> None:
        self.cold_start_prior = cold_start_prior
        self.matched = 0
        self.total_predictions_made = 0

    def record_touch(self, predicted_top: Optional[str], actual_touch: str) -> None:
        """Call once per new real touch event for this incident, passing
        whatever PathPredict's top-of-list (`k=0`) prediction was
        immediately *before* this touch arrived. Updates the running
        matched/total_predictions_made hit-rate (spec S4.2)."""
        self.total_predictions_made += 1
        if predicted_top is not None and predicted_top == actual_touch:
            self.matched += 1

    @property
    def running_hit_rate(self) -> float:
        """matched/total_predictions_made once there's evidence, else the
        cold-start prior (spec S4.3)."""
        if self.total_predictions_made == 0:
            return self.cold_start_prior
        return self.matched / self.total_predictions_made

    @property
    def topk(self) -> str:
        """The demo contract's `ppTopk` field, e.g. "3/3" (spec S1/S4.2)."""
        return f"{self.matched}/{self.total_predictions_made}"


# ---------------------------------------------------------------------------
# S4.3: risk%, confidence, and ETA per target
# ---------------------------------------------------------------------------


def conf_at_k(running_hit_rate: float, k: int, decay: float = DEFAULT_DECAY) -> float:
    """conf(k) = running_hit_rate * decay**k (spec S4.3). Monotonically
    non-increasing in k by construction, for any running_hit_rate in [0, 1]
    and decay in (0, 1]."""
    return running_hit_rate * (decay ** k)


def risk_pct(conf: float) -> int:
    """riskPct = round(100 * conf) (spec S4.3) - inherits conf(k)'s
    monotonic-non-increasing-in-k property by construction."""
    return round(100 * conf)


def eta_seconds(k: int, file_mod_rate: float) -> float:
    """eta = k / (file_mod_rate per second) seconds (spec S4.3), using the
    entity's own already-computed windowed `file_mod_rate` feature - taken
    as an input here, never re-derived.

    Unit fix (resolved, was previously an open caveat): the spec's S4.1/S4.3
    text describes file_mod_rate as "files/second", but the ML engine's
    actual feature (pipeline/features/windowing.py's `_n_filemod / minutes`,
    confirmed directly against that module) computes it as files per
    *minute*. `file_mod_rate` here is documented and expected to be in that
    same real convention - **files per minute**, matching every other caller
    of this feature in this project - and is converted to a per-second rate
    internally before computing the ETA. Do not pass a files/second value
    here; that would silently be treated as files/minute and understate the
    ETA by 60x.
    """
    if file_mod_rate <= 0:
        raise ValueError("file_mod_rate must be > 0 to compute an ETA")
    rate_per_second = file_mod_rate / 60.0
    return k / rate_per_second


def eta_str(k: int, file_mod_rate: float) -> str:
    """"T+{n}s" per the demo contract's `eta` format (spec S1/S4.3).
    `file_mod_rate` is files/minute - see `eta_seconds`'s docstring."""
    return f"T+{round(eta_seconds(k, file_mod_rate))}s"


def default_action_state(path: str) -> str:
    """Default `get_action_state` callback: always "At Risk" when no real
    ARM audit-log lookup is wired in (spec S4.3's `state` field)."""
    return "At Risk"


def target_state(path: str, get_action_state: Optional[Callable[[str], str]] = None) -> str:
    """`state` field: Protected | Backed up | At Risk (spec S4.3), sourced
    from ARM's own action log via a pluggable callback rather than this
    module reaching into arm.py's internals directly - so this can be wired
    to the real audit log later without a hard dependency now."""
    fn = get_action_state or default_action_state
    return fn(path)


# ---------------------------------------------------------------------------
# S4.4: cross-directory frontier fallback (explicitly lower-confidence,
# explicitly unvalidated - see CROSS_DIRECTORY_CONFIDENCE_CEILING above)
# ---------------------------------------------------------------------------


def recent_directories(touched: Sequence[str], active_directory: str) -> List[str]:
    """Directories the entity has recently transitioned through, most-
    recent-first, deduplicated, excluding the (already-exhausted)
    `active_directory` (spec S4.4)."""
    seen: List[str] = []
    for p in reversed(touched):
        d = _parent_directory(p)
        if d != active_directory and d not in seen:
            seen.append(d)
    return seen


def cross_directory_frontier(
    controller: HostController,
    host: str,
    touched: Sequence[str],
    active_directory: str,
    allow_list_path: Optional[Path] = None,
) -> List[str]:
    """Spec S4.4: once the active directory's ranked list is exhausted,
    extend into directories the entity has recently visited, most-recent-
    first, each ranked alphabetically like S4.2. Returns full paths.

    NOTE: this only produces the ranked path list - confidence for these
    entries must go through `conf_at_k` capped by
    CROSS_DIRECTORY_CONFIDENCE_CEILING (see build_prediction below), never
    the uncapped within-directory conf_at_k.
    """
    results: List[str] = []
    for d in recent_directories(touched, active_directory):
        try:
            listing = controller.list_directory(host, d)
        except NotImplementedError:
            continue
        full_paths = [str(PurePosixPath(d) / entry) for entry in listing]
        results.extend(rank_within_directory(full_paths, touched, allow_list_path))
    return results


# ---------------------------------------------------------------------------
# S5: pre-emptive backup action + its reverse, wired here (not actions.py -
# see planning/pathpredict-spec.md's task notes / this task's scope: we are
# extending HostController, not touching actions.py, so the equivalent of
# actions.py's `_run()` wrapper + REVERSAL_HANDLERS entry for backup_file()
# lives in this module instead).
# ---------------------------------------------------------------------------


def now_iso() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def backup_file(controller: HostController, host: str, path: str) -> Dict[str, Any]:
    """Pre-emptive, reversible backup of a PathPredict-predicted target
    (spec S5). Mirrors actions.py's uniform result-dict shape
    (`{action, target, status, timestamp, reversible, detail}`) for
    consistency with the rest of ARM's action log, without importing from or
    modifying actions.py.

    Display-only reminder (spec S7): nothing in this module calls this
    function automatically. Deciding to actually invoke pre-emptive backups
    against PathPredict's predictions is a separate, later wiring decision
    explicitly deferred by the spec until the Linux-validation gap closes.
    """
    target = {"host": host, "path": path}
    try:
        detail = controller.backup_file(host, path)
        return {
            "action": "backup_file",
            "target": target,
            "status": "success",
            "timestamp": now_iso(),
            "reversible": True,
            "detail": detail,
        }
    except Exception as exc:  # noqa: BLE001 - same broad-catch convention as actions.py
        return {
            "action": "backup_file",
            "target": target,
            "status": "failed",
            "timestamp": now_iso(),
            "reversible": True,
            "detail": {"error": str(exc)},
        }


def _reverse_backup_file(controller: HostController, result: Dict[str, Any]) -> None:
    controller.remove_backup(result["target"]["host"], result["detail"].get("backup_id"))


PATHPREDICT_REVERSAL_HANDLERS: Dict[str, Callable[[HostController, Dict[str, Any]], None]] = {
    "backup_file": _reverse_backup_file,
}
"""PathPredict's own reversal-handler table, matching actions.py's
REVERSAL_HANDLERS pattern (same key convention: the `action` name used in
result dicts above) but kept in this module since backend/actions.py is
explicitly not touched by this task."""


# ---------------------------------------------------------------------------
# S1: output assembly - the exact demo contract shape
# ---------------------------------------------------------------------------


def build_prediction(
    controller: HostController,
    host: str,
    touched: Sequence[str],
    file_mod_rate: float,
    tracker: IncidentConfidenceTracker,
    decay: float = DEFAULT_DECAY,
    allow_list_path: Optional[Path] = None,
    get_action_state: Optional[Callable[[str], str]] = None,
    lead: Optional[int] = None,
) -> Dict[str, Any]:
    """Assembles PathPredict's demo-contract output (spec S1):

        {lead, topk, targets: [{path, riskPct, conf, eta, state}, ...]}

    `touched` is the entity's touched-file sequence in arrival order (spec
    S4.1), full paths. `file_mod_rate` is the entity's own already-computed
    windowed feature (files/minute - see `eta_seconds()`'s docstring), taken
    as input, never re-derived here.
    `tracker` is this incident's live IncidentConfidenceTracker (spec S4.2) -
    callers own its lifecycle (one per incident) and are responsible for
    calling `tracker.record_touch(...)` as real touch events arrive; this
    function only reads its current state, it doesn't advance it.

    Within-directory targets (k=0..) come first, ranked alphabetically
    (S4.2); once that directory's entries are exhausted, cross-directory
    frontier targets (S4.4) continue the same k sequence with confidence
    hard-capped at CROSS_DIRECTORY_CONFIDENCE_CEILING.
    """
    if not touched:
        raise ValueError("PathPredict needs at least one touched path to find the active directory")

    active_directory = _parent_directory(touched[-1])
    try:
        listing = controller.list_directory(host, active_directory)
    except NotImplementedError:
        listing = []
    full_listing = [str(PurePosixPath(active_directory) / entry) for entry in listing]
    within_dir_ranked = rank_within_directory(full_listing, touched, allow_list_path)
    frontier_ranked = cross_directory_frontier(controller, host, touched, active_directory, allow_list_path)

    targets: List[Dict[str, Any]] = []
    for k, path in enumerate(within_dir_ranked):
        conf = conf_at_k(tracker.running_hit_rate, k, decay)
        targets.append(
            {
                "path": path,
                "riskPct": risk_pct(conf),
                "conf": conf,
                "eta": eta_str(k, file_mod_rate),
                "state": target_state(path, get_action_state),
            }
        )

    start_k = len(within_dir_ranked)
    for offset, path in enumerate(frontier_ranked):
        k = start_k + offset
        # S4.4: hard cap, regardless of decay/running_hit_rate - this
        # fallback has no S3-equivalent empirical backing.
        conf = min(conf_at_k(tracker.running_hit_rate, k, decay), CROSS_DIRECTORY_CONFIDENCE_CEILING)
        targets.append(
            {
                "path": path,
                "riskPct": risk_pct(conf),
                "conf": conf,
                "eta": eta_str(k, file_mod_rate),
                "state": target_state(path, get_action_state),
            }
        )

    return {
        "lead": lead if lead is not None else len(targets),
        "topk": tracker.topk,
        "targets": targets,
    }


# ---------------------------------------------------------------------------
# Task 3.4b (planning/pathpredict-deployment-spec.md Part 1 #2/#3): the two
# persistence seams the live wiring in backend/irdp/pipeline.py needs.
# `run_once()` is deliberately single-pass, called fresh every poll - without
# persistence, IncidentConfidenceTracker's in-memory state (and the
# touched-so-far history needed to tell which touches in a given poll are
# genuinely new) would reset every poll, defeating the whole "live,
# per-incident, self-correcting" design (spec S4.2).
#
# Both ABCs below mirror ThreatIntelCache's exact pattern (backend/
# risk_fusion.py, task 4.3): one ABC, one in-memory fake for tests, one real
# OpenSearch implementation - and the never-raise discipline is built in from
# the start here, rather than retrofitted the way task 4.3b had to fix
# OpenSearchThreatIntelCache's unguarded raise_for_status() after the fact.
# Neither real class here is exercised against live OpenSearch in this
# phase; constructing either opens no network connection, only get()/put()/
# write_prediction() need a reachable indexer.
# ---------------------------------------------------------------------------


def incident_key(host_id: str, process_id: Optional[int]) -> str:
    """f"{host_id}:{process_id}" - the same (host_id, process_id) -> key
    convention backend/risk_fusion.py's fuse() already uses for its own
    `entity` field, reused here rather than re-picked, and shared by both
    IncidentTrackerStore (the state doc's _id) and PathPredictWriter (the
    prediction doc's _id)."""
    return f"{host_id}:{process_id}"


@dataclass
class IncidentState:
    """Everything an incident's live PathPredict wiring needs to survive
    across `run_once()`'s single-pass invocations - richer than
    `IncidentConfidenceTracker`'s own two-int state because the wiring needs
    the full touch history to know which touches in a given poll are *new*,
    not just the running hit-rate.

    matched / total_predictions_made - mirror IncidentConfidenceTracker's own
        two counters exactly (same semantics, see that class's docstring).
    touched_so_far - full paths, arrival order, every touch recorded for this
        incident across every poll so far.
    """

    matched: int = 0
    total_predictions_made: int = 0
    touched_so_far: List[str] = field(default_factory=list)


class IncidentTrackerStore(ABC):
    """Abstract persistence for `IncidentState`, keyed by `incident_key()`.

    **Never-raise contract (load-bearing, not advisory - same wording as
    `ThreatIntelCache`'s own docstring, deliberately applied here from the
    start)**: both `get()` and `put()` must never raise for an ordinary
    backend failure - connection error, timeout, a non-2xx/404 response, or
    an unparseable body. `get()` must return `None` in those cases, which
    callers treat identically to "no state yet persisted" (i.e. a cold
    start - `matched=0`, `total_predictions_made=0`, `touched_so_far=[]`).
    `put()` must silently no-op in those cases - losing a tracker-state
    write is low-stakes (the incident just re-learns its own hit-rate a
    little slower next poll), so it must never be allowed to propagate and
    take down a caller's whole `run_once()` pass."""

    @abstractmethod
    def get(self, incident_key: str) -> Optional[IncidentState]:
        """Return the persisted `IncidentState` for `incident_key`, or `None`
        on a miss - including a never-before-seen incident or an ordinary
        backend failure (connection error, timeout, non-2xx/404 response,
        unparseable body), which must all behave exactly like a miss (never
        raise)."""

    @abstractmethod
    def put(self, incident_key: str, state: IncidentState) -> None:
        """Persist `state` for `incident_key`, overwriting whatever was
        stored before. Must silently no-op (not raise) on an ordinary
        backend failure."""


class InMemoryIncidentTrackerStore(IncidentTrackerStore):
    """Default store for tests - no filesystem/network access, state lives
    only as long as the Python object does. Mirrors `InMemoryThreatIntelCache`
    /`InMemoryCheckpointStore` exactly (dict-backed, nothing fancier needed at
    this scale) - and, unlike those two, is also the thing that proves real
    multi-poll continuity in tests: the same instance passed into two
    sequential `run_once()`-style calls genuinely carries state between them."""

    def __init__(self) -> None:
        self._data: Dict[str, IncidentState] = {}

    def get(self, incident_key: str) -> Optional[IncidentState]:
        return self._data.get(incident_key)

    def put(self, incident_key: str, state: IncidentState) -> None:
        self._data[incident_key] = state


class OpenSearchIncidentTrackerStore(IncidentTrackerStore):
    """Real implementation, backed by a dedicated OpenSearch index
    (`ai-rdr-pathpredict-incident-state` by default) - one document per
    incident, `_id` = `incident_key`, overwritten in place on every `put()`,
    matching `OpenSearchThreatIntelCache`'s own get/put-by-id semantics
    exactly (deliberately a single, non-rotating index for the same reason:
    `get()` must be able to find a document written in a *previous* poll by
    a stable id, which a daily-rotating index would silently defeat).

    Never exercised against live OpenSearch in this phase, same disclosed-
    not-proven status as every other `OpenSearch*` class in this codebase.
    Built with the never-raise discipline from the start (see
    `IncidentTrackerStore`'s own docstring) - mirrors
    `OpenSearchThreatIntelCache`'s now-fixed get()/put() exactly: no
    `raise_for_status()`, explicit `requests.exceptions.Timeout`/
    `RequestException` handling, explicit non-2xx/404 handling, explicit
    unparseable-body handling.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 9200,
        index: str = "ai-rdr-pathpredict-incident-state",
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

    def get(self, incident_key: str) -> Optional[IncidentState]:
        import requests  # lazy import - see RealXForceClient's own convention

        try:
            resp = requests.get(
                self._url(f"{self.index}/_doc/{incident_key}"),
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
            doc = resp.json()["_source"]
            return IncidentState(
                matched=int(doc.get("matched", 0)),
                total_predictions_made=int(doc.get("total_predictions_made", 0)),
                touched_so_far=list(doc.get("touched_so_far") or []),
            )
        except (ValueError, KeyError, TypeError):
            # 2xx but an unparseable/unexpected body shape - still a
            # failure, not a crash.
            return None

    def put(self, incident_key: str, state: IncidentState) -> None:
        import requests  # lazy import - see RealXForceClient's own convention

        doc = {
            "matched": state.matched,
            "total_predictions_made": state.total_predictions_made,
            "touched_so_far": list(state.touched_so_far),
        }
        try:
            resp = requests.put(
                self._url(f"{self.index}/_doc/{incident_key}"),
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                json=doc,
            )
        except requests.exceptions.Timeout:
            return  # silently no-op - losing a tracker-state write is low-stakes
        except requests.exceptions.RequestException:
            return

        if resp.status_code >= 400:
            return


class PathPredictWriter(ABC):
    """Abstract sink for `build_prediction()`'s output - there's no
    dashboard yet to read PathPredict's output live, and no SDD-defined
    index for it either (same "not in the SDD" situation `OpenSearchActionStore`
    (backend/arm.py) already hit for `ai-rdr-arm-action-state` - a disclosed
    judgment call, not an oversight).

    **Never-raise contract (load-bearing, not advisory)**: `write_prediction()`
    must never raise for an ordinary backend failure - same reasoning as
    `TriggerSender`'s own non-criticality (backend/risk_fusion.py), except
    this is lower-stakes still: display-only, nothing downstream depends on
    it succeeding yet. A write failure here must never crash `run_once()` or
    mask the real response/trigger side of the pipeline."""

    @abstractmethod
    def write_prediction(
        self, host_id: str, process_id: Optional[int], prediction: Dict[str, Any]
    ) -> None:
        """Write `prediction` (`build_prediction()`'s own `{lead, topk,
        targets}` dict) for this `(host_id, process_id)` incident,
        denormalized with `host_id`/`process_id`/a timestamp before writing.
        Must silently no-op (not raise) on an ordinary backend failure."""


class InMemoryPathPredictWriter(PathPredictWriter):
    """Default writer for tests - no filesystem/network access. Keeps one
    document per incident (keyed by `incident_key()`, overwritten on every
    write - matching the real implementation's own "current live state, not
    a log" semantics), so tests can assert on exactly what was last written
    for a given incident."""

    def __init__(self) -> None:
        self.written: Dict[str, Dict[str, Any]] = {}

    def write_prediction(
        self, host_id: str, process_id: Optional[int], prediction: Dict[str, Any]
    ) -> None:
        doc = dict(prediction)
        doc["host_id"] = host_id
        doc["process_id"] = process_id
        doc["@timestamp"] = now_iso()
        self.written[incident_key(host_id, process_id)] = doc


class OpenSearchPathPredictWriter(PathPredictWriter):
    """Real implementation, backed by a new, dedicated index
    (`ai-rdr-pathpredict-predictions` by default) - one document per
    incident, `_id` = `incident_key()`, overwritten each time (this is "the
    incident's current live prediction state," not an append-only log: a log
    of every poll's full target list would grow unboundedly and nothing
    needs the history, the dashboard, when it exists, only needs "what does
    PathPredict think right now").

    Never exercised against live OpenSearch in this phase. Never-raise from
    the start, mirroring `OpenSearchThreatIntelCache`'s now-fixed `put()`
    exactly - no `raise_for_status()`, explicit `Timeout`/`RequestException`
    handling, explicit non-2xx handling. A write failure here must never
    crash `run_once()` or mask the real response/trigger side of the
    pipeline - same reasoning as `TriggerSender`'s own non-criticality,
    except lower-stakes still (display-only, nothing downstream depends on
    it succeeding yet)."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 9200,
        index: str = "ai-rdr-pathpredict-predictions",
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

    def write_prediction(
        self, host_id: str, process_id: Optional[int], prediction: Dict[str, Any]
    ) -> None:
        import requests  # lazy import - see RealXForceClient's own convention

        doc = dict(prediction)
        doc["host_id"] = host_id
        doc["process_id"] = process_id
        doc["@timestamp"] = now_iso()

        try:
            resp = requests.put(
                self._url(f"{self.index}/_doc/{incident_key(host_id, process_id)}"),
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                json=doc,
            )
        except requests.exceptions.Timeout:
            return  # silently no-op - a lost display-only write is low-stakes
        except requests.exceptions.RequestException:
            return

        if resp.status_code >= 400:
            return


# ---------------------------------------------------------------------------
# Task 3.4b Part 1 #4's "subtle part" - the live, per-poll incremental
# hit/miss recording the deployment spec calls out as the one thing in this
# wiring that needs to be gotten right and tested carefully. Lives here, not
# duplicated inline in backend/irdp/pipeline.py's run_once(), so it's
# directly unit-testable against FakeHostController with no IRDP/RawEvent
# machinery involved at all, and so run_once()'s own diff stays a thin
# wiring layer (new params + a loop + calling this).
# ---------------------------------------------------------------------------


def advance_incident_and_predict(
    controller: HostController,
    host: str,
    new_touches: Sequence[str],
    state: Optional[IncidentState],
    file_mod_rate: float,
    decay: float = DEFAULT_DECAY,
    allow_list_path: Optional[Path] = None,
    get_action_state: Optional[Callable[[str], str]] = None,
    lead: Optional[int] = None,
) -> Tuple[Dict[str, Any], IncidentState]:
    """The spec's "subtle part": given this poll's genuinely-new touches
    (already filtered by the caller to exclude anything already present in
    the PERSISTED `touched_so_far` - i.e. `state.touched_so_far` as loaded,
    before this call - in arrival order) and this incident's previously-
    persisted `state` (`None`/missing on cold start), record each new
    touch's hit/miss against what PathPredict's top-of-list (`k=0`)
    prediction would genuinely have been immediately BEFORE that touch
    arrived - using the incrementally-growing `touched_so_far` built up so
    far inside this same call, exactly like `IncidentConfidenceTracker
    .record_touch()`'s own contract expects - then appends the touch before
    moving to the next one, so each successive comparison uses the right
    incremental state. This is what makes `topk` a genuine live accuracy
    readout rather than a number computed after the fact against
    information PathPredict didn't actually have at prediction time.

    The very first touch of a cold-start incident (empty `touched_so_far`,
    no active directory yet to rank) has no prior prediction to compare
    against at all - `predicted_top` is `None` for that one touch, which
    `record_touch()` already treats as "no match" by its own contract
    (never a crash, never a fabricated prediction).

    After all new touches are recorded, calls `build_prediction()` once
    more with the final `touched_so_far` and the entity's real
    `file_mod_rate` for this poll's actual display output, using
    `controller` for the live `list_directory()` call(s).

    Returns `(prediction, updated_state)` - this function has no
    persistence side effects of its own; callers (`run_once()`) write
    `prediction` via a `PathPredictWriter` and persist `updated_state` via
    an `IncidentTrackerStore` themselves. Never calls `backup_file()` -
    display-only, per the spec's own explicit scope boundary.
    """
    state = state or IncidentState()
    touched_so_far: List[str] = list(state.touched_so_far)
    tracker = IncidentConfidenceTracker()
    tracker.matched = state.matched
    tracker.total_predictions_made = state.total_predictions_made

    for path in new_touches:
        predicted_top: Optional[str] = None
        if touched_so_far:
            # "What the top-of-list prediction would have been" immediately
            # before this touch - the file_mod_rate passed here is
            # irrelevant to WHICH path ranks first (only eta_str() reads
            # file_mod_rate, and we only look at targets[0]["path"] below),
            # so a harmless placeholder (1.0) is used rather than the real
            # entity rate, keeping this intermediate call independent of
            # whether the real file_mod_rate is even known yet.
            prior = build_prediction(
                controller,
                host,
                touched_so_far,
                file_mod_rate=1.0,
                tracker=tracker,
                decay=decay,
                allow_list_path=allow_list_path,
            )
            if prior["targets"]:
                predicted_top = prior["targets"][0]["path"]
        tracker.record_touch(predicted_top, path)
        touched_so_far.append(path)

    prediction = build_prediction(
        controller,
        host,
        touched_so_far,
        file_mod_rate=file_mod_rate,
        tracker=tracker,
        decay=decay,
        allow_list_path=allow_list_path,
        get_action_state=get_action_state,
        lead=lead,
    )
    updated_state = IncidentState(
        matched=tracker.matched,
        total_predictions_made=tracker.total_predictions_made,
        touched_so_far=touched_so_far,
    )
    return prediction, updated_state
