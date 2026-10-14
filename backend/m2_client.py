"""
M2Client - the seam to Pavel's separate `m2_pipeline` inference service
(task m2-integration; planning/m2-integration-spec.md Part 1).

**Scope boundary (read the spec's "integration decision" section for the
full reasoning, not re-derived here)**: M2 is a second, parallel,
display-only ML opinion - never a `risk_tier` input. `backend/risk_fusion.py`'s
`fuse()` is never touched by this module and never reads anything this
module produces; see `backend/irdp/pipeline.py`'s wiring-site comment for
the explicit statement of that boundary at the one place it could be
violated by accident.

Layout mirrors `backend/risk_fusion.py`'s `ThreatIntelClient`/
`ThreatIntelCache` pattern and `backend/pathpredict.py`'s
`IncidentTrackerStore`/`PathPredictWriter` pattern exactly - both explicitly
named by this task as the pattern to follow: one ABC, one fake that records
every call for tests, one real implementation that is importable/
instantiable with no live infra (constructing it opens no connection) and
that **never raises for an ordinary failure** - that discipline is built in
from the start here, the same way task 3.4b's `IncidentTrackerStore` was
deliberately written never-raise-safe from its first version rather than
retrofitted the way task 4.3b had to fix `OpenSearchThreatIntelCache`'s
unguarded `raise_for_status()` after the fact.

Kept as its own module (`backend/m2_client.py`), not folded into
`backend/ml_scoring.py`: `ml_scoring.py`'s own module docstring already
explains why IT is one flat file with no ABC/fake/real split - "the 'live'
dependency here is a static file loaded read-only, not a network resource
needing a fake/real pair." M2 is the opposite: a live HTTP seam needing
exactly that split, the same shape as `ThreatIntelClient`/
`IncidentTrackerStore`/`PathPredictWriter`, each of which already lives in
its own module (`risk_fusion.py`, `pathpredict.py`) rather than inside
`ml_scoring.py`. Matching that precedent beats piling a fourth, unrelated
ABC into a file whose own docstring says it deliberately has none.

**Field mapping (spec's own research, confirmed directly against
`RawEvent` - `backend/irdp/event_source.py` - and M2's own
`m2/docs/M2_API_CONTRACT.md`)**:
`RawEvent.auditd_syscall` -> `event_type` AND `operation` (M2's contract:
"operation" is optional, "event_type" is required; both describe the same
syscall-derived verb, so both get the same value), `RawEvent.file_path` ->
`path`, `RawEvent.process_id` -> `pid`, `RawEvent.process_name` ->
`process_name`. `RawEvent` has no `ppid` or `bytes` field at all - both are
simply omitted from the request (both `Optional` in M2's own schema, so
this is a documented-safe omission, not a hack). `RawEvent.timestamp` is an
ISO-8601 string; M2's `EventInput.timestamp` is a float Unix epoch - this
module converts, reusing the same colonless-UTC-offset fix
`backend/ml_scoring.py`'s own `_parse_ts` already needed for real Wazuh
timestamps on Python 3.10 (deliberately duplicated rather than imported -
same reasoning that module's own docstring gives for duplicating rather
than reaching into `backend/irdp/normalize.py`'s private `_parse_ts`: small
enough that duplicating beats a second private cross-module import).

A `RawEvent` with no `auditd_syscall` (e.g. an ordinary non-fs Wazuh alert,
or any event IRDP could not classify) has nothing to map onto M2's
*required* `event_type` field - such events are left out of the request
entirely, mirroring `RealVirusTotalClient.lookup()`'s own "nothing to check,
no HTTP call" short-circuit for `indicators` carrying neither `ip` nor
`hash`. If an entire group has no mappable events, `score()` makes no HTTP
call at all and returns `None` ("no M2 opinion this poll").
"""

from __future__ import annotations

import datetime
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .irdp.event_source import RawEvent

DEFAULT_TOP_K = 8
"""`top_k` sent on every prediction request - M2's contract example uses 8;
no stronger signal exists yet for what value downstream display actually
wants (disclosed judgment call, same category as PathPredict's
DEFAULT_DECAY - a reasonable starting point, not a tuned constant)."""


def _parse_ts_epoch(ts: str) -> float:
    """ISO-8601 string -> float Unix epoch seconds, for M2's
    `EventInput.timestamp` field. Mirrors `backend/ml_scoring.py`'s own
    `_parse_ts` colonless-UTC-offset fix (real Wazuh timestamps carry
    `...+0000`, which `datetime.fromisoformat()` only accepts from Python
    3.11 onward; this project's real deployment target is 3.10) - see that
    function's own docstring for the full story. Raises `ValueError` on a
    genuinely unparseable timestamp; callers here catch that per-event
    rather than letting one malformed `RawEvent` take down the whole
    batch."""
    fixed = ts.replace("Z", "+00:00")
    fixed = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", fixed)
    return datetime.datetime.fromisoformat(fixed).timestamp()


# ---------------------------------------------------------------------------
# M2Result + M2Client ABC
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class M2Result:
    """One M2 `/v1/predict` outcome - mirrors `M2_API_CONTRACT.md`'s
    response shape field-for-field (per the spec's explicit instruction),
    so nothing needs re-deriving later if the contract changes:

      prediction               - M2's verdict string (e.g. "ransomware").
      ransomware_probability   - float in [0, 1].
      threshold                - the decision threshold M2's own model
                                  applied to produce `alert`.
      alert                    - bool.
      model_name                - e.g. "random_forest".
      feature_version          - M2's own feature-contract version string.
      explanation              - the ordered SHAP evidence list, each entry
                                  M2's own `{feature, value, shap_value,
                                  direction}` shape, passed through verbatim
                                  (never interpreted here - M2's own contract
                                  says SHAP direction is "supporting
                                  evidence, not a causal statement").

    Never read by `backend/risk_fusion.py`'s `fuse()` - display-only, per
    this task's load-bearing scope boundary (see this module's own
    docstring)."""

    prediction: str
    ransomware_probability: float
    threshold: float
    alert: bool
    model_name: str
    feature_version: str
    explanation: List[Dict[str, Any]] = field(default_factory=list)


class M2Client(ABC):
    """Abstract M2 scoring seam, mirroring `ThreatIntelClient`'s/
    `IncidentTrackerStore`'s pattern exactly: one ABC, one real
    implementation safe to construct with no live infra, one fake used by
    every test.

    **Never-raise contract (load-bearing, not advisory - same wording as
    `ThreatIntelCache`'s/`IncidentTrackerStore`'s own docstrings,
    deliberately applied here from the start)**: `score()` must never raise
    for an ordinary failure - connection error, timeout, a non-2xx response
    (`503` most importantly: M2's own documented "no trained model loaded
    yet" state, a real and expected condition until Pavel trains one, not a
    bug to special-case away), or a malformed/unparseable response body.
    All of those must return `None`, meaning "no M2 opinion available this
    poll" - callers must treat `None` exactly like "M2 wasn't wired in at
    all" for this poll, never as a crash."""

    @abstractmethod
    def score(self, events: Sequence[RawEvent], run_id: str) -> Optional[M2Result]:
        """Score one entity's-worth of this poll's `RawEvent`s (the same
        `by_host_process` grouping `backend/irdp/pipeline.py`'s `run_once()`
        already builds for Risk Fusion/PathPredict) against M2's model.
        `run_id` should be a stable per-incident identifier (this project's
        own `backend.pathpredict.incident_key()` convention - `"{host_id}:
        {process_id}"` - reused here rather than re-picked, matching M2's
        own `run_id` example shape `"host-01:pid-4126:window-173"` closely
        enough for M2's own audit trail/debugging to make sense of it).
        Returns `None` if no M2 opinion is available this poll (never
        raises for an ordinary failure - see this class's own docstring)."""


# ---------------------------------------------------------------------------
# NOTE: `FakeM2Client` deliberately does NOT live here. The spec's own
# instruction is "FakeM2Client for tests ... matches FakeThreatIntelClient's
# own convention" - and `FakeThreatIntelClient` lives in
# `backend/tests/fakes.py`, not in `risk_fusion.py` alongside
# `ThreatIntelClient`/`RealVirusTotalClient` themselves (contrast
# `ThreatIntelCache`'s own fake, `InMemoryThreatIntelCache`, which DOES live
# in `risk_fusion.py` next to the cache ABC it fakes - this project already
# has both conventions, one per seam "family"). Matching
# `FakeThreatIntelClient`'s convention literally, not just its shape,
# `FakeM2Client` lives in `backend/tests/fakes.py`.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# RealM2Client - the real, schema-verified implementation
# ---------------------------------------------------------------------------


class RealM2Client(M2Client):
    """Real implementation - POSTs to `{base_url}/v1/predict`, mapping a
    group's `RawEvent`s onto M2's documented `EventInput`/prediction-request
    schema (see this module's own docstring for the exact field mapping and
    why `ppid`/`bytes` are omitted). Constructing this class opens no
    connection (same convention as every other `Real*` class in this
    codebase) - only `score()` needs a reachable M2 service.

    No trained M2 model artifact exists yet (Part 2 of the spec - gated on
    someone running M2's own training pipeline against the Lifecycle
    dataset, not this task's job): `/v1/predict` will genuinely return a
    clean `503` on every real call for as long as that remains true. This
    class is designed to handle that gracefully by construction, not as a
    simulated/mocked state - `score()` returns `None` for a `503` exactly
    the same way it would for any other non-2xx response, no special-casing
    needed.

    **Never raises for an ordinary failure**: connection error, timeout, any
    non-2xx response (`503` included), or a malformed/unparseable response
    body all return `None` instead of propagating - mirrors
    `RealVirusTotalClient.lookup()`'s now-established never-raise discipline
    exactly (no `raise_for_status()` anywhere in this class)."""

    def __init__(self, base_url: str, timeout: float = 3.0) -> None:
        self.base_url = base_url.rstrip("/")
        # 3-second timeout - same number `RealVirusTotalClient`/the SDD's
        # own X-Force design used, carried over for the same reasoning: a
        # slow/unreachable M2 service must never stall a whole IRDP poll.
        self.timeout = timeout

    @staticmethod
    def _event_payload(raw: RawEvent) -> Optional[Dict[str, Any]]:
        """One `RawEvent` -> one M2 `EventInput` dict, or `None` if this
        event has nothing mappable onto M2's *required* `event_type` field
        (no `auditd_syscall`) or an unparseable `timestamp` - see this
        module's own docstring for why such events are left out of the
        request entirely rather than sent with a fabricated event_type."""
        if raw.auditd_syscall is None:
            return None
        try:
            ts = _parse_ts_epoch(raw.timestamp)
        except (ValueError, TypeError):
            return None

        payload: Dict[str, Any] = {
            "timestamp": ts,
            "event_type": raw.auditd_syscall,
            "operation": raw.auditd_syscall,
        }
        if raw.process_id is not None:
            payload["pid"] = raw.process_id
        if raw.process_name:
            payload["process_name"] = raw.process_name
        if raw.file_path:
            payload["path"] = raw.file_path
        return payload

    def score(self, events: Sequence[RawEvent], run_id: str) -> Optional[M2Result]:
        mapped: List[Tuple[float, Dict[str, Any]]] = []
        for raw in events:
            payload = self._event_payload(raw)
            if payload is not None:
                mapped.append((payload["timestamp"], payload))

        if not mapped:
            # Nothing mappable this poll - no HTTP call made, mirrors
            # RealVirusTotalClient.lookup()'s own "no indicators to check"
            # short-circuit exactly.
            return None

        mapped.sort(key=lambda pair: pair[0])
        timestamps = [ts for ts, _ in mapped]
        body: Dict[str, Any] = {
            "run_id": run_id,
            "start": timestamps[0],
            "end": timestamps[-1],
            "top_k": DEFAULT_TOP_K,
            "events": [payload for _, payload in mapped],
        }

        import requests  # lazy import - see event_source.RealWazuhEventSource's own convention

        try:
            resp = requests.post(
                f"{self.base_url}/v1/predict",
                json=body,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException:
            # Any other transport-level failure (DNS, connection refused,
            # TLS, etc.) - degraded mode, not a crash.
            return None

        if resp.status_code >= 400:
            # Includes the real, expected 503 "no model loaded yet" state -
            # no special-casing needed, every non-2xx is "no opinion".
            return None

        try:
            data = resp.json()
            return M2Result(
                prediction=data["prediction"],
                ransomware_probability=float(data["ransomware_probability"]),
                threshold=float(data["threshold"]),
                alert=bool(data["alert"]),
                model_name=data["model_name"],
                feature_version=data["feature_version"],
                explanation=list(data.get("explanation") or []),
            )
        except (ValueError, KeyError, TypeError):
            # 2xx but an unparseable/unexpected body shape - still a
            # failure, not a crash.
            return None
