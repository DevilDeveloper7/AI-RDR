"""
Risk Fusion Engine (task 4.4; planning/risk-fusion-spec.md).

Fuses ML anomaly score (backend/ml_scoring.py, task 4.2 - real, live) and
IBM X-Force threat-intel reputation (task 4.3 - not built yet, only the seam
exists here) into the single `risk_tier` ARM's already-live
`POST /api/arm/trigger` endpoint expects (backend/arm.py's `select_playbook`).

**Scope boundary (read planning/risk-fusion-spec.md's "real scope boundary"
section for the full reasoning, not re-derived here)**: honey-file triggers
bypass Risk Fusion entirely - `backend/arm.py`'s `select_playbook()` already
special-cases `honeyfile_triggered`/`"honeyfile" in signals` before ever
looking at `risk_tier`. So `honey_file_triggered` below is accepted only to
populate the dashboard's display-only Honey-File signal slot - it is never
read by the risk_tier computation itself. Don't let that leak; see `fuse()`'s
own docstring and `test_risk_fusion.py`'s explicit guarantee test.

Layout mirrors `backend/host_controller.py` / `backend/irdp/event_source.py` /
`backend/irdp/writer.py`'s established pattern: one ABC, one real
implementation that is importable/instantiable with no live infra (never
exercised live in this phase - no X-Force API key, no live ARM endpoint), and
one fake used by every test (`backend.tests.fakes.FakeThreatIntelClient`,
`FakeTriggerSender` below).

**Phase A only**: this module is not wired into IRDP's `run_once()` and never
makes a real HTTP call in this phase - both explicitly deferred to Phase B
(see the spec's "Explicitly out of scope" section).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from pipeline.training.model import DEFAULT_THRESHOLD

# risk_tier values that warrant notifying ARM at all - "low" is ARM's own
# `logged_only` case (select_playbook() returns None for it, Table 6.4.1a's
# "Low has no playbook"), so a low-tier fused result should never reach
# ARM's /api/arm/trigger in the first place. Kept as a module-level constant,
# not a magic set duplicated at each call site.
ARM_NOTIFIABLE_TIERS = frozenset({"medium", "high", "critical"})


# ---------------------------------------------------------------------------
# Threat-intel client seam (mirrors WazuhEventSource/HostController exactly)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThreatIntelResult:
    """One threat-intel lookup outcome. Deliberately minimal - just enough
    for `fuse()`'s corroboration table and the dashboard's Threat-Intel
    signal slot to work with.

    matched   - True iff at least one submitted indicator came back
                known-bad. False (not None) is the normal "checked, clean"
                result; a lookup that could not be performed at all (e.g. no
                indicators to check) should also produce matched=False, not
                a third tri-state value - `fuse()` treats "no match" and
                "nothing to check" identically per the spec's corroboration
                table (both fall through to the no-match rows).
    indicator - the specific matched indicator (IP/hash/domain/etc.), for
                the dashboard note and the ARM payload's `indicator` field.
                None when matched is False.
    source    - free-text provenance of the result, e.g. "xforce" for a real
                lookup or "fake" for test fixtures - never used for control
                flow, just for audit/debugging.
    raw       - optional passthrough of whatever raw response backed this
                result (e.g. X-Force's own JSON), kept only for debugging/
                audit; never read by `fuse()`.
    """

    matched: bool
    indicator: Optional[str] = None
    source: str = "unknown"
    raw: Optional[Dict[str, Any]] = None


class ThreatIntelClient(ABC):
    """Abstract threat-intel lookup, mirroring `HostController`'s/
    `WazuhEventSource`'s pattern exactly: one ABC, one real stub
    (`RealXForceClient`, parameterized but never exercised live here), one
    fake for tests (`backend.tests.fakes.FakeThreatIntelClient`)."""

    @abstractmethod
    def lookup(self, indicators: Dict[str, Any]) -> ThreatIntelResult:
        """`indicators` is a free-form dict of whatever candidate
        IOCs are available for this entity (e.g. `{"ip": "1.2.3.4", "hash":
        "..."}`) - callers pass only the keys they actually have; a real
        client is free to check any subset it understands. Must return a
        `ThreatIntelResult`, never raise for an ordinary "no match" (only for
        a genuine transport/auth failure)."""


class RealXForceClient(ThreatIntelClient):
    """Stub real implementation - would POST to IBM X-Force Exchange's
    reputation API (`https://api.xforce.ibmcloud.com/...`) using HTTP basic
    auth (API key/password pair, per X-Force's own auth scheme). Task 4.3
    (IBM X-Force integration) does not exist yet - no credentials, no
    request/response shape has been verified against the real API. This
    class exists only as the seam that task will fill in: constructing it is
    always safe (no network call happens until `lookup()` runs), matching
    `RealWazuhEventSource`/`OpenSearchEventWriter`'s own convention. Never
    exercised live in this phase - no API key is available or assumed (task
    instructions)."""

    def __init__(
        self,
        host: str = "api.xforce.ibmcloud.com",
        api_key: str = "",
        api_password: str = "",
        verify_ssl: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.api_key = api_key
        self.api_password = api_password
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def lookup(self, indicators: Dict[str, Any]) -> ThreatIntelResult:
        import requests  # lazy import - see event_source.RealWazuhEventSource's
        # own convention; keeps this module importable with no network deps
        # installed/reachable.

        ip = indicators.get("ip")
        file_hash = indicators.get("hash")
        if ip:
            url = f"https://{self.host}/ipr/{ip}"
        elif file_hash:
            url = f"https://{self.host}/malware/{file_hash}"
        else:
            return ThreatIntelResult(matched=False, source="xforce")

        resp = requests.get(
            url,
            auth=(self.api_key, self.api_password),
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        # Plausible X-Force response shape (ip reputation carries a "score"
        # 1-10, malware lookup carries "malware": {...} when known) - not
        # verified against a live call, same disclosed-not-proven status as
        # RealWazuhEventSource's request/response mapping. Task 4.3 should
        # verify/adjust this against a real key before relying on it.
        matched = bool(body.get("malware")) or float(body.get("score", 0)) >= 5
        return ThreatIntelResult(
            matched=matched, indicator=ip or file_hash, source="xforce", raw=body
        )


class RealVirusTotalClient(ThreatIntelClient):
    """Real, schema-verified implementation (task 4.3; see
    planning/threat-intel-spec.md's "Real, disclosed deviation from the
    SDD/SRS" section for why this - not `RealXForceClient` - is the live
    default once a real API key exists). IBM X-Force Exchange's free tier is
    confirmed gone (checked directly against IBM's own current API docs,
    not assumed); this project's contingency plan (quoted verbatim from the
    SRS's own risk register) names VirusTotal explicitly as the fallback.

    Hits VirusTotal's public API v3 (`https://www.virustotal.com/api/v3`):
    `GET /ip_addresses/{ip}` or `GET /files/{hash}`, auth via the `x-apikey`
    header (not HTTP Basic, unlike X-Force). Schema verified directly
    against `https://virustotal.readme.io/reference/ip-object` and
    `.../reference/files` before writing this - not carried forward as an
    assumption the way `RealXForceClient`'s own `score`/`malware` guess was.

    Constructing this class is always safe (no network call until
    `lookup()` runs) - same convention as every other real class in this
    codebase (`RealXForceClient`, `RealWazuhEventSource`,
    `OpenSearchEventWriter`, etc.).

    **Matched decision (disclosed judgment call - no official VT threshold
    exists for this)**: `last_analysis_stats.malicious >= 1` - at least one
    AV engine flags the indicator. Maps most directly onto Table 6.4.1a's
    "X-Force known-bad indicator" language (any positive hit, not a tuned
    confidence band). Revisit with real false-positive data later (task
    3.5), same disclosed-not-final status as `DEFAULT_THRESHOLD` itself.

    **Field-mapping gap (disclosed)**: VirusTotal's shape doesn't map 1:1
    onto the SDD's `ai-rdr-threat-intel-*` field names (`xforce_score`,
    `malware_family`, `threat_category` were named after X-Force's own
    fields, before this substitution was known to be needed). Rather than
    invent new field names and touch the already-defined data dictionary,
    this class stores VT's real values under those same SDD-named fields,
    inside `ThreatIntelResult.raw` (never read by `fuse()`, only by
    `CachedThreatIntelClient`/`OpenSearchThreatIntelCache` below and by the
    dashboard/audit trail):
      - `xforce_score` <- the vendor-malicious-count (`last_analysis_stats
        .malicious`), NOT `reputation` - documented choice, not the only
        possible one; picked because it is the same number the match
        decision itself is based on, so the two can never disagree.
      - `malware_family` <- `popular_threat_classification
        .suggested_threat_label` when present; VT's docs commonly describe
        this field but it was **not independently confirmed against a real
        response in this pass** (ip lookups don't have it at all - hash-only
        field), so this falls back to `attributes.type_description` when
        absent, exactly as the spec instructs, rather than silently
        assuming the preferred field always exists.
      - `threat_category` <- `attributes.tags` when non-empty, else
        `attributes.type_description`.

    **Never raises for an ordinary failure** (matches `ThreatIntelClient
    .lookup()`'s own documented contract): a timeout, a connection error, a
    non-2xx response (429 most importantly, VT's free/Public tier limit is
    4 req/min, 500/day), or an unparseable body are all caught and turned
    into `ThreatIntelResult(matched=False, source="virustotal", raw=
    {"lookup_status": ...})` instead of propagating - this is what actually
    satisfies the SRS's AVAIL-1.2 degraded-mode requirement, not just an
    assumption that nothing ever fails.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = "", timeout: float = 3.0) -> None:
        self.api_key = api_key
        # 3-second timeout - same number the SDD's own X-Force design
        # called for ("asynchronous IBM X-Force worker with 3-second lookup
        # timeout"), carried over verbatim for VirusTotal per the spec.
        self.timeout = timeout

    def lookup(self, indicators: Dict[str, Any]) -> ThreatIntelResult:
        ip = indicators.get("ip")
        file_hash = indicators.get("hash")
        if ip:
            url = f"{self.BASE_URL}/ip_addresses/{ip}"
        elif file_hash:
            url = f"{self.BASE_URL}/files/{file_hash}"
        else:
            # No indicators to check at all - no HTTP call made, mirrors
            # RealXForceClient's own short-circuit exactly.
            return ThreatIntelResult(matched=False, source="virustotal")

        indicator = ip or file_hash

        import requests  # lazy import - see RealXForceClient's own convention

        try:
            resp = requests.get(
                url,
                headers={"x-apikey": self.api_key},
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            return ThreatIntelResult(
                matched=False, source="virustotal", raw={"lookup_status": "timeout"}
            )
        except requests.exceptions.RequestException:
            # Any other transport-level failure (DNS, connection refused,
            # TLS, etc.) - degraded mode, not a crash.
            return ThreatIntelResult(
                matched=False, source="virustotal", raw={"lookup_status": "failed"}
            )

        if resp.status_code == 429:
            return ThreatIntelResult(
                matched=False, source="virustotal", raw={"lookup_status": "rate_limited"}
            )
        if resp.status_code >= 400:
            return ThreatIntelResult(
                matched=False, source="virustotal", raw={"lookup_status": "failed"}
            )

        try:
            body = resp.json()
            attributes = body["data"]["attributes"]
            stats = attributes.get("last_analysis_stats") or {}
            malicious_count = int(stats.get("malicious") or 0)
        except (ValueError, KeyError, TypeError):
            # 2xx but an unparseable/unexpected body shape - still a
            # failure, not a crash.
            return ThreatIntelResult(
                matched=False, source="virustotal", raw={"lookup_status": "failed"}
            )

        matched = malicious_count >= 1

        malware_family = attributes.get("popular_threat_classification", {})
        if isinstance(malware_family, dict):
            malware_family = malware_family.get("suggested_threat_label")
        if not malware_family:
            malware_family = attributes.get("type_description")

        threat_category = attributes.get("tags") or attributes.get("type_description")

        return ThreatIntelResult(
            matched=matched,
            # Always set (matching RealXForceClient's own convention) -
            # fuse() itself already nulls this out when matched is False
            # (`indicator = ... if (threat_intel_result and matched) else
            # None`), so setting it unconditionally here is harmless there
            # and keeps the checked-but-clean indicator available to the
            # cache/dashboard/audit trail.
            indicator=indicator,
            source="virustotal",
            raw={
                "lookup_status": "ok",
                "xforce_score": malicious_count,
                "malware_family": malware_family,
                "threat_category": threat_category,
                "last_analysis_stats": stats,
            },
        )


class NullThreatIntelClient(ThreatIntelClient):
    """Real, no-op `ThreatIntelClient` implementation - a genuine
    implementation of the ABC (not a bypass of it), used as the live default
    for as long as task 4.3 (IBM X-Force) doesn't exist. Always returns an
    unmatched result regardless of what indicators are passed, so every real
    fused trigger produced through this client is capped at `risk_tier:
    "medium"` (the `fuse()` corroboration table's no-threat-intel-match
    rows) - expected, not a bug. Swapping in `RealXForceClient` later needs
    zero pipeline changes: same constructor-is-always-safe convention, same
    `lookup()` contract."""

    def lookup(self, indicators: Dict[str, Any]) -> ThreatIntelResult:
        return ThreatIntelResult(matched=False, source="none configured")


# ---------------------------------------------------------------------------
# Threat-intel caching layer (task 4.3; planning/threat-intel-spec.md's
# "A caching layer" section). Load-bearing, not optional: VirusTotal's
# free/Public tier allows only 4 requests/minute, 500/day - tighter than
# the IBM X-Force free tier the SDD originally assumed - while IRDP's
# run_once() (backend/irdp/pipeline.py) polls every 30s, so a busy window
# with no cache could burn the whole daily quota in minutes. Mirrors
# `backend.irdp.checkpoint.CheckpointStore`'s exact pattern: one ABC, one
# in-memory fake for tests, one real OpenSearch-backed implementation never
# exercised live in this phase.
# ---------------------------------------------------------------------------


class ThreatIntelCache(ABC):
    """Abstract cache for `ThreatIntelResult`s, keyed by (ioc_type,
    ioc_value) - e.g. ("ip", "1.2.3.4") or ("hash", "deadbeef...") - matching
    the same two indicator kinds `ThreatIntelClient.lookup()` already
    understands.

    **Never-raise contract (load-bearing, not advisory)**: both `get()` and
    `put()` must never raise for an ordinary cache-backend failure -
    connection error, timeout, a non-2xx/404 response, or an unparseable
    body. `get()` must return `None` in those cases, identical to a clean
    cache miss (same as an expired entry). `put()` must silently no-op in
    those cases - losing a cache write is low-stakes (the next lookup just
    hits the real API again), so it must never be allowed to propagate and
    take down a caller's whole batch. Any real implementation (see
    `OpenSearchThreatIntelCache`) must catch these failure categories
    explicitly, mirroring `RealVirusTotalClient.lookup()`'s own never-raise
    discipline - not just trust that nothing ever fails."""

    @abstractmethod
    def get(self, ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        """Return the cached result for (ioc_type, ioc_value), or `None` on
        a miss - including an *expired* entry or an ordinary backend failure
        (connection error, timeout, non-2xx/404 response, unparseable body),
        which must all behave exactly like a miss (never raise, never
        return stale data)."""

    @abstractmethod
    def put(self, ioc_type: str, ioc_value: str, result: ThreatIntelResult, ttl_seconds: float) -> None:
        """Store `result` for (ioc_type, ioc_value), to be treated as a
        miss again once `ttl_seconds` have elapsed. Must silently no-op (not
        raise) on an ordinary backend failure (connection error, timeout,
        non-2xx response, unparseable body) - a lost cache write is not a
        caller-visible failure."""


class InMemoryThreatIntelCache(ThreatIntelCache):
    """Default cache for tests - no filesystem/network access, state lives
    only as long as the Python object does. Mirrors `InMemoryCheckpointStore`
    exactly (dict-backed, nothing fancier needed at this scale)."""

    def __init__(self) -> None:
        self._data: Dict[Tuple[str, str], Tuple[ThreatIntelResult, float]] = {}

    def get(self, ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        entry = self._data.get((ioc_type, ioc_value))
        if entry is None:
            return None
        result, expires_at = entry
        if time.time() >= expires_at:
            # Expired - treat exactly like a miss. Also drop the stale
            # entry so a long-lived process doesn't accumulate dead rows
            # forever (not strictly required by the ABC contract, just
            # good hygiene for the in-memory case).
            del self._data[(ioc_type, ioc_value)]
            return None
        return result

    def put(self, ioc_type: str, ioc_value: str, result: ThreatIntelResult, ttl_seconds: float) -> None:
        self._data[(ioc_type, ioc_value)] = (result, time.time() + ttl_seconds)


class OpenSearchThreatIntelCache(ThreatIntelCache):
    """Real cache implementation, backed by a dedicated OpenSearch index
    using the SDD's already-named `ai-rdr-threat-intel-*` field names
    (`ioc_value`, `ioc_type`, `xforce_score`, `malware_family`,
    `threat_category`, `lookup_status`, `cache_expiry`) - task 4.3 is the
    first thing that actually populates this index. Deliberately NOT
    exercised against live OpenSearch in this phase, same disclosed-not-
    proven status as every other `Real*`/`OpenSearch*` class in this
    codebase; constructing this class opens no network connection, only
    `get()`/`put()` need a reachable indexer.

    **Deliberately a single, non-rotating index** (default `ai-rdr-threat-
    intel-cache`), NOT a daily-rotating `-YYYY.MM.DD` one the way
    `OpenSearchEventWriter`'s append-only log indices are - same category of
    disclosed judgment call `OpenSearchActionStore` (backend/arm.py) already
    made for its own `ai-rdr-arm-action-state` index. A cache needs `get()`
    to find a document written on a *previous* day within its 24h TTL by a
    stable id; a daily-rotating index would silently turn every cache
    lookup into a guaranteed miss once midnight UTC passes mid-TTL, directly
    defeating the whole point of this class. One document per (ioc_type,
    ioc_value) pair, `_id` = `"{ioc_type}:{ioc_value}"`, overwritten in
    place on every `put()` - matching `OpenSearchActionStore`'s own
    get/put-by-id semantics exactly.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 9200,
        index: str = "ai-rdr-threat-intel-cache",
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

    @staticmethod
    def _doc_id(ioc_type: str, ioc_value: str) -> str:
        return f"{ioc_type}:{ioc_value}"

    def get(self, ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        import requests  # lazy import - see RealXForceClient's own convention

        try:
            resp = requests.get(
                self._url(f"{self.index}/_doc/{self._doc_id(ioc_type, ioc_value)}"),
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            return None  # degraded mode - treat exactly like a miss
        except requests.exceptions.RequestException:
            # Any other transport-level failure (DNS, connection refused,
            # TLS, etc.) - same never-raise discipline as
            # RealVirusTotalClient.lookup().
            return None

        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            # Any other non-2xx response (403, 500, etc.) - a cache-backend
            # failure, not a crash. No raise_for_status() here (that's
            # exactly the bug being fixed): treat it as a miss.
            return None

        try:
            doc = resp.json()["_source"]
        except (ValueError, KeyError, TypeError):
            # 2xx but an unparseable/unexpected body shape - still a
            # failure, not a crash.
            return None

        import datetime  # lazy import - see OpenSearchEventWriter._index_name's own convention

        cache_expiry = doc.get("cache_expiry")
        if cache_expiry is not None:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if now >= cache_expiry:
                return None  # expired - treat exactly like a miss

        return ThreatIntelResult(
            matched=bool(doc.get("matched", False)),
            indicator=doc.get("indicator"),
            source=doc.get("source", "virustotal"),
            raw={
                "lookup_status": doc.get("lookup_status"),
                "xforce_score": doc.get("xforce_score"),
                "malware_family": doc.get("malware_family"),
                "threat_category": doc.get("threat_category"),
            },
        )

    def put(self, ioc_type: str, ioc_value: str, result: ThreatIntelResult, ttl_seconds: float) -> None:
        import requests  # lazy import - see RealXForceClient's own convention
        import datetime  # lazy import - see OpenSearchEventWriter._index_name's own convention

        raw = result.raw or {}
        now = datetime.datetime.now(datetime.timezone.utc)
        expiry = (now + datetime.timedelta(seconds=ttl_seconds)).isoformat()
        doc = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "matched": result.matched,
            "indicator": result.indicator,
            "source": result.source,
            "xforce_score": raw.get("xforce_score"),
            "malware_family": raw.get("malware_family"),
            "threat_category": raw.get("threat_category"),
            "lookup_status": raw.get("lookup_status"),
            "cache_expiry": expiry,
        }
        try:
            resp = requests.put(
                self._url(f"{self.index}/_doc/{self._doc_id(ioc_type, ioc_value)}"),
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                json=doc,
            )
        except requests.exceptions.Timeout:
            return  # silently no-op - losing a cache write is low-stakes
        except requests.exceptions.RequestException:
            return

        if resp.status_code >= 400:
            # Non-2xx (403, 500, etc.) - silently no-op, same reasoning as
            # above. No raise_for_status() here (that's exactly the bug
            # being fixed).
            return


class CachedThreatIntelClient(ThreatIntelClient):
    """Wraps any other `ThreatIntelClient` + a `ThreatIntelCache` - the
    actual rate-limit protection VirusTotal's 4/min, 500/day free tier
    needs, proven (not just asserted) by
    `backend/tests/test_risk_fusion.py`'s call-counting tests against a
    `FakeThreatIntelClient`.

    `lookup()` checks the cache first, keyed on whichever of `ip`/`hash` is
    present in `indicators` - same key priority the wrapped client itself
    uses (`ip` before `hash`; see `RealVirusTotalClient.lookup()`). On a
    cache hit, the wrapped client's `lookup()` is **not called at all**. On
    a miss, calls the wrapped client once and writes the result back with
    `ttl_seconds` (default **24 hours** - disclosed judgment call, balances
    staleness against the free tier's daily quota; revisit with real usage
    data later).

    If `indicators` carries neither `ip` nor `hash`, there is nothing to key
    the cache on - this falls straight through to the wrapped client
    (itself a no-op/no-HTTP-call short-circuit for every real client in this
    codebase), without touching the cache at all.

    **Disclosed scope note**: caches whatever `ThreatIntelResult` the
    wrapped client returns, including a `lookup_status` of `"timeout"`/
    `"rate_limited"`/`"failed"` - simplest correct behavior for Phase A ("the
    result" is cached, full stop, matching the spec's literal wording), not
    a judgment that caching failures is definitely the right long-term
    choice. A smarter failure-aware TTL (e.g. don't cache transient
    failures, or cache them for a much shorter time) is a plausible later
    refinement, not built here.
    """

    def __init__(
        self,
        wrapped: ThreatIntelClient,
        cache: ThreatIntelCache,
        ttl_seconds: float = 24 * 60 * 60.0,
    ) -> None:
        self.wrapped = wrapped
        self.cache = cache
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _key(indicators: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        ip = indicators.get("ip")
        file_hash = indicators.get("hash")
        if ip:
            return "ip", ip
        if file_hash:
            return "hash", file_hash
        return None, None

    def lookup(self, indicators: Dict[str, Any]) -> ThreatIntelResult:
        ioc_type, ioc_value = self._key(indicators)
        if ioc_type is None or ioc_value is None:
            return self.wrapped.lookup(indicators)

        # Belt-and-suspenders: `cache.get()` is contractually never
        # supposed to raise (see `ThreatIntelCache`'s own docstring), but a
        # cache-backend failure of any kind must degrade to "one entity's
        # enrichment falls through to the real client", never crash the
        # whole batch - don't just trust the contract, defend against a
        # violation of it too. Mirrors this codebase's layered-safety style
        # (RealVirusTotalClient catches several distinct exception
        # categories rather than relying on a single broad guard).
        try:
            cached = self.cache.get(ioc_type, ioc_value)
        except Exception:
            cached = None
        if cached is not None:
            return cached

        result = self.wrapped.lookup(indicators)
        try:
            self.cache.put(ioc_type, ioc_value, result, self.ttl_seconds)
        except Exception:
            pass  # losing a cache write is low-stakes - never let it mask a real result
        return result


# ---------------------------------------------------------------------------
# The fusion rule itself
# ---------------------------------------------------------------------------


def fuse(
    ml_detection: Dict[str, Any],
    threat_intel_result: Optional[ThreatIntelResult],
    honey_file_triggered: bool = False,
) -> Dict[str, Any]:
    """The core corroboration-table fusion rule (planning/risk-fusion-spec.md
    - designed here, not extracted from the SDD, which gives no formula for
    this; disclosed there explicitly).

    `ml_detection` is one `ai-rdr-ml-detections-*`-shaped dict, matching
    `backend/ml_scoring.py`'s `score_windows()` output field names exactly
    (`host_id`, `process_id`, `anomaly_score`). `anomaly_score` may be absent
    or None to represent "no ML signal available for this entity" (the
    corroboration table's 3rd row) - `host_id` is still required even then,
    since Risk Fusion always operates on a known entity.

    `threat_intel_result` may be None (equivalent to an unmatched/no-op
    lookup - the same as `ThreatIntelResult(matched=False)`) for callers that
    have not run a threat-intel lookup at all yet.

    `honey_file_triggered` is accepted ONLY to populate the dashboard's
    display-only Honey-File signal slot (planning/risk-fusion-spec.md's
    output-shape section) - it never participates in the risk_tier decision
    below. Honey-file's real routing is ARM's own `select_playbook()`
    special-case, upstream of this function entirely.

    Corroboration table (spec's exact 4 rows, `threshold` = DEFAULT_THRESHOLD
    = 0.65, `model.DEFAULT_THRESHOLD`):

        anomaly_score < threshold (or absent) , no match  -> low
        anomaly_score >= threshold            , no match  -> medium
        any / no ML signal                    , match     -> high
        anomaly_score >= threshold            , match     -> critical

    Returns one dict carrying BOTH output shapes the spec describes, under
    unambiguous, distinctly-named keys so a caller can't confuse them:

      ARM's trigger-payload fields (flat, matches `POST /api/arm/trigger` /
      `select_playbook()`'s own contract exactly):
        risk_tier, host, entity, arm_signals (flat list, e.g.
        ["ml_anomaly"], ["threat_intel"], or both - a caller building the
        real ARM payload maps this list onto the `signals` key
        `select_playbook()` reads), process_id, indicator.

      The dashboard/explainability fields (analysis/demo-analysis.md's
      contract - a DIFFERENT shape under a DIFFERENT key than arm_signals,
      named distinctly on purpose):
        dashboard_signals: [{label, v (0-1), note}] x3 (Honey-File/ML/
        Threat-Intel, in that order), fusion_line (templated string, no LLM
        call, per task-breakdown.md's "Verdict-sentence generator" note).
    """
    threshold = DEFAULT_THRESHOLD

    host_id = ml_detection.get("host_id") if ml_detection else None
    process_id = ml_detection.get("process_id") if ml_detection else None
    ml_score = ml_detection.get("anomaly_score") if ml_detection else None
    ml_above_threshold = ml_score is not None and ml_score >= threshold

    matched = bool(threat_intel_result and threat_intel_result.matched)
    indicator = threat_intel_result.indicator if (threat_intel_result and matched) else None

    # The tier lattice - order matters (critical checked first): a
    # corroboration requirement, not a blend, per the spec's "Why this
    # shape, not a weighted-sum score" section - no single weak signal can
    # reach the top tier alone, by construction.
    if ml_above_threshold and matched:
        risk_tier = "critical"
    elif matched:
        risk_tier = "high"
    elif ml_above_threshold:
        risk_tier = "medium"
    else:
        risk_tier = "low"

    arm_signals: List[str] = []
    if ml_above_threshold:
        arm_signals.append("ml_anomaly")
    if matched:
        arm_signals.append("threat_intel")

    entity = f"{host_id}:{process_id}" if (host_id and process_id is not None) else host_id

    # --- dashboard signals (display-only Honey-File slot included here) ---
    dashboard_signals = [
        {
            "label": "Honey-File",
            "v": 1.0 if honey_file_triggered else 0.0,
            "note": (
                "Honey-file access detected (routed separately by ARM's own "
                "PB-04 bypass; shown here for display only)"
                if honey_file_triggered
                else "No honey-file activity observed"
            ),
        },
        {
            "label": "ML Anomaly",
            "v": float(ml_score) if ml_score is not None else 0.0,
            "note": (
                f"anomaly_score={ml_score:.2f} (threshold={threshold:.2f})"
                if ml_score is not None
                else "no ML anomaly signal available"
            ),
        },
        {
            "label": "Threat-Intel",
            "v": 1.0 if matched else 0.0,
            "note": (f"known-bad match on {indicator}" if matched else "no threat-intel match"),
        },
    ]

    # --- fusion_line: templated, no LLM call ---
    ml_phrase = (
        f"ML anomaly score of {ml_score:.2f}" if ml_score is not None else "no ML anomaly signal available"
    )
    ti_phrase = (
        f"corroborated by a known-bad X-Force match on {indicator}" if matched else "no threat-intel match"
    )
    fusion_line = f"{ml_phrase}; {ti_phrase} -> risk_tier: {risk_tier}."

    return {
        # ARM trigger-payload fields
        "risk_tier": risk_tier,
        "host": host_id,
        "entity": entity,
        "process_id": process_id,
        "indicator": indicator,
        "arm_signals": arm_signals,
        # dashboard/explainability fields
        "dashboard_signals": dashboard_signals,
        "fusion_line": fusion_line,
    }


# ---------------------------------------------------------------------------
# Trigger-sender seam (mirrors EventWriter exactly)
# ---------------------------------------------------------------------------


class TriggerSender(ABC):
    """Abstraction for actually notifying ARM of a fused result - same seam
    pattern as `backend.irdp.writer.EventWriter`. `send()` takes `fuse()`'s
    output dict directly (not a pre-built ARM payload) so implementations
    own the mapping from `arm_signals` onto the `signals` key
    `select_playbook()` reads, in one place."""

    @abstractmethod
    def send(self, fused: Dict[str, Any]) -> Dict[str, Any]:
        """Notify ARM of `fused` (a `fuse()` result dict) and return
        whatever response comes back (a real implementation returns ARM's
        JSON response body; a fake returns a synthetic acknowledgement)."""


def _arm_payload(fused: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the exact flat payload `POST /api/arm/trigger` /
    `select_playbook()` expects out of a `fuse()` result - the one place
    that maps `arm_signals` onto the `signals` key ARM's code actually reads,
    so `TriggerSender` implementations don't each have to know that mapping
    themselves."""
    payload = {
        "host": fused["host"],
        "entity": fused["entity"],
        "risk_tier": fused["risk_tier"],
        "signals": list(fused.get("arm_signals") or []),
    }
    if fused.get("process_id") is not None:
        payload["process_id"] = fused["process_id"]
    if fused.get("indicator"):
        payload["indicator"] = fused["indicator"]
    return payload


class HttpTriggerSender(TriggerSender):
    """Real implementation - POSTs `_arm_payload(fused)` to ARM's already-live
    `POST /api/arm/trigger` (backend/app.py). Deliberately NOT exercised
    against a live endpoint in this phase (no reachable ARM deployment is
    assumed here - task instructions); constructing this class opens no
    connection, only `send()` needs a reachable ARM endpoint, matching every
    other real-HTTP class's convention in this codebase (lazy `requests`
    import)."""

    def __init__(self, base_url: str, timeout: float = 10.0, verify_ssl: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def send(self, fused: Dict[str, Any]) -> Dict[str, Any]:
        import requests  # lazy import - see event_source.RealWazuhEventSource

        resp = requests.post(
            f"{self.base_url}/api/arm/trigger",
            json=_arm_payload(fused),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()
        return resp.json()


def send_trigger_if_needed(fused: Dict[str, Any], sender: TriggerSender) -> Optional[Dict[str, Any]]:
    """Calls `sender.send()` only for `risk_tier` in `ARM_NOTIFIABLE_TIERS`
    ({"medium", "high", "critical"}) - matches `select_playbook()`'s own
    "Low tier has no playbook" design (arm.py: `select_playbook()` returns
    `None` for `risk_tier == "low"`, and `handle_trigger()` treats that as
    `logged_only`, never calling any playbook). Returns `None` (and never
    calls `sender`) for `low`, so a low-tier fused result never reaches ARM
    at all - not even to be told to ignore it."""
    if fused["risk_tier"] not in ARM_NOTIFIABLE_TIERS:
        return None
    return sender.send(fused)
