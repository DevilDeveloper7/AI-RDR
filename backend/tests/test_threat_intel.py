"""
Threat Intelligence Enrichment tests (task 4.3; planning/threat-intel-spec.md).

Covers `RealVirusTotalClient` (real, schema-verified HTTP client, exercised
here only against mocked `requests` responses - no live network, no real
API key, per the spec's explicit Phase-A boundary) and the caching layer
(`InMemoryThreatIntelCache` + `CachedThreatIntelClient`) that makes
VirusTotal's tight free-tier rate limit (4 req/min, 500/day) survivable.
Also proves the new client is a true drop-in `ThreatIntelClient` for
`fuse()` - no upstream changes needed.

No live OpenSearch access, no live VirusTotal access - every `requests`
call is mocked, matching `backend/tests/test_action_store.py`'s own
established pattern for this codebase (`unittest.mock.patch` on the
lazily-imported `requests` module, since RealVirusTotalClient/
OpenSearchThreatIntelCache both lazy-import `requests` the same way
`RealXForceClient` does).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from pipeline.training.model import DEFAULT_THRESHOLD

from backend.risk_fusion import (
    CachedThreatIntelClient,
    InMemoryThreatIntelCache,
    OpenSearchThreatIntelCache,
    RealVirusTotalClient,
    ThreatIntelCache,
    ThreatIntelResult,
    fuse,
)
from backend.tests.fakes import FakeThreatIntelClient


def _opensearch_response(status_code=200, source=None):
    # Mirrors test_action_store.py's own `_fake_response` convention
    # exactly: a MagicMock doesn't raise on `.raise_for_status()` unless
    # its `side_effect` is configured, so this is what actually makes a
    # mocked 403/500 exercise the real raise_for_status() bug/fix instead
    # of silently no-op'ing on an unconfigured mock method.
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status.side_effect = (
        requests.HTTPError() if status_code >= 400 else None
    )
    if source is not None:
        resp.json.return_value = {"_source": source}
    return resp


class BrokenThreatIntelCache(ThreatIntelCache):
    """Deliberately-broken `ThreatIntelCache` fake - `get()`/`put()` raise
    on every call, violating the ABC's own never-raise contract on purpose.
    Used only to prove `CachedThreatIntelClient.lookup()`'s own belt-and-
    suspenders try/except actually works, independent of whether any real
    `ThreatIntelCache` implementation (e.g. `OpenSearchThreatIntelCache`)
    honors that contract correctly."""

    def get(self, ioc_type: str, ioc_value: str):
        raise RuntimeError("cache backend is on fire")

    def put(self, ioc_type: str, ioc_value: str, result: ThreatIntelResult, ttl_seconds: float) -> None:
        raise RuntimeError("cache backend is on fire")


def _vt_response(status_code=200, malicious=0, extra_attributes=None):
    resp = MagicMock()
    resp.status_code = status_code
    attributes = {"last_analysis_stats": {"malicious": malicious, "harmless": 10}}
    if extra_attributes:
        attributes.update(extra_attributes)
    resp.json.return_value = {"data": {"attributes": attributes}}
    return resp


# ---------------------------------------------------------------------------
# RealVirusTotalClient
# ---------------------------------------------------------------------------


def test_malicious_match_sets_matched_true():
    with patch("requests.get", return_value=_vt_response(malicious=3)) as mock_get:
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"ip": "1.2.3.4"})

    assert result.matched is True
    assert result.indicator == "1.2.3.4"
    assert result.source == "virustotal"
    assert result.raw["lookup_status"] == "ok"
    assert result.raw["xforce_score"] == 3
    mock_get.assert_called_once()
    called_url = mock_get.call_args.args[0]
    assert called_url == "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"
    assert mock_get.call_args.kwargs["headers"] == {"x-apikey": "test-key"}
    assert mock_get.call_args.kwargs["timeout"] == 3.0


def test_clean_result_sets_matched_false():
    with patch("requests.get", return_value=_vt_response(malicious=0)):
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"ip": "1.2.3.4"})

    assert result.matched is False
    assert result.raw["lookup_status"] == "ok"
    assert result.raw["xforce_score"] == 0


def test_hash_lookup_hits_files_endpoint():
    with patch("requests.get", return_value=_vt_response(malicious=1)) as mock_get:
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"hash": "deadbeef"})

    assert result.matched is True
    assert result.indicator == "deadbeef"
    called_url = mock_get.call_args.args[0]
    assert called_url == "https://www.virustotal.com/api/v3/files/deadbeef"


def test_timeout_does_not_raise_and_reports_lookup_status():
    with patch("requests.get", side_effect=requests.exceptions.Timeout()):
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"ip": "1.2.3.4"})

    assert result.matched is False
    assert result.source == "virustotal"
    assert result.raw == {"lookup_status": "timeout"}


def test_rate_limited_429_does_not_raise_and_reports_lookup_status():
    with patch("requests.get", return_value=_vt_response(status_code=429)):
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"ip": "1.2.3.4"})

    assert result.matched is False
    assert result.raw == {"lookup_status": "rate_limited"}


def test_ordinary_http_failure_does_not_raise():
    with patch("requests.get", return_value=_vt_response(status_code=500)):
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"ip": "1.2.3.4"})

    assert result.matched is False
    assert result.raw == {"lookup_status": "failed"}


def test_connection_error_does_not_raise():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError()):
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"ip": "1.2.3.4"})

    assert result.matched is False
    assert result.raw == {"lookup_status": "failed"}


def test_no_indicators_makes_no_http_call():
    with patch("requests.get") as mock_get:
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({})

    mock_get.assert_not_called()
    assert result.matched is False
    assert result.source == "virustotal"
    assert result.raw is None


def test_malware_family_falls_back_to_type_description_when_label_absent():
    with patch(
        "requests.get",
        return_value=_vt_response(malicious=1, extra_attributes={"type_description": "Win32 EXE"}),
    ):
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"hash": "abc123"})

    assert result.raw["malware_family"] == "Win32 EXE"


def test_malware_family_prefers_suggested_threat_label_when_present():
    with patch(
        "requests.get",
        return_value=_vt_response(
            malicious=1,
            extra_attributes={
                "type_description": "Win32 EXE",
                "popular_threat_classification": {"suggested_threat_label": "trojan.generic"},
            },
        ),
    ):
        client = RealVirusTotalClient(api_key="test-key")
        result = client.lookup({"hash": "abc123"})

    assert result.raw["malware_family"] == "trojan.generic"


# ---------------------------------------------------------------------------
# CachedThreatIntelClient - the actual rate-limit protection, proven by
# counting calls to the wrapped (fake) client, not just asserted.
# ---------------------------------------------------------------------------


def test_first_lookup_is_a_cache_miss_and_calls_wrapped_once():
    wrapped = FakeThreatIntelClient(ThreatIntelResult(matched=True, indicator="1.2.3.4", source="fake"))
    client = CachedThreatIntelClient(wrapped, InMemoryThreatIntelCache(), ttl_seconds=3600)

    result = client.lookup({"ip": "1.2.3.4"})

    assert result.matched is True
    assert len(wrapped.calls) == 1


def test_second_lookup_within_ttl_is_a_cache_hit_and_calls_wrapped_zero_more_times():
    wrapped = FakeThreatIntelClient(ThreatIntelResult(matched=True, indicator="1.2.3.4", source="fake"))
    client = CachedThreatIntelClient(wrapped, InMemoryThreatIntelCache(), ttl_seconds=3600)

    first = client.lookup({"ip": "1.2.3.4"})
    assert len(wrapped.calls) == 1

    second = client.lookup({"ip": "1.2.3.4"})

    # The actual rate-limit-protection proof: the wrapped client was NOT
    # called again.
    assert len(wrapped.calls) == 1
    assert second == first


def test_different_ioc_is_a_separate_cache_entry_and_does_call_wrapped():
    wrapped = FakeThreatIntelClient(ThreatIntelResult(matched=False, source="fake"))
    client = CachedThreatIntelClient(wrapped, InMemoryThreatIntelCache(), ttl_seconds=3600)

    client.lookup({"ip": "1.2.3.4"})
    client.lookup({"ip": "5.6.7.8"})

    assert len(wrapped.calls) == 2


def test_expired_cache_entry_triggers_exactly_one_more_real_call(monkeypatch):
    wrapped = FakeThreatIntelClient(ThreatIntelResult(matched=False, source="fake"))
    cache = InMemoryThreatIntelCache()
    client = CachedThreatIntelClient(wrapped, cache, ttl_seconds=10)

    fake_now = [1_000_000.0]
    monkeypatch.setattr("time.time", lambda: fake_now[0])

    client.lookup({"ip": "1.2.3.4"})
    assert len(wrapped.calls) == 1

    # Still within TTL - cache hit, no additional call.
    fake_now[0] += 5
    client.lookup({"ip": "1.2.3.4"})
    assert len(wrapped.calls) == 1

    # Past the TTL - exactly one more real call.
    fake_now[0] += 10
    client.lookup({"ip": "1.2.3.4"})
    assert len(wrapped.calls) == 2


def test_no_indicators_bypasses_cache_entirely():
    wrapped = FakeThreatIntelClient(ThreatIntelResult(matched=False, source="fake"))
    cache = InMemoryThreatIntelCache()
    client = CachedThreatIntelClient(wrapped, cache, ttl_seconds=3600)

    client.lookup({})
    client.lookup({})

    # Nothing to key the cache on - every call falls through to the
    # wrapped client, same as a real client's own no-indicators
    # short-circuit would.
    assert len(wrapped.calls) == 2


def test_hash_and_ip_keyed_separately_even_for_same_wrapped_result():
    wrapped = FakeThreatIntelClient(ThreatIntelResult(matched=False, source="fake"))
    cache = InMemoryThreatIntelCache()
    client = CachedThreatIntelClient(wrapped, cache, ttl_seconds=3600)

    client.lookup({"ip": "1.2.3.4"})
    client.lookup({"hash": "1.2.3.4"})  # same string value, different ioc_type

    assert len(wrapped.calls) == 2


# ---------------------------------------------------------------------------
# fuse() round-trip: RealVirusTotalClient (mocked HTTP) -> fuse() -> the
# existing corroboration table still produces high/critical correctly.
# Proves the new client is a true drop-in ThreatIntelClient.
# ---------------------------------------------------------------------------


def _ml(anomaly_score=None, host_id="airdr-target", process_id=42):
    detection = {"host_id": host_id, "process_id": process_id}
    if anomaly_score is not None:
        detection["anomaly_score"] = anomaly_score
    return detection


def test_fuse_round_trip_with_virustotal_match_is_high():
    with patch("requests.get", return_value=_vt_response(malicious=5)):
        client = RealVirusTotalClient(api_key="test-key")
        ti_result = client.lookup({"ip": "9.9.9.9"})

    fused = fuse(_ml(anomaly_score=0.10), ti_result)

    assert fused["risk_tier"] == "high"
    assert fused["arm_signals"] == ["threat_intel"]
    assert fused["indicator"] == "9.9.9.9"


def test_fuse_round_trip_with_virustotal_match_and_high_ml_is_critical():
    with patch("requests.get", return_value=_vt_response(malicious=2)):
        client = RealVirusTotalClient(api_key="test-key")
        ti_result = client.lookup({"ip": "9.9.9.9"})

    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.2), ti_result)

    assert fused["risk_tier"] == "critical"
    assert fused["arm_signals"] == ["ml_anomaly", "threat_intel"]


def test_fuse_round_trip_with_virustotal_clean_result_is_capped_below_high():
    with patch("requests.get", return_value=_vt_response(malicious=0)):
        client = RealVirusTotalClient(api_key="test-key")
        ti_result = client.lookup({"ip": "9.9.9.9"})

    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.2), ti_result)

    assert fused["risk_tier"] == "medium"
    assert fused["arm_signals"] == ["ml_anomaly"]


def test_fuse_round_trip_through_cache_hit_still_fuses_correctly():
    """Full stack: CachedThreatIntelClient wrapping RealVirusTotalClient,
    second lookup served from cache (zero additional HTTP calls), result
    still fuses into the same risk_tier."""
    with patch("requests.get", return_value=_vt_response(malicious=4)) as mock_get:
        real_client = RealVirusTotalClient(api_key="test-key")
        cached_client = CachedThreatIntelClient(real_client, InMemoryThreatIntelCache(), ttl_seconds=3600)

        first = cached_client.lookup({"ip": "9.9.9.9"})
        second = cached_client.lookup({"ip": "9.9.9.9"})

        assert mock_get.call_count == 1  # second lookup was a cache hit

    fused = fuse(_ml(anomaly_score=0.10), second)
    assert fused["risk_tier"] == "high"
    assert first == second


# ---------------------------------------------------------------------------
# OpenSearchThreatIntelCache - never-raise contract on an ordinary
# cache-backend failure (task 4.3b; disclosed gap from MR!3's review).
# ---------------------------------------------------------------------------


def test_opensearch_cache_get_returns_none_on_connection_error():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError()):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        result = cache.get("ip", "1.2.3.4")

    assert result is None


def test_opensearch_cache_get_returns_none_on_timeout():
    with patch("requests.get", side_effect=requests.exceptions.Timeout()):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        result = cache.get("ip", "1.2.3.4")

    assert result is None


def test_opensearch_cache_get_returns_none_on_404():
    with patch("requests.get", return_value=_opensearch_response(status_code=404)):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        result = cache.get("ip", "1.2.3.4")

    assert result is None


def test_opensearch_cache_get_returns_none_on_500_without_raising():
    with patch("requests.get", return_value=_opensearch_response(status_code=500)):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        # Must not raise (the bug being fixed was an unguarded
        # raise_for_status() on exactly this case).
        result = cache.get("ip", "1.2.3.4")

    assert result is None


def test_opensearch_cache_get_returns_none_on_403_without_raising():
    with patch("requests.get", return_value=_opensearch_response(status_code=403)):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        result = cache.get("ip", "1.2.3.4")

    assert result is None


def test_opensearch_cache_get_returns_none_on_unparseable_body():
    resp = _opensearch_response(status_code=200)
    resp.json.side_effect = ValueError("not json")
    with patch("requests.get", return_value=resp):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        result = cache.get("ip", "1.2.3.4")

    assert result is None


def test_opensearch_cache_put_does_not_raise_on_connection_error():
    with patch("requests.put", side_effect=requests.exceptions.ConnectionError()):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        # Must not raise.
        cache.put("ip", "1.2.3.4", ThreatIntelResult(matched=False, source="virustotal"), ttl_seconds=3600)


def test_opensearch_cache_put_does_not_raise_on_timeout():
    with patch("requests.put", side_effect=requests.exceptions.Timeout()):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        cache.put("ip", "1.2.3.4", ThreatIntelResult(matched=False, source="virustotal"), ttl_seconds=3600)


def test_opensearch_cache_put_does_not_raise_on_500():
    with patch("requests.put", return_value=_opensearch_response(status_code=500)):
        cache = OpenSearchThreatIntelCache(host="opensearch.example", username="u", password="p")
        # Must not raise (the bug being fixed was an unguarded
        # raise_for_status() on exactly this case).
        cache.put("ip", "1.2.3.4", ThreatIntelResult(matched=False, source="virustotal"), ttl_seconds=3600)


# ---------------------------------------------------------------------------
# CachedThreatIntelClient's own defensive catch - the proof that matters:
# exercises lookup()'s belt-and-suspenders try/except around cache.get()/
# cache.put(), independent of OpenSearchThreatIntelCache's own fix above.
# ---------------------------------------------------------------------------


def test_lookup_falls_through_to_wrapped_client_when_cache_raises_on_every_call():
    wrapped = FakeThreatIntelClient(ThreatIntelResult(matched=True, indicator="1.2.3.4", source="fake"))
    client = CachedThreatIntelClient(wrapped, BrokenThreatIntelCache(), ttl_seconds=3600)

    # Must not raise, even though the cache raises on both get() and put().
    result = client.lookup({"ip": "1.2.3.4"})

    assert result.matched is True
    assert result.indicator == "1.2.3.4"
    assert result.source == "fake"
    assert len(wrapped.calls) == 1
