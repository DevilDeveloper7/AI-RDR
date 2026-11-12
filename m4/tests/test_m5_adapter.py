"""M5 adapter: mapping rules, M5's freshness window, and the /enrich/m5 endpoint.

`M5RuleMirror` copies the acceptance rules from m5/ai_rdr_risk.py so the contract
is checked even when M5 is not next to M4. `RealM5CrossCheck` additionally feeds
the adapter output through M5's real RiskMatrix when ../m5 exists.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import requests

from m4_threat_intel import m4_client
from m4_threat_intel.enricher import Enricher
from m4_threat_intel.m5_adapter import to_m5_record, unavailable_record

from .fakes import FakeResponse, FakeSession, StaticProvider
from .test_app import AppTestBase

SHA = "a" * 64
MAX_AGE, SKEW = 900, 30


def m4_result(verdict="malicious", ioc_type="hash", value=SHA, sources=("malwarebazaar",),
              tags=(), error=None, cached=False, enriched_at=None, score=95):
    return {"alert_id": "A1", "type": ioc_type, "value": value, "verdict": verdict,
            "score": score, "sources": list(sources), "tags": list(tags), "cached": cached,
            "error": error, "details": [], "latency_ms": 1.0,
            "enriched_at": enriched_at or datetime.now(timezone.utc).isoformat()}


def m5_accepts(record, bundle, now):
    """Mirror of the threat_intel block in m5/ai_rdr_risk.py. Returns the M5 reason."""
    status = record.get("status")
    if status in ("unavailable", "no_match", "stale"):
        return "ti_" + status
    if status != "match" or record.get("malicious") is not True:
        return "invalid_ti_contract"
    try:
        checked = datetime.fromisoformat(record["checked_at"].replace("Z", "+00:00"))
        if checked.tzinfo is None:
            return "invalid_ti_contract"
        age = (now - checked).total_seconds()
        if not isinstance(record.get("provider"), str) or not record["provider"].strip():
            return "invalid_ti_contract"
        if record.get("indicator_type") == "sha256":
            matches = record["indicator"].lower() == str(bundle.get("sha256")).lower()
        elif record.get("indicator_type") == "ip":
            matches = record["indicator"] == bundle.get("src_ip")
        else:
            return "invalid_ti_contract"
    except (KeyError, ValueError, TypeError, AttributeError):
        return "invalid_ti_contract"
    if not matches:
        return "ti_unrelated_indicator"
    return "ti_match" if -SKEW <= age <= MAX_AGE else "ti_stale"


class MappingTests(unittest.TestCase):
    def test_malicious_hash_is_a_match(self):
        r = to_m5_record(m4_result())
        self.assertEqual((r["status"], r["malicious"], r["indicator_type"], r["indicator"]),
                         ("match", True, "sha256", SHA))
        self.assertEqual(r["provider"], "abuse.ch")
        self.assertNotIn("timestamp", r)

    def test_malicious_ip_is_a_match(self):
        r = to_m5_record(m4_result(ioc_type="ip", value="203.0.113.9", sources=["otx", "threatfox"]))
        self.assertEqual((r["status"], r["indicator_type"], r["provider"]), ("match", "ip", "abuse.ch+otx"))

    def test_otx_only_provider_name(self):
        self.assertEqual(to_m5_record(m4_result(sources=["otx"]))["provider"], "otx")

    def test_provider_never_empty(self):
        self.assertEqual(to_m5_record(m4_result(sources=[]))["provider"], "m4")

    def test_non_malicious_verdicts_are_no_match_never_a_match(self):
        for verdict in ("suspicious", "clean", "unknown"):
            r = to_m5_record(m4_result(verdict=verdict, score=20, sources=[]))
            self.assertEqual((r["status"], r["malicious"], r["m4_verdict"]), ("no_match", False, verdict))

    def test_unknown_with_error_is_unavailable_not_no_match(self):
        r = to_m5_record(m4_result(verdict="unknown", error="abusech: timeout", sources=[]))
        self.assertEqual((r["status"], r["reason"]), ("unavailable", "lookup_failed"))

    def test_malicious_survives_a_secondary_provider_error(self):
        r = to_m5_record(m4_result(error="otx: HTTP 500"))
        self.assertEqual(r["status"], "match")

    def test_types_m5_cannot_use_return_none(self):
        self.assertIsNone(to_m5_record(m4_result(value="d" * 32)))      # md5
        self.assertIsNone(to_m5_record(m4_result(value="d" * 40)))      # sha1
        self.assertIsNone(to_m5_record(m4_result(ioc_type="domain", value="evil.example")))

    def test_synthetic_is_never_a_match_by_default(self):
        for kwargs in ({"sources": ["mock_abusech"]}, {"tags": ["MOCK-DATA"]}):
            r = to_m5_record(m4_result(**kwargs))
            self.assertEqual((r["status"], r["reason"], r["synthetic"]),
                             ("unavailable", "synthetic_data_not_allowed", True))

    def test_synthetic_allowed_is_flagged(self):
        r = to_m5_record(m4_result(sources=["mock_abusech"], tags=["MOCK-DATA"]), allow_synthetic=True)
        self.assertEqual((r["status"], r["synthetic"]), ("match", True))

    def test_checked_at_is_original_enriched_at_and_aware(self):
        old = (datetime.now(timezone.utc) - timedelta(seconds=500)).isoformat()
        r = to_m5_record(m4_result(enriched_at=old, cached=True))
        self.assertEqual(datetime.fromisoformat(r["checked_at"].replace("Z", "+00:00")),
                         datetime.fromisoformat(old))
        self.assertTrue(r["checked_at"].endswith("Z"))
        self.assertTrue(r["cached"])

    def test_naive_or_bad_enriched_at_still_gives_aware_checked_at(self):
        for bad in ("2026-01-01T00:00:00", "garbage"):
            r = to_m5_record(m4_result(enriched_at=bad))
            self.assertIsNotNone(datetime.fromisoformat(r["checked_at"].replace("Z", "+00:00")).tzinfo)

    def test_unavailable_record(self):
        r = unavailable_record("hash", SHA, "A1", "m4_down")
        self.assertEqual((r["status"], r["indicator"]), ("unavailable", SHA))
        self.assertIsNone(unavailable_record("domain", "evil.example", "A1", "m4_down"))


class M5AcceptanceTests(unittest.TestCase):
    """The adapter output must be accepted by M5's rules, at the freshness edges."""
    NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def record_aged(self, seconds, **kwargs):
        stamp = (self.NOW - timedelta(seconds=seconds)).isoformat()
        return to_m5_record(m4_result(enriched_at=stamp, **kwargs))

    def test_sha256_match_is_accepted(self):
        self.assertEqual(m5_accepts(self.record_aged(5), {"sha256": SHA.upper()}, self.NOW), "ti_match")

    def test_ip_match_is_accepted(self):
        r = self.record_aged(5, ioc_type="ip", value="203.0.113.9")
        self.assertEqual(m5_accepts(r, {"src_ip": "203.0.113.9"}, self.NOW), "ti_match")

    def test_freshness_boundaries(self):
        for age, want in ((0, "ti_match"), (899, "ti_match"), (900, "ti_match"),
                          (901, "ti_stale"), (-30, "ti_match"), (-31, "ti_stale")):
            with self.subTest(age=age):
                self.assertEqual(m5_accepts(self.record_aged(age), {"sha256": SHA}, self.NOW), want)

    def test_other_indicator_is_unrelated(self):
        self.assertEqual(m5_accepts(self.record_aged(5), {"sha256": "b" * 64}, self.NOW),
                         "ti_unrelated_indicator")

    def test_non_match_records_are_recorded_with_zero_contribution(self):
        for verdict in ("clean", "suspicious", "unknown"):
            r = self.record_aged(5, verdict=verdict, sources=[])
            self.assertEqual(m5_accepts(r, {"sha256": SHA}, self.NOW), "ti_no_match")
        r = self.record_aged(5, verdict="unknown", error="x", sources=[])
        self.assertEqual(m5_accepts(r, {"sha256": SHA}, self.NOW), "ti_unavailable")


class EndpointTests(AppTestBase):
    def post(self, c, ioc_type, value):
        return c.post("/enrich/m5", json={"alert_id": "A9", "type": ioc_type, "value": value})

    def test_malicious_hash(self):
        c = self.client(enricher=Enricher(StaticProvider(name="abusech", status="hit", score=95)))
        resp = self.post(c, "hash", SHA.upper())
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual((body["status"], body["malicious"], body["indicator"], body["alert_id"]),
                         ("match", True, SHA, "A9"))
        self.assertEqual(m5_accepts(body, {"sha256": SHA}, datetime.now(timezone.utc)), "ti_match")

    def test_cached_hit_keeps_original_checked_at(self):
        from m4_threat_intel.cache import Cache
        cache = Cache(os.path.join(self.tmp.name, "m5.sqlite3"))
        c = self.client(enricher=Enricher(StaticProvider(name="abusech", status="hit", score=95),
                                          cache=cache))
        first = self.post(c, "hash", SHA).get_json()
        second = self.post(c, "hash", SHA).get_json()
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(first["checked_at"], second["checked_at"])

    def test_miss_is_no_match(self):
        c = self.client(enricher=Enricher(StaticProvider(name="abusech", status="miss")))
        body = self.post(c, "ip", "203.0.113.9").get_json()
        self.assertEqual((body["status"], body["malicious"]), ("no_match", False))

    def test_provider_error_is_unavailable(self):
        c = self.client(enricher=Enricher(StaticProvider(name="abusech", status="error",
                                                         error="boom")))
        self.assertEqual(self.post(c, "hash", SHA).get_json()["status"], "unavailable")

    def test_unsupported_types_are_422(self):
        c = self.client(enricher=Enricher(StaticProvider(name="abusech", status="hit", score=95)))
        for ioc_type, value in (("hash", "d" * 32), ("hash", "d" * 40), ("domain", "evil.example")):
            self.assertEqual(self.post(c, ioc_type, value).status_code, 422)

    def test_invalid_input_is_400(self):
        self.assertEqual(self.post(self.client(), "hash", "zz").status_code, 400)

    def test_mock_mode_is_flagged_and_allowed(self):
        app_client = self.mock_client()
        body = self.post(app_client, "hash", SHA).get_json()
        self.assertTrue(body["synthetic"])

    def mock_client(self):
        from m4_threat_intel.app import create_app
        app = create_app(self.settings, mock=True)
        self.apps.append(app)
        return app.test_client()

    def test_live_mode_hides_synthetic_data(self):
        c = self.client(enricher=Enricher(StaticProvider(name="mock_abusech", status="hit",
                                                         score=95, tags=["MOCK-DATA"])))
        body = self.post(c, "hash", SHA).get_json()
        self.assertEqual((body["status"], body["reason"]), ("unavailable", "synthetic_data_not_allowed"))


class ClientTests(unittest.TestCase):
    def test_m4_down_gives_unavailable(self):
        session = mock.Mock()
        session.post.side_effect = requests.ConnectionError("down")
        r = m4_client.enrich_for_m5("hash", SHA, "A1", session=session)
        self.assertEqual((r["status"], r["reason"]), ("unavailable", "lookup_failed"))
        self.assertIn("M4 unreachable", r["error"])

    def test_timeout_gives_unavailable(self):
        session = mock.Mock()
        session.post.side_effect = requests.Timeout()
        self.assertEqual(m4_client.enrich_for_m5("ip", "203.0.113.9", "A1", session=session)["status"],
                         "unavailable")

    def test_unsupported_type_is_none_even_when_m4_is_down(self):
        session = mock.Mock()
        session.post.side_effect = requests.ConnectionError("down")
        self.assertIsNone(m4_client.enrich_for_m5("domain", "evil.example", "A1", session=session))

    def test_happy_path(self):
        session = mock.Mock()
        session.post.return_value = FakeResponse(200, m4_result())
        self.assertEqual(m4_client.enrich_for_m5("hash", SHA, "A1", session=session)["status"], "match")


def _load_real_m5():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "m5")
    if not os.path.exists(os.path.join(path, "ai_rdr_risk.py")):
        return None
    sys.path.insert(0, os.path.abspath(path))
    try:
        import ai_rdr_risk
        return ai_rdr_risk
    except Exception:       # M5 needs files/config we do not have: skip, do not fail
        return None
    finally:
        sys.path.pop(0)


REAL_M5 = _load_real_m5()


@unittest.skipUnless(REAL_M5, "M5 code not found next to M4")
class RealM5CrossCheck(unittest.TestCase):
    NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def evaluate(self, record, bundle):
        data = {"agent_id": "host-1", "threat_intel": record, **bundle}
        return REAL_M5.RiskMatrix().evaluate(data, agent_id="host-1", case_id="C1", now=self.NOW)

    def ti_evidence(self, result):
        return [e for e in result["evidence"] if e["source"] == "threat_intel"]

    def aged(self, seconds, **kwargs):
        stamp = (self.NOW - timedelta(seconds=seconds)).isoformat()
        return to_m5_record(m4_result(enriched_at=stamp, **kwargs))

    def test_fresh_match_counts_with_weight_55(self):
        result = self.evaluate(self.aged(10), {"sha256": SHA})
        (e,) = self.ti_evidence(result)
        self.assertEqual((e["reason"], e["contribution"]), ("ti_match", 55))
        self.assertEqual(result["invalid_sources"], [])

    def test_boundaries_agree_with_the_mirror(self):
        for age in (899, 900, 901, -30, -31):
            with self.subTest(age=age):
                record = self.aged(age)
                (e,) = self.ti_evidence(self.evaluate(record, {"sha256": SHA}))
                self.assertEqual("ti_" + ("match" if e["contribution"] else e["status"]),
                                 m5_accepts(record, {"sha256": SHA}, self.NOW))

    def test_no_match_unavailable_and_synthetic_never_score(self):
        records = [self.aged(10, verdict="clean", sources=[]),
                   self.aged(10, verdict="unknown", error="x", sources=[]),
                   to_m5_record(m4_result(sources=["mock_abusech"]), allow_synthetic=False)]
        for record in records:
            result = self.evaluate(record, {"sha256": SHA})
            (e,) = self.ti_evidence(result)
            self.assertEqual(e["contribution"], 0)
            self.assertEqual(result["invalid_sources"], [])

    def test_ip_match(self):
        record = self.aged(10, ioc_type="ip", value="203.0.113.9")
        (e,) = self.ti_evidence(self.evaluate(record, {"src_ip": "203.0.113.9"}))
        self.assertEqual(e["contribution"], 55)


if __name__ == "__main__":
    unittest.main()
