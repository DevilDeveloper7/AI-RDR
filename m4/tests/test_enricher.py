import unittest

from m4_threat_intel.allowlist import Allowlist
from m4_threat_intel.enricher import Enricher

from .fakes import StaticProvider

SHA256 = "d" * 64
CONTRACT_KEYS = {"alert_id", "type", "value", "verdict", "score", "sources", "tags",
                 "cached", "error", "details", "latency_ms", "enriched_at"}


def abuse(**kw):
    return StaticProvider(name="abusech", **kw)


def otx(**kw):
    return StaticProvider(name="otx", context_only=True, **kw)


class VerdictTests(unittest.TestCase):
    def test_response_has_contract_fields(self):
        out = Enricher(abuse(), otx()).enrich("A1", "hash", SHA256)
        self.assertEqual(set(out), CONTRACT_KEYS)

    def test_not_found_is_unknown_not_clean(self):
        out = Enricher(abuse(), otx()).enrich("A1", "domain", "example.com")
        self.assertEqual((out["verdict"], out["score"], out["error"]), ("unknown", 0, None))

    def test_failure_is_never_clean(self):
        out = Enricher(abuse(status="error", error="timeout"),
                       otx(status="error", error="HTTP 503")).enrich("A1", "ip", "8.8.8.8")
        self.assertEqual(out["verdict"], "unknown")
        self.assertNotEqual(out["verdict"], "clean")
        self.assertIn("abusech: timeout", out["error"])
        self.assertIn("otx: HTTP 503", out["error"])

    def test_otx_alone_is_never_malicious(self):
        # Even if OTX claimed the maximum score, it is capped below 80.
        out = Enricher(abuse(), otx(status="hit", score=100)).enrich("A1", "domain", "bad.example")
        self.assertEqual(out["verdict"], "suspicious")
        self.assertLessEqual(out["score"], 60)
        self.assertEqual(out["sources"], ["otx"])

    def test_abusech_high_score_is_malicious(self):
        out = Enricher(abuse(status="hit", score=95), otx()).enrich("A1", "domain", "bad.example")
        self.assertEqual((out["verdict"], out["score"]), ("malicious", 95))

    def test_medium_score_is_suspicious_low_score_unknown(self):
        out = Enricher(abuse(status="hit", score=50), None).enrich("A1", "domain", "x.example")
        self.assertEqual(out["verdict"], "suspicious")
        out = Enricher(abuse(status="hit", score=10), None).enrich("A1", "domain", "x.example")
        self.assertEqual(out["verdict"], "unknown")

    def test_partial_failure_keeps_hit_and_reports_error(self):
        out = Enricher(abuse(status="hit", score=90),
                       otx(status="error", error="timeout")).enrich("A1", "ip", "8.8.4.4")
        self.assertEqual(out["verdict"], "malicious")
        self.assertEqual(out["error"], "otx: timeout")


class GuardTests(unittest.TestCase):
    def test_private_ip_makes_zero_provider_calls(self):
        a, o = abuse(status="hit", score=95), otx(status="hit", score=60)
        for ip in ("10.0.0.1", "127.0.0.1", "192.168.5.5", "169.254.0.1", "::1", "fe80::1"):
            self.assertEqual(Enricher(a, o).enrich("A1", "ip", ip)["verdict"], "unknown")
        self.assertEqual((a.calls, o.calls), ([], []))

    def test_allowlist_is_clean_without_calls(self):
        a = abuse(status="hit", score=95)
        out = Enricher(a, otx(), Allowlist({"domain": ["example.org"]})).enrich(
            "A1", "domain", "Example.ORG.")
        self.assertEqual(out["verdict"], "clean")
        self.assertEqual(a.calls, [])


class RoutingTests(unittest.TestCase):
    def test_hash_confirmed_by_abusech_skips_otx(self):
        a, o = abuse(status="hit", score=95), otx()
        Enricher(a, o).enrich("A1", "hash", SHA256)
        self.assertEqual((len(a.calls), len(o.calls)), (1, 0))

    def test_hash_not_confirmed_asks_otx(self):
        a, o = abuse(), otx()
        Enricher(a, o).enrich("A1", "hash", SHA256)
        self.assertEqual((len(a.calls), len(o.calls)), (1, 1))

    def test_ip_and_domain_always_ask_both(self):
        a, o = abuse(status="hit", score=95), otx()
        Enricher(a, o).enrich("A1", "ip", "8.8.4.4")
        Enricher(a, o).enrich("A1", "domain", "bad.example")
        self.assertEqual((len(a.calls), len(o.calls)), (2, 2))


if __name__ == "__main__":
    unittest.main()
