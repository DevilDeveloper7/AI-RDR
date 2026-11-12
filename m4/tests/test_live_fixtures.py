"""Parsers checked against REAL abuse.ch responses (tests/fixtures/, recorded
2026-10-18). Replayed through a fake session: still no network in tests."""
import json
import unittest
from pathlib import Path

from m4_threat_intel.enricher import Enricher
from m4_threat_intel.providers.abusech import AbuseChProvider

from .fakes import FakeResponse as R
from .fakes import fake_http

LIVE = json.loads((Path(__file__).parent / "fixtures" / "abusech_live_2026-10-18.json").read_text())
MB, TF, UH = "mb-api.abuse.ch", "threatfox-api.abuse.ch", "urlhaus-api.abuse.ch"
KNOWN = "3474645503ee71af316f174c9f842261a1d37bf596376c8f90483cec57333b78"


def provider(routes):
    http, _ = fake_http({k: [R(body=v)] for k, v in routes.items()})
    return AbuseChProvider("test-key", http)


class LiveResponseTests(unittest.TestCase):
    def test_known_sample_found_in_malwarebazaar(self):
        r = provider({MB: LIVE["malwarebazaar_found"], TF: LIVE["threatfox_no_result"]}).lookup("hash", KNOWN)
        self.assertEqual((r.status, r.score, r.tags), ("hit", 95, ["elf"]))
        self.assertIsNone(r.error)                       # signature null handled
        self.assertEqual(r.details["services"]["threatfox"], {"status": "miss"})

    def test_unknown_hash_is_miss_in_both(self):
        r = provider({MB: LIVE["malwarebazaar_not_found"], TF: LIVE["threatfox_no_result"]}).lookup("hash", "0" * 64)
        self.assertEqual((r.status, r.error), ("miss", None))

    def test_threatfox_no_result_with_string_data_is_miss(self):
        r = provider({TF: LIVE["threatfox_no_result"],
                      UH: {"query_status": "no_results"}}).lookup("domain", "x.example")
        self.assertEqual(r.details["services"]["threatfox"], {"status": "miss"})

    def test_example_com_urlhaus_offline_only(self):
        r = provider({TF: LIVE["threatfox_no_result"], UH: LIVE["urlhaus_host_example_com"]}).lookup("domain", "example.com")
        self.assertEqual((r.status, r.score), ("hit", 25))
        self.assertEqual(r.details["services"]["urlhaus"]["urls_online"], 0)
        out = Enricher(provider({TF: LIVE["threatfox_no_result"], UH: LIVE["urlhaus_host_example_com"]})).enrich(
            "A1", "domain", "example.com")
        # Benign reserved domain with one old offline URL: context only, NOT suspicious.
        self.assertEqual(out["verdict"], "unknown")
        self.assertEqual(out["sources"], ["urlhaus"])        # analyst still sees the context
        self.assertIn("honeypot", out["tags"])


if __name__ == "__main__":
    unittest.main()
