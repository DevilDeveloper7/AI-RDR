import unittest

import requests

from m4_threat_intel.providers.otx import OTXProvider, otx_score

from .fakes import FakeResponse as R
from .fakes import fake_http

OTX = "otx.alienvault.com"


def pulses(n, tags=("ransomware",)):
    return {"pulse_info": {"count": n, "pulses": [
        {"name": f"pulse {i}", "tags": list(tags)} for i in range(n)]}}


def provider(routes, key="otx-key"):
    http, session = fake_http(routes)
    return OTXProvider(key, http), session


class OTXTests(unittest.TestCase):
    def test_hit_score_formula_and_cap(self):
        self.assertEqual(otx_score(1), 30)
        self.assertEqual(otx_score(5), 50)
        self.assertEqual(otx_score(100), 60)
        p, _ = provider({OTX: [R(body=pulses(3))]})
        r = p.lookup("ip", "203.0.113.5")
        self.assertEqual((r.status, r.score, r.tags), ("hit", 40, ["ransomware"]))
        self.assertEqual(r.details["pulse_count"], 3)

    def test_url_slug_and_header(self):
        p, session = provider({OTX: [R(status_code=404, body={})]})
        p.lookup("ip", "203.0.113.5")
        p.lookup("ip", "2001:db8::1")
        p.lookup("domain", "example.com")
        p.lookup("hash", "a" * 32)
        urls = [c["url"] for c in session.calls]
        base = "https://otx.alienvault.com/api/v1/indicators/"
        self.assertEqual(urls, [base + "IPv4/203.0.113.5/general",
                                base + "IPv6/2001:db8::1/general",
                                base + "domain/example.com/general",
                                base + "file/" + "a" * 32 + "/general"])
        self.assertEqual(session.calls[0]["headers"], {"X-OTX-API-KEY": "otx-key"})

    def test_404_is_miss(self):
        p, _ = provider({OTX: [R(status_code=404, body={})]})
        self.assertEqual(p.lookup("domain", "example.com").status, "miss")

    def test_zero_pulses_is_miss(self):
        p, _ = provider({OTX: [R(body=pulses(0))]})
        self.assertEqual(p.lookup("domain", "example.com").status, "miss")

    def test_validation_is_miss_never_clean(self):
        body = dict(pulses(4), validation=[{"source": "whitelist", "name": "known good"}])
        p, _ = provider({OTX: [R(body=body)]})
        r = p.lookup("domain", "example.com")
        self.assertEqual(r.status, "miss")

    def test_invalid_key_403(self):
        p, _ = provider({OTX: [R(status_code=403, body={})]})
        r = p.lookup("domain", "example.com")
        self.assertEqual(r.status, "error")
        self.assertIn("authentication failed", r.error)

    def test_malformed_and_non_object_json(self):
        p, _ = provider({OTX: [R(text="not json")]})
        self.assertEqual(p.lookup("domain", "example.com").status, "error")
        p, _ = provider({OTX: [R(body=[1, 2])]})
        self.assertEqual(p.lookup("domain", "example.com").status, "error")

    def test_missing_pulse_info_is_error(self):
        p, _ = provider({OTX: [R(body={"indicator": "example.com"})]})
        self.assertEqual(p.lookup("domain", "example.com").status, "error")

    def test_unexpected_status_and_timeout(self):
        p, _ = provider({OTX: [R(status_code=418, body={})]})
        self.assertIn("unexpected HTTP 418", p.lookup("domain", "example.com").error)
        p, _ = provider({OTX: [requests.Timeout()]})
        self.assertEqual(p.lookup("domain", "example.com").error, "timeout")

    def test_missing_key_makes_no_network_call(self):
        p, session = provider({OTX: [R(body=pulses(1))]}, key="")
        self.assertIn("OTX_API_KEY", p.lookup("domain", "example.com").error)
        self.assertEqual(session.calls, [])


if __name__ == "__main__":
    unittest.main()
