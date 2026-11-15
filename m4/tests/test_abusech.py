import unittest

import requests

from m4_threat_intel.providers.abusech import AbuseChProvider

from .fakes import FakeResponse as R
from .fakes import fake_http

SHA256 = "c" * 64
SHA1 = "c" * 40
MB, TF, UH = "mb-api.abuse.ch", "threatfox-api.abuse.ch", "urlhaus-api.abuse.ch"

MB_HIT = R(body={"query_status": "ok", "data": [
    {"sha256_hash": SHA256, "signature": "LockBit", "tags": ["ransomware", "LockBit"],
     "file_type": "elf", "first_seen": "2026-01-01 00:00:00"}]})
MB_MISS = R(body={"query_status": "hash_not_found"})
TF_MISS = R(body={"query_status": "no_result"})
TF_HIT = R(body={"query_status": "ok", "data": [
    {"ioc": "evil.example", "threat_type": "botnet_cc", "malware_printable": "Cobalt Strike",
     "confidence_level": 90, "tags": ["c2"]}]})
UH_MISS = R(body={"query_status": "no_results"})


def provider(routes, key="test-key"):
    http, session = fake_http(routes)
    return AbuseChProvider(key, http), session


class AbuseChHashTests(unittest.TestCase):
    def test_malwarebazaar_hit(self):
        p, session = provider({MB: [MB_HIT], TF: [TF_MISS]})
        r = p.lookup("hash", SHA256)
        self.assertEqual((r.status, r.score), ("hit", 95))
        self.assertEqual(r.tags, ["LockBit", "ransomware"])
        self.assertEqual(r.details["hit_services"], ["malwarebazaar"])
        self.assertIsNone(r.error)

    def test_auth_key_header_and_form_body(self):
        p, session = provider({MB: [MB_MISS], TF: [TF_MISS]})
        p.lookup("hash", SHA256)
        mb_call = session.calls[0]
        self.assertEqual(mb_call["headers"], {"Auth-Key": "test-key"})
        self.assertEqual(mb_call["data"], {"query": "get_info", "hash": SHA256})
        self.assertEqual(session.calls[1]["json"], {"query": "search_hash", "hash": SHA256})

    def test_both_miss_is_miss(self):
        p, _ = provider({MB: [MB_MISS], TF: [TF_MISS]})
        r = p.lookup("hash", SHA256)
        self.assertEqual(r.status, "miss")
        self.assertIsNone(r.error)

    def test_one_service_failing_without_hit_is_error_not_miss(self):
        p, _ = provider({MB: [R(status_code=500, body={})], TF: [TF_MISS]})
        r = p.lookup("hash", SHA256)
        self.assertEqual(r.status, "error")
        self.assertIn("malwarebazaar: HTTP 500", r.error)

    def test_hit_with_partial_failure_keeps_hit_and_reports_error(self):
        p, _ = provider({MB: [MB_HIT], TF: [requests.Timeout()]})
        r = p.lookup("hash", SHA256)
        self.assertEqual(r.status, "hit")
        self.assertIn("threatfox: timeout", r.error)

    def test_malformed_json_is_error(self):
        p, _ = provider({MB: [R(text="<html>oops</html>")], TF: [TF_MISS]})
        r = p.lookup("hash", SHA256)
        self.assertEqual(r.status, "error")
        self.assertIn("not valid JSON", r.error)

    def test_non_object_json_is_error(self):
        p, _ = provider({MB: [R(body=["a", "b"])], TF: [TF_MISS]})
        self.assertIn("not an object", p.lookup("hash", SHA256).error)

    def test_unexpected_query_status_is_error_not_miss(self):
        p, _ = provider({MB: [R(body={"query_status": "something_new"})], TF: [TF_MISS]})
        r = p.lookup("hash", SHA256)
        self.assertEqual(r.status, "error")
        self.assertIn("something_new", r.error)

    def test_ok_with_bad_data_is_error(self):
        p, _ = provider({MB: [R(body={"query_status": "ok", "data": "nope"})], TF: [TF_MISS]})
        self.assertEqual(p.lookup("hash", SHA256).status, "error")

    def test_auth_failure(self):
        p, _ = provider({MB: [R(status_code=401, body={})], TF: [R(status_code=403, body={})]})
        r = p.lookup("hash", SHA256)
        self.assertEqual(r.status, "error")
        self.assertIn("authentication failed", r.error)

    def test_missing_key_makes_no_network_call(self):
        p, session = provider({MB: [MB_HIT]}, key=None)
        r = p.lookup("hash", SHA256)
        self.assertEqual(r.status, "error")
        self.assertIn("ABUSECH_AUTH_KEY", r.error)
        self.assertEqual(session.calls, [])

    def test_sha1_skips_threatfox(self):
        p, session = provider({MB: [MB_MISS], TF: [TF_HIT]})
        self.assertEqual(p.lookup("hash", SHA1).status, "miss")
        self.assertEqual(len(session.calls), 1)


class AbuseChHostTests(unittest.TestCase):
    def test_ip_routes_to_threatfox_and_urlhaus(self):
        p, session = provider({TF: [TF_MISS], UH: [UH_MISS]})
        self.assertEqual(p.lookup("ip", "203.0.113.5").status, "miss")
        self.assertEqual([c["url"] for c in session.calls],
                         ["https://threatfox-api.abuse.ch/api/v1/",
                          "https://urlhaus-api.abuse.ch/v1/host/"])
        self.assertEqual(session.calls[0]["json"],
                         {"query": "search_ioc", "search_term": "203.0.113.5", "exact_match": True})
        self.assertEqual(session.calls[1]["data"], {"host": "203.0.113.5"})

    def test_threatfox_confidence_is_score(self):
        p, _ = provider({TF: [TF_HIT], UH: [UH_MISS]})
        r = p.lookup("domain", "evil.example")
        self.assertEqual((r.status, r.score), ("hit", 90))
        self.assertIn("Cobalt Strike", r.tags)

    def test_threatfox_without_confidence_uses_default(self):
        body = {"query_status": "ok", "data": [{"ioc": "evil.example"}]}
        p, _ = provider({TF: [R(body=body)], UH: [UH_MISS]})
        self.assertEqual(p.lookup("domain", "evil.example").score, 75)

    def test_urlhaus_online_and_offline_scores(self):
        online = R(body={"query_status": "ok", "urls": [
            {"url_status": "online", "threat": "malware_download", "tags": ["elf"]},
            {"url_status": "offline"}]})
        offline = R(body={"query_status": "ok", "urls": [{"url_status": "offline"}]})
        p, _ = provider({TF: [TF_MISS], UH: [online]})
        r = p.lookup("domain", "bad.example")
        self.assertEqual((r.score, r.details["services"]["urlhaus"]["urls_online"]), (85, 1))
        p, _ = provider({TF: [TF_MISS], UH: [offline]})
        self.assertEqual(p.lookup("domain", "bad.example").score, 25)

    def test_urlhaus_ok_with_no_urls_is_miss(self):
        p, _ = provider({TF: [TF_MISS], UH: [R(body={"query_status": "ok", "urls": []})]})
        self.assertEqual(p.lookup("domain", "x.example").status, "miss")


if __name__ == "__main__":
    unittest.main()
