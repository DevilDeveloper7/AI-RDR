"""Wazuh integration script and M5 client: offline tests (no sockets)."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

import requests

from m4_threat_intel.m4_client import enrich

from .fakes import FakeResponse as R
from .fakes import FakeSession

_SCRIPT = Path(__file__).resolve().parent.parent / "integrations" / "custom-m4-enrich.py"
_spec = importlib.util.spec_from_file_location("custom_m4_enrich", _SCRIPT)
integ = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(integ)

SHA256, SHA1, MD5 = "a" * 64, "b" * 40, "c" * 32

# SYNTHETIC alert: only the field names confirmed/assumed in FIELD_PATHS.
FIM_ALERT = {"id": "1729250000.12345", "agent": {"id": "001"},
             "syscheck": {"path": "/srv/data/x.docx", "sha256_after": SHA256,
                          "sha1_after": SHA1, "md5_after": MD5}}


class ExtractTests(unittest.TestCase):
    def test_prefers_sha256(self):
        self.assertEqual(integ.extract_indicators(FIM_ALERT), [("hash", SHA256)])

    def test_falls_back_to_confirmed_md5_field(self):
        alert = {"id": "1", "syscheck": {"md5_after": MD5.upper()}}
        self.assertEqual(integ.extract_indicators(alert), [("hash", MD5)])

    def test_invalid_or_missing_fields_give_nothing(self):
        for alert in ({}, {"syscheck": {"sha256_after": "xyz"}}, {"syscheck": "oops"},
                      {"data": {"srcip": "not-an-ip"}}):
            self.assertEqual(integ.extract_indicators(alert), [])

    def test_only_public_ips_extracted(self):
        alert = {"data": {"srcip": "10.0.0.5", "dstip": "8.8.4.4"}}
        self.assertEqual(integ.extract_indicators(alert), [("ip", "8.8.4.4")])


class ProcessAlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "integrations.log")

    def tearDown(self):
        self.tmp.cleanup()

    def test_submits_to_async_endpoint(self):
        sent = []

        def post(url, payload):
            sent.append((url, payload))
            return 202, {"job_id": "j1"}

        out = integ.process_alert(FIM_ALERT, "http://127.0.0.1:5004/", post=post, log_file=self.log)
        self.assertEqual(sent, [("http://127.0.0.1:5004/enrich/async",
                                 {"alert_id": "1729250000.12345", "type": "hash", "value": SHA256})])
        self.assertEqual(out[0][2], "queued job j1")

    def test_survives_m4_down_slow_or_erroring(self):
        def down(url, payload):
            raise ConnectionRefusedError()

        def slow(url, payload):
            raise TimeoutError()

        def erroring(url, payload):
            return 500, None

        for post, expected in ((down, "unreachable (ConnectionRefusedError)"),
                               (slow, "unreachable (TimeoutError)"),
                               (erroring, "HTTP 500")):
            out = integ.process_alert(FIM_ALERT, "http://m4", post=post, log_file=self.log)
            self.assertIn(expected, out[0][2])

    def test_main_never_fails(self):
        self.assertEqual(integ.main(["script"]), 0)                       # bad args
        self.assertEqual(integ.main(["s", "/no/such/file", "", "http://m4"]), 0)
        bad = os.path.join(self.tmp.name, "bad.json")
        Path(bad).write_text("{not json")
        self.assertEqual(integ.main(["s", bad, "", "http://m4"]), 0)

    def test_log_contains_no_secret(self):
        integ.process_alert(FIM_ALERT, "http://m4", post=lambda u, p: (202, {"job_id": "j"}),
                            log_file=self.log)
        integ.main(["s", "/no/file", "SECRET-API-KEY", "http://m4"])
        self.assertNotIn("SECRET", Path(self.log).read_text())


class M4ClientTests(unittest.TestCase):
    def test_success_returns_contract_dict(self):
        body = {"alert_id": "A1", "verdict": "malicious", "score": 95}
        session = FakeSession({"/enrich": [R(200, body)]})
        # FakeSession.request is used by requests-style .post via this shim:
        session.post = lambda url, **kw: session.request("POST", url, **kw)
        self.assertEqual(enrich("hash", SHA256, "A1", session=session), body)

    def test_failures_are_unknown_never_clean(self):
        cases = [requests.ConnectionError(), requests.Timeout(), R(500, {}),
                 R(200, text="<html>"), R(200, {"verdict": "safe"})]
        for item in cases:
            session = FakeSession({"/enrich": [item]})
            session.post = lambda url, s=session, **kw: s.request("POST", url, **kw)
            out = enrich("hash", SHA256, "A1", session=session)
            self.assertEqual(out["verdict"], "unknown", item)
            self.assertTrue(out["error"])
            self.assertEqual(out["alert_id"], "A1")


if __name__ == "__main__":
    unittest.main()
