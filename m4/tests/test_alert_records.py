"""GET /alerts/<id>/threat_intel: what M5's bundle builder pulls after the Wazuh script queued indicators."""
import unittest
from datetime import datetime, timezone
from unittest import mock

import requests

from m4_threat_intel import m4_client
from m4_threat_intel.enricher import Enricher
from m4_threat_intel.recent import RecentLog

from .fakes import StaticProvider
from .test_app import AppTestBase
from .test_m5_adapter import SHA, m5_accepts


class AlertRecordTests(AppTestBase):
    def enricher(self):
        return Enricher(StaticProvider(name="abusech", status="hit", score=95), recent=RecentLog())

    def queue(self, c, alert_id, ioc_type, value):
        job = c.post("/enrich/async", json={"alert_id": alert_id, "type": ioc_type, "value": value}).get_json()
        self.wait_done(c, job["job_id"])

    def test_records_for_one_alert_only_and_accepted_by_m5(self):
        c = self.client(enricher=self.enricher())
        self.queue(c, "A1", "hash", SHA)
        self.queue(c, "A1", "ip", "185.220.101.47")
        self.queue(c, "A2", "hash", "d" * 64)
        body = c.get("/alerts/A1/threat_intel").get_json()
        self.assertEqual(body["alert_id"], "A1")
        self.assertEqual(sorted(r["indicator_type"] for r in body["records"]), ["ip", "sha256"])
        bundle = {"sha256": SHA, "src_ip": "185.220.101.47"}
        for record in body["records"]:
            self.assertEqual(record["status"], "match")
            self.assertEqual(m5_accepts(record, bundle, datetime.now(timezone.utc)), "ti_match")

    def test_md5_sha1_and_domain_are_left_out(self):
        c = self.client(enricher=self.enricher())
        for ioc_type, value in (("hash", "d" * 32), ("hash", "d" * 40), ("domain", "evil.example")):
            self.queue(c, "A3", ioc_type, value)
        self.assertEqual(c.get("/alerts/A3/threat_intel").get_json()["records"], [])

    def test_unknown_alert_gives_an_empty_list_not_an_error(self):
        c = self.client(enricher=self.enricher())
        resp = c.get("/alerts/nope/threat_intel")
        self.assertEqual((resp.status_code, resp.get_json()["records"]), (200, []))


class ClientTests(unittest.TestCase):
    def test_returns_records(self):
        session = mock.Mock()
        session.get.return_value.json.return_value = {"records": [{"status": "match"}]}
        self.assertEqual(m4_client.threat_intel_for_alert("A/1", session=session), [{"status": "match"}])
        self.assertIn("/alerts/A%2F1/threat_intel", session.get.call_args[0][0])

    def test_never_raises(self):
        session = mock.Mock()
        session.get.side_effect = requests.ConnectionError("down")
        self.assertEqual(m4_client.threat_intel_for_alert("A1", session=session), [])
        session.get.side_effect = None
        session.get.return_value.json.return_value = ["not a dict"]
        self.assertEqual(m4_client.threat_intel_for_alert("A1", session=session), [])


if __name__ == "__main__":
    unittest.main()
