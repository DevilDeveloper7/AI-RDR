"""M6 adapter: mapping to M6's INDICATOR contract, /enrich/m6 and /indicators."""
import os
import unittest
from datetime import datetime, timezone

from m4_threat_intel.enricher import Enricher
from m4_threat_intel.m6_adapter import to_m6_indicator
from m4_threat_intel.recent import RecentLog

from .fakes import StaticProvider
from .test_app import AppTestBase
from .test_m5_adapter import SHA, m4_result

# Mirror of m6/backend/app/integrations/contracts.py INDICATOR.
FIELDS = {"indicator": str, "type": str, "reputation": str, "source": str,
          "related_alert": (str, type(None)), "last_checked": str, "notes": str,
          "enrichment_status": str}


def valid_for_m6(item):
    for field, types in FIELDS.items():
        assert field in item and isinstance(item[field], types), field
        if types is str:
            assert item[field], field
    datetime.fromisoformat(item["last_checked"].replace("Z", "+00:00"))
    return item


class MappingTests(unittest.TestCase):
    def test_malicious_hash(self):
        i = valid_for_m6(to_m6_indicator(m4_result()))
        self.assertEqual((i["type"], i["reputation"], i["enrichment_status"], i["related_alert"]),
                         ("SHA-256", "Malicious", "enriched", "A1"))
        self.assertEqual(i["source"], "abuse.ch MalwareBazaar")
        self.assertIn("Context only", i["notes"])

    def test_every_verdict(self):
        want = {"malicious": "Malicious", "suspicious": "Suspicious", "clean": "Clean", "unknown": "Unknown"}
        for verdict, label in want.items():
            self.assertEqual(valid_for_m6(to_m6_indicator(m4_result(verdict=verdict, sources=[])))["reputation"], label)

    def test_status_enriched_no_data_unavailable(self):
        self.assertEqual(to_m6_indicator(m4_result(verdict="unknown", sources=[]))["enrichment_status"], "no_data")
        self.assertEqual(to_m6_indicator(m4_result(verdict="clean", sources=["local_allowlist"]))["enrichment_status"], "enriched")
        failed = valid_for_m6(to_m6_indicator(m4_result(verdict="unknown", sources=[], error="abusech: timeout")))
        self.assertEqual(failed["enrichment_status"], "unavailable")
        self.assertIn("Lookup incomplete", failed["notes"])
        self.assertIn("not proof", failed["notes"])

    def test_malicious_with_secondary_error_stays_enriched(self):
        self.assertEqual(to_m6_indicator(m4_result(error="otx: HTTP 500"))["enrichment_status"], "enriched")

    def test_unknown_is_never_presented_as_clean(self):
        i = to_m6_indicator(m4_result(verdict="unknown", sources=[]))
        self.assertEqual(i["reputation"], "Unknown")
        self.assertIn("not proof", i["notes"])

    def test_type_labels(self):
        for ioc_type, value, label in (("hash", "d" * 32, "MD5"), ("hash", "d" * 40, "SHA-1"),
                                       ("hash", SHA, "SHA-256"), ("ip", "203.0.113.9", "IP address"),
                                       ("domain", "evil.example", "Domain")):
            self.assertEqual(to_m6_indicator(m4_result(ioc_type=ioc_type, value=value))["type"], label)

    def test_m6_own_lookup_is_not_a_related_alert(self):
        r = m4_result()
        r["alert_id"] = "m6-lookup"
        self.assertIsNone(to_m6_indicator(r)["related_alert"])

    def test_mock_data_is_labelled(self):
        i = to_m6_indicator(m4_result(sources=["mock_abusech"], tags=["MOCK-DATA"]))
        self.assertIn("(mock)", i["source"])
        self.assertIn("MOCK DATA", i["notes"])

    def test_non_routable_ip_note(self):
        r = m4_result(verdict="unknown", ioc_type="ip", value="10.0.0.5", sources=[])
        r["details"] = [{"provider": "local_policy", "note": "non-routable IP: not sent to external services"}]
        self.assertIn("Non-routable IP", to_m6_indicator(r)["notes"])

    def test_bad_enriched_at_still_gives_valid_time(self):
        valid_for_m6(to_m6_indicator(m4_result(enriched_at="garbage")))


class RecentLogTests(unittest.TestCase):
    def test_newest_first_dedupe_and_cap(self):
        log = RecentLog(maxlen=3)
        for n in range(5):
            log.add(m4_result(value=f"{n:064x}"))
        self.assertEqual(len(log), 3)
        self.assertEqual([r["value"] for r in log.items()], [f"{n:064x}" for n in (4, 3, 2)])
        log.add(m4_result(value=f"{2:064x}"))            # same key moves to the front
        self.assertEqual(log.items(1)[0]["value"], f"{2:064x}")
        self.assertEqual(len(log), 3)

    def test_same_indicator_for_two_alerts_is_kept_twice(self):
        log = RecentLog()
        a, b = m4_result(), m4_result()
        b["alert_id"] = "A2"
        log.add(a)
        log.add(b)
        self.assertEqual(len(log), 2)

    def test_m6_lookups_are_not_remembered(self):
        log = RecentLog()
        r = m4_result()
        r["alert_id"] = "m6-lookup"
        log.add(r)
        self.assertEqual(len(log), 0)


class EndpointTests(AppTestBase):
    def enricher(self, **kw):
        return Enricher(StaticProvider(name="abusech", status="hit", score=95, **kw), recent=RecentLog())

    def test_enrich_m6(self):
        c = self.client(enricher=self.enricher())
        body = c.post("/enrich/m6", json={"alert_id": "A5", "type": "hash", "value": SHA.upper()}).get_json()
        valid_for_m6(body)
        self.assertEqual((body["indicator"], body["reputation"], body["related_alert"]), (SHA, "Malicious", "A5"))

    def test_enrich_m6_bad_input_is_400(self):
        c = self.client(enricher=self.enricher())
        self.assertEqual(c.post("/enrich/m6", json={"alert_id": "A", "type": "hash", "value": "zz"}).status_code, 400)

    def test_indicators_lists_recent_answers_newest_first(self):
        c = self.client(enricher=self.enricher())
        for n, ioc in enumerate((("hash", SHA), ("ip", "203.0.113.9"))):
            c.post("/enrich", json={"alert_id": f"A{n}", "type": ioc[0], "value": ioc[1]})
        body = c.get("/indicators").get_json()
        self.assertEqual([i["indicator"] for i in body["items"]], ["203.0.113.9", SHA])
        for item in body["items"]:
            valid_for_m6(item)
        self.assertEqual(len(c.get("/indicators?limit=1").get_json()["items"]), 1)

    def test_async_lookups_are_listed_too(self):
        c = self.client(enricher=self.enricher())
        job = c.post("/enrich/async", json={"alert_id": "A9", "type": "hash", "value": SHA}).get_json()
        self.wait_done(c, job["job_id"])
        self.assertEqual(c.get("/indicators").get_json()["items"][0]["related_alert"], "A9")

    def test_m6_lookup_is_not_listed(self):
        c = self.client(enricher=self.enricher())
        c.post("/enrich/m6", json={"alert_id": "m6-lookup", "type": "hash", "value": SHA})
        self.assertEqual(c.get("/indicators").get_json()["items"], [])

    def test_limit_validation(self):
        c = self.client(enricher=self.enricher())
        for bad in ("0", "501", "x"):
            self.assertEqual(c.get(f"/indicators?limit={bad}").status_code, 400)

    def test_without_recent_log_the_list_is_empty(self):
        c = self.client(enricher=Enricher(StaticProvider(name="abusech", status="hit", score=95)))
        self.assertEqual(c.get("/indicators").get_json()["items"], [])


if __name__ == "__main__":
    unittest.main()
