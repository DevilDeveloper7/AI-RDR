import os
import tempfile
import threading
import time
import unittest

from m4_threat_intel.app import create_app, shutdown_app
from m4_threat_intel.config import Settings
from m4_threat_intel.enricher import Enricher
from m4_threat_intel.providers.base import Provider

from .fakes import StaticProvider

CONTRACT_KEYS = {"alert_id", "type", "value", "verdict", "score", "sources", "tags",
                 "cached", "error", "details", "latency_ms", "enriched_at"}


class AppTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = Settings(cache_path=os.path.join(self.tmp.name, "c.sqlite3"),
                                 abusech_auth_key=None, otx_api_key=None, max_jobs=1000)
        self.apps = []

    def tearDown(self):
        for app in self.apps:
            shutdown_app(app)
        self.tmp.cleanup()

    def client(self, **kwargs):
        app = create_app(self.settings, mock=False, **kwargs)
        self.apps.append(app)
        return app.test_client()

    def wait_done(self, client, job_id):
        for _ in range(500):
            body = client.get(f"/enrich/jobs/{job_id}").get_json()
            if body["status"] != "pending":
                return body
            time.sleep(0.005)
        self.fail("job did not finish")


class SyncTests(AppTestBase):
    def test_health_reports_keys_missing(self):
        body = self.client().get("/health").get_json()
        self.assertEqual((body["abusech_key"], body["otx_key"], body["mode"]),
                         ("missing", "missing", "live"))

    def test_without_keys_result_is_unknown_with_error_never_clean(self):
        resp = self.client().post("/enrich", json={"alert_id": "A1", "type": "ip",
                                                   "value": "8.8.8.8"})
        body = resp.get_json()
        self.assertEqual(set(body), CONTRACT_KEYS)
        self.assertEqual(body["verdict"], "unknown")
        self.assertIn("ABUSECH_AUTH_KEY is not set", body["error"])
        self.assertIn("OTX_API_KEY is not set", body["error"])

    def test_invalid_input_is_400(self):
        resp = self.client().post("/enrich", json={"alert_id": "A1", "type": "hash", "value": "zz"})
        self.assertEqual(resp.status_code, 400)


class AsyncTests(AppTestBase):
    def test_async_end_to_end(self):
        c = self.client(enricher=Enricher(StaticProvider(name="abusech", status="hit", score=95)))
        resp = c.post("/enrich/async", json={"alert_id": "A7", "type": "hash", "value": "f" * 64})
        self.assertEqual(resp.status_code, 202)
        job_id = resp.get_json()["job_id"]
        self.assertEqual(resp.headers["Location"], f"/enrich/jobs/{job_id}")
        job = self.wait_done(c, job_id)
        self.assertEqual(job["status"], "done")
        self.assertEqual(set(job["result"]), CONTRACT_KEYS)
        self.assertEqual((job["result"]["alert_id"], job["result"]["verdict"]), ("A7", "malicious"))

    def test_async_bad_input_is_400_and_not_queued(self):
        c = self.client()
        resp = c.post("/enrich/async", json={"alert_id": "A1", "type": "ip", "value": "nope"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(c.get("/stats").get_json()["jobs"]["submitted"], 0)

    def test_unknown_job_is_404(self):
        self.assertEqual(self.client().get("/enrich/jobs/nope").status_code, 404)

    def test_async_does_not_wait_for_slow_provider(self):
        gate = threading.Event()

        class Slow(Provider):
            name = "slow"
            supported_types = frozenset({"hash", "ip", "domain"})

            def _lookup(self, ioc_type, value):
                gate.wait(5)
                return self.error("too slow")

        c = self.client(enricher=Enricher(Slow()))
        started = time.perf_counter()
        resp = c.post("/enrich/async", json={"alert_id": "A1", "type": "domain",
                                             "value": "x.example"})
        self.assertLess(time.perf_counter() - started, 1.0)
        job_id = resp.get_json()["job_id"]
        self.assertEqual(c.get(f"/enrich/jobs/{job_id}").get_json()["status"], "pending")
        gate.set()
        self.assertEqual(self.wait_done(c, job_id)["result"]["verdict"], "unknown")

    def test_worker_exception_marks_job_failed(self):
        class Exploding(Enricher):
            def enrich(self, *args):
                raise RuntimeError("boom")

        c = self.client(enricher=Exploding(StaticProvider()))
        job_id = c.post("/enrich/async", json={"alert_id": "A1", "type": "domain",
                                               "value": "x.example"}).get_json()["job_id"]
        job = self.wait_done(c, job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIn("RuntimeError", job["error"])

    def test_job_store_is_bounded(self):
        self.settings.max_jobs = 3
        c = self.client(enricher=Enricher(StaticProvider()))
        ids = [c.post("/enrich/async", json={"alert_id": f"A{i}", "type": "domain",
                                             "value": "x.example"}).get_json()["job_id"]
               for i in range(5)]
        self.assertEqual(c.get(f"/enrich/jobs/{ids[0]}").status_code, 404)   # evicted
        self.wait_done(c, ids[-1])
        self.assertEqual(c.get("/stats").get_json()["jobs"]["stored"], 3)

    def test_stats_endpoint_shape(self):
        c = self.client()
        body = {"alert_id": "A1", "type": "ip", "value": "10.1.1.1"}
        c.post("/enrich", json=body)
        stats = c.get("/stats").get_json()
        self.assertIn("cache", stats)
        self.assertIn("jobs", stats)


class MockModeTests(AppTestBase):
    def test_mock_mode_is_labelled_and_caches(self):
        app = create_app(self.settings, mock=True)
        self.apps.append(app)
        c = app.test_client()
        self.assertEqual(c.get("/health").get_json()["mode"], "MOCK")
        body = {"alert_id": "A1", "type": "domain", "value": "mock-c2.example"}
        first = c.post("/enrich", json=body).get_json()
        second = c.post("/enrich", json=dict(body, alert_id="A2")).get_json()
        self.assertEqual(first["verdict"], "malicious")
        self.assertIn("MOCK-DATA", first["tags"])
        self.assertEqual(first["sources"], ["mock_abusech", "mock_otx"])
        self.assertTrue(second["cached"])
        self.assertEqual(second["alert_id"], "A2")


if __name__ == "__main__":
    unittest.main()
