"""M4 must stay fast and alive when the internet, the cache folder or the cwd is wrong."""
import os
import tempfile
import unittest

from m4_threat_intel.app import build_enricher, create_app, shutdown_app
from m4_threat_intel.breaker import ProviderBreaker
from m4_threat_intel.config import Settings
from m4_threat_intel.enricher import Enricher
from m4_threat_intel.providers.base import Provider
from m4_threat_intel.schema import STATUS_ERROR, STATUS_MISS, ProviderResult

SHA = "c" * 64
NET = "malwarebazaar: network error (ProxyError) (gave up after 4 attempts)"


class Counting(Provider):
    name = "abusech"
    supported_types = frozenset({"hash", "ip", "domain"})

    def __init__(self, status=STATUS_ERROR, error=NET):
        self.calls, self.status, self.error_text = 0, status, error

    def _lookup(self, ioc_type, value):
        self.calls += 1
        return ProviderResult(provider=self.name, status=self.status,
                              error=self.error_text if self.status == STATUS_ERROR else None)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class BreakerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.provider = Counting()
        self.breaker = ProviderBreaker(threshold=2, cooldown=30, clock=self.clock)
        self.enricher = Enricher(self.provider, breaker=self.breaker)

    def ask(self, n=0):
        return self.enricher.enrich("A", "hash", f"{n:064x}")

    def test_opens_after_two_network_failures_and_stops_calling_the_provider(self):
        self.ask(1)
        self.ask(2)
        self.assertEqual(self.provider.calls, 2)
        third = self.ask(3)
        self.assertEqual(self.provider.calls, 2)                 # not called: skipped
        self.assertIn("skipped", third["error"])
        self.assertEqual((third["verdict"], third["score"]), ("unknown", 0))   # never clean

    def test_closes_after_the_cooldown_and_a_good_answer_resets_it(self):
        self.ask(1)
        self.ask(2)
        self.clock.now += 31
        self.provider.status = STATUS_MISS
        self.ask(3)
        self.assertEqual(self.provider.calls, 3)
        self.assertEqual(self.breaker.stats(), {})
        self.ask(4)
        self.assertEqual(self.provider.calls, 4)

    def test_http_errors_and_misses_do_not_open_it(self):
        self.provider.error_text = "HTTP 503 (gave up after 4 attempts)"
        for n in range(5):
            self.ask(n)
        self.assertEqual(self.provider.calls, 5)

    def test_only_consecutive_failures_count(self):
        self.ask(1)                                              # failure 1
        self.provider.status = STATUS_MISS
        self.ask(2)                                              # good answer resets the count
        self.provider.status = STATUS_ERROR
        self.ask(3)                                              # failure 1 again
        self.assertEqual(self.breaker.stats(), {})
        self.ask(4)                                              # failure 2 -> opens
        self.assertIn("abusech", self.breaker.stats())

    def test_unsupported_type_is_not_counted(self):
        self.provider.supported_types = frozenset({"hash"})
        for n in range(4):
            self.enricher.enrich("A", "ip", f"198.51.100.{n}")
            self.enricher.enrich("A", "ip", f"198.51.100.{n}")
        self.assertEqual(self.breaker.stats(), {})


class StartupTests(unittest.TestCase):
    def test_unwritable_cache_folder_does_not_stop_m4(self):
        settings = Settings(cache_path="/proc/nope/c.sqlite3")
        app = create_app(settings, mock=True)
        try:
            enricher = app.extensions["m4"]["enricher"]
            self.assertIsNone(enricher.cache)
            body = app.test_client().post("/enrich", json={"alert_id": "A", "type": "hash", "value": SHA}).get_json()
            self.assertEqual(body["verdict"], "unknown")
            self.assertIsNone(app.test_client().get("/stats").get_json()["cache"])
        finally:
            shutdown_app(app)

    def test_mock_data_is_found_from_any_working_directory(self):
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                app = create_app(Settings(cache_path=os.path.join(tmp, "c.sqlite3")), mock=True)
                shutdown_app(app)
            finally:
                os.chdir(old)

    def test_breaker_can_be_switched_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            enricher = build_enricher(Settings(cache_path=os.path.join(tmp, "c.sqlite3"),
                                               breaker_cooldown=0), mock=True)
            self.assertIsNone(enricher.breaker)
            enricher.cache.close()

    def test_stats_show_skipped_providers(self):
        provider = Counting()
        enricher = Enricher(provider, breaker=ProviderBreaker(threshold=1, cooldown=60))
        app = create_app(Settings(), enricher=enricher)
        try:
            c = app.test_client()
            c.post("/enrich", json={"alert_id": "A", "type": "hash", "value": SHA})
            self.assertIn("abusech", c.get("/stats").get_json()["skipped_providers"])
        finally:
            shutdown_app(app)


if __name__ == "__main__":
    unittest.main()
