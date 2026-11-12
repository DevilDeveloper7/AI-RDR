import os
import tempfile
import threading
import unittest

from m4_threat_intel.cache import Cache
from m4_threat_intel.enricher import Enricher

from .fakes import StaticProvider


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class CacheTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = FakeClock()
        self.cache = Cache(os.path.join(self.tmp.name, "c.sqlite3"), clock=self.clock)

    def tearDown(self):
        self.cache.close()
        self.tmp.cleanup()


class CacheTests(CacheTestBase):
    def test_round_trip_and_stats(self):
        self.assertIsNone(self.cache.get("ip", "8.8.8.8"))
        self.cache.set("ip", "8.8.8.8", {"verdict": "unknown", "error": None}, 60)
        self.assertEqual(self.cache.get("ip", "8.8.8.8")["verdict"], "unknown")
        self.assertEqual(self.cache.stats(),
                         {"entries": 1, "hits": 1, "misses": 1, "hit_rate": 0.5})

    def test_ttl_expiry_and_purge(self):
        self.cache.set("ip", "8.8.8.8", {"error": None}, 60)
        self.cache.set("ip", "1.1.1.1", {"error": None}, 600)
        self.clock.now += 61
        self.assertIsNone(self.cache.get("ip", "8.8.8.8"))
        self.assertIsNotNone(self.cache.get("ip", "1.1.1.1"))
        self.assertEqual(self.cache.purge_expired(), 1)
        self.assertEqual(self.cache.stats()["entries"], 1)

    def test_refuses_errors(self):
        with self.assertRaises(ValueError):
            self.cache.set("ip", "8.8.8.8", {"error": "timeout"}, 60)

    def test_thread_safety(self):
        def worker(n):
            for i in range(50):
                self.cache.set("domain", f"d{n}-{i}.example", {"error": None}, 60)
                self.cache.get("domain", f"d{n}-{i}.example")
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.cache.stats()["entries"], 200)


class EnricherCachingTests(CacheTestBase):
    def enricher(self, abuse, otx=None):
        return Enricher(abuse, otx, cache=self.cache, ttl_hit=86400, ttl_miss=3600)

    def test_second_identical_lookup_makes_zero_provider_calls(self):
        a = StaticProvider(name="abusech", status="hit", score=95)
        e = self.enricher(a)
        first = e.enrich("A1", "hash", "e" * 64)
        second = e.enrich("A2", "hash", "E" * 64)
        self.assertEqual(len(a.calls), 1)
        self.assertEqual((first["cached"], second["cached"]), (False, True))
        self.assertEqual(second["alert_id"], "A2")            # current request's id
        self.assertEqual(second["verdict"], "malicious")
        self.assertEqual(second["enriched_at"], first["enriched_at"])

    def test_errors_are_never_cached(self):
        a = StaticProvider(name="abusech", status="error", error="timeout")
        e = self.enricher(a)
        e.enrich("A1", "domain", "x.example")
        out = e.enrich("A1", "domain", "x.example")
        self.assertEqual(len(a.calls), 2)
        self.assertFalse(out["cached"])
        self.assertEqual(self.cache.stats()["entries"], 0)

    def test_partial_failure_not_cached(self):
        a = StaticProvider(name="abusech", status="hit", score=95)
        o = StaticProvider(name="otx", status="error", error="HTTP 503", context_only=True)
        e = self.enricher(a, o)
        e.enrich("A1", "domain", "x.example")
        e.enrich("A1", "domain", "x.example")
        self.assertEqual(len(a.calls), 2)

    def test_hit_and_miss_ttls(self):
        hit = StaticProvider(name="abusech", status="hit", score=95)
        miss = StaticProvider(name="abusech")
        self.enricher(hit).enrich("A1", "domain", "hit.example")
        self.enricher(miss).enrich("A1", "domain", "miss.example")
        self.clock.now += 3601                                  # miss TTL (1 h) passed
        self.assertIsNotNone(self.cache.get("domain", "hit.example"))
        self.assertIsNone(self.cache.get("domain", "miss.example"))
        self.clock.now += 86400                                 # hit TTL (24 h) passed
        self.assertIsNone(self.cache.get("domain", "hit.example"))

    def test_private_ip_and_allowlist_not_cached(self):
        e = self.enricher(StaticProvider(name="abusech"))
        e.enrich("A1", "ip", "10.0.0.1")
        self.assertEqual(self.cache.stats()["entries"], 0)


if __name__ == "__main__":
    unittest.main()
