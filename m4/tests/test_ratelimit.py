import unittest

import requests

from m4_threat_intel.ratelimit import TokenBucket, request_with_retry
from m4_threat_intel.schema import ProviderError

from .fakes import FakeResponse as R
from .fakes import FakeSession

URL = "https://api.example/x"


class FakeClock:
    """A clock that only moves when sleep() is called: no real waiting."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class TokenBucketTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def bucket(self, rate=1.0, burst=2, max_wait=10.0):
        return TokenBucket(rate, burst, max_wait=max_wait, clock=self.clock, sleep=self.clock.sleep)

    def test_burst_then_throttle(self):
        b = self.bucket(rate=2.0, burst=3)
        for _ in range(3):
            b.acquire()
        self.assertEqual(self.clock.sleeps, [])          # burst: no waiting
        b.acquire()
        self.assertAlmostEqual(self.clock.sleeps[-1], 0.5)  # 1 token at 2/s

    def test_refill_over_time(self):
        b = self.bucket(rate=1.0, burst=2)
        b.acquire(), b.acquire()
        self.clock.now += 5                               # long idle: refills to burst only
        b.acquire(), b.acquire()
        self.assertEqual(self.clock.sleeps, [])
        b.acquire()
        self.assertAlmostEqual(self.clock.sleeps[-1], 1.0)

    def test_gives_up_when_wait_exceeds_max(self):
        b = self.bucket(rate=0.01, burst=1, max_wait=5)
        b.acquire()
        with self.assertRaises(ProviderError):
            b.acquire()
        self.assertEqual(self.clock.sleeps, [])

    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            TokenBucket(0, 1)


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def call(self, responses, **kw):
        session = FakeSession({"api.example": responses})
        kw.setdefault("max_retries", 3)
        try:
            return request_with_retry(session, "GET", URL, timeout=1, sleep=self.clock.sleep,
                                      **kw), session
        finally:
            self.session = session

    def test_retries_5xx_with_exponential_backoff(self):
        resp, session = self.call([R(503, {}), R(502, {}), R(200, {"ok": 1})])
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.clock.sleeps, [1.0, 2.0])
        self.assertEqual(len(session.calls), 3)

    def test_backoff_is_capped(self):
        with self.assertRaises(ProviderError):
            self.call([R(500, {})], max_retries=6, backoff_max=5)
        self.assertEqual(self.clock.sleeps, [1, 2, 4, 5, 5, 5])

    def test_honours_retry_after_with_cap(self):
        self.call([R(429, {}, headers={"Retry-After": "7"}), R(200, {})])
        self.call([R(429, {}, headers={"Retry-After": "999"}), R(200, {})])
        self.assertEqual(self.clock.sleeps, [7.0, 30.0])

    def test_non_numeric_retry_after_falls_back_to_backoff(self):
        self.call([R(429, {}, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}), R(200, {})])
        self.assertEqual(self.clock.sleeps, [1.0])

    def test_gives_up_after_n_attempts(self):
        with self.assertRaises(ProviderError) as ctx:
            self.call([R(503, {})], max_retries=2)
        self.assertIn("HTTP 503 (gave up after 3 attempts)", str(ctx.exception))
        self.assertEqual(len(self.session.calls), 3)

    def test_auth_failure_not_retried(self):
        for status in (401, 403):
            with self.assertRaises(ProviderError) as ctx:
                self.call([R(status, {}), R(200, {})])
            self.assertIn("authentication failed: check API key", str(ctx.exception))
            self.assertEqual(len(self.session.calls), 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_other_4xx_not_retried(self):
        with self.assertRaises(ProviderError):
            self.call([R(400, {}), R(200, {})])
        self.assertEqual(len(self.session.calls), 1)

    def test_timeout_retried_then_reported(self):
        with self.assertRaises(ProviderError) as ctx:
            self.call([requests.Timeout()], max_retries=1)
        self.assertEqual(str(ctx.exception), "timeout (gave up after 2 attempts)")
        resp, _ = self.call([requests.ConnectionError(), R(200, {})])
        self.assertEqual(resp.status_code, 200)

    def test_extra_accepted_status(self):
        resp, _ = self.call([R(404, {})], accept=(200, 404))
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.clock.sleeps, [])

    def test_uses_bucket_for_every_attempt(self):
        bucket = TokenBucket(1.0, 1, clock=self.clock, sleep=self.clock.sleep)
        self.call([R(503, {}), R(200, {})], bucket=bucket)
        # attempt 1 uses the burst token; backoff 1 s refills it; no extra wait
        self.assertEqual(self.clock.sleeps, [1.0])


if __name__ == "__main__":
    unittest.main()
