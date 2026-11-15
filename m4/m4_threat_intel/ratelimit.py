"""Client-side rate limiting and retry with exponential backoff.

TokenBucket: at most `burst` requests at once, refilled at `rate` per second.
request_with_retry(): one HTTP request with
  * a token taken from the bucket first (so we stay under the provider limit),
  * a timeout,
  * retries on 429/500/502/503/504 and network errors, waiting
    backoff_base * 2^attempt seconds (capped), or the server's Retry-After
    (capped at retry_after_cap),
  * no retry on 401/403: "authentication failed: check API key",
  * a ProviderError when it gives up.
Clock and sleep are injectable so tests never really wait.
"""
import threading
import time
from typing import Any, Callable, Iterable, Optional

import requests

from .schema import ProviderError

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
AUTH_STATUSES = frozenset({401, 403})


class TokenBucket:
    def __init__(self, rate: float, burst: int, max_wait: float = 10.0,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self.rate = rate
        self.burst = burst
        self.max_wait = max_wait
        self._clock = clock
        self._sleep = sleep
        self._tokens = float(burst)
        self._last = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + (now - self._last) * self.rate)
        self._last = now

    def acquire(self) -> None:
        """Take one token, waiting if needed. Raises ProviderError if the
        wait would exceed max_wait (so a caller is never stuck for long)."""
        with self._lock:
            self._refill()
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rate
                if wait > self.max_wait:
                    raise ProviderError("client rate limit: no request slot available")
                self._sleep(wait)
                self._refill()
            self._tokens -= 1


def _retry_after_seconds(resp: Any, cap: float) -> Optional[float]:
    """Retry-After in seconds (numeric form only), capped; None if absent/unparsable."""
    value = (getattr(resp, "headers", None) or {}).get("Retry-After")
    try:
        return max(0.0, min(cap, float(value)))
    except (TypeError, ValueError):
        return None


def request_with_retry(
    session: Any, method: str, url: str, *,
    timeout: float,
    accept: Iterable[int] = (200,),
    bucket: Optional[TokenBucket] = None,
    max_retries: int = 0,
    backoff_base: float = 1.0,
    backoff_max: float = 30.0,
    retry_after_cap: float = 30.0,
    sleep: Callable[[float], None] = time.sleep,
    **kwargs: Any,
) -> requests.Response:
    accept = tuple(accept)
    attempts = max_retries + 1
    last_problem = "no attempt made"
    for attempt in range(attempts):
        if bucket is not None:
            bucket.acquire()
        delay = min(backoff_max, backoff_base * (2 ** attempt))
        try:
            resp = session.request(method, url, timeout=timeout, **kwargs)
        except requests.Timeout:
            last_problem = "timeout"
        except requests.RequestException as exc:
            last_problem = f"network error ({type(exc).__name__})"
        else:
            if resp.status_code in accept:
                return resp
            if resp.status_code in AUTH_STATUSES:
                raise ProviderError("authentication failed: check API key")
            if resp.status_code not in RETRY_STATUSES:
                raise ProviderError(f"unexpected HTTP {resp.status_code}")
            last_problem = f"HTTP {resp.status_code}"
            server_delay = _retry_after_seconds(resp, retry_after_cap)
            if server_delay is not None:
                delay = server_delay
        if attempt < attempts - 1:
            sleep(delay)
    if attempts == 1:
        raise ProviderError(last_problem)
    raise ProviderError(f"{last_problem} (gave up after {attempts} attempts)")
