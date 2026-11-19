"""Skip a provider for a while after it was unreachable several times in a row.

Without internet (a lab VM with no outbound access, a blocked proxy) every
lookup would wait for all retries of every service (about 24 s measured), longer
than the callers' timeouts (M6 waits 10 s), and the same wait would repeat for
every alert because errors are never cached. After `threshold` consecutive
"unreachable" answers the provider is skipped for `cooldown` seconds; the
answer is then an honest error ("unknown", never "clean"). Only network errors
and timeouts count: HTTP errors and normal "not found" answers do not.
"""
import threading
import time
from typing import Callable, Dict, Optional

from .schema import STATUS_ERROR, ProviderResult


def is_unreachable(result: ProviderResult) -> bool:
    error = result.error or ""
    return result.status == STATUS_ERROR and ("network error" in error or "timeout" in error)


class ProviderBreaker:
    def __init__(self, threshold: int = 2, cooldown: float = 30.0,
                 clock: Callable[[], float] = time.monotonic):
        self.threshold = threshold
        self.cooldown = cooldown
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: Dict[str, int] = {}
        self._open_until: Dict[str, float] = {}

    def skip_reason(self, name: str) -> Optional[str]:
        """Text for the error when `name` must be skipped now, else None."""
        with self._lock:
            remaining = self._open_until.get(name, 0.0) - self._clock()
        if remaining > 0:
            return (f"skipped: {name} was unreachable recently "
                    f"(next try in about {int(remaining) + 1} s)")
        return None

    def record(self, name: str, result: ProviderResult) -> None:
        with self._lock:
            if not is_unreachable(result):
                self._failures[name] = 0
                return
            self._failures[name] = self._failures.get(name, 0) + 1
            if self._failures[name] >= self.threshold:
                self._open_until[name] = self._clock() + self.cooldown
                self._failures[name] = 0      # after the cooldown, one fresh try decides

    def stats(self) -> Dict[str, float]:
        now = self._clock()
        with self._lock:
            return {name: round(until - now, 1) for name, until in self._open_until.items() if until > now}
