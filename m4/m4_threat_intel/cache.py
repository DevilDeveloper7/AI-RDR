"""Thread-safe SQLite cache with a per-entry expiry time (TTL).

Only successful lookups are stored. A payload carrying an error is refused,
so a temporary outage can never be remembered as "not found".
"""
import json
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment_cache (
    ioc_type   TEXT NOT NULL,
    value      TEXT NOT NULL,
    payload    TEXT NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (ioc_type, value)
)
"""


class Cache:
    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        # One connection shared by all worker threads, protected by a lock.
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=5)
        with self._conn:
            self._conn.execute(_SCHEMA)
        self.hits = 0
        self.misses = 0

    def get(self, ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload, expires_at FROM enrichment_cache "
                "WHERE ioc_type = ? AND value = ?", (ioc_type, value)).fetchone()
            if row is None or row[1] <= self._clock():
                self.misses += 1
                return None
            self.hits += 1
            return json.loads(row[0])

    def set(self, ioc_type: str, value: str, payload: Dict[str, Any], ttl: int) -> None:
        if payload.get("error"):
            raise ValueError("refusing to cache a result that contains an error")
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO enrichment_cache (ioc_type, value, payload, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (ioc_type, value, json.dumps(payload), self._clock() + ttl))

    def purge_expired(self) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM enrichment_cache WHERE expires_at <= ?", (self._clock(),))
            return cur.rowcount

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            (entries,) = self._conn.execute("SELECT COUNT(*) FROM enrichment_cache").fetchone()
            lookups = self.hits + self.misses
            return {"entries": entries, "hits": self.hits, "misses": self.misses,
                    "hit_rate": round(self.hits / lookups, 3) if lookups else None}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
