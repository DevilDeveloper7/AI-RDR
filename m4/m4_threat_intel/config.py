"""Settings for M4, read from environment variables.

API keys come from the environment only. They are never hard-coded, logged
or committed (`.env` is git-ignored).
"""
import os
from dataclasses import dataclass
from typing import Optional

# --- Verdict thresholds ------------------------------------------------------
# DESIGN CHOICES, not measured values. To be tuned with the Week 7 labelled
# hash set and agreed with the supervisor.
MALICIOUS_THRESHOLD = 80   # score >= 80 with a hit -> "malicious"
SUSPICIOUS_THRESHOLD = 30  # score >= 30 with a hit -> "suspicious"

# --- Per-source scores (design choices, see docs/interface_contract.md) -------
MALWAREBAZAAR_HIT_SCORE = 95       # hash is a known malware sample
THREATFOX_DEFAULT_SCORE = 75       # used when confidence_level is missing
URLHAUS_ONLINE_SCORE = 85          # host serves at least one URL still online
# Offline-only URLhaus history is CONTEXT, not evidence: below SUSPICIOUS_THRESHOLD,
# so the verdict stays "unknown" but the analyst still sees it. Decided after a
# real run (18 Oct 2026) where benign example.com had one offline honeypot-reported URL.
URLHAUS_OFFLINE_SCORE = 25         # host only has offline (historic) URLs
OTX_MAX_SCORE = 60                 # OTX alone is capped below MALICIOUS_THRESHOLD
OTX_BASE_SCORE = 25                # OTX score = min(60, 25 + 5 * pulse_count)
OTX_PER_PULSE = 5
MAX_TAGS_PER_PROVIDER = 20

assert OTX_MAX_SCORE < MALICIOUS_THRESHOLD, "OTX alone must never reach malicious"


def _str(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name, "").strip()
    return value or default


def _int(name: str, default: int) -> int:
    value = _str(name)
    return int(value) if value is not None else default


def _float(name: str, default: float) -> float:
    value = _str(name)
    return float(value) if value is not None else default


@dataclass
class Settings:
    # Secrets (environment only)
    abusech_auth_key: Optional[str] = None
    otx_api_key: Optional[str] = None

    # HTTP behaviour
    http_timeout: float = 10.0          # seconds per request
    max_retries: int = 3                # retries after the first attempt
    backoff_base: float = 1.0           # 1 s, 2 s, 4 s, ...
    backoff_max: float = 30.0
    retry_after_cap: float = 30.0       # never wait longer than this for Retry-After

    # Client-side rate limits (conservative defaults; see docs/api_notes.md)
    abusech_rate: float = 1.0           # tokens per second
    abusech_burst: int = 2
    otx_rate: float = 1.0
    otx_burst: int = 2
    rate_max_wait: float = 10.0         # give up if no token within this time

    # Cache
    cache_path: str = "m4_cache.sqlite3"
    ttl_hit: int = 600            # found (malicious/suspicious)
    ttl_miss: int = 300                # not found
    # errors are never cached

    # Local allowlist (the only source of "clean")
    allowlist_path: Optional[str] = None

    # Async workers
    workers: int = 4
    max_jobs: int = 1000                # oldest jobs evicted beyond this

    @classmethod
    def from_env(cls) -> "Settings":
        d = cls()
        return cls(
            abusech_auth_key=_str("ABUSECH_AUTH_KEY"),
            otx_api_key=_str("OTX_API_KEY"),
            http_timeout=_float("M4_HTTP_TIMEOUT", d.http_timeout),
            max_retries=_int("M4_MAX_RETRIES", d.max_retries),
            backoff_base=_float("M4_BACKOFF_BASE", d.backoff_base),
            backoff_max=_float("M4_BACKOFF_MAX", d.backoff_max),
            retry_after_cap=_float("M4_RETRY_AFTER_CAP", d.retry_after_cap),
            abusech_rate=_float("M4_ABUSECH_RATE", d.abusech_rate),
            abusech_burst=_int("M4_ABUSECH_BURST", d.abusech_burst),
            otx_rate=_float("M4_OTX_RATE", d.otx_rate),
            otx_burst=_int("M4_OTX_BURST", d.otx_burst),
            rate_max_wait=_float("M4_RATE_MAX_WAIT", d.rate_max_wait),
            cache_path=_str("M4_CACHE_PATH", d.cache_path),
            ttl_hit=_int("M4_TTL_HIT", d.ttl_hit),
            ttl_miss=_int("M4_TTL_MISS", d.ttl_miss),
            allowlist_path=_str("M4_ALLOWLIST_PATH"),
            workers=_int("M4_WORKERS", d.workers),
            max_jobs=_int("M4_MAX_JOBS", d.max_jobs),
        )

    def __repr__(self) -> str:
        # Never print the keys themselves (e.g. in logs or tracebacks).
        return (
            f"Settings(abusech_key={'set' if self.abusech_auth_key else 'missing'}, "
            f"otx_key={'set' if self.otx_api_key else 'missing'}, "
            f"cache_path={self.cache_path!r}, workers={self.workers})"
        )
