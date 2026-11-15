"""Enrichment of one indicator: routing, verdict and response building.

Flow:
  normalise -> allowlist ("clean") -> non-routable IP guard (zero external
  calls) -> cache -> providers -> verdict -> cache (only if no error)

Provider routing:
  * abuse.ch (primary) is always asked first.
  * OTX (secondary) is asked for ip/domain (extra context), and for a hash
    only when abuse.ch did NOT confirm it.
"""
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .allowlist import Allowlist
from .cache import Cache
from .config import MALICIOUS_THRESHOLD, OTX_MAX_SCORE, SUSPICIOUS_THRESHOLD
from .providers.base import Provider
from .schema import (
    STATUS_HIT, VERDICT_CLEAN, VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_UNKNOWN,
    ProviderResult, is_non_routable, normalize,
)


def verdict_for(results: List[ProviderResult]) -> Dict[str, Any]:
    """Turn provider results into verdict, score, sources, tags and error.

    * score >= MALICIOUS_THRESHOLD -> malicious; >= SUSPICIOUS_THRESHOLD -> suspicious
    * no hit at all (not found OR failed) -> unknown. Never "clean".
    * a context-only source (OTX) counts at most OTX_MAX_SCORE, so on its own
      it can never reach malicious.
    """
    score = 0
    sources: List[str] = []
    tags: List[str] = []
    trusted_hit = False
    for r in results:
        if r.status != STATUS_HIT:
            continue
        hit_score = max(0, min(100, int(r.score)))
        if r.context_only:
            hit_score = min(hit_score, OTX_MAX_SCORE)
        else:
            trusted_hit = True
        score = max(score, hit_score)
        sources.extend(_hit_sources(r))
        tags.extend(t for t in r.tags if t not in tags)

    if score >= MALICIOUS_THRESHOLD and trusted_hit:
        verdict = VERDICT_MALICIOUS
    elif score >= SUSPICIOUS_THRESHOLD and sources:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_UNKNOWN

    errors = [f"{r.provider}: {r.error}" for r in results if r.error]
    return {"verdict": verdict, "score": score if sources else 0,
            "sources": sources, "tags": tags, "error": "; ".join(errors) or None}


def _hit_sources(result: ProviderResult) -> List[str]:
    """Name the services that hit (e.g. 'malwarebazaar'), not just 'abusech'."""
    names = result.details.get("hit_services") if isinstance(result.details, dict) else None
    return list(names) if names else [result.provider]


class Enricher:
    def __init__(self, primary: Provider, secondary: Optional[Provider] = None,
                 allowlist: Optional[Allowlist] = None, cache: Optional[Cache] = None,
                 ttl_hit: int = 600, ttl_miss: int = 300, recent=None):
        self.primary = primary
        self.secondary = secondary
        self.allowlist = allowlist or Allowlist()
        self.cache = cache
        self.ttl_hit = ttl_hit
        self.ttl_miss = ttl_miss
        self.recent = recent          # optional RecentLog (answers listed to M6)

    def enrich(self, alert_id: str, ioc_type: str, value: str) -> Dict[str, Any]:
        started = time.perf_counter()
        value = normalize(ioc_type, value)
        cached = False

        if self.allowlist.contains(ioc_type, value):
            core = _local(VERDICT_CLEAN, "local_allowlist", "on the local allowlist")
        elif ioc_type == "ip" and is_non_routable(value):
            core = _local(VERDICT_UNKNOWN, None,
                          "non-routable IP: not sent to external services")
        else:
            stored = self.cache.get(ioc_type, value) if self.cache else None
            if stored is not None:
                core, cached = stored, True
            else:
                core = self._lookup(ioc_type, value)
                # Errors and timeouts are NEVER cached (also enforced in cache.py).
                if self.cache is not None and core["error"] is None:
                    ttl = self.ttl_hit if core["sources"] else self.ttl_miss
                    self.cache.set(ioc_type, value, core, ttl)

        # alert_id always comes from the CURRENT request, even for a cached answer.
        response = _response(alert_id, ioc_type, value, core, cached=cached, started=started)
        if self.recent is not None:
            self.recent.add(response)
        return response

    def _lookup(self, ioc_type: str, value: str) -> Dict[str, Any]:
        results = [self._ask(self.primary, ioc_type, value)]
        primary_confirmed_hash = ioc_type == "hash" and results[0].status == STATUS_HIT
        if self.secondary is not None and not primary_confirmed_hash:
            results.append(self._ask(self.secondary, ioc_type, value))
        core = verdict_for(results)
        core["details"] = [r.to_dict() for r in results]
        core["enriched_at"] = _now()
        return core

    @staticmethod
    def _ask(provider: Provider, ioc_type: str, value: str) -> ProviderResult:
        result = provider.lookup(ioc_type, value)   # never raises (base class)
        # Taken from the provider class, so a result cannot claim otherwise.
        result.context_only = provider.context_only
        return result


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _local(verdict: str, source: Optional[str], note: str) -> Dict[str, Any]:
    return {"verdict": verdict, "score": 0, "sources": [source] if source else [],
            "tags": [], "error": None, "enriched_at": _now(),
            "details": [{"provider": source or "local_policy", "note": note}]}


def _response(alert_id: str, ioc_type: str, value: str, core: Dict[str, Any],
              cached: bool, started: float) -> Dict[str, Any]:
    return {
        "alert_id": alert_id, "type": ioc_type, "value": value,
        "verdict": core["verdict"], "score": core["score"],
        "sources": list(core["sources"]), "tags": list(core["tags"]),
        "cached": cached, "error": core["error"], "details": list(core["details"]),
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        "enriched_at": core["enriched_at"],
    }
