"""AlienVault/LevelBlue OTX provider (SECONDARY, context only).

Format verified against AlienVault's official Python SDK (docs/api_notes.md):
GET /api/v1/indicators/<IPv4|IPv6|domain|file>/<value>/general with header
X-OTX-API-KEY. 404 = not found, 403 = bad key.

OTX is community data and noisy, so its score is capped at OTX_MAX_SCORE
(60), below the malicious threshold: OTX alone can never make "malicious".
"""
import ipaddress
from typing import Any, Dict, List, Optional

from ..config import MAX_TAGS_PER_PROVIDER, OTX_BASE_SCORE, OTX_MAX_SCORE, OTX_PER_PULSE
from ..http import HttpClient, ProviderError, json_object
from ..schema import STATUS_HIT, STATUS_MISS, ProviderResult
from .base import Provider

OTX_INDICATORS_URL = "https://otx.alienvault.com/api/v1/indicators"


def otx_score(pulse_count: int) -> int:
    return min(OTX_MAX_SCORE, OTX_BASE_SCORE + OTX_PER_PULSE * pulse_count)


def _slug(ioc_type: str, value: str) -> str:
    if ioc_type == "hash":
        return "file"
    if ioc_type == "ip":
        return "IPv6" if ipaddress.ip_address(value).version == 6 else "IPv4"
    return "domain"


class OTXProvider(Provider):
    name = "otx"
    supported_types = frozenset({"hash", "ip", "domain"})
    context_only = True

    def __init__(self, api_key: Optional[str], http: Optional[HttpClient] = None):
        self._api_key = api_key
        self._http = http or HttpClient()

    def _lookup(self, ioc_type: str, value: str) -> ProviderResult:
        if not self._api_key:
            return self.error("OTX_API_KEY is not set")   # no network call
        url = f"{OTX_INDICATORS_URL}/{_slug(ioc_type, value)}/{value}/general"
        try:
            resp = self._http.request("GET", url, accept=(200, 404),
                                      headers={"X-OTX-API-KEY": self._api_key})
            if resp.status_code == 404:
                return self._miss(reason="not found (404)")
            body = json_object(resp)
            return self._parse(body)
        except ProviderError as exc:
            return self.error(str(exc))

    def _parse(self, body: Dict[str, Any]) -> ProviderResult:
        # OTX marks known-benign indicators with a non-empty "validation"
        # field. The official example then ignores the pulses. We treat it as
        # a miss: only OUR allowlist may say "clean".
        if body.get("validation"):
            return self._miss(reason="whitelisted by OTX validation", otx_validation=True)

        pulse_info = body.get("pulse_info")
        pulses = pulse_info.get("pulses") if isinstance(pulse_info, dict) else None
        if not isinstance(pulses, list):
            raise ProviderError("unexpected 'pulse_info.pulses' in response")
        pulses = [p for p in pulses if isinstance(p, dict)]
        if not pulses:
            return self._miss(reason="no pulses")

        tags: List[str] = []
        for pulse in pulses:
            for tag in pulse.get("tags") or []:
                if isinstance(tag, str) and tag.strip() and tag.strip() not in tags:
                    tags.append(tag.strip())
        return ProviderResult(
            provider=self.name, status=STATUS_HIT, score=otx_score(len(pulses)),
            tags=tags[:MAX_TAGS_PER_PROVIDER],
            details={"pulse_count": len(pulses),
                     "pulse_names": [p.get("name") for p in pulses[:5] if p.get("name")]},
        )

    def _miss(self, **details: Any) -> ProviderResult:
        return ProviderResult(provider=self.name, status=STATUS_MISS, details=details)
