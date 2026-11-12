"""MOCK providers for offline demos and the end-to-end smoke test.

Enabled ONLY when M4_MOCK_PROVIDERS=1. They make no network calls and return
canned answers from data/mock_iocs.json. Every result is labelled
"mock_*" and tagged "MOCK-DATA" so it can never be mistaken for real
threat intelligence.
"""
import json
from typing import Dict, Optional

from ..schema import STATUS_HIT, STATUS_MISS, ProviderResult
from .base import Provider

MOCK_TAG = "MOCK-DATA"


class MockProvider(Provider):
    supported_types = frozenset({"hash", "ip", "domain"})

    def __init__(self, name: str, iocs: Dict[str, Dict[str, int]], context_only: bool = False):
        self.name = name
        self.context_only = context_only
        self._iocs = iocs   # {"hash": {value: score}, "ip": {...}, "domain": {...}}

    def _lookup(self, ioc_type: str, value: str) -> ProviderResult:
        score = self._iocs.get(ioc_type, {}).get(value)
        if score is None:
            return ProviderResult(provider=self.name, status=STATUS_MISS,
                                  details={"note": "mock provider"})
        return ProviderResult(provider=self.name, status=STATUS_HIT, score=int(score),
                              tags=[MOCK_TAG], details={"note": "mock provider"})


def load_mock_providers(path: Optional[str] = None):
    """(primary, secondary) mock providers from a JSON file:
    {"abusech": {"hash": {"<sha256>": 95}}, "otx": {"domain": {"x.example": 40}}}"""
    with open(path or "data/mock_iocs.json", encoding="utf-8") as fh:
        data = json.load(fh)
    return (MockProvider("mock_abusech", data.get("abusech", {})),
            MockProvider("mock_otx", data.get("otx", {}), context_only=True))
