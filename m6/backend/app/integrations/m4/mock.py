import copy

from ...mock import load_json
from . import M4Adapter


class MockM4(M4Adapter):
    """MOCK M4. Sample enrichment from JSON. No external provider is called."""

    kind = "mock"

    def __init__(self):
        self._items = load_json("threat_intelligence.json")["items"]

    def health(self):
        return {"status": "Stubbed", "detail": "Mock adapter. No threat-intelligence provider is connected."}

    def list_indicators(self):
        return copy.deepcopy(self._items)

    def enrich(self, indicator):
        return next((copy.deepcopy(i) for i in self._items if i["indicator"] == indicator), None)
