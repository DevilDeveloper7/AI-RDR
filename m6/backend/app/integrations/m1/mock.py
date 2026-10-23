import copy

from ...mock import load_json
from . import M1Adapter


class MockM1(M1Adapter):
    """MOCK M1. Serves sample normalized events from mock/m1_events.json. Not real telemetry."""

    kind = "mock"

    def __init__(self):
        self._events = sorted(load_json("m1_events.json")["events"], key=lambda e: e["timestamp"])

    def health(self):
        return {"status": "Stubbed", "detail": f"Mock adapter with {len(self._events)} sample events. No real M1 is connected."}

    def list_events(self, host=None, since=None, until=None, limit=100):
        items = [e for e in self._events
                 if (not host or e["host"] == host) and (not since or e["timestamp"] >= since) and (not until or e["timestamp"] <= until)]
        return copy.deepcopy(items[:limit])

    def get_event(self, event_id):
        return next((copy.deepcopy(e) for e in self._events if e["event_id"] == event_id), None)
