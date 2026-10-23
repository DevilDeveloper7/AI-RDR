import copy

from ...mock import load_json
from . import M3Adapter


class MockM3(M3Adapter):
    """MOCK M3. Honey-file status and triggers from JSON. No real watcher exists."""

    kind = "mock"

    def __init__(self):
        self._files = load_json("honey_files.json")
        self._triggers = load_json("m3_triggers.json")["triggers"]

    def health(self):
        return {"status": "Stubbed", "detail": "Mock adapter. No real inotify watcher is connected."}

    def list_honey_files(self):
        return {"items": copy.deepcopy(self._files["items"]), "activity": copy.deepcopy(self._files["activity"]), "watcher_status": "Running"}

    def list_triggers(self):
        return copy.deepcopy(self._triggers)
