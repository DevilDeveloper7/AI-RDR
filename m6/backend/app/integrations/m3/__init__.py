from ..base import BaseAdapter


class M3Adapter(BaseAdapter):
    """M3: honey-file deception (the inotify watcher lives in M3, not M6).

    A honey-file trigger is its own high-confidence detection path. It goes straight to M6 and
    response; it is NOT routed through M2/ML.

    PROVISIONAL / M6 STUB.
    """

    module = "m3"

    def list_honey_files(self):
        """Return {"items": [HONEY_ITEM...], "activity": [{"timestamp","text","hot"}...], "watcher_status": str}."""
        raise NotImplementedError

    def list_triggers(self):
        """Honey-file trigger alerts (see contracts.TRIGGER), newest first."""
        raise NotImplementedError
