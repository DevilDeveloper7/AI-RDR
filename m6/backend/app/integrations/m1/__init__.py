from ..base import BaseAdapter


class M1Adapter(BaseAdapter):
    """M1: SIEM and telemetry pipeline. Supplies normalized security events (see contracts.EVENT).

    PROVISIONAL / M6 STUB. M6 only reads events; it never collects telemetry itself.
    """

    module = "m1"

    def list_events(self, host=None, since=None, until=None, limit=100):
        """Normalized events, oldest first. `since`/`until` are ISO timestamps (inclusive)."""
        raise NotImplementedError

    def get_event(self, event_id):
        """One event, or None if unknown."""
        raise NotImplementedError
