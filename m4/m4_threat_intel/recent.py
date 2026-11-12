"""Bounded, thread-safe memory of the most recent enrichment answers.

M6 lists "indicators related to an alert". M4 keeps no indicator database (the
cache expires entries), so it remembers the last answers here, one per
(alert_id, type, value), newest first. In memory only: a restart empties it.
Lookups made by M6 itself for the detail view (alert id starting with
`m6-lookup`) are not remembered, so they never appear as related to an alert.
"""
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional

NOT_LOGGED_PREFIX = "m6-lookup"


class RecentLog:
    def __init__(self, maxlen: int = 500):
        self._maxlen = maxlen
        self._lock = threading.Lock()
        self._items: "OrderedDict[tuple, Dict[str, Any]]" = OrderedDict()

    def add(self, result: Dict[str, Any]) -> None:
        alert_id = str(result.get("alert_id", ""))
        if alert_id.startswith(NOT_LOGGED_PREFIX):
            return
        key = (alert_id, result.get("type"), result.get("value"))
        with self._lock:
            self._items[key] = dict(result)
            self._items.move_to_end(key)
            while len(self._items) > self._maxlen:
                self._items.popitem(last=False)

    def items(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Newest first."""
        with self._lock:
            out = [dict(v) for v in reversed(self._items.values())]
        return out[:limit] if limit else out

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
