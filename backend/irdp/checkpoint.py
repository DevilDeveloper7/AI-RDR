"""
CheckpointStore - tracks the last-processed watermark so run_once() doesn't
reprocess the same events. Pluggable per the spec: an in-memory default for
tests, and a local-file implementation structured so a real persistent store
(a local file now, an OpenSearch document later) can swap in without
touching pipeline.run_once at all - both implementations share the same tiny
ABC.

Checkpoint values are opaque strings from this module's point of view - in
practice pipeline.py stores the max `RawEvent.timestamp` seen so far (an
ISO-8601 UTC string, zero-padded so plain string comparison sorts
correctly). Known, documented limitation kept simple on purpose for this
phase: watermarking on timestamp alone can't distinguish two events with the
*exact* same timestamp - a production version should tiebreak on event_id
too (e.g. store `(timestamp, {ids at that timestamp})` and treat "seen
before" as exact-id membership at the boundary instant, not just `> last`).
Not needed for a demo-scope polling consumer; documented here rather than
silently assumed, same as host_controller.py documents its own demo-scope
tradeoffs.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional


class CheckpointStore(ABC):
    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Return the stored checkpoint for `key`, or None if nothing has
        been stored yet (i.e. this is the first-ever poll)."""

    @abstractmethod
    def set(self, key: str, value: str) -> None:
        """Persist `value` as the new checkpoint for `key`."""


class InMemoryCheckpointStore(CheckpointStore):
    """Default store for tests - no filesystem/network access, state lives
    only as long as the Python object does."""

    def __init__(self) -> None:
        self._data: Dict[str, str] = {}

    def get(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value


class FileCheckpointStore(CheckpointStore):
    """Persists checkpoints as a small JSON object on local disk - the
    "e.g. a local file" persistent option the spec calls for, usable by a
    real deployment without any OpenSearch access at all. Reads/writes the
    whole small JSON dict each call rather than a database; that's fine at
    this scale (one key per pipeline instance) and keeps this file
    dependency-free.
    """

    def __init__(self, path: "str | Path") -> None:
        self.path = Path(path)

    def _read_all(self) -> Dict[str, str]:
        if not self.path.exists():
            return {}
        text = self.path.read_text().strip()
        if not text:
            return {}
        return json.loads(text)

    def get(self, key: str) -> Optional[str]:
        return self._read_all().get(key)

    def set(self, key: str, value: str) -> None:
        data = self._read_all()
        data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename would be more robust against a crash mid-write;
        # kept as a plain write for this demo-scope phase, same tradeoff
        # class host_controller.py documents elsewhere (e.g. SSHHostController
        # .snapshot()'s best-effort backup).
        self.path.write_text(json.dumps(data))
