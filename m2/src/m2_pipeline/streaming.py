"""Turn a live syscall stream into M2 window feature rows as events arrive.

Each event only updates counters, so memory stays constant per host and the
model runs once per closed window instead of once per event. Rows are
identical to ``extract_window_features`` over the same non-overlapping windows.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

from .features import (
    CLOSE_SYSCALLS,
    DELETE_SYSCALLS,
    FEATURE_VERSION,
    MEMORY_SYSCALLS,
    METADATA_SYSCALLS,
    NETWORK_SYSCALLS,
    OPEN_SYSCALLS,
    PROCESS_SYSCALLS,
    READ_SYSCALLS,
    RENAME_SYSCALLS,
    SYNC_SYSCALLS,
    WRITE_SYSCALLS,
)
from .schema import _optional_int, _parse_timestamp, _string_or_none

OPEN_THEN_READ = frozenset({"open", "openat"})

# libsinsp names that differ from the kernel tracepoint names used in training.
FALCO_SYSCALL_ALIASES = {"pread": "pread64", "pwrite": "pwrite64"}
# libsinsp event types that are not syscalls; training traced sys_enter_* only.
FALCO_NON_SYSCALL_EVENTS = frozenset(
    {
        "asyncevent",
        "container",
        "cpu_hotplug",
        "drop",
        "infra",
        "notification",
        "page_fault",
        "pluginevent",
        "procexit",
        "procinfo",
        "scapevent",
        "signaldeliver",
        "switch",
    }
)
_EXTRA_FRACTION_DIGITS = re.compile(r"(\.\d{6})\d+")


def stream_window_id(host: str, start: float, end: float) -> str:
    identity = f"stream:{host}:{start:.9f}:{end:.9f}"
    return hashlib.sha256(identity.encode()).hexdigest()[:20]


@dataclass(frozen=True, slots=True)
class WindowFeatures:
    host: str
    start: float
    end: float
    features: dict[str, float]
    feature_version: str = FEATURE_VERSION

    @property
    def window_id(self) -> str:
        return stream_window_id(self.host, self.start, self.end)

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "host": self.host,
            "start": self.start,
            "end": self.end,
            "feature_version": self.feature_version,
            "features": dict(self.features),
        }


class _Window:
    __slots__ = (
        "start",
        "total",
        "syscalls",
        "pids",
        "processes",
        "read_bytes",
        "write_bytes",
        "last",
        "open_to_read",
        "read_to_write",
        "write_to_sync",
    )

    def __init__(self, start: float) -> None:
        self.start = start
        self.total = 0
        self.syscalls: Counter[str] = Counter()
        self.pids: Counter[int] = Counter()
        self.processes: set[str] = set()
        self.read_bytes = 0
        self.write_bytes = 0
        self.last: str | None = None
        self.open_to_read = 0
        self.read_to_write = 0
        self.write_to_sync = 0

    def add(
        self,
        syscall: str,
        pid: int | None,
        process_name: str | None,
        nbytes: int | None,
    ) -> None:
        self.total += 1
        self.syscalls[syscall] += 1
        if pid is not None:
            self.pids[pid] += 1
        if process_name is not None:
            self.processes.add(process_name)
        last = self.last
        if syscall in READ_SYSCALLS:
            self.read_bytes += nbytes or 0
            if syscall == "read" and last in OPEN_THEN_READ:
                self.open_to_read += 1
        if syscall in WRITE_SYSCALLS:
            self.write_bytes += nbytes or 0
            if last in READ_SYSCALLS:
                self.read_to_write += 1
        if syscall in SYNC_SYSCALLS and last in WRITE_SYSCALLS:
            self.write_to_sync += 1
        self.last = syscall

    def features(self, end: float) -> dict[str, float]:
        # Keep formulas and summation order in step with
        # extract_window_features; tests require identical rows.
        total = self.total
        duration = max(end - self.start, 1e-9)
        syscalls = self.syscalls

        def count(names: set[str]) -> int:
            return sum(syscalls[name] for name in names)

        read_count = count(READ_SYSCALLS)
        write_count = count(WRITE_SYSCALLS)
        open_count = count(OPEN_SYSCALLS)
        close_count = count(CLOSE_SYSCALLS)
        rename_count = count(RENAME_SYSCALLS)
        delete_count = count(DELETE_SYSCALLS)
        sync_count = count(SYNC_SYSCALLS)
        metadata_count = count(METADATA_SYSCALLS)
        memory_count = count(MEMORY_SYSCALLS)
        network_count = count(NETWORK_SYSCALLS)
        process_count = count(PROCESS_SYSCALLS)

        entropy = 0.0
        for frequency in syscalls.values():
            probability = frequency / total
            entropy -= probability * math.log2(probability)

        return {
            "event_count": total,
            "event_rate": total / duration,
            "unique_syscalls": len(syscalls),
            "syscall_entropy": entropy,
            "unique_pids": len(self.pids),
            "unique_processes": len(self.processes),
            "max_pid_share": max(self.pids.values(), default=0) / total,
            "read_count": read_count,
            "write_count": write_count,
            "open_count": open_count,
            "close_count": close_count,
            "rename_count": rename_count,
            "delete_count": delete_count,
            "sync_count": sync_count,
            "metadata_count": metadata_count,
            "memory_count": memory_count,
            "network_count": network_count,
            "process_count": process_count,
            "read_ratio": read_count / total,
            "write_ratio": write_count / total,
            "open_ratio": open_count / total,
            "rename_delete_ratio": (rename_count + delete_count) / total,
            "sync_ratio": sync_count / total,
            "metadata_ratio": metadata_count / total,
            "memory_ratio": memory_count / total,
            "network_ratio": network_count / total,
            "read_bytes_requested": self.read_bytes,
            "write_bytes_requested": self.write_bytes,
            "open_to_read": self.open_to_read,
            "read_to_write": self.read_to_write,
            "write_to_sync": self.write_to_sync,
        }


class HostWindowAggregator:
    """Host-wide, non-overlapping windows aligned to each host's first event.

    Events should arrive in timestamp order per host; an event older than the
    open window is counted in it rather than dropped. Windows are host-wide on
    purpose: the model was trained on all processes of a host per window.
    """

    def __init__(self, size: float = 5.0, min_events: int = 2) -> None:
        if size <= 0:
            raise ValueError("Window size must be positive")
        if min_events < 1:
            raise ValueError("min_events must be at least 1")
        self.size = size
        self.min_events = min_events
        self._windows: dict[str, _Window] = {}
        self._next_start: dict[str, float] = {}

    def add(
        self,
        host: str,
        timestamp: float,
        syscall: str,
        *,
        pid: int | None = None,
        process_name: str | None = None,
        nbytes: int | None = None,
    ) -> WindowFeatures | None:
        """Count one event with a normalized syscall name.

        Returns the host's previous window when this event closes it.
        """
        window = self._windows.get(host)
        closed = None
        if window is None:
            window = self._open(host, self._next_start.pop(host, timestamp), timestamp)
        elif timestamp >= window.start + self.size:
            closed = self._close(host, window)
            window = self._open(host, window.start + self.size, timestamp)
        window.add(syscall, pid, process_name, nbytes)
        return closed

    def expire(self, now: float) -> list[WindowFeatures]:
        """Close windows that ended by ``now``, on the event timestamp clock."""
        closed = []
        for host, window in list(self._windows.items()):
            end = window.start + self.size
            if now >= end:
                del self._windows[host]
                self._next_start[host] = end
                row = self._close(host, window)
                if row is not None:
                    closed.append(row)
        return closed

    def flush(self) -> list[WindowFeatures]:
        """Close every open window, e.g. at the end of the input."""
        closed = [
            row
            for host, window in self._windows.items()
            if (row := self._close(host, window)) is not None
        ]
        self._windows.clear()
        self._next_start.clear()
        return closed

    def _open(self, host: str, start: float, timestamp: float) -> _Window:
        while timestamp >= start + self.size:
            start += self.size
        window = self._windows[host] = _Window(start)
        return window

    def _close(self, host: str, window: _Window) -> WindowFeatures | None:
        if window.total < self.min_events:
            return None
        end = window.start + self.size
        return WindowFeatures(
            host=host,
            start=window.start,
            end=end,
            features=window.features(end),
        )


@dataclass(frozen=True, slots=True)
class StreamEvent:
    host: str
    timestamp: float
    syscall: str
    pid: int | None = None
    process_name: str | None = None
    nbytes: int | None = None


def parse_falco_line(line: str, *, default_host: str = "unknown-host") -> StreamEvent | None:
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    return parse_falco_record(record, default_host=default_host)


def parse_falco_record(
    record: Mapping[str, Any],
    *,
    default_host: str = "unknown-host",
) -> StreamEvent | None:
    """Map one Falco JSON alert, or a flat event with Falco field names.

    Returns None for records that are not usable syscall events. Enter events
    are dropped so a stream carrying both directions counts each call once.
    """
    source = record.get("source")
    if source is not None and source != "syscall":
        return None
    fields = record.get("output_fields")
    if not isinstance(fields, Mapping):
        fields = record
    if fields.get("evt.dir") == ">":
        return None
    syscall = fields.get("evt.type")
    if not isinstance(syscall, str) or not syscall:
        return None
    syscall = syscall.lower()
    if syscall in FALCO_NON_SYSCALL_EVENTS:
        return None
    timestamp = _event_timestamp(fields, record)
    if timestamp is None:
        return None

    # Training PIDs come from ftrace task IDs, which are thread IDs.
    pid = _optional_int(fields.get("thread.tid"))
    if pid is None:
        pid = _optional_int(fields.get("proc.pid"))
    nbytes = _optional_int(fields.get("evt.rawarg.size"))
    if nbytes is None:
        nbytes = _optional_int(fields.get("evt.arg.size"))
    host = record.get("hostname") or fields.get("evt.hostname") or default_host
    return StreamEvent(
        host=str(host),
        timestamp=timestamp,
        syscall=FALCO_SYSCALL_ALIASES.get(syscall, syscall),
        pid=pid,
        process_name=_string_or_none(fields.get("proc.name")),
        nbytes=nbytes,
    )


def _event_timestamp(fields: Mapping[str, Any], record: Mapping[str, Any]) -> float | None:
    candidates = (
        fields.get("evt.rawtime"),
        fields.get("evt.time"),
        fields.get("timestamp"),
        record.get("time"),
    )
    for value in candidates:
        if value in (None, "") or isinstance(value, bool):
            continue
        if isinstance(value, str):
            value = _EXTRA_FRACTION_DIGITS.sub(r"\1", value)
        try:
            timestamp = _parse_timestamp(value, 0.0)
        except ValueError:
            # Falco's text evt.time is a time of day; try the next field.
            continue
        if math.isfinite(timestamp):
            return timestamp
    return None


class WindowScorer(Protocol):
    feature_version: str

    def predict_features(self, features: Mapping[str, Any], *, top_k: int = 8) -> Any: ...


def score_falco_stream(
    lines: Iterable[str],
    service: WindowScorer,
    output: TextIO,
    *,
    default_host: str = "unknown-host",
    size: float = 5.0,
    min_events: int = 2,
    lateness: float = 5.0,
    top_k: int = 8,
) -> dict[str, int]:
    """Score Falco JSON lines and write one JSON result line per closed window.

    A quiet host's window is closed once any host's events are ``lateness``
    seconds past its end, so it does not wait for the end of the input.
    """
    if service.feature_version != FEATURE_VERSION:
        raise ValueError(
            f"Model expects feature version {service.feature_version}, "
            f"the stream produces {FEATURE_VERSION}"
        )
    if lateness < 0:
        raise ValueError("lateness must not be negative")

    aggregator = HostWindowAggregator(size=size, min_events=min_events)
    stats = {"events": 0, "skipped_lines": 0, "windows": 0, "alerts": 0}
    hosts: set[str] = set()
    next_check = -math.inf

    def emit(window: WindowFeatures) -> None:
        result = service.predict_features(window.features, top_k=top_k).to_dict()
        row = {
            "window_id": window.window_id,
            "host": window.host,
            "start": window.start,
            "end": window.end,
            **result,
            "features": window.features,
        }
        output.write(json.dumps(row, separators=(",", ":")) + "\n")
        output.flush()
        stats["windows"] += 1
        stats["alerts"] += int(result["alert"])

    for line in lines:
        event = parse_falco_line(line, default_host=default_host)
        if event is None:
            stats["skipped_lines"] += 1
            continue
        stats["events"] += 1
        hosts.add(event.host)
        closed = aggregator.add(
            event.host,
            event.timestamp,
            event.syscall,
            pid=event.pid,
            process_name=event.process_name,
            nbytes=event.nbytes,
        )
        if closed is not None:
            emit(closed)
        if event.timestamp >= next_check:
            next_check = event.timestamp + 1.0
            for window in aggregator.expire(event.timestamp - lateness):
                emit(window)
    for window in aggregator.flush():
        emit(window)
    return {**stats, "hosts": len(hosts)}
