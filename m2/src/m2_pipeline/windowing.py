from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import asdict, dataclass
from itertools import groupby
from typing import Any, Iterable, Iterator, Literal

from .schema import NormalizedEvent, SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class SlidingWindowConfig:
    mode: Literal["time", "events"] = "time"
    size: float = 5.0
    stride: float = 1.0
    min_events: int = 2

    def __post_init__(self) -> None:
        if self.size <= 0 or self.stride <= 0:
            raise ValueError("Window size and stride must be positive")
        if self.min_events < 1:
            raise ValueError("min_events must be at least one")
        if self.mode == "events" and (
            not self.size.is_integer() or not self.stride.is_integer()
        ):
            raise ValueError("Event windows require integer size and stride")


@dataclass(frozen=True, slots=True)
class WindowRecord:
    window_id: str
    run_id: str
    label: str
    split: str
    start: float
    end: float
    event_count: int
    events: tuple[NormalizedEvent, ...]
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["events"] = [_compact_event(event) for event in self.events]
        return value


def split_for_run(
    run_id: str,
    *,
    train: float = 0.70,
    validation: float = 0.15,
    salt: str = "ai-rdr-m2-v1",
) -> str:
    if not 0 < train < 1 or not 0 <= validation < 1 or train + validation >= 1:
        raise ValueError("Split ratios must leave non-zero test data")
    digest = hashlib.sha256(f"{salt}:{run_id}".encode()).digest()
    value = int.from_bytes(digest[:8], "big") / 2**64
    if value < train:
        return "train"
    if value < train + validation:
        return "validation"
    return "test"


def iter_windows(
    events: Iterable[NormalizedEvent],
    config: SlidingWindowConfig,
) -> Iterator[WindowRecord]:
    ordered = sorted(events, key=lambda event: (event.run_id, event.timestamp))
    for run_id, run_events_iter in groupby(ordered, key=lambda event: event.run_id):
        run_events = list(run_events_iter)
        labels = {event.label for event in run_events}
        if len(labels) != 1:
            raise ValueError(f"Run {run_id!r} contains mixed labels: {sorted(labels)}")
        if config.mode == "time":
            yield from _time_windows(run_events, config)
        else:
            yield from _event_windows(run_events, config)


def iter_run_windows(
    events: Iterable[NormalizedEvent],
    config: SlidingWindowConfig,
) -> Iterator[WindowRecord]:
    """Window one already ordered run without loading the full trace."""
    if config.mode == "time":
        yield from _stream_time_windows(iter(events), config)
    else:
        yield from _stream_event_windows(iter(events), config)


def _time_windows(
    events: list[NormalizedEvent],
    config: SlidingWindowConfig,
) -> Iterator[WindowRecord]:
    if not events:
        return
    first = events[0].timestamp
    last = events[-1].timestamp
    start = first
    left = 0
    right = 0
    while start <= last:
        end = start + config.size
        while left < len(events) and events[left].timestamp < start:
            left += 1
        right = max(right, left)
        while right < len(events) and events[right].timestamp < end:
            right += 1
        selected = events[left:right]
        if len(selected) >= config.min_events:
            yield _record(selected, start, end)
        start += config.stride


def _event_windows(
    events: list[NormalizedEvent],
    config: SlidingWindowConfig,
) -> Iterator[WindowRecord]:
    size = int(config.size)
    stride = int(config.stride)
    for start_index in range(0, len(events), stride):
        selected = events[start_index : start_index + size]
        if len(selected) < max(config.min_events, size):
            break
        yield _record(
            selected,
            selected[0].timestamp,
            selected[-1].timestamp,
            ordinal=start_index,
        )


def _record(
    events: list[NormalizedEvent],
    start: float,
    end: float,
    *,
    ordinal: int | None = None,
) -> WindowRecord:
    run_id = events[0].run_id
    identity = f"{run_id}:{start:.9f}:{end:.9f}:{ordinal}"
    window_id = hashlib.sha256(identity.encode()).hexdigest()[:20]
    return WindowRecord(
        window_id=window_id,
        run_id=run_id,
        label=events[0].label,
        split=split_for_run(run_id),
        start=start,
        end=end,
        event_count=len(events),
        events=tuple(events),
    )


def _stream_time_windows(
    events: Iterator[NormalizedEvent],
    config: SlidingWindowConfig,
) -> Iterator[WindowRecord]:
    try:
        first = next(events)
    except StopIteration:
        return

    run_id = first.run_id
    label = first.label
    start = first.timestamp
    last_timestamp = first.timestamp
    active: deque[NormalizedEvent] = deque([first])

    for event in events:
        _validate_stream_event(event, run_id, label, last_timestamp)
        while event.timestamp >= start + config.size:
            if len(active) >= config.min_events:
                yield _record(list(active), start, start + config.size)
            start += config.stride
            while active and active[0].timestamp < start:
                active.popleft()
        active.append(event)
        last_timestamp = event.timestamp

    while start <= last_timestamp:
        if len(active) >= config.min_events:
            yield _record(list(active), start, start + config.size)
        start += config.stride
        while active and active[0].timestamp < start:
            active.popleft()


def _stream_event_windows(
    events: Iterator[NormalizedEvent],
    config: SlidingWindowConfig,
) -> Iterator[WindowRecord]:
    size = int(config.size)
    stride = int(config.stride)
    buffer: list[NormalizedEvent] = []
    skip = 0
    ordinal = 0
    run_id: str | None = None
    label: str | None = None
    last_timestamp = float("-inf")

    for event in events:
        if run_id is None:
            run_id, label = event.run_id, event.label
        _validate_stream_event(event, run_id, label or "unknown", last_timestamp)
        last_timestamp = event.timestamp
        if skip:
            skip -= 1
            ordinal += 1
            continue
        buffer.append(event)
        if len(buffer) == size:
            if len(buffer) >= config.min_events:
                yield _record(
                    buffer,
                    buffer[0].timestamp,
                    buffer[-1].timestamp,
                    ordinal=ordinal - size + 1,
                )
            if stride <= size:
                del buffer[:stride]
            else:
                buffer.clear()
                skip = stride - size
        ordinal += 1


def _validate_stream_event(
    event: NormalizedEvent,
    run_id: str,
    label: str,
    previous_timestamp: float,
) -> None:
    if event.run_id != run_id:
        raise ValueError(f"Streaming window crossed run boundary: {run_id!r}")
    if event.label != label:
        raise ValueError(f"Run {run_id!r} contains mixed labels")
    if event.timestamp < previous_timestamp:
        raise ValueError(f"Run {run_id!r} is not timestamp ordered")


def _compact_event(event: NormalizedEvent) -> dict[str, Any]:
    value: dict[str, Any] = {
        "timestamp": event.timestamp,
        "event_type": event.event_type,
    }
    optional = {
        "operation": event.operation
        if event.operation != event.event_type
        else None,
        "pid": event.pid,
        "ppid": event.ppid,
        "process_name": event.process_name,
        "path": event.path,
        "bytes": event.bytes,
    }
    value.update({key: item for key, item in optional.items() if item is not None})
    return value
