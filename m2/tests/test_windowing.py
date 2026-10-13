from m2_pipeline.schema import NormalizedEvent
from m2_pipeline.windowing import (
    SlidingWindowConfig,
    iter_run_windows,
    iter_windows,
    split_for_run,
)


def event(timestamp: float, run_id: str, label: str = "benign") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        run_id=run_id,
        label=label,
        event_type="write",
        operation="write",
    )


def test_time_windows_never_cross_run_boundaries() -> None:
    events = [
        event(0.0, "benign-backup"),
        event(1.0, "benign-backup"),
        event(0.0, "ransom-1", "ransomware"),
        event(1.0, "ransom-1", "ransomware"),
    ]

    windows = list(
        iter_windows(
            events,
            SlidingWindowConfig(mode="time", size=2.0, stride=1.0, min_events=2),
        )
    )

    assert len(windows) == 2
    assert all(len({item.run_id for item in window.events}) == 1 for window in windows)
    assert {window.label for window in windows} == {"benign", "ransomware"}


def test_all_windows_from_a_run_have_one_split() -> None:
    events = [event(float(index), "same-run") for index in range(6)]
    windows = list(
        iter_windows(
            events,
            SlidingWindowConfig(mode="events", size=3.0, stride=1.0),
        )
    )

    assert len(windows) == 4
    assert {window.split for window in windows} == {split_for_run("same-run")}


def test_mixed_labels_in_one_run_are_rejected() -> None:
    events = [event(0.0, "bad-run"), event(1.0, "bad-run", "ransomware")]

    try:
        list(iter_windows(events, SlidingWindowConfig()))
    except ValueError as error:
        assert "mixed labels" in str(error)
    else:
        raise AssertionError("Mixed-label run must fail")


def test_streaming_windows_match_batch_windows() -> None:
    events = [event(value, "stream-run") for value in (0.0, 0.4, 0.8, 1.2)]
    config = SlidingWindowConfig(mode="time", size=1.0, stride=0.5, min_events=2)

    batch = list(iter_windows(events, config))
    streamed = list(iter_run_windows(iter(events), config))

    assert [
        (window.start, window.end, window.event_count) for window in streamed
    ] == [(window.start, window.end, window.event_count) for window in batch]
