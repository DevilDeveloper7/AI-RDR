import io
import json
import math
import random
from datetime import datetime, timezone

import pytest

from m2_pipeline import cli
from m2_pipeline.features import FEATURE_VERSION, extract_window_features
from m2_pipeline.inference import InferenceService
from m2_pipeline.schema import NormalizedEvent
from m2_pipeline.streaming import (
    HostWindowAggregator,
    parse_falco_line,
    score_falco_stream,
)
from m2_pipeline.windowing import SlidingWindowConfig, iter_run_windows

SYSCALLS = (
    "openat",
    "open",
    "read",
    "pread64",
    "write",
    "pwrite64",
    "fsync",
    "close",
    "renameat2",
    "unlinkat",
    "newfstatat",
    "mmap",
    "sendto",
    "recvfrom",
    "clone",
    "getpid",
)
WINDOW_METADATA = {"feature_version", "window_id", "run_id", "label", "start", "end"}
NANOSECONDS = 1_000_000_000
BASE_NS = 1_763_460_000 * NANOSECONDS


def synthetic_events(seed: int, count: int, offset: float = 0.0) -> list[NormalizedEvent]:
    rng = random.Random(seed)
    timestamp = 1_763_460_000.0 + offset
    events = []
    for index in range(count):
        # Occasional long gaps leave empty and single-event windows behind.
        timestamp += 7.5 if index % 97 == 96 else rng.choice((0.001, 0.02, 0.3, 1.1))
        events.append(
            NormalizedEvent(
                timestamp=timestamp,
                run_id="host-a",
                label="unknown",
                event_type=rng.choice(SYSCALLS),
                operation="test",
                pid=rng.choice((None, 10, 11, 12)),
                process_name=rng.choice((None, "worker", "tar")),
                bytes=rng.choice((None, 0, 512, 4096)),
                source="test",
            )
        )
    return events


def batch_rows(events: list[NormalizedEvent]) -> list[dict]:
    config = SlidingWindowConfig(mode="time", size=5.0, stride=5.0, min_events=2)
    return [extract_window_features(window) for window in iter_run_windows(events, config)]


def stream_rows(events: list[NormalizedEvent], host: str = "host-a") -> list:
    aggregator = HostWindowAggregator()
    rows = []
    for event in events:
        closed = aggregator.add(
            host,
            event.timestamp,
            event.event_type,
            pid=event.pid,
            process_name=event.process_name,
            nbytes=event.bytes,
        )
        if closed is not None:
            rows.append(closed)
    return rows + aggregator.flush()


def falco_line(host: str, nanoseconds: int, syscall: str, **extra) -> str:
    fields = {
        "evt.type": syscall,
        "evt.rawtime": nanoseconds,
        "thread.tid": 4127,
        "proc.pid": 4126,
        "proc.name": "worker",
        "evt.rawarg.size": 4096,
    }
    fields.update({name.replace("_", "."): value for name, value in extra.items()})
    return json.dumps({"hostname": host, "source": "syscall", "output_fields": fields})


class CountModel:
    def predict_proba(self, rows):
        write_count = rows[0][1]
        probability = 0.9 if write_count >= 3 else 0.1
        return [[1.0 - probability, probability]]


class RecordingModel:
    def __init__(self) -> None:
        self.rows: list[list[float]] = []

    def predict_proba(self, rows):
        self.rows.append(list(rows[0]))
        return [[0.5, 0.5]]


def count_service() -> InferenceService:
    return InferenceService(
        {
            "model": CountModel(),
            "threshold": 0.5,
            "feature_names": ["event_count", "write_count"],
            "feature_version": FEATURE_VERSION,
        },
        model_name="fake",
        enable_shap=False,
    )


def test_stream_rows_are_identical_to_batch_feature_extraction() -> None:
    events = synthetic_events(seed=7, count=3000)

    expected = batch_rows(events)
    actual = stream_rows(events)

    assert len(actual) == len(expected) > 20
    for window, row in zip(actual, expected):
        assert (window.start, window.end) == (row["start"], row["end"])
        assert set(window.features) == set(row) - WINDOW_METADATA
        assert window.features == {name: row[name] for name in window.features}


def test_hosts_are_windowed_independently() -> None:
    host_a = synthetic_events(seed=1, count=800)
    host_b = synthetic_events(seed=2, count=800, offset=2.5)
    merged = sorted(
        [("a", event) for event in host_a] + [("b", event) for event in host_b],
        key=lambda item: item[1].timestamp,
    )
    aggregator = HostWindowAggregator()
    rows: dict[str, list] = {"a": [], "b": []}

    for host, event in merged:
        closed = aggregator.add(
            host,
            event.timestamp,
            event.event_type,
            pid=event.pid,
            process_name=event.process_name,
            nbytes=event.bytes,
        )
        if closed is not None:
            rows[closed.host].append(closed)
    for window in aggregator.flush():
        rows[window.host].append(window)

    assert rows["a"] == stream_rows(host_a, "a")
    assert rows["b"] == stream_rows(host_b, "b")


def test_expire_closes_quiet_host_and_keeps_window_alignment() -> None:
    aggregator = HostWindowAggregator()
    for timestamp in (100.0, 101.0, 102.0):
        assert aggregator.add("quiet", timestamp, "write") is None

    assert aggregator.expire(104.9) == []
    [closed] = aggregator.expire(105.0)
    aggregator.add("quiet", 113.0, "read")
    aggregator.add("quiet", 114.0, "read")
    [later] = aggregator.flush()

    assert (closed.start, closed.end, closed.features["event_count"]) == (100.0, 105.0, 3)
    assert (later.start, later.end, later.features["read_count"]) == (110.0, 115.0, 2)


def test_window_row_scores_like_the_raw_event_window() -> None:
    events = synthetic_events(seed=3, count=400)
    windows = stream_rows(events)
    model = RecordingModel()
    service = InferenceService(
        {
            "model": model,
            "threshold": 0.5,
            "feature_names": list(windows[0].features),
            "feature_version": FEATURE_VERSION,
        },
        enable_shap=False,
    )

    for window in windows:
        inside = [event for event in events if window.start <= event.timestamp < window.end]
        service.predict(inside, run_id="host-a", start=window.start, end=window.end)
        service.predict_features(window.features)

    assert len(model.rows) == 2 * len(windows)
    assert model.rows[0::2] == model.rows[1::2]


def test_feature_rows_must_be_complete_and_finite() -> None:
    service = count_service()

    with pytest.raises(ValueError, match="write_count"):
        service.predict_features({"event_count": 3})
    with pytest.raises(ValueError, match="finite"):
        service.predict_features({"event_count": math.inf, "write_count": 1})


def test_falco_records_map_to_training_event_fields() -> None:
    event = parse_falco_line(
        falco_line("web-01", BASE_NS + 123_456_789, "pread", evt_dir="<")
    )
    iso_only = parse_falco_line(
        json.dumps(
            {
                "time": "2026-11-18T10:00:00.123456789Z",
                "output_fields": {"evt.type": "WRITE", "proc.pid": 7},
            }
        ),
        default_host="fallback",
    )
    flat = parse_falco_line(
        json.dumps({"evt.type": "openat", "evt.time": BASE_NS, "proc.name": "tar"})
    )

    assert event is not None
    assert (event.host, event.syscall, event.pid, event.process_name, event.nbytes) == (
        "web-01",
        "pread64",
        4127,
        "worker",
        4096,
    )
    assert event.timestamp == pytest.approx(1_763_460_000.123456789, abs=1e-6)
    assert iso_only is not None
    assert (iso_only.host, iso_only.syscall, iso_only.pid) == ("fallback", "write", 7)
    assert iso_only.timestamp == datetime(
        2026, 11, 18, 10, 0, 0, 123456, tzinfo=timezone.utc
    ).timestamp()
    assert flat is not None
    assert (flat.syscall, flat.timestamp, flat.process_name) == ("openat", 1_763_460_000.0, "tar")


@pytest.mark.parametrize(
    "line",
    [
        falco_line("web-01", BASE_NS, "read", evt_dir=">"),
        falco_line("web-01", BASE_NS, "switch"),
        json.dumps({"source": "k8s_audit", "output_fields": {"evt.type": "read"}}),
        json.dumps({"output_fields": {"evt.type": "read", "evt.time": "10:00:00.1"}}),
        "not json",
        "[]",
    ],
)
def test_falco_lines_without_a_usable_syscall_are_skipped(line: str) -> None:
    assert parse_falco_line(line) is None


def test_stream_scores_one_alert_only_row_per_window() -> None:
    lines = [falco_line("web-01", BASE_NS + i * NANOSECONDS // 2, "write") for i in range(8)]
    lines += [falco_line("web-01", BASE_NS + 5_200_000_000 + i, "read") for i in range(2)]
    lines.append("not json")
    output = io.StringIO()

    summary = score_falco_stream(lines, count_service(), output)
    rows = [json.loads(line) for line in output.getvalue().splitlines()]

    assert summary == {"events": 10, "skipped_lines": 1, "windows": 2, "alerts": 1, "hosts": 1}
    assert [row["alert"] for row in rows] == [True, False]
    assert {row["response_mode"] for row in rows} == {"alert_only"}
    assert (rows[0]["host"], rows[0]["end"] - rows[0]["start"]) == ("web-01", 5.0)
    assert rows[0]["features"]["write_count"] == 8
    assert rows[0]["features"]["write_bytes_requested"] == 8 * 4096
    assert len(rows[0]["window_id"]) == 20


def test_quiet_host_is_scored_before_the_input_ends() -> None:
    lines = [falco_line("quiet", BASE_NS + offset, "write") for offset in (100, 600_000_000)]
    lines += [falco_line("busy", BASE_NS + i * NANOSECONDS // 2, "read") for i in range(40)]
    lines.sort(key=lambda line: json.loads(line)["output_fields"]["evt.rawtime"])
    output = io.StringIO()

    score_falco_stream(lines, count_service(), output)
    hosts = [json.loads(line)["host"] for line in output.getvalue().splitlines()]

    assert hosts == ["busy", "busy", "quiet", "busy", "busy"]


def test_stream_rejects_a_model_with_another_feature_version() -> None:
    service = count_service()
    service.feature_version = "0.9"

    with pytest.raises(ValueError, match="feature version"):
        score_falco_stream([], service, io.StringIO())


def test_stream_command_writes_rows_to_stdout_and_summary_to_stderr(
    tmp_path, monkeypatch, capsys
) -> None:
    falco_output = tmp_path / "falco.jsonl"
    falco_output.write_text(
        "\n".join(falco_line("web-01", BASE_NS + i, "write") for i in range(4)) + "\n",
        encoding="utf-8",
    )
    model_path = tmp_path / "model.joblib"
    model_path.touch()
    monkeypatch.setattr(
        cli.InferenceService, "from_path", staticmethod(lambda path: count_service())
    )

    exit_code = cli.main(["stream", str(falco_output), "--model", str(model_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    [row] = [json.loads(line) for line in captured.out.splitlines()]
    assert (row["host"], row["alert"], row["response_mode"]) == ("web-01", True, "alert_only")
    assert json.loads(captured.err)["windows"] == 1
