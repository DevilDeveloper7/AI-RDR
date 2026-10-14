from m2_pipeline.features import extract_window_features
from m2_pipeline.schema import NormalizedEvent
from m2_pipeline.training import assign_run_splits, _benign_workload_metrics
from m2_pipeline.windowing import WindowRecord


def test_feature_extraction_uses_parity_safe_syscall_statistics() -> None:
    events = (
        NormalizedEvent(0.0, "run-1", "ransomware", "openat", "openat", pid=7),
        NormalizedEvent(
            0.1, "run-1", "ransomware", "read", "read", pid=7, bytes=1024
        ),
        NormalizedEvent(
            0.2, "run-1", "ransomware", "write", "write", pid=7, bytes=1024
        ),
        NormalizedEvent(0.3, "run-1", "ransomware", "fsync", "fsync", pid=7),
    )
    window = WindowRecord(
        window_id="window-1",
        run_id="run-1",
        label="ransomware",
        split="train",
        start=0.0,
        end=1.0,
        event_count=4,
        events=events,
    )

    row = extract_window_features(window)

    assert row["event_rate"] == 4
    assert row["open_to_read"] == 1
    assert row["read_to_write"] == 1
    assert row["write_to_sync"] == 1
    assert row["write_ratio"] == 0.25


def test_run_split_is_stratified_and_has_no_overlap() -> None:
    labels = {
        **{f"benign-{index}": "benign" for index in range(20)},
        **{f"ransom-{index}": "ransomware" for index in range(20)},
    }

    assignments = assign_run_splits(labels)

    assert set(assignments) == set(labels)
    for label in ("benign", "ransomware"):
        splits = {
            assignments[run_id] for run_id, value in labels.items() if value == label
        }
        assert splits == {"train", "validation", "test"}


def test_false_positives_are_reported_by_benign_workload() -> None:
    rows = [
        {"run_id": "compression__zip_1", "label": "benign"},
        {"run_id": "compression__zip_1", "label": "benign"},
        {"run_id": "browser__download_1", "label": "benign"},
        {"run_id": "ransom__exec_1", "label": "ransomware"},
    ]

    result = _benign_workload_metrics(rows, [0.7, 0.1, 0.2, 0.9], 0.5)

    assert result["compression"]["runs"] == 1
    assert result["compression"]["false_positive_rate"] == 0.5
    assert result["browser"]["false_positive_rate"] == 0.0
