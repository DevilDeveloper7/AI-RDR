from pathlib import Path

from m2_pipeline.schema import NormalizedEvent


def test_wazuh_style_nested_aliases_are_normalized() -> None:
    event = NormalizedEvent.from_mapping(
        {
            "@timestamp": "2026-02-06T08:47:07Z",
            "auditd.data.syscall": "write",
            "auditd.data.pid": "42",
            "process.name": "tar",
            "file.path": "/srv/backup.tar",
        },
        source_path=Path("benign/backup-run.jsonl"),
        run_id="backup-run",
    )

    assert event.timestamp == 1770367627.0
    assert event.run_id == "backup-run"
    assert event.label == "benign"
    assert event.event_type == "write"
    assert event.pid == 42
    assert event.process_name == "tar"


def test_nanosecond_epoch_is_converted_to_seconds() -> None:
    event = NormalizedEvent.from_mapping(
        {"timestamp": 1_700_000_000_000_000_000, "syscall": "openat"},
        source_path=Path("ransomware/scenario-1.csv"),
    )

    assert event.timestamp == 1_700_000_000.0
    assert event.label == "ransomware"
