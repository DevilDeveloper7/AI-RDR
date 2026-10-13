import json

from m2_pipeline.io import iter_normalized_file


def test_nested_wazuh_jsonl_is_flattened(tmp_path) -> None:
    trace = tmp_path / "benign" / "backup.jsonl"
    trace.parent.mkdir()
    trace.write_text(
        json.dumps(
            {
                "@timestamp": "2026-01-01T00:00:00Z",
                "auditd": {"data": {"syscall": "write", "pid": "7"}},
                "process": {"name": "rsync"},
                "file": {"path": "/srv/copy.bin"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = list(iter_normalized_file(trace, root=tmp_path, source="irdp"))

    assert len(events) == 1
    assert events[0].event_type == "write"
    assert events[0].pid == 7
    assert events[0].process_name == "rsync"
    assert events[0].label == "benign"
