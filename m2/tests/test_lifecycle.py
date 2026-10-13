from m2_pipeline.lifecycle import parse_trace_line


def test_trace_cmd_sys_enter_line_is_parsed() -> None:
    event = parse_trace_line(
        " exfiltrate.py-412641 [017] 984321.315446: "
        "sys_enter_write: fd: 0x4, buf: 0xabc, count: 0x20\n",
        run_id="exec-1",
        label="ransomware",
    )

    assert event is not None
    assert event.timestamp == 984321.315446
    assert event.event_type == "write"
    assert event.pid == 412641
    assert event.process_name == "exfiltrate.py"
    assert event.bytes == 32


def test_sys_exit_line_is_dropped_for_auditd_parity() -> None:
    event = parse_trace_line(
        " trace-cmd-10229 [024] 28549.159524: sys_exit_write: 0x1\n",
        run_id="benign-1",
        label="benign",
    )

    assert event is None
