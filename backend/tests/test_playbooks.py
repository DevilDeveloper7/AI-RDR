"""Each playbook fires the right action sequence, in the right order, given a
synthetic trigger - independent of ARM's approval-gating logic (that's
test_arm.py's job)."""

from backend import playbooks


def _run_steps(playbook, trigger, controller):
    steps = playbook.build_steps(trigger)
    return [step.run(controller) for step in steps]


def test_pb01_ordering_and_actions(controller):
    trigger = {
        "host": "airdr-target",
        "entity": "airdr-target:1234",
        "risk_tier": "critical",
        "process_id": 1234,
        "target_paths": ["/data/finance"],
        "source_ip": "10.0.0.5",
    }
    results = _run_steps(playbooks.PB_01, trigger, controller)

    # Quarantine-bridge fix: isolate happens first, but is NOT a full cutoff,
    # so the subsequent terminate_process step can still reach the host.
    assert [r["action"] for r in results] == [
        "isolate_host",
        "terminate_process",
        "lock_directory",
        "snapshot_target",
        "block_ip_hash",
        "notify_and_open_case",
    ]
    assert controller.calls == [
        ("isolate", ("airdr-target",)),
        ("terminate_process", ("airdr-target", 1234)),
        ("lock_directory", ("airdr-target", "/data/finance")),
        ("snapshot", ("airdr-target",)),
        ("block_ip_hash", ("airdr-target", "10.0.0.5")),
    ]
    assert all(r["status"] == "success" for r in results)
    # terminate_process must never claim to be reversible.
    terminate_result = next(r for r in results if r["action"] == "terminate_process")
    assert terminate_result["reversible"] is False


def test_pb02_ordering_and_actions(controller):
    trigger = {"host": "airdr-target", "entity": "airdr-target:99", "risk_tier": "medium", "process_id": 99}
    results = _run_steps(playbooks.PB_02, trigger, controller)

    assert [r["action"] for r in results] == ["snapshot_target", "update_policy", "notify_and_open_case"]
    assert controller.calls == [
        ("snapshot", ("airdr-target",)),
        ("update_policy", ("airdr-target", "throttle_process:99")),
    ]
    assert all(r["status"] == "success" for r in results)
    # None of PB-02's actions are the disruptive ones (isolate/terminate/quarantine).
    assert all(r["action"] not in ("isolate_host", "terminate_process", "quarantine_file") for r in results)


def test_pb03_ordering_and_actions(controller):
    trigger = {
        "host": "airdr-target",
        "entity": "airdr-target:xforce",
        "risk_tier": "high",
        "indicator": "1.2.3.4",
        "file_path": "/tmp/evil.exe",
    }
    results = _run_steps(playbooks.PB_03, trigger, controller)

    assert [r["action"] for r in results] == [
        "block_ip_hash",
        "quarantine_file",
        "isolate_host",
        "notify_and_open_case",
    ]
    assert controller.calls == [
        ("block_ip_hash", ("airdr-target", "1.2.3.4")),
        ("quarantine_file", ("airdr-target", "/tmp/evil.exe")),
        ("isolate", ("airdr-target",)),
    ]


def test_pb04_ordering_and_actions(controller):
    trigger = {"host": "airdr-target", "entity": "airdr-target:honeyfile", "signals": ["honeyfile"]}
    results = _run_steps(playbooks.PB_04, trigger, controller)

    assert [r["action"] for r in results] == ["isolate_host", "notify_and_open_case"]
    assert controller.calls == [("isolate", ("airdr-target",))]


def test_pb01_tolerates_partial_trigger(controller):
    """No process_id / target_paths / source -> those optional steps are
    skipped, not a KeyError."""
    trigger = {"host": "airdr-target", "entity": "airdr-target:min", "risk_tier": "critical"}
    results = _run_steps(playbooks.PB_01, trigger, controller)
    assert [r["action"] for r in results] == ["isolate_host", "snapshot_target", "notify_and_open_case"]
