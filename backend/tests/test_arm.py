"""
Core ARM orchestration tests: approval gating, idempotency, rate limiting,
allow-list, and undo. Uses FakeHostController exclusively - no live SSH/
hypervisor API access.
"""

from backend.arm import ARM, TokenBucket


def test_pb01_critical_is_gated_not_executed(arm, controller):
    trigger = {"host": "airdr-target", "entity": "e1", "risk_tier": "critical", "process_id": 1}
    result = arm.handle_trigger(trigger)

    assert result["status"] == "pending_approval"
    assert result["playbook_id"] == "PB-01"
    assert controller.calls == []  # nothing executed yet
    record = arm.store.get(result["action_id"])
    assert record["status"] == "pending_approval"
    assert record["results"] == []


def test_pb03_high_is_gated_not_executed(arm, controller):
    trigger = {"host": "airdr-target", "entity": "e2", "risk_tier": "high", "indicator": "1.2.3.4"}
    result = arm.handle_trigger(trigger)
    assert result["status"] == "pending_approval"
    assert result["playbook_id"] == "PB-03"
    assert controller.calls == []


def test_pb04_honeyfile_is_gated_not_executed(arm, controller):
    trigger = {"host": "airdr-target", "entity": "e3", "signals": ["honeyfile"]}
    result = arm.handle_trigger(trigger)
    assert result["status"] == "pending_approval"
    assert result["playbook_id"] == "PB-04"
    assert controller.calls == []


def test_pb02_medium_auto_executes(arm, controller):
    trigger = {"host": "airdr-target", "entity": "e4", "risk_tier": "medium", "process_id": 42}
    result = arm.handle_trigger(trigger)

    assert result["status"] == "executed"
    assert result["playbook_id"] == "PB-02"
    assert len(result["results"]) == 3
    assert controller.calls == [
        ("snapshot", ("airdr-target",)),
        ("update_policy", ("airdr-target", "throttle_process:42")),
    ]
    record = arm.store.get(result["action_id"])
    assert record["status"] == "executed"


def test_low_tier_is_logged_only_no_playbook(arm, controller):
    trigger = {"host": "airdr-target", "entity": "e5", "risk_tier": "low"}
    result = arm.handle_trigger(trigger)
    assert result["status"] == "logged_only"
    assert controller.calls == []
    assert arm.store.all() == []  # nothing stored - Low tier isn't a playbook record


def test_allow_listed_host_forces_approval_even_for_pb02(tmp_path, controller):
    allow_list_path = tmp_path / "critical_assets.yml"
    allow_list_path.write_text("hosts:\n  - airdr-target\n")
    arm = ARM(controller=controller, audit_log_path=tmp_path / "audit.jsonl", allow_list_path=allow_list_path)

    trigger = {"host": "airdr-target", "entity": "e6", "risk_tier": "medium", "process_id": 1}
    result = arm.handle_trigger(trigger)

    assert result["status"] == "pending_approval"
    assert controller.calls == []


def test_approve_executes_a_pending_action(arm, controller):
    trigger = {"host": "airdr-target", "entity": "e7", "risk_tier": "critical", "process_id": 7}
    triggered = arm.handle_trigger(trigger)
    action_id = triggered["action_id"]
    assert controller.calls == []

    approved = arm.approve(action_id)

    assert approved["status"] == "executed"
    assert len(approved["results"]) > 0
    assert controller.calls  # something actually ran now
    assert arm.store.get(action_id)["status"] == "executed"


def test_deny_prevents_execution(arm, controller):
    trigger = {"host": "airdr-target", "entity": "e8", "risk_tier": "critical", "process_id": 8}
    triggered = arm.handle_trigger(trigger)
    action_id = triggered["action_id"]

    denied = arm.deny(action_id)

    assert denied["status"] == "denied"
    assert controller.calls == []
    assert arm.store.get(action_id)["status"] == "denied"

    # Approving an already-denied action must fail cleanly, not execute anyway.
    approve_after_deny = arm.approve(action_id)
    assert approve_after_deny["status"] == "error"
    assert controller.calls == []


def test_idempotency_same_trigger_twice_dedupes(arm, controller):
    trigger = {
        "host": "airdr-target",
        "entity": "e9",
        "risk_tier": "critical",
        "process_id": 9,
        "trigger_timestamp": "2026-09-28T00:00:00+00:00",
    }
    first = arm.handle_trigger(trigger)
    second = arm.handle_trigger(dict(trigger))  # identical payload, fired again

    assert first["status"] == "pending_approval"
    assert second["status"] == "deduped"
    assert second["action_id"] == first["action_id"]
    assert len(arm.store.all()) == 1  # one pending record, not two


def test_rate_limit_rejects_burst_for_same_entity(tmp_path, controller):
    arm = ARM(
        controller=controller,
        rate_limiter=TokenBucket(capacity=1, period=60.0),
        audit_log_path=tmp_path / "audit.jsonl",
        allow_list_path=tmp_path / "critical_assets.yml",
    )
    base = {"host": "airdr-target", "entity": "flapping-entity", "risk_tier": "critical", "process_id": 1}

    first = arm.handle_trigger({**base, "trigger_timestamp": "t1"})
    second = arm.handle_trigger({**base, "trigger_timestamp": "t2"})  # different action_id - not a dedupe case
    third = arm.handle_trigger({**base, "trigger_timestamp": "t3"})

    assert first["status"] == "pending_approval"
    assert second["status"] == "rate_limited"
    assert third["status"] == "rate_limited"
    # Only the first trigger actually got a stored record.
    assert len(arm.store.all()) == 1


def test_rate_limit_is_per_entity(arm, controller):
    t1 = arm.handle_trigger(
        {"host": "airdr-target", "entity": "entA", "risk_tier": "critical", "trigger_timestamp": "t1"}
    )
    t2 = arm.handle_trigger(
        {"host": "airdr-target", "entity": "entB", "risk_tier": "critical", "trigger_timestamp": "t1"}
    )
    assert t1["status"] == "pending_approval"
    assert t2["status"] == "pending_approval"  # different entity - own bucket


def test_undo_reverses_reversible_actions_and_reports_terminate_process_honestly(arm, controller):
    trigger = {
        "host": "airdr-target",
        "entity": "e10",
        "risk_tier": "critical",
        "process_id": 10,
        "target_paths": ["/data/x"],
        "source_ip": "9.9.9.9",
    }
    triggered = arm.handle_trigger(trigger)
    action_id = triggered["action_id"]
    arm.approve(action_id)  # now executed: isolate, terminate, lock, snapshot, block, notify

    calls_before_undo = len(controller.calls)
    result = arm.undo(action_id)

    assert result["status"] == "undone"
    by_action = {r["action"]: r for r in result["undo_results"]}

    assert by_action["isolate_host"]["status"] == "reversed"
    assert by_action["lock_directory"]["status"] == "reversed"
    assert by_action["snapshot_target"]["status"] == "reversed"
    assert by_action["block_ip_hash"]["status"] == "reversed"

    # The hard requirement: terminate_process must say "not reversible", not
    # silently no-op or fake success.
    assert by_action["terminate_process"]["status"] == "not_reversible"
    assert by_action["notify_and_open_case"]["status"] == "not_reversible"

    # The reverse operations actually got called on the controller.
    reverse_call_names = {name for name, _ in controller.calls[calls_before_undo:]}
    assert reverse_call_names == {"release_host", "unlock_directory", "remove_snapshot", "unblock_ip_hash"}
    assert arm.store.get(action_id)["status"] == "undone"


def test_undo_on_pending_action_is_an_error(arm, controller):
    trigger = {"host": "airdr-target", "entity": "e11", "risk_tier": "critical", "process_id": 11}
    triggered = arm.handle_trigger(trigger)
    result = arm.undo(triggered["action_id"])
    assert result["status"] == "error"


def test_undo_unknown_action_id(arm):
    result = arm.undo("does-not-exist")
    assert result["status"] == "not_found"
