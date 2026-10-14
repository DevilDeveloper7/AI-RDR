"""
AICM tests (task 4.6; planning/aicm-spec.md).

Covers: correlation grouping (same entity/host within the window -> one
case; outside the window -> two), every lifecycle transition including
rejecting invalid ones, `recommend()` against each of the 4 playbook-id
rule branches, `score_from_history()` genuinely changing after
`record_feedback()`, and the two integration points
(`notify_and_open_case()` returning a real `case_id`; ARM's `_execute()`/
`approve()` both routing through the shared `_update_case()` helper).

No live OpenSearch access - `OpenSearchCaseStore` is only exercised against
mocked `requests` calls, matching `test_action_store.py`/
`test_threat_intel.py`'s own established convention.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from backend import actions, aicm, arm as arm_module
from backend.aicm import (
    Case,
    CaseState,
    InMemoryCaseStore,
    InvalidCaseTransition,
    OpenSearchCaseStore,
    close,
    is_valid_transition,
    mark_recovered,
    open_or_update_case,
    record_feedback,
    recommend,
    resolve,
    score_from_history,
    update_case,
    validate_transition,
)
from backend.arm import ARM


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def test_second_trigger_within_window_correlates_into_one_case():
    store = InMemoryCaseStore()
    first = open_or_update_case(
        "airdr-target:99", "airdr-target", {"risk_tier": "medium"}, playbook_id="PB-02",
        store=store, now="2026-10-01T00:00:00+00:00",
    )
    second = open_or_update_case(
        "airdr-target:99", "airdr-target", {"risk_tier": "high"}, playbook_id="PB-03",
        store=store, now="2026-10-01T01:00:00+00:00",  # 1h later, well within 24h
    )

    assert second.case_id == first.case_id
    assert len(store.all()) == 1
    # Severity bump: high > medium, so the correlated case's severity updates.
    assert second.severity == "HIGH"


def test_trigger_outside_window_creates_a_second_case():
    store = InMemoryCaseStore()
    first = open_or_update_case(
        "airdr-target:99", "airdr-target", {"risk_tier": "medium"}, playbook_id="PB-02",
        store=store, now="2026-10-01T00:00:00+00:00",
    )
    second = open_or_update_case(
        "airdr-target:99", "airdr-target", {"risk_tier": "medium"}, playbook_id="PB-02",
        store=store, now="2026-10-03T00:00:00+00:00",  # 48h later, outside the 24h window
    )

    assert second.case_id != first.case_id
    assert len(store.all()) == 2


def test_different_entity_never_correlates():
    store = InMemoryCaseStore()
    first = open_or_update_case(
        "airdr-target:1", "airdr-target", {"risk_tier": "medium"}, store=store,
        now="2026-10-01T00:00:00+00:00",
    )
    second = open_or_update_case(
        "airdr-target:2", "airdr-target", {"risk_tier": "medium"}, store=store,
        now="2026-10-01T00:00:01+00:00",
    )
    assert first.case_id != second.case_id


def test_correlation_skips_a_resolved_case_and_opens_a_new_one():
    store = InMemoryCaseStore()
    first = open_or_update_case(
        "airdr-target:3", "airdr-target", {"risk_tier": "medium"}, store=store,
        now="2026-10-01T00:00:00+00:00",
    )
    update_case(first.case_id, [{"action": "snapshot_target", "status": "success"}], store=store)
    mark_recovered(first.case_id, store=store)
    resolve(first.case_id, store=store)

    second = open_or_update_case(
        "airdr-target:3", "airdr-target", {"risk_tier": "medium"}, store=store,
        now="2026-10-01T00:00:01+00:00",  # same instant - would correlate if still open
    )
    assert second.case_id != first.case_id


def test_new_case_opens_in_triaged_state_with_recommendations_attached():
    store = InMemoryCaseStore()
    case = open_or_update_case(
        "airdr-target:4", "airdr-target", {"risk_tier": "critical"}, playbook_id="PB-01", store=store
    )
    assert case.state == CaseState.TRIAGED  # New -> Triaged is automatic
    assert case.triaged_at is not None


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------


def test_valid_transition_table():
    assert is_valid_transition(CaseState.NEW, CaseState.TRIAGED)
    assert is_valid_transition(CaseState.TRIAGED, CaseState.CONTAINED)
    assert is_valid_transition(CaseState.CONTAINED, CaseState.RECOVERED)
    assert is_valid_transition(CaseState.RECOVERED, CaseState.RESOLVED)
    assert is_valid_transition(CaseState.RESOLVED, CaseState.CLOSED)


@pytest.mark.parametrize(
    "frm,to",
    [
        (CaseState.CLOSED, CaseState.NEW),
        (CaseState.NEW, CaseState.CLOSED),
        (CaseState.NEW, CaseState.CONTAINED),
        (CaseState.TRIAGED, CaseState.RECOVERED),
        (CaseState.CONTAINED, CaseState.RESOLVED),
        (CaseState.RESOLVED, CaseState.RECOVERED),
    ],
)
def test_invalid_transitions_are_rejected(frm, to):
    assert not is_valid_transition(frm, to)
    with pytest.raises(InvalidCaseTransition):
        validate_transition(frm, to)


def test_update_case_auto_transitions_triaged_to_contained_on_success():
    store = InMemoryCaseStore()
    case = open_or_update_case("e1", "h1", {"risk_tier": "critical"}, playbook_id="PB-01", store=store)
    assert case.state == CaseState.TRIAGED

    updated = update_case(
        case.case_id,
        [
            {"action": "isolate_host", "status": "success"},
            {"action": "notify_and_open_case", "status": "success"},
        ],
        store=store,
    )
    assert updated.state == CaseState.CONTAINED
    assert updated.contained_at is not None
    assert len(updated.actions_taken) == 2


def test_update_case_does_not_transition_when_only_notify_succeeded():
    store = InMemoryCaseStore()
    case = open_or_update_case("e2", "h1", {"risk_tier": "medium"}, store=store)
    updated = update_case(
        case.case_id, [{"action": "notify_and_open_case", "status": "success"}], store=store
    )
    assert updated.state == CaseState.TRIAGED  # not contained - only the n/a notify action ran


def test_update_case_does_not_transition_on_a_failed_action():
    store = InMemoryCaseStore()
    case = open_or_update_case("e3", "h1", {"risk_tier": "medium"}, store=store)
    updated = update_case(
        case.case_id, [{"action": "isolate_host", "status": "failed"}], store=store
    )
    assert updated.state == CaseState.TRIAGED


def test_full_lifecycle_walk_mark_recovered_resolve_close():
    store = InMemoryCaseStore()
    case = open_or_update_case("e4", "h1", {"risk_tier": "high"}, store=store)
    update_case(case.case_id, [{"action": "block_ip_hash", "status": "success"}], store=store)
    assert store.get(case.case_id).state == CaseState.CONTAINED

    recovered = mark_recovered(case.case_id, store=store)
    assert recovered.state == CaseState.RECOVERED
    assert recovered.recovered_at is not None

    resolved = resolve(case.case_id, notes="root cause confirmed", store=store)
    assert resolved.state == CaseState.RESOLVED
    assert resolved.resolution_notes == "root cause confirmed"

    closed = close(case.case_id, store=store)
    assert closed.state == CaseState.CLOSED
    assert closed.closed_at is not None


def test_mark_recovered_before_contained_is_rejected():
    store = InMemoryCaseStore()
    case = open_or_update_case("e5", "h1", {"risk_tier": "medium"}, store=store)  # still Triaged
    with pytest.raises(InvalidCaseTransition):
        mark_recovered(case.case_id, store=store)


def test_close_skipping_recovered_and_resolved_is_rejected():
    store = InMemoryCaseStore()
    case = open_or_update_case("e6", "h1", {"risk_tier": "medium"}, store=store)
    update_case(case.case_id, [{"action": "isolate_host", "status": "success"}], store=store)
    with pytest.raises(InvalidCaseTransition):
        close(case.case_id, store=store)  # Contained -> Closed directly


# ---------------------------------------------------------------------------
# recommend() - all 4 playbook-id rule branches
# ---------------------------------------------------------------------------


def _bare_case(**overrides) -> Case:
    defaults = dict(
        case_id="c-test",
        entity="e",
        host="h",
        risk_score=0.5,
        severity="HIGH",
        state=CaseState.TRIAGED,
    )
    defaults.update(overrides)
    return Case(**defaults)


def test_recommend_pb01_full_context():
    store = InMemoryCaseStore()
    case = _bare_case(
        actions_taken=[{"action": "snapshot_target", "status": "success"}],
        predicted_targets=[{"path": "/data/x", "riskPct": 80}],
        context={"user_id": "alice"},
    )
    recs = recommend(case, "PB-01", store=store)
    actions_recommended = {r["action"] for r in recs}
    assert "Restore from snapshot" in actions_recommended
    assert "Reset credentials for affected user" in actions_recommended
    assert "Review predicted-target directories for residual risk" in actions_recommended
    assert all(r["justification"] for r in recs)


def test_recommend_pb01_minimal_context_has_no_candidates():
    store = InMemoryCaseStore()
    case = _bare_case()  # no successful snapshot/backup, no user_id, no predicted_targets
    recs = recommend(case, "PB-01", store=store)
    assert recs == []


def test_recommend_pb02():
    store = InMemoryCaseStore()
    case = _bare_case(severity="MEDIUM")
    recs = recommend(case, "PB-02", store=store)
    actions_recommended = {r["action"] for r in recs}
    assert actions_recommended == {
        "Confirm or dismiss as false positive",
        "Escalate to PB-01 if encryption confirmed",
    }
    assert all(r["justification"] for r in recs)


def test_recommend_pb03():
    store = InMemoryCaseStore()
    case = _bare_case(severity="HIGH")
    recs = recommend(case, "PB-03", store=store)
    actions_recommended = {r["action"] for r in recs}
    assert actions_recommended == {
        "Block the matched indicator at the network perimeter",
        "Investigate related cases for the same indicator",
    }
    assert all(r["justification"] for r in recs)


def test_recommend_pb04():
    store = InMemoryCaseStore()
    case = _bare_case(severity="CRITICAL")
    recs = recommend(case, "PB-04", store=store)
    actions_recommended = {r["action"] for r in recs}
    assert actions_recommended == {
        "Treat as confirmed malicious - escalate to full containment if not already at Critical",
        "Review host for lateral movement",
    }
    assert all(r["justification"] for r in recs)


def test_recommend_unknown_playbook_id_returns_no_candidates():
    store = InMemoryCaseStore()
    case = _bare_case()
    assert recommend(case, "PB-99", store=store) == []
    assert recommend(case, None, store=store) == []


def test_recommend_every_candidate_gets_a_cold_start_confidence_with_no_history():
    store = InMemoryCaseStore()
    case = _bare_case(severity="MEDIUM")
    recs = recommend(case, "PB-02", store=store)
    assert all(r["confidence"] == aicm.COLD_START_CONFIDENCE for r in recs)


# ---------------------------------------------------------------------------
# score_from_history() / record_feedback() - the real learning-from-feedback
# mechanism, proven to genuinely move, not just return the cold-start prior
# forever.
# ---------------------------------------------------------------------------


def test_score_from_history_is_cold_start_prior_with_no_feedback():
    store = InMemoryCaseStore()
    assert score_from_history("Confirm or dismiss as false positive", store=store) == 0.5


def test_score_from_history_rises_after_mostly_accepted_feedback():
    store = InMemoryCaseStore()
    action = "Confirm or dismiss as false positive"

    # Three separate cases each recommend the same action; an analyst
    # accepts it every time.
    for i in range(3):
        case = open_or_update_case(f"e-{i}", "h1", {"risk_tier": "medium"}, playbook_id="PB-02", store=store)
        rec = next(r for r in case.recommendations if r["action"] == action)
        record_feedback(case.case_id, rec["recommendation_id"], accepted=True, store=store)

    assert score_from_history(action, store=store) == 1.0  # strictly above the 0.5 cold-start prior


def test_score_from_history_falls_after_mostly_rejected_feedback():
    store = InMemoryCaseStore()
    action = "Confirm or dismiss as false positive"

    for i in range(3):
        case = open_or_update_case(f"e-{i}", "h1", {"risk_tier": "medium"}, playbook_id="PB-02", store=store)
        rec = next(r for r in case.recommendations if r["action"] == action)
        record_feedback(case.case_id, rec["recommendation_id"], accepted=False, store=store)

    assert score_from_history(action, store=store) == 0.0  # strictly below the 0.5 cold-start prior


def test_record_feedback_moves_future_recommend_confidence_too():
    """Not just score_from_history() in isolation - a brand new case's own
    freshly-generated recommendation for the same action should carry the
    updated confidence, proving the learning loop actually feeds forward
    into recommend()."""
    store = InMemoryCaseStore()
    action = "Escalate to PB-01 if encryption confirmed"

    first_case = open_or_update_case("e-a", "h1", {"risk_tier": "medium"}, playbook_id="PB-02", store=store)
    first_rec = next(r for r in first_case.recommendations if r["action"] == action)
    assert first_rec["confidence"] == 0.5
    record_feedback(first_case.case_id, first_rec["recommendation_id"], accepted=True, store=store)

    second_case = open_or_update_case("e-b", "h1", {"risk_tier": "medium"}, playbook_id="PB-02", store=store)
    second_rec = next(r for r in second_case.recommendations if r["action"] == action)
    assert second_rec["confidence"] == 1.0


def test_record_feedback_unknown_recommendation_id_raises():
    store = InMemoryCaseStore()
    case = open_or_update_case("e-z", "h1", {"risk_tier": "medium"}, playbook_id="PB-02", store=store)
    with pytest.raises(KeyError):
        record_feedback(case.case_id, "does-not-exist", accepted=True, store=store)


# ---------------------------------------------------------------------------
# Integration point 1: backend/actions.py's notify_and_open_case() calls
# open_or_update_case() for real and returns the real case_id.
# ---------------------------------------------------------------------------


def test_notify_and_open_case_returns_a_real_case_id(controller):
    store = InMemoryCaseStore()
    aicm.set_default_store(store)

    result = actions.notify_and_open_case(
        controller, "airdr-target", "PB-01 Ransomware Containment triggered", priority="critical"
    )

    assert result["status"] == "success"
    case_id = result["detail"]["case_id"]
    assert case_id is not None

    case = store.get(case_id)
    assert case is not None
    assert case.host == "airdr-target"
    assert case.entity == "airdr-target"  # no richer entity available at this call site - see actions.py
    assert case.severity == "CRITICAL"
    assert case.last_playbook_id == "PB-01"
    assert case.state == CaseState.TRIAGED


def test_notify_and_open_case_different_hosts_do_not_collide(controller):
    store = InMemoryCaseStore()
    aicm.set_default_store(store)

    first = actions.notify_and_open_case(controller, "host-a", "PB-02 Suspicious Behaviour - prioritised alert")
    second = actions.notify_and_open_case(controller, "host-b", "PB-02 Suspicious Behaviour - prioritised alert")

    assert first["detail"]["case_id"] != second["detail"]["case_id"]


# ---------------------------------------------------------------------------
# Integration point 2: backend/arm.py's _execute()/approve() both route
# through the single shared ARM._update_case() helper.
# ---------------------------------------------------------------------------


def test_arm_auto_execute_pb02_updates_the_same_case_via_execute(arm, controller):
    store = InMemoryCaseStore()
    aicm.set_default_store(store)

    trigger = {"host": "airdr-target", "entity": "airdr-target:42", "risk_tier": "medium", "process_id": 42}
    result = arm.handle_trigger(trigger)
    assert result["status"] == "executed"

    notify_result = next(r for r in result["results"] if r["action"] == "notify_and_open_case")
    case_id = notify_result["detail"]["case_id"]
    case = store.get(case_id)

    assert case is not None
    # update_case() received the full results list, including the two
    # disruptive PB-02 actions -> Triaged auto-advances to Contained.
    assert case.state == CaseState.CONTAINED
    assert [a["action"] for a in case.actions_taken] == [
        "snapshot_target",
        "update_policy",
        "notify_and_open_case",
    ]


def test_arm_approve_updates_the_same_case_via_the_shared_helper(arm, controller):
    store = InMemoryCaseStore()
    aicm.set_default_store(store)

    trigger = {"host": "airdr-target", "entity": "airdr-target:7", "risk_tier": "critical", "process_id": 7}
    triggered = arm.handle_trigger(trigger)
    assert triggered["status"] == "pending_approval"

    # Nothing executed/case-updated yet - the gate holds the playbook.
    approved = arm.approve(triggered["action_id"])
    assert approved["status"] == "executed"

    notify_result = next(r for r in approved["results"] if r["action"] == "notify_and_open_case")
    case_id = notify_result["detail"]["case_id"]
    case = store.get(case_id)

    assert case is not None
    assert case.state == CaseState.CONTAINED  # isolate_host succeeded -> auto Contained
    assert any(a["action"] == "isolate_host" and a["status"] == "success" for a in case.actions_taken)


def test_arm_execute_and_approve_share_one_helper_not_duplicated_logic():
    """`approve()` calls `_execute()` directly (no separate AICM-update
    logic of its own) - the one place `update_case()` is invoked is
    `ARM._update_case()`, called only from inside `_execute()`."""
    import inspect

    execute_src = inspect.getsource(ARM._execute)
    approve_src = inspect.getsource(ARM.approve)

    assert "_update_case" in execute_src
    assert "_update_case" not in approve_src  # approve() doesn't call it directly
    assert "self._execute(record)" in approve_src  # ...it goes through _execute() instead


def test_arm_execute_is_a_noop_aicm_hook_when_no_notify_step_ran():
    """Defensive: a hand-built results list with no notify_and_open_case
    entry at all must not raise."""
    arm_module.ARM._update_case  # exists
    a = ARM.__new__(ARM)  # bypass __init__ - this test only exercises _update_case
    a._update_case([{"action": "isolate_host", "status": "success"}])  # must not raise


# ---------------------------------------------------------------------------
# OpenSearchCaseStore - never-raise contract on an ordinary backend failure.
# ---------------------------------------------------------------------------


def _fake_response(status_code=200, json_body=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    return resp


def test_opensearch_case_store_get_returns_none_on_404():
    with patch("requests.get", return_value=_fake_response(404)):
        store = OpenSearchCaseStore(host="opensearch.example", username="u", password="p")
        assert store.get("does-not-exist") is None


def test_opensearch_case_store_get_returns_none_on_500_without_raising():
    with patch("requests.get", return_value=_fake_response(500)):
        store = OpenSearchCaseStore(host="opensearch.example", username="u", password="p")
        assert store.get("x") is None  # must not raise


def test_opensearch_case_store_get_returns_none_on_connection_error():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError()):
        store = OpenSearchCaseStore(host="opensearch.example", username="u", password="p")
        assert store.get("x") is None


def test_opensearch_case_store_put_does_not_raise_on_timeout():
    with patch("requests.put", side_effect=requests.exceptions.Timeout()):
        store = OpenSearchCaseStore(host="opensearch.example", username="u", password="p")
        store.put(_bare_case())  # must not raise


def test_opensearch_case_store_put_does_not_raise_on_500():
    with patch("requests.put", return_value=_fake_response(500)):
        store = OpenSearchCaseStore(host="opensearch.example", username="u", password="p")
        store.put(_bare_case())  # must not raise


def test_opensearch_case_store_all_returns_empty_list_on_failure_not_raise():
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
        store = OpenSearchCaseStore(host="opensearch.example", username="u", password="p")
        assert store.all() == []


def test_opensearch_case_store_round_trips_a_case_through_doc_serialization():
    case = _bare_case(attack_techniques=["T1486"], state=CaseState.TRIAGED)
    doc = {"_source": aicm._case_to_doc(case)}
    with patch("requests.get", return_value=_fake_response(200, doc)):
        store = OpenSearchCaseStore(host="opensearch.example", username="u", password="p")
        round_tripped = store.get(case.case_id)

    assert round_tripped is not None
    assert round_tripped.case_id == case.case_id
    assert round_tripped.state == CaseState.TRIAGED
    assert round_tripped.attack_techniques == ["T1486"]


def test_opensearch_case_store_default_index_is_concrete_not_the_literal_glob():
    store = OpenSearchCaseStore(host="opensearch.example", username="u", password="p")
    # Disclosed deviation from the SDD's literal "ai-rdr-incident-cases-*" -
    # see the class docstring for why a concrete, non-rotating index is used
    # for get/put-by-id instead.
    assert store.index == "ai-rdr-incident-cases"
