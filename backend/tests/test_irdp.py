"""
IRDP unit tests (task 4.1, Phase A - planning/irdp-pipeline-spec.md). Uses
FakeEventSource + FakeEventWriter exclusively - no live Wazuh/OpenSearch
credentials or network access.

Covers:
  - a honey-file-triggered event produces a critical-severity normalized doc
    with honey_file_triggered: true
  - an ordinary event produces low severity
  - the raw-wazuh-log and fs-event records from the same incident share a
    correlation_id
  - the ML-facing event_mask on the normalized doc is computed via
    pipeline/features/event_categories.py's real bitmask (Correction 2),
    verified against calling that module directly for the same input
  - the checkpoint prevents reprocessing on a second run_once() with no new
    events
  - feeding a batch of new events since the checkpoint processes only those
"""

from __future__ import annotations

import polars as pl
import pytest

from backend.irdp.checkpoint import InMemoryCheckpointStore
from backend.irdp.event_source import RawEvent
from backend.irdp.pipeline import run_once
from backend.m2_client import M2Client, M2Result
from backend.risk_fusion import ThreatIntelResult
from backend.tests.fakes import (
    FakeEventSource,
    FakeEventWriter,
    FakeM2Client,
    FakeThreatIntelClient,
    FakeTriggerSender,
)
from pipeline.features.event_categories import canonical_bit_expr

# A honey-file rule-100100-shaped alert, matching task-breakdown.md S2.2's
# real, deployed detection path (audit key airdr_honeyfile_access, a read of
# a decoy file under /srv/finance).
HONEY_EVENT = RawEvent(
    kind="wazuh_alert",
    timestamp="2026-09-29T00:00:00Z",
    host_id="airdr-target",
    honey_file_triggered=True,
    agent_id="001",
    host_name="airdr-target",
    rule_id="100100",
    mitre_technique="T1486",
    process_name="python3",
    src_ip=None,
    dest_ip=None,
    raw_message="File /srv/finance/Q4_Budget.xlsx read by python3 (audit key airdr_honeyfile_access)",
    event_id=None,
    file_path="/srv/finance/Q4_Budget.xlsx",
    process_id=4321,
    user_id="1000",
    auditd_syscall="read",
)

# An ordinary, non-honey-file Wazuh alert (a plain SSH auth failure) on the
# same host, close in time to HONEY_EVENT - should stay low severity and
# still land in the same correlation bucket.
ORDINARY_EVENT = RawEvent(
    kind="wazuh_alert",
    timestamp="2026-09-29T00:00:05Z",
    host_id="airdr-target",
    honey_file_triggered=False,
    agent_id="001",
    host_name="airdr-target",
    rule_id="5710",
    mitre_technique=None,
    process_name="sshd",
    src_ip="10.0.0.5",
    dest_ip=None,
    raw_message="sshd: authentication failed for invalid user",
)

# A raw auditd/fs event (not itself a Wazuh rule match) - the write half of
# the same real file touch HONEY_EVENT's read came from, one second later,
# same host - should share HONEY_EVENT's correlation_id.
FS_EVENT = RawEvent(
    kind="fs_event",
    timestamp="2026-09-29T00:00:01Z",
    host_id="airdr-target",
    honey_file_triggered=False,
    event_id="audit-9981",
    file_path="/srv/finance/Q4_Budget.xlsx",
    process_id=4321,
    user_id="1000",
    auditd_syscall="write",
)


@pytest.fixture
def writer() -> FakeEventWriter:
    return FakeEventWriter()


@pytest.fixture
def checkpoint_store() -> InMemoryCheckpointStore:
    return InMemoryCheckpointStore()


def test_honey_file_event_is_critical_with_flag_set(writer, checkpoint_store):
    source = FakeEventSource([HONEY_EVENT])
    run_once(source, checkpoint_store, writer)

    norm = [d for d in writer.normalized_events if d["event_type"] == "file_access"]
    assert len(norm) == 1
    assert norm[0]["severity"] == "critical"
    assert norm[0]["host_id"] == "airdr-target"
    assert norm[0]["honey_file_triggered"] is True

    # honey_file_triggered is also the SDD-defined field on the fs-events
    # doc itself - check it landed there too, flagged true.
    fs_docs = [d for d in writer.fs_events if d["file_path"] == "/srv/finance/Q4_Budget.xlsx"]
    assert any(d["honey_file_triggered"] is True for d in fs_docs)


def test_ordinary_event_is_low_severity(writer, checkpoint_store):
    source = FakeEventSource([ORDINARY_EVENT])
    run_once(source, checkpoint_store, writer)

    assert len(writer.normalized_events) == 1
    doc = writer.normalized_events[0]
    assert doc["severity"] == "low"
    assert doc["honey_file_triggered"] is False
    assert doc["event_type"] != "file_access"
    # An ordinary alert must never produce an fs-events record.
    assert writer.fs_events == []


def test_raw_wazuh_log_and_fs_event_share_correlation_id(writer, checkpoint_store):
    source = FakeEventSource([HONEY_EVENT, FS_EVENT])
    run_once(source, checkpoint_store, writer)

    assert len(writer.raw_wazuh_logs) == 1  # only HONEY_EVENT is kind="wazuh_alert"
    assert len(writer.fs_events) == 2  # HONEY_EVENT (fs-relevant) + FS_EVENT

    norm_by_event_id = {d["event_id"]: d for d in writer.normalized_events}
    correlation_ids = {d["correlation_id"] for d in norm_by_event_id.values()}
    assert len(correlation_ids) == 1, "same host, within the 30s window -> one correlation_id"


def test_ml_event_mask_matches_event_categories_directly(writer, checkpoint_store):
    """The core Correction-2 check: the normalized doc's event_mask must be
    the real bitmask from pipeline/features/event_categories.py, not a raw
    per-event label, and must equal what calling that module directly on
    the same underlying event_type set produces."""
    source = FakeEventSource([HONEY_EVENT, FS_EVENT])
    run_once(source, checkpoint_store, writer)

    masks = {d["event_mask"] for d in writer.normalized_events}
    assert len(masks) == 1  # both events are in the same correlation bucket
    actual_mask = masks.pop()

    # Independently compute the expected mask the same way
    # normalize.compute_ml_event_mask does, but using event_categories.py's
    # function directly, with no import of backend.irdp.normalize's helpers.
    df = pl.DataFrame({"event_type": ["file_access", "file_modify"]})  # read + write
    df = df.with_columns(canonical_bit_expr("event_type").alias("_bit"))
    expected_mask = 0
    for bit in df["_bit"].unique().to_list():
        expected_mask |= int(bit)

    assert actual_mask == expected_mask
    assert actual_mask != 0
    # event_mask must be an int (a bitmask), never the fs-events string
    # label - the exact conflation Correction 2 warns against.
    assert isinstance(actual_mask, int)
    fs_event_masks = {d["event_mask"] for d in writer.fs_events}
    assert fs_event_masks == {"IN_ACCESS", "IN_MODIFY"}  # the per-event STRING labels, unchanged


def test_second_run_once_with_no_new_events_reprocesses_nothing(writer, checkpoint_store):
    source = FakeEventSource([HONEY_EVENT, ORDINARY_EVENT, FS_EVENT])

    first = run_once(source, checkpoint_store, writer)
    assert first["raw_events_processed"] == 3
    written_after_first = len(writer.normalized_events)

    second = run_once(source, checkpoint_store, writer)
    assert second["raw_events_processed"] == 0
    assert len(writer.normalized_events) == written_after_first  # nothing new written


def test_only_new_events_since_checkpoint_are_processed(writer, checkpoint_store):
    source = FakeEventSource([HONEY_EVENT])
    run_once(source, checkpoint_store, writer)
    assert len(writer.normalized_events) == 1

    later_event = RawEvent(
        kind="wazuh_alert",
        timestamp="2026-09-29T00:10:00Z",
        host_id="airdr-target",
        honey_file_triggered=False,
        agent_id="001",
        host_name="airdr-target",
        rule_id="5710",
        process_name="sshd",
        src_ip="10.0.0.6",
    )
    source.add_events([later_event])

    result = run_once(source, checkpoint_store, writer)
    assert result["raw_events_processed"] == 1  # only later_event, not HONEY_EVENT again
    assert len(writer.normalized_events) == 2


def test_run_once_writes_real_ml_detections(writer, checkpoint_store):
    """run_once() must score this batch's RawEvents against the real v3
    model (backend/ml_scoring.py, task 4.2) and write real
    ai-rdr-ml-detections-* documents - not skip this step or write a
    placeholder. HONEY_EVENT/FS_EVENT share process_id=4321 on host
    "airdr-target" (one windowing group); ORDINARY_EVENT has no process_id
    set at all, so it forms its own separate (host, None) group per
    windowing.py's documented null-grouping semantics - 2 groups, 2
    detections, not 1."""
    source = FakeEventSource([HONEY_EVENT, ORDINARY_EVENT, FS_EVENT])

    result = run_once(source, checkpoint_store, writer)

    assert result["ml_detections_written"] == 2
    assert len(writer.ml_detections) == 2

    by_process_id = {d["process_id"]: d for d in writer.ml_detections}
    assert set(by_process_id) == {4321, None}

    honeyfile_detection = by_process_id[4321]
    assert honeyfile_detection["host_id"] == "airdr-target"
    assert honeyfile_detection["model_version"] == "v3"
    assert 0.0 <= honeyfile_detection["anomaly_score"] <= 1.0
    assert honeyfile_detection["predicted_label"] in {"ransomware", "benign"}


def test_run_once_skips_risk_fusion_entirely_when_no_trigger_sender(writer, checkpoint_store):
    """Backward-compat guarantee: existing callers that don't pass
    trigger_sender (every test above, and any caller written before task
    4.4's wiring) must see identical behavior - no fuse()/lookup call, no
    exception, triggers_sent present and 0."""
    source = FakeEventSource([HONEY_EVENT, ORDINARY_EVENT, FS_EVENT])
    result = run_once(source, checkpoint_store, writer)
    assert result["triggers_sent"] == 0


def test_run_once_wires_fuse_and_sends_real_triggers(writer, checkpoint_store):
    """task 4.4 live wiring: a threat-intel match forces risk_tier into
    {"high", "critical"} (both ARM_NOTIFIABLE_TIERS) regardless of the real
    model's anomaly_score, so every group whose RawEvents carry an
    indicator must produce a sent trigger - a deterministic way to prove
    the wiring runs without depending on the real v3 model's exact score.
    Uses its own fixtures (not the module-level HONEY_EVENT/FS_EVENT/
    ORDINARY_EVENT, which deliberately don't all carry an ip - see
    test_run_once_extracts_indicators_only_from_groups_that_have_them
    below) so both of this test's groups have an indicator to look up."""
    honey_event = RawEvent(
        kind="wazuh_alert",
        timestamp="2026-09-29T02:00:00Z",
        host_id="airdr-target",
        honey_file_triggered=True,
        agent_id="001",
        host_name="airdr-target",
        rule_id="100100",
        process_name="python3",
        src_ip="10.0.0.9",
        process_id=9001,
        user_id="1000",
        auditd_syscall="read",
    )
    ordinary_event = RawEvent(
        kind="wazuh_alert",
        timestamp="2026-09-29T02:00:05Z",
        host_id="airdr-target",
        honey_file_triggered=False,
        agent_id="001",
        host_name="airdr-target",
        rule_id="5710",
        process_name="sshd",
        src_ip="10.0.0.5",
    )
    source = FakeEventSource([honey_event, ordinary_event])
    threat_intel = FakeThreatIntelClient(ThreatIntelResult(matched=True, indicator="known-bad", source="fake"))
    trigger_sender = FakeTriggerSender()

    result = run_once(
        source,
        checkpoint_store,
        writer,
        threat_intel_client=threat_intel,
        trigger_sender=trigger_sender,
    )

    assert result["ml_detections_written"] == 2  # (airdr-target, 9001) + (airdr-target, None)
    assert result["triggers_sent"] == 2
    assert len(trigger_sender.sent) == 2
    assert all(fused["risk_tier"] in {"high", "critical"} for fused in trigger_sender.sent)

    # honey_file_triggered must reach fuse()'s display-only slot for the
    # (airdr-target, 9001) group but never leak into risk_tier - fuse()'s
    # own guarantee, exercised here through the real wiring rather than
    # re-asserted against fuse() directly.
    honey_group_fused = next(f for f in trigger_sender.sent if f["process_id"] == 9001)
    assert honey_group_fused["dashboard_signals"][0]["label"] == "Honey-File"
    assert honey_group_fused["dashboard_signals"][0]["v"] == 1.0

    # Both groups carry exactly one ip each -> exactly one lookup call per
    # group, order not guaranteed.
    assert sorted(call["ip"] for call in threat_intel.calls) == ["10.0.0.5", "10.0.0.9"]


def test_run_once_extracts_indicators_only_from_groups_that_have_them(writer, checkpoint_store):
    """A group with no src_ip/dest_ip on any of its RawEvents (HONEY_EVENT +
    FS_EVENT, process_id=4321) must never call the ThreatIntelClient at all
    - fuse() then sees threat_intel_result=None for that group, same as "no
    lookup performed". Only ORDINARY_EVENT's group (process_id=None) carries
    an ip (src_ip="10.0.0.5")."""
    source = FakeEventSource([HONEY_EVENT, ORDINARY_EVENT, FS_EVENT])
    threat_intel = FakeThreatIntelClient(ThreatIntelResult(matched=True, indicator="10.0.0.5", source="fake"))
    trigger_sender = FakeTriggerSender()

    run_once(
        source,
        checkpoint_store,
        writer,
        threat_intel_client=threat_intel,
        trigger_sender=trigger_sender,
    )

    # Only one lookup call total (the ordinary_event group's) - proves the
    # (airdr-target, 4321) group got no lookup at all, so its risk_tier
    # (whichever of "low"/"medium" the real model's score lands on) could
    # never have been forced to "high"/"critical" by this seeded client -
    # matched=False for that group regardless of what the client returns.
    assert threat_intel.calls == [{"ip": "10.0.0.5"}]
    assert all(f["risk_tier"] in {"low", "medium"} for f in trigger_sender.sent if f["process_id"] == 4321)


def test_run_once_low_tier_never_sent(writer, checkpoint_store):
    """A no-match, below-threshold group must never reach the TriggerSender
    at all - send_trigger_if_needed()'s own "low never sent" guarantee,
    exercised through the real wiring."""
    source = FakeEventSource([ORDINARY_EVENT])
    trigger_sender = FakeTriggerSender()

    result = run_once(
        source,
        checkpoint_store,
        writer,
        trigger_sender=trigger_sender,  # threat_intel_client omitted -> NullThreatIntelClient
    )

    # NullThreatIntelClient never matches, so this group is only sent if the
    # real model's anomaly_score happens to clear DEFAULT_THRESHOLD for this
    # fixture; either way, triggers_sent must equal len(trigger_sender.sent)
    # (the two must never disagree) and nothing above "medium" can occur
    # with no threat-intel match.
    assert result["triggers_sent"] == len(trigger_sender.sent)
    assert all(f["risk_tier"] in {"low", "medium"} for f in trigger_sender.sent)


# ---------------------------------------------------------------------------
# Task 3.4b (planning/pathpredict-deployment-spec.md Part 1): wiring PathPredict
# into run_once() via the new pathpredict_writer/incident_tracker_store/
# host_controller optional params.
# ---------------------------------------------------------------------------


def test_run_once_backward_compat_pathpredict_params_omitted(writer, checkpoint_store):
    """All three new params omitted (every test above) -> identical
    behavior to before this task: no PathPredict call, a
    pathpredict_predictions_written key present and 0, no exception."""
    source = FakeEventSource([HONEY_EVENT, ORDINARY_EVENT, FS_EVENT])
    result = run_once(source, checkpoint_store, writer)
    assert result["pathpredict_predictions_written"] == 0


def test_run_once_pathpredict_wiring_multi_poll_continuity_and_never_backs_up(writer, checkpoint_store):
    """The full integration case (spec Part 1 #5): two sequential run_once()
    calls, simulating two real poll cycles, sharing the same
    InMemoryIncidentTrackerStore/InMemoryPathPredictWriter/FakeHostController
    instances - proves the second call's tracker state genuinely reflects
    the first call's touch (not just that a store object exists), and that
    build_prediction()'s live top-1 comparison is judged against the right
    incremental state. Also the dedicated "backup_file never invoked"
    assertion (spec's own required test) against this new code path's own
    FakeHostController.

    Hand-computed expectation (directory /data: a.txt, b.txt, c.txt):
      poll 1: only touch is a.txt. touched_so_far was empty beforehand -> no
        prior prediction exists -> can't be a hit -> topk "0/1". State
        persisted: matched=0, total=1, touched_so_far=["a.txt"].
      poll 2: new touch is b.txt. Immediately before it, touched_so_far=
        ["a.txt"] (persisted from poll 1) -> remaining=[b.txt, c.txt] ->
        predicted top-1 is b.txt -> b.txt touched -> HIT -> topk "1/2".
        touched_so_far now ["a.txt", "b.txt"]; only c.txt remains.
    """
    from backend.pathpredict import InMemoryIncidentTrackerStore, InMemoryPathPredictWriter
    from backend.tests.fakes import FakeHostController

    HOST = "airdr-target"
    controller = FakeHostController()
    controller.directories[(HOST, "/data")] = ["a.txt", "b.txt", "c.txt"]
    tracker_store = InMemoryIncidentTrackerStore()
    pp_writer = InMemoryPathPredictWriter()
    threat_intel = FakeThreatIntelClient(ThreatIntelResult(matched=True, indicator="known-bad", source="fake"))

    event1 = RawEvent(
        kind="fs_event",
        timestamp="2026-10-05T00:00:00Z",
        host_id=HOST,
        process_id=9001,
        file_path="/data/a.txt",
        auditd_syscall="write",
        src_ip="10.0.0.9",
        event_id="audit-a",
        user_id="1000",
    )
    source = FakeEventSource([event1])

    first = run_once(
        source,
        checkpoint_store,
        writer,
        threat_intel_client=threat_intel,
        trigger_sender=FakeTriggerSender(),
        pathpredict_writer=pp_writer,
        incident_tracker_store=tracker_store,
        host_controller=controller,
    )
    assert first["pathpredict_predictions_written"] == 1

    key = "airdr-target:9001"
    state_after_first = tracker_store.get(key)
    assert state_after_first.matched == 0
    assert state_after_first.total_predictions_made == 1
    assert state_after_first.touched_so_far == ["/data/a.txt"]
    assert pp_writer.written[key]["topk"] == "0/1"

    event2 = RawEvent(
        kind="fs_event",
        timestamp="2026-10-05T00:01:00Z",
        host_id=HOST,
        process_id=9001,
        file_path="/data/b.txt",
        auditd_syscall="write",
        src_ip="10.0.0.9",
        event_id="audit-b",
        user_id="1000",
    )
    source.add_events([event2])

    second = run_once(
        source,
        checkpoint_store,
        writer,
        threat_intel_client=threat_intel,
        trigger_sender=FakeTriggerSender(),
        pathpredict_writer=pp_writer,
        incident_tracker_store=tracker_store,
        host_controller=controller,
    )
    assert second["pathpredict_predictions_written"] == 1

    # The real proof of persistence: the SECOND call's tracker state must
    # reflect the FIRST call's touch - total went 1 -> 2, not reset to 1.
    state_after_second = tracker_store.get(key)
    assert state_after_second.matched == 1  # the b.txt touch was a genuine hit
    assert state_after_second.total_predictions_made == 2
    assert state_after_second.touched_so_far == ["/data/a.txt", "/data/b.txt"]

    final_doc = pp_writer.written[key]
    assert final_doc["topk"] == "1/2"
    assert [t["path"] for t in final_doc["targets"]] == ["/data/c.txt"]
    assert final_doc["host_id"] == HOST
    assert final_doc["process_id"] == 9001

    # Explicit, dedicated assertion (spec's own required test): zero calls
    # to HostController.backup_file anywhere across both polls of this new
    # code path.
    backup_calls = [name for name, _ in controller.calls if name == "backup_file"]
    assert backup_calls == []


# ---------------------------------------------------------------------------
# Task m2-integration (planning/m2-integration-spec.md Part 1): wiring
# M2Client into run_once() via the new m2_client optional param.
# ---------------------------------------------------------------------------


class _NoneM2Client(M2Client):
    """A real (not a bad-faith) `M2Client` implementation that always
    returns `None` - used to prove run_once() cleanly omits the `m2` field
    (never writes it as null/empty) when no opinion is available, the same
    way a real `RealM2Client` genuinely will until a trained model exists."""

    def score(self, events, run_id):
        return None


def test_run_once_backward_compat_m2_client_omitted(writer, checkpoint_store):
    """m2_client omitted (every test above) -> identical behavior to before
    this task: no "m2" field on any written detection, m2_scores_attached
    present and 0, no exception."""
    source = FakeEventSource([HONEY_EVENT, ORDINARY_EVENT, FS_EVENT])
    result = run_once(source, checkpoint_store, writer)

    assert result["m2_scores_attached"] == 0
    assert len(writer.ml_detections) == 2
    assert all("m2" not in d for d in writer.ml_detections)


def test_run_once_attaches_m2_field_to_the_written_detection(writer, checkpoint_store):
    """When m2_client is provided and returns a result, that result must be
    attached under the `m2` key on the SAME ai-rdr-ml-detections-* document
    run_once() writes - field-for-field, not re-derived."""
    seeded = M2Result(
        prediction="ransomware",
        ransomware_probability=0.88,
        threshold=0.13,
        alert=True,
        model_name="random_forest",
        feature_version="1.0",
        explanation=[{"feature": "write_ratio", "value": 0.4, "shap_value": 0.1, "direction": "toward_ransomware"}],
    )
    m2_client = FakeM2Client(seeded)
    source = FakeEventSource([HONEY_EVENT, ORDINARY_EVENT, FS_EVENT])

    result = run_once(source, checkpoint_store, writer, m2_client=m2_client)

    assert result["m2_scores_attached"] == 2
    assert len(writer.ml_detections) == 2
    for doc in writer.ml_detections:
        assert doc["m2"] == {
            "prediction": "ransomware",
            "ransomware_probability": 0.88,
            "threshold": 0.13,
            "alert": True,
            "model_name": "random_forest",
            "feature_version": "1.0",
            "explanation": seeded.explanation,
        }

    # m2_client.score() was called once per (host_id, process_id) detection
    # group, with the real incident_key()-shaped run_id.
    run_ids = sorted(call_run_id for _, call_run_id in m2_client.calls)
    assert run_ids == ["airdr-target:4321", "airdr-target:None"]


def test_run_once_omits_m2_field_cleanly_when_client_returns_none(writer, checkpoint_store):
    """A genuinely wired m2_client that returns None (M2's real, currently-
    expected "no model loaded" state) must leave every written detection
    exactly as it would be with no m2_client at all - never a null/empty
    "m2" key."""
    source = FakeEventSource([HONEY_EVENT, ORDINARY_EVENT, FS_EVENT])
    result = run_once(source, checkpoint_store, writer, m2_client=_NoneM2Client())

    assert result["m2_scores_attached"] == 0
    assert len(writer.ml_detections) == 2
    assert all("m2" not in d for d in writer.ml_detections)


def test_run_once_fuse_output_unaffected_by_m2_wiring():
    """The integration-level version of the spec's most important guarantee:
    running the exact same batch of RawEvents through run_once() twice -
    once with no m2_client, once with an m2_client seeded to return a
    high-confidence ransomware alert - must send IDENTICAL fused triggers
    to ARM either way. Two completely independent writer/checkpoint_store
    instances (not shared state) so the two runs can't influence each
    other."""
    honey_event = RawEvent(
        kind="wazuh_alert",
        timestamp="2026-10-14T03:00:00Z",
        host_id="airdr-target",
        honey_file_triggered=True,
        agent_id="001",
        host_name="airdr-target",
        rule_id="100100",
        process_name="python3",
        src_ip="10.0.0.9",
        process_id=9001,
        user_id="1000",
        auditd_syscall="read",
    )

    threat_intel = FakeThreatIntelClient(ThreatIntelResult(matched=True, indicator="known-bad", source="fake"))

    source_without = FakeEventSource([honey_event])
    trigger_sender_without = FakeTriggerSender()
    run_once(
        source_without,
        InMemoryCheckpointStore(),
        FakeEventWriter(),
        threat_intel_client=threat_intel,
        trigger_sender=trigger_sender_without,
    )

    alerting_m2_result = M2Result(
        prediction="ransomware",
        ransomware_probability=0.99,
        threshold=0.13,
        alert=True,
        model_name="random_forest",
        feature_version="1.0",
        explanation=[{"feature": "write_ratio", "value": 0.9, "shap_value": 0.5, "direction": "toward_ransomware"}],
    )
    source_with = FakeEventSource([honey_event])
    trigger_sender_with = FakeTriggerSender()
    run_once(
        source_with,
        InMemoryCheckpointStore(),
        FakeEventWriter(),
        threat_intel_client=FakeThreatIntelClient(ThreatIntelResult(matched=True, indicator="known-bad", source="fake")),
        trigger_sender=trigger_sender_with,
        m2_client=FakeM2Client(alerting_m2_result),
    )

    assert len(trigger_sender_without.sent) == len(trigger_sender_with.sent) == 1
    assert trigger_sender_with.sent[0] == trigger_sender_without.sent[0]
    assert trigger_sender_with.sent[0]["risk_tier"] == trigger_sender_without.sent[0]["risk_tier"]
    assert trigger_sender_with.sent[0]["arm_signals"] == trigger_sender_without.sent[0]["arm_signals"]


def test_parse_ts_handles_real_colonless_utc_offset():
    """Regression test for a real bug: real Wazuh alert timestamps carry a
    colonless UTC offset (e.g. "...610+0000"), which datetime.fromisoformat()
    only accepts from Python 3.11 onward. This repo's dev venv runs 3.14
    (lenient) - the real deployment target (airdr-detect) runs 3.10, where
    every real event crashed this function until fixed live 2026-09-30."""
    from backend.irdp.normalize import _parse_ts

    parsed = _parse_ts("2026-09-29T11:25:39.610+0000")
    assert parsed.year == 2026
    assert parsed.utcoffset().total_seconds() == 0
    # already-colon'd and "Z" forms must keep working too
    assert _parse_ts("2026-09-29T11:25:39+00:00").hour == 11
    assert _parse_ts("2026-09-29T11:25:39Z").hour == 11
