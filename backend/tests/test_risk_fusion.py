"""
Risk Fusion Engine tests (task 4.4; planning/risk-fusion-spec.md).

Covers the full corroboration table (all 4 rows + the below-threshold/
no-signal case), the honey-file display-only guarantee, and - the important
integration check - round-tripping each computed risk_tier through
backend/arm.py's REAL, imported select_playbook() (not a fake, not a guess)
to prove medium/high/critical actually route to PB-02/PB-03/PB-01. Also
covers the TriggerSender gating (low never calls it; medium/high/critical
do).
"""

from pipeline.training.model import DEFAULT_THRESHOLD

from backend.arm import select_playbook
from backend.risk_fusion import (
    ARM_NOTIFIABLE_TIERS,
    ThreatIntelResult,
    fuse,
    send_trigger_if_needed,
)
from backend.tests.fakes import FakeTriggerSender


def _ml(anomaly_score=None, host_id="airdr-target", process_id=42):
    detection = {"host_id": host_id, "process_id": process_id}
    if anomaly_score is not None:
        detection["anomaly_score"] = anomaly_score
    return detection


NO_MATCH = ThreatIntelResult(matched=False, source="fake")
MATCH = ThreatIntelResult(matched=True, indicator="1.2.3.4", source="fake")


# ---------------------------------------------------------------------------
# Corroboration table - the spec's exact 4 rows, plus the no-signal-at-all
# case (belongs to row 1: below-threshold/absent ML + no match -> low).
# ---------------------------------------------------------------------------


def test_below_threshold_no_match_is_low():
    fused = fuse(_ml(anomaly_score=0.10), NO_MATCH)
    assert fused["risk_tier"] == "low"
    assert fused["arm_signals"] == []


def test_no_ml_signal_at_all_no_match_is_low():
    # ml_detection carries no anomaly_score key at all - "no ML signal
    # available", not merely a low score.
    fused = fuse(_ml(anomaly_score=None), NO_MATCH)
    assert fused["risk_tier"] == "low"
    assert fused["arm_signals"] == []


def test_above_threshold_no_match_is_medium():
    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.05), NO_MATCH)
    assert fused["risk_tier"] == "medium"
    assert fused["arm_signals"] == ["ml_anomaly"]


def test_at_exact_threshold_counts_as_above():
    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD), NO_MATCH)
    assert fused["risk_tier"] == "medium"


def test_any_ml_with_match_is_high():
    fused = fuse(_ml(anomaly_score=0.10), MATCH)
    assert fused["risk_tier"] == "high"
    assert fused["arm_signals"] == ["threat_intel"]


def test_no_ml_signal_with_match_is_high():
    fused = fuse(_ml(anomaly_score=None), MATCH)
    assert fused["risk_tier"] == "high"
    assert fused["arm_signals"] == ["threat_intel"]


def test_above_threshold_and_match_is_critical():
    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.2), MATCH)
    assert fused["risk_tier"] == "critical"
    assert fused["arm_signals"] == ["ml_anomaly", "threat_intel"]


def test_threat_intel_result_none_behaves_like_no_match():
    fused = fuse(_ml(anomaly_score=0.10), None)
    assert fused["risk_tier"] == "low"


# ---------------------------------------------------------------------------
# Honey-file display-only guarantee
# ---------------------------------------------------------------------------


def test_honey_file_triggered_never_escalates_risk_tier():
    fused = fuse(_ml(anomaly_score=0.05), NO_MATCH, honey_file_triggered=True)
    assert fused["risk_tier"] == "low"
    # It DOES still show up in the dashboard signals, for display only.
    honeyfile_slot = fused["dashboard_signals"][0]
    assert honeyfile_slot["label"] == "Honey-File"
    assert honeyfile_slot["v"] == 1.0
    # But it must never appear in the ARM-facing flat signals list - that's
    # ARM's own PB-04 bypass's job, not fuse()'s.
    assert "honeyfile" not in fused["arm_signals"]


def test_honey_file_not_triggered_shows_zero_in_dashboard():
    fused = fuse(_ml(anomaly_score=0.05), NO_MATCH, honey_file_triggered=False)
    assert fused["dashboard_signals"][0]["v"] == 0.0


# ---------------------------------------------------------------------------
# Output shape sanity
# ---------------------------------------------------------------------------


def test_output_has_both_arm_and_dashboard_shapes_distinctly_named():
    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.1), MATCH, honey_file_triggered=True)

    # ARM payload fields
    assert fused["host"] == "airdr-target"
    assert fused["entity"] == "airdr-target:42"
    assert isinstance(fused["arm_signals"], list)

    # Dashboard fields - a DIFFERENT shape under a DIFFERENT key.
    assert len(fused["dashboard_signals"]) == 3
    labels = [s["label"] for s in fused["dashboard_signals"]]
    assert labels == ["Honey-File", "ML Anomaly", "Threat-Intel"]
    for slot in fused["dashboard_signals"]:
        assert 0.0 <= slot["v"] <= 1.0
        assert isinstance(slot["note"], str) and slot["note"]

    assert isinstance(fused["fusion_line"], str) and fused["fusion_line"]
    assert "critical" in fused["fusion_line"]


def test_fusion_line_reflects_no_signals():
    fused = fuse(_ml(anomaly_score=None), NO_MATCH)
    assert "no ML anomaly signal" in fused["fusion_line"]
    assert "no threat-intel match" in fused["fusion_line"]


def test_fusion_line_reflects_corroborated_match():
    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.1), MATCH)
    assert "1.2.3.4" in fused["fusion_line"]


# ---------------------------------------------------------------------------
# The important integration check: round-trip each risk_tier through arm.py's
# REAL select_playbook(), not a re-guess of its behavior.
# ---------------------------------------------------------------------------


def _arm_trigger_payload(fused):
    return {
        "host": fused["host"],
        "entity": fused["entity"],
        "risk_tier": fused["risk_tier"],
        "signals": fused["arm_signals"],
    }


def test_medium_routes_to_pb02_via_real_select_playbook():
    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.05), NO_MATCH)
    playbook = select_playbook(_arm_trigger_payload(fused))
    assert playbook is not None
    assert playbook.id == "PB-02"


def test_high_routes_to_pb03_via_real_select_playbook():
    fused = fuse(_ml(anomaly_score=0.05), MATCH)
    playbook = select_playbook(_arm_trigger_payload(fused))
    assert playbook is not None
    assert playbook.id == "PB-03"


def test_critical_routes_to_pb01_via_real_select_playbook():
    fused = fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.2), MATCH)
    playbook = select_playbook(_arm_trigger_payload(fused))
    assert playbook is not None
    assert playbook.id == "PB-01"


def test_low_routes_to_no_playbook_via_real_select_playbook():
    fused = fuse(_ml(anomaly_score=0.05), NO_MATCH)
    playbook = select_playbook(_arm_trigger_payload(fused))
    assert playbook is None


# ---------------------------------------------------------------------------
# TriggerSender gating: low never calls it, medium/high/critical do.
# ---------------------------------------------------------------------------


def test_low_never_triggers_sender():
    sender = FakeTriggerSender()
    fused = fuse(_ml(anomaly_score=0.05), NO_MATCH)
    result = send_trigger_if_needed(fused, sender)
    assert result is None
    assert sender.sent == []


def test_medium_high_critical_all_trigger_sender():
    sender = FakeTriggerSender()
    cases = [
        fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.05), NO_MATCH),  # medium
        fuse(_ml(anomaly_score=0.05), MATCH),  # high
        fuse(_ml(anomaly_score=DEFAULT_THRESHOLD + 0.2), MATCH),  # critical
    ]
    for fused in cases:
        assert fused["risk_tier"] in ARM_NOTIFIABLE_TIERS
        result = send_trigger_if_needed(fused, sender)
        assert result is not None

    assert len(sender.sent) == 3
    assert [f["risk_tier"] for f in sender.sent] == ["medium", "high", "critical"]
