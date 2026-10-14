"""
M2Client tests (task m2-integration; planning/m2-integration-spec.md
Part 1). No live network, no live M2 service - every `requests` call is
mocked, matching `backend/tests/test_threat_intel.py`'s own established
pattern for this codebase (`unittest.mock.patch` on the lazily-imported
`requests` module).

Covers:
  - field-mapping correctness: a `RawEvent` batch maps to the EXACT
    `EventInput`/prediction-request JSON M2's own contract
    (`m2/docs/M2_API_CONTRACT.md`) documents - asserted against the actual
    POST body, not just that a call happened.
  - never-raise behavior: timeout, connection error, a 503 ("no model
    loaded yet" - M2's own real, expected state right now), and a malformed
    response body (unparseable JSON, and valid JSON missing a required key)
    all return `None`, never propagate.
  - the "nothing to score" short-circuit: a group with no `auditd_syscall`-
    bearing events makes no HTTP call at all.
  - a real, well-formed response parses into `M2Result` field-for-field.
  - the single most important guarantee in this task: `fuse()`'s output is
    bit-for-bit identical whether or not an `m2` field is present on the
    `ml_detection` dict it's given - M2's presence can never change
    risk_tier/arm_signals, proven directly against the real `fuse()`, not a
    fake.
"""

from __future__ import annotations

import datetime as dt
from unittest.mock import MagicMock, patch

import requests

from backend.irdp.event_source import RawEvent
from backend.m2_client import DEFAULT_TOP_K, M2Result, RealM2Client
from backend.risk_fusion import ThreatIntelResult, fuse
from backend.tests.fakes import FakeM2Client


def _epoch(iso: str) -> float:
    """Independent (not reusing RealM2Client's own private helper) ISO-8601
    -> epoch conversion, for computing this test's own expected values."""
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _m2_response(
    status_code=200,
    prediction="ransomware",
    ransomware_probability=0.73,
    threshold=0.13,
    alert=True,
    model_name="random_forest",
    feature_version="1.0",
    explanation=None,
):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {
        "prediction": prediction,
        "ransomware_probability": ransomware_probability,
        "threshold": threshold,
        "alert": alert,
        "response_mode": "alert_only",
        "model_name": model_name,
        "feature_version": feature_version,
        "inference_ms": 34.1,
        "explanation": explanation
        if explanation is not None
        else [
            {
                "feature": "write_ratio",
                "value": 0.41,
                "shap_value": 0.08,
                "direction": "toward_ransomware",
            }
        ],
    }
    return resp


EVENT_1 = RawEvent(
    kind="fs_event",
    timestamp="2026-10-14T00:00:00Z",
    host_id="airdr-target",
    process_id=4321,
    process_name="worker",
    file_path="/srv/data/report.docx",
    auditd_syscall="write",
    event_id="e1",
    user_id="1000",
)

EVENT_2 = RawEvent(
    kind="fs_event",
    timestamp="2026-10-14T00:00:05Z",
    host_id="airdr-target",
    process_id=4321,
    process_name="worker",
    file_path="/srv/data/report2.docx",
    auditd_syscall="read",
    event_id="e2",
    user_id="1000",
)

# A RawEvent with no auditd_syscall at all (e.g. an ordinary non-fs Wazuh
# alert) - nothing mappable onto M2's required event_type field.
NON_FS_EVENT = RawEvent(
    kind="wazuh_alert",
    timestamp="2026-10-14T00:00:10Z",
    host_id="airdr-target",
    process_id=4321,
    rule_id="5710",
    process_name="sshd",
)


# ---------------------------------------------------------------------------
# Field-mapping correctness
# ---------------------------------------------------------------------------


def test_request_body_matches_m2_contract_shape_exactly():
    """Asserts the actual POST body JSON, field-for-field, against
    M2_API_CONTRACT.md's documented prediction-request shape - not just
    that a call happened."""
    with patch("requests.post", return_value=_m2_response()) as mock_post:
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([EVENT_1, EVENT_2], run_id="airdr-target:4321")

    assert result is not None
    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == "http://127.0.0.1:8000/v1/predict"
    assert mock_post.call_args.kwargs["timeout"] == 3.0

    expected_body = {
        "run_id": "airdr-target:4321",
        "start": _epoch(EVENT_1.timestamp),
        "end": _epoch(EVENT_2.timestamp),
        "top_k": DEFAULT_TOP_K,
        "events": [
            {
                "timestamp": _epoch(EVENT_1.timestamp),
                "event_type": "write",
                "operation": "write",
                "pid": 4321,
                "process_name": "worker",
                "path": "/srv/data/report.docx",
            },
            {
                "timestamp": _epoch(EVENT_2.timestamp),
                "event_type": "read",
                "operation": "read",
                "pid": 4321,
                "process_name": "worker",
                "path": "/srv/data/report2.docx",
            },
        ],
    }
    assert mock_post.call_args.kwargs["json"] == expected_body

    # No unknown/stray keys anywhere - M2's contract explicitly rejects
    # those to surface M1/M2 schema drift.
    assert set(mock_post.call_args.kwargs["json"].keys()) == {
        "run_id",
        "start",
        "end",
        "top_k",
        "events",
    }
    for event_payload in mock_post.call_args.kwargs["json"]["events"]:
        assert set(event_payload.keys()) <= {
            "timestamp",
            "event_type",
            "operation",
            "pid",
            "ppid",
            "process_name",
            "path",
            "bytes",
        }
        # ppid/bytes are never present - RawEvent has no such fields at all
        # (spec's own confirmed research), simply omitted, never sent null.
        assert "ppid" not in event_payload
        assert "bytes" not in event_payload


def test_base_url_trailing_slash_is_stripped():
    with patch("requests.post", return_value=_m2_response()) as mock_post:
        client = RealM2Client(base_url="http://127.0.0.1:8000/")
        client.score([EVENT_1], run_id="airdr-target:4321")

    assert mock_post.call_args.args[0] == "http://127.0.0.1:8000/v1/predict"


def test_non_fs_events_are_left_out_of_the_request_entirely():
    """A group mixing a mappable fs_event with a non-fs wazuh_alert must
    only submit the mappable one - event_type is required by M2's contract,
    and NON_FS_EVENT has no auditd_syscall to map onto it."""
    with patch("requests.post", return_value=_m2_response()) as mock_post:
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        client.score([EVENT_1, NON_FS_EVENT], run_id="airdr-target:4321")

    assert len(mock_post.call_args.kwargs["json"]["events"]) == 1
    assert mock_post.call_args.kwargs["json"]["events"][0]["path"] == "/srv/data/report.docx"


def test_group_with_no_mappable_events_makes_no_http_call():
    with patch("requests.post") as mock_post:
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([NON_FS_EVENT], run_id="airdr-target:4321")

    mock_post.assert_not_called()
    assert result is None


def test_empty_events_makes_no_http_call():
    with patch("requests.post") as mock_post:
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([], run_id="airdr-target:4321")

    mock_post.assert_not_called()
    assert result is None


# ---------------------------------------------------------------------------
# Successful parse
# ---------------------------------------------------------------------------


def test_successful_response_parses_into_m2result_field_for_field():
    with patch("requests.post", return_value=_m2_response()):
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([EVENT_1], run_id="airdr-target:4321")

    assert result == M2Result(
        prediction="ransomware",
        ransomware_probability=0.73,
        threshold=0.13,
        alert=True,
        model_name="random_forest",
        feature_version="1.0",
        explanation=[
            {
                "feature": "write_ratio",
                "value": 0.41,
                "shap_value": 0.08,
                "direction": "toward_ransomware",
            }
        ],
    )


# ---------------------------------------------------------------------------
# Never-raise behavior - every failure mode the spec calls out by name
# ---------------------------------------------------------------------------


def test_timeout_does_not_raise_returns_none():
    with patch("requests.post", side_effect=requests.exceptions.Timeout()):
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([EVENT_1], run_id="airdr-target:4321")
    assert result is None


def test_connection_error_does_not_raise_returns_none():
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([EVENT_1], run_id="airdr-target:4321")
    assert result is None


def test_503_no_model_loaded_does_not_raise_returns_none():
    """M2's own real, currently-expected state (no trained .joblib artifact
    exists yet) - /v1/predict returns a clean 503. Must be treated exactly
    like any other ordinary failure, not specially re-raised."""
    with patch("requests.post", return_value=_m2_response(status_code=503)):
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([EVENT_1], run_id="airdr-target:4321")
    assert result is None


def test_other_non_2xx_does_not_raise_returns_none():
    with patch("requests.post", return_value=_m2_response(status_code=500)):
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([EVENT_1], run_id="airdr-target:4321")
    assert result is None


def test_unparseable_json_body_does_not_raise_returns_none():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.side_effect = ValueError("not json")
    with patch("requests.post", return_value=resp):
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([EVENT_1], run_id="airdr-target:4321")
    assert result is None


def test_well_formed_json_missing_required_key_does_not_raise_returns_none():
    resp = MagicMock()
    resp.status_code = 200
    # Valid JSON, but missing "ransomware_probability" - a malformed body
    # by M2's own contract, not a transport failure.
    resp.json.return_value = {
        "prediction": "ransomware",
        "threshold": 0.13,
        "alert": True,
        "model_name": "random_forest",
        "feature_version": "1.0",
    }
    with patch("requests.post", return_value=resp):
        client = RealM2Client(base_url="http://127.0.0.1:8000")
        result = client.score([EVENT_1], run_id="airdr-target:4321")
    assert result is None


# ---------------------------------------------------------------------------
# FakeM2Client - sanity check on the fake itself
# ---------------------------------------------------------------------------


def test_fake_m2_client_records_calls_and_returns_seeded_result():
    seeded = M2Result(
        prediction="ransomware",
        ransomware_probability=0.9,
        threshold=0.13,
        alert=True,
        model_name="random_forest",
        feature_version="1.0",
        explanation=[],
    )
    client = FakeM2Client(seeded)
    result = client.score([EVENT_1, EVENT_2], run_id="airdr-target:4321")

    assert result is seeded
    assert len(client.calls) == 1
    recorded_events, recorded_run_id = client.calls[0]
    assert recorded_events == [EVENT_1, EVENT_2]
    assert recorded_run_id == "airdr-target:4321"


# ---------------------------------------------------------------------------
# The load-bearing guarantee: fuse() is provably unaffected by M2's presence
# ---------------------------------------------------------------------------


def test_fuse_output_identical_with_and_without_m2_field():
    """The single most important test (spec Part 1 #3): running the SAME
    trigger through fuse() with and without an `m2` field present on the
    ml_detection dict must produce bit-for-bit identical output - proving
    fuse()'s risk_tier/arm_signals computation can never be swayed by M2's
    presence, without fuse() itself needing to know the field exists at
    all. Exercised against the real, imported fuse() - not a fake."""
    detection_without_m2 = {
        "host_id": "airdr-target",
        "process_id": 42,
        "anomaly_score": 0.9,
        "model_version": "v3",
    }
    detection_with_m2 = dict(detection_without_m2)
    detection_with_m2["m2"] = {
        "prediction": "ransomware",
        "ransomware_probability": 0.99,
        "threshold": 0.13,
        "alert": True,
        "model_name": "random_forest",
        "feature_version": "1.0",
        "explanation": [
            {
                "feature": "write_ratio",
                "value": 0.41,
                "shap_value": 0.08,
                "direction": "toward_ransomware",
            }
        ],
    }

    threat_intel_match = ThreatIntelResult(matched=True, indicator="1.2.3.4", source="fake")

    fused_without = fuse(detection_without_m2, threat_intel_match, honey_file_triggered=True)
    fused_with = fuse(detection_with_m2, threat_intel_match, honey_file_triggered=True)

    assert fused_with == fused_without
    assert fused_with["risk_tier"] == "critical"
    assert fused_with["arm_signals"] == ["ml_anomaly", "threat_intel"]

    # Also check a low-tier case, where it would be easiest for a stray "M2
    # says ransomware!" read to accidentally leak in and inflate risk_tier.
    low_without = fuse({"host_id": "h", "process_id": 1, "anomaly_score": 0.01}, None)
    low_with = fuse(
        {
            "host_id": "h",
            "process_id": 1,
            "anomaly_score": 0.01,
            "m2": {
                "prediction": "ransomware",
                "ransomware_probability": 0.99,
                "threshold": 0.13,
                "alert": True,
                "model_name": "random_forest",
                "feature_version": "1.0",
                "explanation": [],
            },
        },
        None,
    )
    assert low_with == low_without
    assert low_with["risk_tier"] == "low"
