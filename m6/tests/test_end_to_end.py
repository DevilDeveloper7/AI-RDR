"""Mock end-to-end lifecycle of simulated ransomware alerts, driven only through the M6 API.

Everything below the API (M1-M5) is the mock adapter layer, so this proves the pieces work together
through routes -> services -> adapters; it says nothing about real modules.
"""
from app.integrations.base import IntegrationUnavailable
from stubs import Failing

V1 = "/api/v1"


def get(client, path):
    res = client.get(V1 + path)
    assert res.status_code == 200, (path, res.get_json())
    return res.get_json()


def act(client, alert_id, action, expect=200):
    res = client.post(f"{V1}/alerts/{alert_id}/action", json={"action": action})
    assert res.status_code == expect, res.get_json()
    return res.get_json()


def events(alert):
    return [t["event"] for t in alert["timeline"]]


def test_confirmed_ransomware_lifecycle(client):
    # Detection is available to M6 and the analyst sees it in the feed.
    feed = get(client, "/alerts?page_size=5")
    first = next(a for a in feed["items"] if a["id"] == "A-2041")
    assert (first["severity"], first["response_state"], first["status"]) == ("Critical", "Frozen", "Open")
    assert feed["summary"]["active"] == 3

    # Investigation: detail, evidence, timeline (M1 + M2 + M5 data assembled by M6).
    alert = get(client, "/alerts/A-2041")
    assert [e["label"] for e in alert["evidence"]] == ["write_rate", "rename_ratio", "syscall_frequency", "FIM"]
    assert events(alert)[:3] == ["Telemetry received", "Behavioural anomaly detected", "ML threshold exceeded"]
    assert alert["timeline"][-1]["pending"] is True

    # SHAP comes from M2 and agrees with the detection.
    shap = get(client, "/alerts/A-2041/shap")
    assert shap["ransomware_likelihood"] == alert["confidence"] == 0.94
    assert shap["features"][0]["feature"] == "write_rate"

    # Threat intelligence is context for the alert's indicators, never the decision.
    assert len(alert["indicators"]) == 2
    for indicator in alert["indicators"]:
        enrichment = get(client, f"/threat-intelligence/{indicator}")
        assert enrichment["related_alert"] == "A-2041" and enrichment["enrichment_status"] == "enriched"

    # Honey-file context for the same host: M3 reports the decoy that was touched.
    honey = get(client, "/honey-files")
    hit = next(i for i in honey["items"] if i["host"] == alert["host"])
    assert hit["status"] == "Triggered" and hit["alert_id"] == "A-2042"
    assert get(client, "/alerts/A-2042")["host"] == alert["host"]

    # The analyst acknowledges; the response workflow continues: Freeze (already) -> Verify -> Isolate.
    assert client.post(f"{V1}/alerts/A-2041/acknowledge").get_json()["alert"]["status"] == "Acknowledged"
    verified = act(client, "A-2041", "verify")
    assert (verified["alert"]["response_state"], verified["alert"]["verification_state"]) == ("Frozen", "Verifying")
    isolated = act(client, "A-2041", "isolate")
    assert isolated["executor"] == "M5 (mock adapter)"
    assert (isolated["alert"]["response_state"], isolated["alert"]["verification_state"]) == ("Isolated", "Confirmed")

    # State updated everywhere M6 reads it.
    final = get(client, "/alerts/A-2041")
    assert events(final)[-2:] == ["Verification started", "Isolation initiated"] and not final["timeline"][-1]["pending"]
    latest = get(client, "/response-activity?limit=1")["items"][0]
    assert (latest["event"], latest["alert_id"]) == ("Isolation", "A-2041")
    assert get(client, "/alerts?page_size=1")["summary"]["active"] == 2
    assert act(client, "A-2041", "thaw", expect=409)["error"]["code"] == "ACTION_REJECTED"  # a finished response cannot be thawed


def test_false_positive_lifecycle_ends_in_thaw(client):
    assert get(client, "/alerts/A-2038")["response_state"] == "Frozen"
    act(client, "A-2038", "verify")
    thawed = act(client, "A-2038", "thaw")["alert"]
    assert (thawed["response_state"], thawed["verification_state"]) == ("Thawed", "False positive")
    assert events(get(client, "/alerts/A-2038"))[-1] == "Process thawed"
    assert "released" in get(client, "/alerts/A-2038")["summary"]
    assert act(client, "A-2038", "kill", expect=409)["error"]["code"] == "ACTION_REJECTED"


def test_analyst_override_lifecycle(client):
    assert client.post(f"{V1}/alerts/A-2041/override", json={"reason": " "}).status_code == 400
    res = client.post(f"{V1}/alerts/A-2041/override", json={"reason": "Scheduled backup job, confirmed with host owner"})
    alert = res.get_json()["alert"]
    assert (alert["response_state"], alert["verification_state"], alert["status"]) == ("Thawed", "Analyst override", "Acknowledged")
    latest = get(client, "/response-activity?limit=1")["items"][0]
    assert latest["event"] == "Analyst override → Thaw" and latest["alert_id"] == "A-2041"
    assert client.post(f"{V1}/alerts/A-2041/override", json={"reason": "again please"}).status_code == 409


def test_kill_and_isolate_are_separate_actions_with_separate_history(client):
    act(client, "A-2038", "kill")
    act(client, "A-2041", "isolate")
    assert events(get(client, "/alerts/A-2038"))[-1] == "Process killed"
    assert events(get(client, "/alerts/A-2041"))[-1] == "Isolation initiated"


def test_freeze_can_start_a_new_response_cycle(client):
    assert act(client, "A-2039", "freeze")["alert"]["response_state"] == "Frozen"  # was Thawed
    assert act(client, "A-2039", "isolate")["alert"]["response_state"] == "Isolated"


# ---------------------------------------------------------------- honey-file path is independent of M2
def test_honey_file_alert_is_handled_end_to_end_while_m2_is_down(app):
    client = app.test_client()
    app.extensions["adapters"]["m2"] = Failing(IntegrationUnavailable("M2 is not reachable."))

    feed = get(client, "/alerts?page_size=50")
    ids = {a["id"] for a in feed["items"]}
    assert "A-2042" in ids and "A-2041" not in ids  # honey alert present, ML alerts missing
    assert feed["meta"]["unavailable"] == ["m2"]  # the outage is reported, not hidden

    alert = get(client, "/alerts/A-2042")
    assert alert["detection_type"] == "Honey-File Trigger" and alert["confidence"] is None
    assert [e["label"] for e in alert["evidence"]][-1] == "Model stage" and alert["evidence"][-1]["value"] == "Bypassed (fast path)"
    assert events(alert)[:2] == ["Honey-file event received (inotify)", "Fast-path alert created"]
    assert get(client, "/honey-files")["summary"]["triggered"] == 2

    assert client.get(f"{V1}/alerts/A-2042/shap").get_json()["error"]["code"] == "SHAP_NOT_APPLICABLE"  # no ML stage, M2 never asked
    assert client.get(f"{V1}/alerts/A-2041").status_code == 503  # ML alert cannot be shown without M2
    assert client.get(f"{V1}/alerts/A-2041/shap").status_code == 503

    assert client.post(f"{V1}/alerts/A-2042/acknowledge").status_code == 200
    act(client, "A-2042", "verify")
    assert act(client, "A-2042", "isolate")["alert"]["response_state"] == "Isolated"


def test_ml_alerts_keep_working_while_m3_is_down(app):
    client = app.test_client()
    from app.integrations.base import IntegrationTimeout
    app.extensions["adapters"]["m3"] = Failing(IntegrationTimeout("M3 timed out."))
    feed = get(client, "/alerts?page_size=50")
    ids = {a["id"] for a in feed["items"]}
    assert "A-2041" in ids and "A-2042" not in ids and feed["meta"]["unavailable"] == ["m3"]
    assert get(client, "/alerts/A-2041/shap")["ransomware_likelihood"] == 0.94
    assert client.get(f"{V1}/alerts/A-2042").status_code == 504
    assert client.get(f"{V1}/honey-files").status_code == 504


def test_when_both_detection_sources_fail_the_api_reports_the_error(app):
    app.extensions["adapters"]["m2"] = Failing(IntegrationUnavailable("M2 down"))
    app.extensions["adapters"]["m3"] = Failing(IntegrationUnavailable("M3 down"))
    res = app.test_client().get(f"{V1}/alerts")
    assert res.status_code == 503 and res.get_json()["error"]["code"] == "INTEGRATION_UNAVAILABLE"
