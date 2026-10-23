"""API tests for the M6 endpoints. All data is MOCK data; state resets with each app."""
V1 = "/api/v1"


def test_alert_list_shape_and_paging(client):
    body = client.get(f"{V1}/alerts?page_size=5").get_json()
    assert len(body["items"]) == 5 and body["total"] == 80 and body["pages"] == 16
    assert body["items"][0]["id"] == "A-2042"
    assert body["summary"] == {"active": 3, "critical": 2, "open": 3, "total": 80}
    assert body["meta"]["is_mock"] is True


def test_alert_list_filters(client):
    body = client.get(f"{V1}/alerts?severity=Critical&detection_type=Honey-File Trigger").get_json()
    assert body["items"][0]["id"] == "A-2042" and body["total"] == 4  # older pages repeat the pattern
    ids = [a["id"] for a in client.get(f"{V1}/alerts?host=HOST-03&q=enc_worker").get_json()["items"]]
    assert ids[:2] == ["A-2042", "A-2041"]
    assert client.get(f"{V1}/alerts?range_minutes=60").get_json()["total"] == 5


def test_alert_list_rejects_bad_filter(client):
    res = client.get(f"{V1}/alerts?severity=Banana")
    assert res.status_code == 400 and res.get_json()["error"]["code"] == "INVALID_PARAMETER"
    assert client.get(f"{V1}/alerts?page=abc").status_code == 400


def test_alert_detail(client):
    body = client.get(f"{V1}/alerts/A-2041").get_json()
    assert body["host"] == "HOST-03" and body["timeline"] and body["evidence"]


def test_invalid_and_unknown_alert_id(client):
    assert client.get(f"{V1}/alerts/not-an-id").get_json()["error"]["code"] == "INVALID_ALERT_ID"
    assert client.get(f"{V1}/alerts/A-9999").status_code == 404


def test_shap_for_ml_alert(client):
    body = client.get(f"{V1}/alerts/A-2041/shap").get_json()
    assert body["ransomware_likelihood"] == 0.94 and body["features"][0]["feature"] == "write_rate"


def test_shap_missing_or_not_applicable(client):
    assert client.get(f"{V1}/alerts/A-2042/shap").get_json()["error"]["code"] == "SHAP_NOT_APPLICABLE"
    assert client.get(f"{V1}/alerts/A-2040/shap").get_json()["error"]["code"] == "SHAP_NOT_AVAILABLE"


def test_acknowledge(client):
    res = client.post(f"{V1}/alerts/A-2041/acknowledge")
    assert res.status_code == 200 and res.get_json()["alert"]["status"] == "Acknowledged"
    assert client.get(f"{V1}/alerts?page_size=1").get_json()["summary"]["open"] == 2
    assert client.get(f"{V1}/response-activity?limit=1").get_json()["items"][0]["event"] == "Analyst acknowledgement"


def test_override_requires_reason_and_frozen_state(client):
    assert client.post(f"{V1}/alerts/A-2041/override", json={}).get_json()["error"]["code"] == "INVALID_REASON"
    assert client.post(f"{V1}/alerts/A-2039/override", json={"reason": "already thawed"}).status_code == 409
    res = client.post(f"{V1}/alerts/A-2041/override", json={"reason": "Scheduled backup job"})
    alert = res.get_json()["alert"]
    assert alert["response_state"] == "Thawed" and alert["verification_state"] == "Analyst override"
    assert alert["status"] == "Acknowledged"


def test_response_action_goes_through_m5_adapter(client):
    res = client.post(f"{V1}/alerts/A-2041/action", json={"action": "isolate"})
    body = res.get_json()
    assert res.status_code == 200 and body["alert"]["response_state"] == "Isolated"
    assert body["executor"].startswith("M5")
    assert client.post(f"{V1}/alerts/A-2041/action", json={"action": "thaw"}).status_code == 409


def test_invalid_action(client):
    res = client.post(f"{V1}/alerts/A-2041/action", json={"action": "delete-everything"})
    assert res.status_code == 400 and res.get_json()["error"]["code"] == "INVALID_ACTION"
    assert client.post(f"{V1}/alerts/A-2041/action", data="not json").status_code == 400


def test_honey_files(client):
    body = client.get(f"{V1}/honey-files").get_json()
    assert body["summary"]["triggered"] == 2 and body["summary"]["triggered_hosts"] == ["HOST-02", "HOST-03"]
    assert len(body["items"]) == 6


def test_threat_intelligence(client):
    items = client.get(f"{V1}/threat-intelligence?limit=4").get_json()["items"]
    assert len(items) == 4
    one = client.get(f"{V1}/threat-intelligence/185.220.101.47").get_json()
    assert one["reputation"] == "Suspicious" and one["related_alert"] == "A-2041"
    assert client.get(f"{V1}/threat-intelligence/8.8.8.8").status_code == 404
    assert client.get(f"{V1}/threat-intelligence/bad%20value").status_code == 400


def test_integration_status_and_check(client):
    rows = {r["module"]: r for r in client.get(f"{V1}/integrations/status").get_json()["components"]}
    assert all(rows[m]["status"] == "Stubbed" and rows[m]["provisional"] for m in ("M1", "M2", "M3", "M4", "M5"))
    assert rows["M6"]["status"] == "Connected"
    assert client.post(f"{V1}/integrations/check", json={"module": "m2"}).status_code == 200
    assert client.post(f"{V1}/integrations/check", json={"module": "m9"}).status_code == 400
