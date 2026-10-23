"""Required fields of the M6 API responses (the structure the React pages rely on)."""
V1 = "/api/v1"
LIST_FIELDS = {"id", "severity", "detection_type", "host", "process", "activity", "timestamp",
               "response_state", "verification_state", "status", "source", "confidence"}


def body(client, path):
    res = client.get(V1 + path)
    assert res.status_code == 200 and res.mimetype == "application/json", path
    return res.get_json()


def test_alert_list_structure(client):
    b = body(client, "/alerts?page_size=3")
    assert {"items", "total", "page", "page_size", "pages", "summary", "facets", "meta"} <= set(b)
    assert {"active", "critical", "open", "total"} == set(b["summary"])
    assert {"hosts", "severities", "detection_types", "response_states"} == set(b["facets"])
    assert all(LIST_FIELDS <= set(a) for a in b["items"])
    assert all(a["severity"] in ("Critical", "High", "Medium") and a["response_state"] in ("Frozen", "Isolated", "Thawed") for a in b["items"])
    assert all(a["status"] in ("Open", "Acknowledged") and a["timestamp"].endswith("Z") for a in b["items"])


def test_alert_detail_structure(client):
    for alert_id in ("A-2041", "A-2042"):
        a = body(client, f"/alerts/{alert_id}")
        assert LIST_FIELDS | {"summary", "evidence", "timeline", "indicators", "evidence_status", "enrichment_status"} <= set(a)
        assert all({"label", "value"} == set(e) for e in a["evidence"])
        assert all({"timestamp", "event", "pending", "hot"} == set(t) for t in a["timeline"])


def test_shap_structure(client):
    s = body(client, "/alerts/A-2041/shap")
    assert {"alert_id", "severity", "host", "model", "ransomware_likelihood", "explained_at", "summary", "features"} <= set(s)
    assert all({"feature", "value"} == set(f) for f in s["features"])


def test_honey_file_structure(client):
    h = body(client, "/honey-files")
    assert {"watcher_status", "total_files", "monitored_hosts", "total_hosts", "healthy", "triggered", "triggered_hosts", "last_interaction"} <= set(h["summary"])
    assert all({"host", "file", "location", "status", "last_event", "alert_id"} <= set(i) for i in h["items"])
    assert all({"timestamp", "text", "hot"} == set(a) for a in h["activity"])


def test_threat_intelligence_structure(client):
    items = body(client, "/threat-intelligence")["items"]
    assert items and all({"indicator", "type", "reputation", "source", "related_alert", "last_checked", "notes", "enrichment_status"} <= set(i) for i in items)
    assert {i["reputation"] for i in items} <= {"Malicious", "Suspicious", "Clean", "Unknown"}


def test_integration_status_structure(client):
    b = body(client, "/integrations/status")
    assert [c["module"] for c in b["components"]] == ["M1", "M2", "M3", "M4", "M5", "M6"]
    assert all({"module", "name", "interface", "endpoint", "status", "last_check", "mode", "provisional"} <= set(c) for c in b["components"])
    assert all({"path", "contract", "result", "timestamp"} == set(t) for t in b["recent_tests"])


def test_response_activity_structure(client):
    items = body(client, "/response-activity?limit=3")["items"]
    assert len(items) == 3 and all({"timestamp", "event", "detail", "alert_id"} == set(i) for i in items)


def test_every_error_is_json_with_code_and_message(client):
    for method, path in (("get", "/alerts/A-9999"), ("get", "/alerts/bad"), ("get", "/nothing-here"), ("post", "/health"), ("get", "/alerts?severity=x")):
        res = getattr(client, method)(V1 + path)
        err = res.get_json()["error"]
        assert res.status_code >= 400 and set(err) == {"code", "message"} and "Traceback" not in res.get_data(as_text=True)
