"""Real M2 adapter: OpenSearch `m2` field -> M6 detection/SHAP contracts. Uses a local fake OpenSearch over HTTP."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import create_app
from app.integrations import contracts as C
from app.integrations.base import IntegrationTimeout, IntegrationUnavailable, MalformedResponse
from app.integrations.m2.real import RealM2

V1 = "/api/v1"
M2 = {"prediction": "ransomware", "ransomware_probability": 0.73, "threshold": 0.13, "alert": True, "response_mode": "alert_only",
      "model_name": "random_forest", "feature_version": "1.0", "inference_ms": 34.1,
      "explanation": [{"feature": "write_ratio", "value": 0.41, "shap_value": 0.08, "direction": "toward_ransomware"},
                      {"feature": "rename_ratio", "value": 0.2, "shap_value": -0.02, "direction": "toward_benign"}]}


def doc(_id="abc123", ts="2026-11-05T10:00:00.250Z", m2=M2, **extra):
    src = {"@timestamp": ts, "detection_id": _id, "host_id": "HOST-09", "agent_id": "agent-009", "process_id": 4126,
           "process_name": "worker", "m2": m2}
    src.update(extra)
    return {"_id": _id, "_index": "ai-rdr-ml-detections-2026.11.05", "_source": src}


class Fake:
    """Tiny OpenSearch stand-in. `reply` is (status, body-or-callable); requests are recorded."""

    def __init__(self):
        self.reply, self.requests, self.delay = (200, {"hits": {"hits": []}}), [], 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((self.path, body, self.headers.get("Authorization")))
                time.sleep(outer.delay)
                status, payload = outer.reply
                if self.path.endswith("_count") and status == 200:
                    payload = {"count": len(payload["hits"]["hits"])}
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status); self.end_headers(); self.wfile.write(raw)

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def hits(self, *docs):
        self.reply = (200, {"hits": {"hits": list(docs)}})


@pytest.fixture()
def fake():
    f = Fake()
    yield f
    f.server.shutdown()


@pytest.fixture()
def m2(fake):
    return RealM2(fake.url)


def test_detection_maps_m2_fields_without_changing_them(fake, m2):
    fake.hits(doc())
    d = m2.list_detections()[0]
    C.validate_detection(d)
    assert (d["prediction"], d["confidence"]) == ("ransomware", 0.73)
    assert d["m2"] == {"probability": 0.73, "threshold": 0.13, "alert": True, "prediction": "ransomware", "model_name": "random_forest",
                       "feature_version": "1.0", "response_mode": "alert_only", "inference_ms": 34.1,
                       "detection_id": "abc123", "document_id": "abc123", "index": "ai-rdr-ml-detections-2026.11.05"}
    assert d["alert_id"] == "A-abc123" and d["host"] == "HOST-09" and d["process"] == "worker"
    assert d["timestamp"] == "2026-11-05T10:00:00Z" and d["source"] == "m2-opensearch" and m2.kind == "real"


def test_adapter_never_assigns_severity(fake, m2):
    fake.hits(doc(m2={**M2, "severity": "Critical"}))
    assert m2.list_detections()[0]["severity"] is None


def test_query_targets_the_m2_field_in_the_detection_index(fake, m2):
    fake.hits(doc())
    m2.list_detections()
    path, body, _ = fake.requests[0]
    assert path == "/ai-rdr-ml-detections-*/_search"
    assert {"exists": {"field": "m2"}} in body["query"]["bool"]["filter"] and {"term": {"m2.alert": True}} in body["query"]["bool"]["filter"]


def test_shap_preserves_values_and_order(fake, m2):
    fake.hits(doc())
    s = m2.get_shap("A-abc123")
    C.validate_shap(s)
    assert [(f["feature"], f["value"], f["feature_value"], f["direction"]) for f in s["features"]] == [
        ("write_ratio", 0.08, 0.41, "toward_ransomware"), ("rename_ratio", -0.02, 0.2, "toward_benign")]
    assert (s["model"], s["ransomware_likelihood"], s["threshold"], s["feature_version"], s["response_mode"]) == ("random_forest", 0.73, 0.13, "1.0", "alert_only")
    assert m2.get_shap("A-nope") is None


def test_missing_explanation_means_no_shap_but_detection_still_listed(fake, m2):
    fake.hits(doc(m2={k: v for k, v in M2.items() if k != "explanation"}))
    assert len(m2.list_detections()) == 1 and m2.get_shap("A-abc123") is None


def test_empty_result_is_an_empty_list(fake, m2):
    fake.hits()
    assert m2.list_detections() == []


def test_malformed_documents_are_skipped_and_counted(fake, m2):
    bad_prob = doc("bad1", m2={**M2, "ransomware_probability": "high"})
    no_host = {"_id": "bad2", "_source": {"@timestamp": "2026-11-05T10:00:00Z", "detection_id": "bad2", "process_name": "p", "m2": M2}}
    fake.hits(doc("ok1"), bad_prob, no_host, {"_id": "bad3", "_source": {"m2": "x"}})
    assert [d["alert_id"] for d in m2.list_detections()] == ["A-ok1"] and m2.skipped == 3


def test_only_malformed_documents_is_a_controlled_error(fake, m2):
    fake.hits(doc(m2={"prediction": "ransomware"}))
    with pytest.raises(MalformedResponse):
        m2.list_detections()


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"hits": 5}', b"{}"])
def test_bad_opensearch_payloads_are_malformed_responses(fake, m2, payload):
    fake.reply = (200, payload)
    with pytest.raises(MalformedResponse):
        m2.list_detections()


@pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
def test_http_errors_are_unavailable(fake, m2, status):
    fake.reply = (status, {"error": "x"})
    with pytest.raises(IntegrationUnavailable):
        m2.list_detections()


def test_connection_refused_is_unavailable():
    with pytest.raises(IntegrationUnavailable):
        RealM2("http://127.0.0.1:9", {"timeout": "1"}).list_detections()


def test_slow_opensearch_is_a_timeout(fake):
    fake.delay = 1.0
    with pytest.raises(IntegrationTimeout):
        RealM2(fake.url, {"timeout": "0.2"}).list_detections()


def test_host_and_process_fallbacks(fake, m2):
    src = {"@timestamp": "2026-11-05T10:00:00Z", "detection_id": "A-5", "agent_id": "agent-5", "process_id": 99, "m2": M2}
    fake.hits({"_id": "x", "_source": src})
    d = m2.list_detections()[0]
    assert (d["alert_id"], d["host"], d["process"]) == ("A-5", "agent-5", "99")  # host_id/process_name absent -> agent_id/process_id


def test_missing_detection_id_is_skipped_not_invented(fake, m2):
    d = doc("x")
    del d["_source"]["detection_id"]
    fake.hits(d, doc("ok"))
    assert [x["alert_id"] for x in m2.list_detections()] == ["A-ok"]


def test_basic_auth_and_configurable_fields(fake):
    src = {"event_time": 1762336800, "uid": "77", "h": "H1", "p": "x", "m2": M2}
    fake.hits({"_id": "q", "_source": src})
    a = RealM2(fake.url, {"username": "u", "password": "p", "timestamp_field": "event_time", "id_field": "uid", "host_field": "h",
                          "process_field": "p"})
    d = a.list_detections()[0]
    assert (d["alert_id"], d["host"], d["process"], d["timestamp"]) == ("A-77", "H1", "x", "2025-11-05T10:00:00Z")
    assert fake.requests[0][2].startswith("Basic ")


def test_health_connected_warning_and_failed(fake, m2):
    fake.hits(doc())
    assert m2.health()["status"] == "Connected"
    fake.hits()
    assert m2.health()["status"] == "Warning"
    fake.reply = (503, {})
    with pytest.raises(IntegrationUnavailable):
        m2.health()


def test_real_mode_requires_a_url():
    with pytest.raises(ValueError):
        RealM2("")


# ---------------------------------------------------------------- through the M6 API (M2 real, everything else mock)
@pytest.fixture()
def real_client(fake, monkeypatch):
    monkeypatch.setenv("M2_MODE", "real")
    monkeypatch.setenv("M2_BASE_URL", fake.url)
    fake.hits(doc("1001"))
    return create_app({"TESTING": False}).test_client()


def test_api_serves_real_m2_alert_unrated_and_not_assessed(real_client):
    items = {a["id"]: a for a in real_client.get(f"{V1}/alerts?page_size=100").get_json()["items"]}
    a = items["A-1001"]
    assert a["severity"] == "Unrated" and a["source"] == "m2-opensearch" and a["confidence"] == 0.73
    assert a["response_state"] == "Not assessed" and "A-2041" not in items  # no mock M2 detections mixed in
    detail = real_client.get(f"{V1}/alerts/A-1001").get_json()
    assert {"label": "M2 threshold", "value": "0.13"} in detail["evidence"] and detail["m2"]["response_mode"] == "alert_only"


def test_api_shap_and_integration_status_for_real_m2(real_client):
    s = real_client.get(f"{V1}/alerts/A-1001/shap").get_json()
    assert s["features"][0]["value"] == 0.08 and s["severity"] == "Unrated" and s["threshold"] == 0.13
    rows = {r["module"]: r for r in real_client.get(f"{V1}/integrations/status").get_json()["components"]}
    assert rows["M2"]["mode"] == "real" and rows["M2"]["status"] == "Connected"


def test_m2_alert_does_not_authorise_containment(real_client):
    res = real_client.post(f"{V1}/alerts/A-1001/action", json={"action": "kill"})
    assert res.status_code == 409
    assert real_client.get(f"{V1}/alerts/A-1001").get_json()["response_state"] == "Not assessed"


def test_api_reports_opensearch_outage_as_503(real_client, fake):
    fake.reply = (500, {})
    assert real_client.get(f"{V1}/alerts/A-1001/shap").status_code == 503