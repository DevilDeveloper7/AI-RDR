"""Response workflow (M5 boundary), adapter failures and error handling. All adapters are MOCK or test stubs."""
import pytest

from app import create_app
from app.integrations.base import IntegrationTimeout, IntegrationUnavailable
from app.integrations.m2.mock import MockM2
from app.integrations.m5.mock import MockM5
from stubs import Failing

V1 = "/api/v1"


def state(client, alert_id):
    a = client.get(f"{V1}/alerts/{alert_id}").get_json()
    return a["response_state"], a["verification_state"]


# ---- Detection -> Freeze -> Verify -> Kill/Isolate  OR  Thaw
def test_confirmed_path_freeze_verify_isolate(client):
    assert state(client, "A-2038") == ("Frozen", "Verifying")
    assert client.post(f"{V1}/alerts/A-2038/action", json={"action": "verify"}).status_code == 200
    res = client.post(f"{V1}/alerts/A-2038/action", json={"action": "isolate"}).get_json()
    assert res["alert"]["response_state"] == "Isolated" and res["alert"]["verification_state"] == "Confirmed"


def test_kill_is_a_separate_accepted_action(client):
    res = client.post(f"{V1}/alerts/A-2038/action", json={"action": "kill"})
    assert res.status_code == 200 and res.get_json()["alert"]["response_state"] == "Isolated"  # PROVISIONAL mock semantics


def test_false_positive_path_thaw(client):
    res = client.post(f"{V1}/alerts/A-2038/action", json={"action": "thaw"}).get_json()
    assert res["alert"]["response_state"] == "Thawed" and res["alert"]["verification_state"] == "False positive"


def test_rejected_action_does_not_change_state(client):
    before = state(client, "A-2039")  # already Thawed
    res = client.post(f"{V1}/alerts/A-2039/action", json={"action": "isolate"})
    assert res.status_code == 409 and res.get_json()["error"]["code"] == "ACTION_REJECTED"
    assert state(client, "A-2039") == before


def test_freeze_can_be_requested_again_after_thaw(client):
    res = client.post(f"{V1}/alerts/A-2039/action", json={"action": "freeze"}).get_json()
    assert res["alert"]["response_state"] == "Frozen"


def test_action_is_recorded_in_activity(client):
    client.post(f"{V1}/alerts/A-2038/action", json={"action": "isolate"})
    top = client.get(f"{V1}/response-activity?limit=1").get_json()["items"][0]
    assert top["event"] == "Isolation" and top["alert_id"] == "A-2038" and top["timestamp"].endswith("Z")


def test_timeline_uses_iso_timestamps(client):
    t = client.get(f"{V1}/alerts/A-2041").get_json()["timeline"]
    assert t[0]["timestamp"] == "2026-09-29T09:41:12Z" and t[-1]["pending"] is True and t[-1]["timestamp"] is None


# ---- Invalid requests
@pytest.mark.parametrize("method,path,kwargs,code", [
    ("get", "/alerts/A-1", {}, "ALERT_NOT_FOUND"),
    ("get", "/alerts/xyz", {}, "INVALID_ALERT_ID"),
    ("get", "/alerts/A-2041/shap/extra", {}, "NOT_FOUND"),
    ("post", "/alerts/A-2041/action", {"json": {"action": "format-disk"}}, "INVALID_ACTION"),
    ("post", "/alerts/A-2041/action", {"json": {}}, "INVALID_ACTION"),
    ("post", "/alerts/A-2041/action", {"json": [1, 2]}, "INVALID_BODY"),
    ("post", "/alerts/A-2041/override", {"json": {"reason": "x"}}, "INVALID_REASON"),
    ("get", "/alerts?page_size=0", {}, "INVALID_PARAMETER"),
    ("get", "/alerts?page_size=1000", {}, "INVALID_PARAMETER"),
    ("get", "/threat-intelligence?limit=-1", {}, "INVALID_PARAMETER"),
    ("post", "/integrations/check", {"json": {"module": "m6"}}, "INVALID_MODULE"),
])
def test_invalid_requests_return_clean_json_errors(client, method, path, kwargs, code):
    res = getattr(client, method)(V1 + path, **kwargs)
    body = res.get_json()
    assert 400 <= res.status_code < 500 and body["error"]["code"] == code
    assert "Traceback" not in res.get_data(as_text=True)


def test_empty_alert_list(client):
    body = client.get(f"{V1}/alerts?q=no-such-process-anywhere").get_json()
    assert body["items"] == [] and body["total"] == 0 and body["pages"] == 1 and body["page"] == 1


def test_facets_come_from_the_api(client):
    f = client.get(f"{V1}/alerts?page_size=1").get_json()["facets"]
    assert f["severities"] == ["Critical", "High", "Medium"] and f["response_states"] == ["Frozen", "Isolated", "Thawed"]
    assert "HOST-03" in f["hosts"] and "Honey-File Trigger" in f["detection_types"]


# ---- Adapter failures: unavailable (503), timeout (504), malformed (502)
def test_m2_unavailable(app):
    app.extensions["adapters"]["m2"] = Failing(IntegrationUnavailable("M2 is not reachable."))
    res = app.test_client().get(f"{V1}/alerts/A-2041/shap")
    assert res.status_code == 503 and res.get_json()["error"]["code"] == "INTEGRATION_UNAVAILABLE"


def test_m2_malformed_response(app):
    class BadM2(MockM2):
        def get_shap(self, alert_id):
            return {"model": "x"}
    app.extensions["adapters"]["m2"] = BadM2()
    res = app.test_client().get(f"{V1}/alerts/A-2041/shap")
    assert res.status_code == 502 and res.get_json()["error"]["code"] == "MALFORMED_RESPONSE"


def test_m3_unavailable(app):
    app.extensions["adapters"]["m3"] = Failing(IntegrationUnavailable("M3 is not reachable."))
    assert app.test_client().get(f"{V1}/honey-files").status_code == 503


def test_m4_timeout(app):
    app.extensions["adapters"]["m4"] = Failing(IntegrationTimeout("M4 timed out."))
    res = app.test_client().get(f"{V1}/threat-intelligence")
    assert res.status_code == 504 and res.get_json()["error"]["code"] == "INTEGRATION_TIMEOUT"


def test_m5_unavailable_leaves_alert_unchanged(app):
    c = app.test_client()
    working = app.extensions["adapters"]["m5"]
    app.extensions["adapters"]["m5"] = Failing(IntegrationUnavailable("M5 is not reachable."))
    assert c.post(f"{V1}/alerts/A-2038/action", json={"action": "isolate"}).status_code == 503
    assert c.post(f"{V1}/alerts/A-2038/override", json={"reason": "valid reason"}).status_code == 503
    assert c.get(f"{V1}/alerts").status_code == 503  # response state is unknown without M5
    app.extensions["adapters"]["m5"] = working
    assert state(c, "A-2038") == ("Frozen", "Verifying")


def test_m5_malformed_response(app):
    class BadM5(MockM5):
        def request_action(self, *a, **k):
            return {"unexpected": True}
    app.extensions["adapters"]["m5"] = BadM5()
    res = app.test_client().post(f"{V1}/alerts/A-2038/action", json={"action": "isolate"})
    assert res.status_code == 502 and state(app.test_client(), "A-2038") == ("Frozen", "Verifying")


def test_integration_status_reports_failed_module_instead_of_crashing(app):
    app.extensions["adapters"]["m1"] = Failing(IntegrationUnavailable("M1 is not reachable."))
    rows = {r["module"]: r for r in app.test_client().get(f"{V1}/integrations/status").get_json()["components"]}
    assert rows["M1"]["status"] == "Failed" and rows["M2"]["status"] == "Stubbed"


def test_integration_check_updates_last_check(client):
    before = {r["module"]: r["last_check"] for r in client.get(f"{V1}/integrations/status").get_json()["components"]}
    after = {r["module"]: r["last_check"] for r in client.post(f"{V1}/integrations/check", json={"module": "m2"}).get_json()["components"]}
    assert after["M2"] != before["M2"] and after["M3"] == before["M3"]


def test_real_mode_is_refused_until_implemented(monkeypatch):
    monkeypatch.setenv("M2_MODE", "real")
    with pytest.raises(NotImplementedError):
        create_app()
