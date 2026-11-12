"""M1-M5 adapter contract tests and cross-module consistency of the MOCK data. Everything here is mock."""
import pytest

from app.config import Config
from app.integrations import contracts as C
from app.integrations.base import ActionRejected, IntegrationUnavailable, MalformedResponse
from app.integrations.registry import build_adapters
from stubs import Failing

V1 = "/api/v1"


@pytest.fixture()
def ad(app):
    return app.extensions["adapters"]


# ---------------------------------------------------------------- registry
def test_registry_builds_a_mock_adapter_for_every_module(ad):
    assert set(ad) == {"m1", "m2", "m3", "m4", "m5"}
    for module, adapter in ad.items():
        assert adapter.kind == "mock" and adapter.module == module
        assert adapter.health()["status"] == "Stubbed"


def test_registry_refuses_real_mode_until_a_real_adapter_exists():
    cfg = Config().INTEGRATIONS
    cfg["m1"] = {"mode": "real", "base_url": ""}   # M4 has a real adapter; M1 does not yet
    with pytest.raises(NotImplementedError):
        build_adapters(cfg)


# ---------------------------------------------------------------- M1
def test_m1_events_follow_the_contract_and_are_ordered(ad):
    events = ad["m1"].list_events(limit=1000)
    assert len(events) > 200
    for e in events:
        C.validate_event(e)
    assert [e["timestamp"] for e in events] == sorted(e["timestamp"] for e in events)


def test_m1_filters_by_host_and_time_window(ad):
    got = ad["m1"].list_events(host="HOST-03", since="2026-09-29T09:41:00Z", until="2026-09-29T09:41:30Z")
    assert got and all(e["host"] == "HOST-03" for e in got)
    assert {e["source"] for e in got} >= {"irdp", "auditd", "wazuh-fim"}
    assert ad["m1"].list_events(host="HOST-03", limit=2).__len__() == 2
    assert ad["m1"].get_event(got[0]["event_id"])["event_id"] == got[0]["event_id"]
    assert ad["m1"].get_event("EVT-nope") is None


def test_alert_events_endpoint_goes_through_m1(client):
    body = client.get(f"{V1}/alerts/A-2041/events").get_json()
    assert {e["host"] for e in body["items"]} == {"HOST-03"} and len(body["items"]) >= 3
    assert client.get(f"{V1}/alerts/A-9999/events").status_code == 404


# ---------------------------------------------------------------- M2
def test_m2_detections_and_shap_follow_the_contract(ad):
    dets = ad["m2"].list_detections()
    assert len(dets) == 72
    for d in dets:
        C.validate_detection(d)
    shap = ad["m2"].get_shap("A-2041")
    C.validate_shap(shap)
    assert ad["m2"].get_shap("A-9999") is None


# ---------------------------------------------------------------- M3 (independent path)
def test_m3_triggers_follow_the_contract_and_are_not_m2_detections(ad):
    trig = ad["m3"].list_triggers()
    assert len(trig) == 8 and {"A-2042", "A-2037"} <= {t["alert_id"] for t in trig}
    ml_ids = {d["alert_id"] for d in ad["m2"].list_detections()}
    for t in trig:
        C.validate_trigger(t)
        assert t["high_confidence"] is True and t["alert_id"] not in ml_ids
    for item in ad["m3"].list_honey_files()["items"]:
        C.validate_honey_item(item)


def test_honey_alert_is_built_without_m2(app):
    """If M2 is down, honey-file alerts cannot be listed together with ML ones, but the M3 trigger itself is untouched."""
    app.extensions["adapters"]["m2"] = Failing(IntegrationUnavailable("M2 down"))
    assert app.test_client().get(f"{V1}/honey-files").status_code == 200  # M3 screen does not depend on M2


# ---------------------------------------------------------------- M4
def test_m4_indicators_follow_the_contract(ad):
    items = ad["m4"].list_indicators()
    assert len(items) == 6
    for i in items:
        C.validate_indicator(i)
    assert {i["enrichment_status"] for i in items} == {"enriched", "no_data"}
    assert ad["m4"].enrich("185.220.101.47")["reputation"] == "Suspicious"
    assert ad["m4"].enrich("example.invalid") is None


# ---------------------------------------------------------------- M5
def test_m5_cases_audit_and_workflow(ad):
    m5 = ad["m5"]
    for c in m5.list_cases():
        C.validate_case(c)
    for a in m5.list_audit():
        C.validate_audit(a)
    target = {"host": "HOST-05", "process": "tar (PID 22014)"}
    r = C.validate_action_result(m5.request_action("A-2038", "verify", target, "A. Khan"))
    assert (r["response_state"], r["verification_state"]) == ("Frozen", "Verifying")
    r = m5.request_action("A-2038", "kill", target, "A. Khan")
    assert r["response_state"] == "Isolated" and m5.get_case("A-2038")["history"][-1]["event"] == "Process killed"
    assert m5.list_audit(1)[0]["event"] == "Kill" and m5.list_audit(1)[0]["detail"] == "HOST-05 · PID 22014"


def test_m5_kill_and_isolate_are_recorded_as_different_actions(ad):
    m5, t = ad["m5"], {"host": "HOST-05", "process": "tar (PID 22014)"}
    m5.request_action("A-2038", "isolate", t, "A. Khan")
    assert m5.get_case("A-2038")["history"][-1]["event"] == "Isolation initiated"


def test_m5_rejects_invalid_transitions_and_unknown_actions(ad):
    t = {"host": "HOST-01", "process": "rsync (PID 1893)"}
    with pytest.raises(ActionRejected):
        ad["m5"].request_action("A-2039", "isolate", t, "A. Khan")  # already thawed
    with pytest.raises(ActionRejected):
        ad["m5"].request_action("A-2038", "format-disk", {"host": "HOST-05", "process": ""}, "A. Khan")
    with pytest.raises(ActionRejected):
        ad["m5"].request_action("A-0000", "freeze", t, "A. Khan")


def test_m5_override_is_marked_in_state_and_audit(ad):
    r = ad["m5"].request_action("A-2038", "thaw", {"host": "HOST-05", "process": "tar (PID 22014)"}, "A. Khan", "Backup job", analyst_override=True)
    assert r["verification_state"] == "Analyst override"
    assert ad["m5"].list_audit(1)[0]["event"] == "Analyst override → Thaw"


# ---------------------------------------------------------------- contracts reject bad payloads
@pytest.mark.parametrize("validator,payload", [
    (C.validate_event, {"event_id": "E1"}),
    (C.validate_detection, {"alert_id": "A-1", "severity": "Severe", "host": "h", "process": "p", "activity": "a", "timestamp": "t", "threshold_exceeded_at": "t", "prediction": "x", "confidence": 1}),
    (C.validate_trigger, {"alert_id": "A-1"}),
    (C.validate_indicator, {"indicator": "x"}),
    (C.validate_case, {"alert_id": "A-1", "response_state": "Exploded", "verification_state": "x", "history": []}),
    (C.validate_action_result, "not a dict"),
    (C.validate_shap, {"model": "m", "ransomware_likelihood": 0.5, "explained_at": "t", "summary": "s", "features": [{"feature": "f"}]}),
])
def test_contracts_reject_malformed_payloads(validator, payload):
    with pytest.raises(MalformedResponse):
        validator(payload)


# ---------------------------------------------------------------- the mock data tells one consistent story
def test_mock_data_is_consistent_across_modules(ad):
    det = {d["alert_id"]: d for d in ad["m2"].list_detections()}
    trig = {t["alert_id"]: t for t in ad["m3"].list_triggers()}
    cases = {c["alert_id"] for c in ad["m5"].list_cases()}
    assert not set(det) & set(trig) and cases == set(det) | set(trig)
    for ind in ad["m4"].list_indicators():
        assert ind["related_alert"] in cases
    for item in ad["m3"].list_honey_files()["items"]:
        if item["status"] == "Triggered":
            assert item["alert_id"] in trig and trig[item["alert_id"]]["host"] == item["host"]
    for alert_id, d in det.items():
        behavioural = [e for e in ad["m1"].list_events(host=d["host"], since=d["timestamp"][:17] + "00Z", limit=1000) if d["process"] == e["details"].get("process")]
        assert behavioural, f"no M1 events for {alert_id}"
    for alert_id in ("A-2041", "A-2039", "A-2038"):
        assert ad["m2"].get_shap(alert_id)["ransomware_likelihood"] == det[alert_id]["confidence"]


# ---------------------------------------------------------------- service <-> adapter communication
def test_response_state_comes_from_m5_not_from_m6(app):
    class FixedM5(type(app.extensions["adapters"]["m5"])):
        calls = []

        def request_action(self, alert_id, action, target, actor, reason=None, analyst_override=False):
            FixedM5.calls.append((alert_id, action, target, actor, analyst_override))
            return super().request_action(alert_id, action, target, actor, reason, analyst_override)

    app.extensions["adapters"]["m5"] = FixedM5()
    c = app.test_client()
    c.post(f"{V1}/alerts/A-2038/override", json={"reason": "Backup job verified"})
    assert FixedM5.calls == [("A-2038", "thaw", {"host": "HOST-05", "process": "tar (PID 22014)"}, app.config["ANALYST_NAME"], True)]
    assert c.get(f"{V1}/alerts/A-2038").get_json()["response_state"] == "Thawed"


def test_threat_intel_failure_does_not_break_the_alert_page(app):
    app.extensions["adapters"]["m4"] = Failing(IntegrationUnavailable("M4 down"))
    body = app.test_client().get(f"{V1}/alerts/A-2041").get_json()
    assert body["indicators"] == [] and body["enrichment_status"] == "unavailable"


def test_telemetry_failure_does_not_break_the_alert_page(app):
    app.extensions["adapters"]["m1"] = Failing(IntegrationUnavailable("M1 down"))
    c = app.test_client()
    body = c.get(f"{V1}/alerts/A-2041").get_json()
    assert body["evidence"] == [] and body["evidence_status"] == "unavailable" and body["timeline"]
    assert c.get(f"{V1}/alerts/A-2041/events").status_code == 503


def test_integration_status_reports_mock_mode(client):
    rows = {r["module"]: r for r in client.get(f"{V1}/integrations/status").get_json()["components"]}
    for m in ("M1", "M2", "M3", "M4", "M5"):
        assert rows[m]["mode"] == "mock" and rows[m]["status"] == "Stubbed" and rows[m]["provisional"] is True


# ---------------------------------------------------------------- services call the right adapter methods
def test_services_call_the_expected_adapter_methods(app):
    class Recorder:
        def __init__(self, inner):
            self._inner, self.calls = inner, []

        def __getattr__(self, name):
            fn = getattr(self._inner, name)
            if not callable(fn) or name in ("health",):
                return fn

            def call(*args, **kwargs):
                self.calls.append((name, args, kwargs))
                return fn(*args, **kwargs)
            return call

    rec = {m: Recorder(a) for m, a in app.extensions["adapters"].items()}
    app.extensions["adapters"].update(rec)
    c = app.test_client()
    c.get(f"{V1}/alerts/A-2041")
    c.get(f"{V1}/alerts/A-2041/shap")
    c.get(f"{V1}/honey-files")
    c.get(f"{V1}/threat-intelligence/185.220.101.47")
    c.post(f"{V1}/alerts/A-2041/action", json={"action": "verify"})

    names = lambda m: [n for n, _, _ in rec[m].calls]
    assert "list_events" in names("m1") and rec["m1"].calls[0][2]["host"] == "HOST-03"
    assert ("get_shap", ("A-2041",), {}) in rec["m2"].calls
    assert "list_honey_files" in names("m3")
    assert ("enrich", ("185.220.101.47",), {}) in rec["m4"].calls
    request = next(call for call in rec["m5"].calls if call[0] == "request_action")
    assert request[1][:3] == ("A-2041", "verify", {"host": "HOST-03", "process": "enc_worker.py (PID 4127)"})


def test_m5_supports_every_response_action(ad):
    m5, t = ad["m5"], {"host": "HOST-05", "process": "tar (PID 22014)"}
    assert m5.request_action("A-2039", "freeze", {"host": "HOST-01", "process": "rsync (PID 1893)"}, "A. Khan")["response_state"] == "Frozen"
    assert m5.request_action("A-2039", "verify", {"host": "HOST-01", "process": "rsync (PID 1893)"}, "A. Khan")["verification_state"] == "Verifying"
    assert m5.request_action("A-2039", "thaw", {"host": "HOST-01", "process": "rsync (PID 1893)"}, "A. Khan")["response_state"] == "Thawed"
    assert m5.request_action("A-2038", "kill", t, "A. Khan")["response_state"] == "Isolated"
    assert m5.request_action("A-2041", "isolate", {"host": "HOST-03", "process": "enc_worker.py (PID 4127)"}, "A. Khan")["response_state"] == "Isolated"
    assert [h["event"] for h in m5.get_case("A-2039")["history"]][-3:] == ["Process frozen", "Verification started", "Process thawed"]


def test_integration_status_recovers_after_a_module_comes_back(app):
    c = app.test_client()
    original = app.extensions["adapters"]["m1"]
    app.extensions["adapters"]["m1"] = Failing(IntegrationUnavailable("M1 down"))
    rows = {r["module"]: r["status"] for r in c.post(f"{V1}/integrations/check", json={"module": "m1"}).get_json()["components"]}
    assert rows["M1"] == "Failed"
    app.extensions["adapters"]["m1"] = original
    rows = {r["module"]: r["status"] for r in c.post(f"{V1}/integrations/check", json={"module": "m1"}).get_json()["components"]}
    assert rows["M1"] == "Stubbed"
