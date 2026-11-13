"""Real M3 adapter: raw M3 honeyfile events -> M6 trigger contract. Sample events use the real M3 Alert fields."""
import pytest

from app import create_app
from app.integrations import contracts as C
from app.integrations.base import IntegrationTimeout, IntegrationUnavailable, MalformedResponse
from app.integrations.m3.real import RealM3, normalize_event
from app.integrations.m5.mock import MockM5

V1 = "/api/v1"


def ev(op="WRITE", flags=("IN_CLOSE_WRITE",), time="2026-11-12 10:30:00", decoy="d1", path="/lab/documents/report.txt", details=None):
    return {"decoy_id": decoy, "path": path, "operation": op, "event_flags": list(flags), "time": time, "details": {} if details is None else details}


SAMPLES = [
    ev("READ", ["IN_ACCESS"]),
    ev("WRITE"),
    ev("DELETE", ["IN_DELETE"]),
    ev("RENAME", ["IN_MOVED_TO"], details={"from": "/lab/documents/report.txt", "to": "/lab/documents/report.old"}),
    ev("MOVE_OUT", ["IN_MOVED_FROM"], details={"destination": "unobservable (left monitored tree)"}),
    ev("MOVE_IN", ["IN_MOVED_TO"], details={"source": "unobservable"}),
]


@pytest.mark.parametrize("raw", SAMPLES, ids=[s["operation"] for s in SAMPLES])
def test_every_m3_operation_normalises_to_a_valid_trigger(raw):
    t = normalize_event(raw)
    C.validate_trigger(t)
    assert t["alert_id"].startswith("A-M3-") and t["honey_file"] == raw["path"] and t["source"] == "m3-events"
    assert t["m3"]["operation"] == raw["operation"] and t["m3"]["raw"] == raw and t["m3"]["details"] == raw["details"]
    assert t["m3"]["decoy_id"] == "d1" and t["m3"]["file_name"] == raw["path"].split("/")[-1]
    assert "d1" in t["activity"] and raw["operation"] in t["activity"] and "Registered honeyfile" in t["activity"]


def test_no_invented_host_process_severity_or_confidence():
    t = normalize_event(ev())
    assert (t["host"], t["process"], t["severity"], t["high_confidence"]) == ("Unattributed", "Unattributed", None, False)


def test_local_time_gets_no_timezone():
    t = normalize_event(ev(time="2026-11-12 10:30:00"))
    assert t["timestamp"] == "2026-11-12T10:30:00" and not t["timestamp"].endswith("Z")
    assert t["m3"]["timestamp_timezone"] == "not provided by M3" and t["m3"]["time_raw"] == "2026-11-12 10:30:00"


def test_alert_id_is_per_event_not_per_decoy():
    a, b = normalize_event(ev(time="2026-11-12 10:30:00")), normalize_event(ev(time="2026-11-12 10:30:07"))
    assert a["alert_id"] != b["alert_id"] and a["alert_id"] == normalize_event(ev(time="2026-11-12 10:30:00"))["alert_id"]
    assert a["alert_id"] != normalize_event(ev(op="READ", flags=["IN_ACCESS"]))["alert_id"]


def test_details_may_be_text_and_flags_may_be_empty():
    t = normalize_event(ev(details="Honeyfile modified", flags=[]))
    assert t["m3"]["details"] == "Honeyfile modified" and t["event"] == "WRITE"


@pytest.mark.parametrize("bad", [
    None, [], "x", {}, ev(decoy=""), {**ev(), "path": None}, ev(op="EXECUTE"), {**ev(), "event_flags": "IN_MODIFY"},
    {**ev(), "event_flags": [None]}, ev(time="yesterday"), {**ev(), "time": None}, {**ev(), "details": 5}])
def test_malformed_events_are_rejected(bad):
    with pytest.raises((ValueError, TypeError)):
        normalize_event(bad)


def test_adapter_lists_valid_events_newest_first_and_counts_skipped():
    a = RealM3(event_source=lambda: [ev(time="2026-11-12 10:00:00"), {"junk": 1}, ev("DELETE", ["IN_DELETE"], time="2026-11-12 11:00:00")])
    assert [t["m3"]["operation"] for t in a.list_triggers()] == ["DELETE", "WRITE"] and a.skipped == 1 and a.kind == "real"
    assert a.health()["status"] == "Warning"


def test_empty_event_list_is_fine():
    a = RealM3(event_source=lambda: [])
    assert a.list_triggers() == [] and a.health()["status"] == "Connected"


def test_without_an_event_source_m3_is_unavailable_and_never_mock():
    a = RealM3()
    with pytest.raises(IntegrationUnavailable):
        a.list_triggers()
    with pytest.raises(IntegrationUnavailable):
        a.health()


def test_event_source_failures_map_to_controlled_errors():
    def boom(exc):
        def f():
            raise exc
        return f
    with pytest.raises(IntegrationTimeout):
        RealM3(event_source=boom(TimeoutError())).list_triggers()
    with pytest.raises(IntegrationUnavailable):
        RealM3(event_source=boom(ConnectionRefusedError())).list_triggers()
    with pytest.raises(MalformedResponse):
        RealM3(event_source=lambda: {"not": "a list"}).list_triggers()
    with pytest.raises(MalformedResponse):
        RealM3(event_source=lambda: [{"junk": 1}]).list_triggers()


def test_honey_status_page_stays_mock_data():
    d = RealM3().list_honey_files()
    assert d["items"] and d["watcher_status"] == "Unavailable (sample data)" and d["status_source"] == "mock"
    assert "Running" not in d["watcher_status"] and "not live M3" in d["status_note"]
    [C.validate_honey_item(i) for i in d["items"]]


def test_alert_id_depends_on_event_details_but_not_their_key_order():
    base = dict(op="RENAME", flags=["IN_MOVED_TO"])
    a = normalize_event(ev(**base, details={"from": "/x", "to": "/y"}))
    b = normalize_event(ev(**base, details={"to": "/y", "from": "/x"}))  # same details, other key order
    c = normalize_event(ev(**base, details={"from": "/x", "to": "/z"}))  # different rename target
    assert a["alert_id"] == b["alert_id"] and a["alert_id"] != c["alert_id"]
    assert normalize_event(ev(details={}))["alert_id"] == normalize_event({**ev(), "details": None})["alert_id"]
    assert normalize_event(ev(details="a"))["alert_id"] != normalize_event(ev(details="b"))["alert_id"]


def test_alert_id_change_does_not_touch_raw_evidence():
    raw = ev("RENAME", ["IN_MOVED_TO"], details={"to": "/y", "from": "/x"})
    t = normalize_event(raw)
    assert t["m3"]["raw"] == raw and list(t["m3"]["raw"]["details"]) == ["to", "from"] and t["m3"]["details"] == raw["details"]


def test_trigger_with_a_timezone_offset_is_converted_to_utc():
    t = normalize_event(ev(time="2026-11-12T10:30:00+02:00"))
    assert t["timestamp"] == "2026-11-12T08:30:00Z" and "offset" in t["m3"]["timestamp_timezone"]


# ---------------------------------------------------------------- through the M6 API (M3 real, everything else mock)
@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("M3_MODE", "real")
    app = create_app({"TESTING": False})
    app.extensions["adapters"]["m3"].set_event_source(lambda: [ev(), ev("RENAME", ["IN_MOVED_TO"], time="2026-11-12 10:31:00", details={"from": "/a", "to": "/b"})])
    return app.test_client()


def test_api_shows_m3_event_as_unrated_not_assessed_alert(client):
    items = client.get(f"{V1}/alerts?page_size=100&range_minutes=60").get_json()["items"]
    m3 = [a for a in items if a["source"] == "m3-events"]
    assert len(m3) == 2 and all(a["severity"] == "Unrated" and a["response_state"] == "Not assessed" for a in m3)
    assert all(a["host"] == "Unattributed" and a["process"] == "Unattributed" for a in m3)
    assert not any(a["id"] in ("A-2042", "A-2037") for a in items)  # no mock M3 triggers mixed in


def test_api_alert_detail_shows_evidence_and_no_process_claim(client):
    aid = next(a["id"] for a in client.get(f"{V1}/alerts?page_size=100").get_json()["items"] if a["source"] == "m3-events")
    d = client.get(f"{V1}/alerts/{aid}").get_json()
    labels = {r["label"]: r["value"] for r in d["evidence"]}
    assert labels["Decoy ID"] == "d1" and labels["Process"].startswith("Unattributed") and labels["Timezone"] == "not provided by M3"
    assert "does not identify the responsible process" in d["summary"] and d["m3"]["raw"]["decoy_id"] == "d1"
    assert client.get(f"{V1}/alerts/{aid}/shap").status_code == 404  # honeyfile alerts have no SHAP
    ev_res = client.get(f"{V1}/alerts/{aid}/events")
    assert ev_res.status_code == 200 and ev_res.get_json()["items"] == []  # no timezone -> no M1 time correlation


class SpyM5(MockM5):
    def __init__(self):
        super().__init__()
        self.action_calls = 0

    def request_action(self, *a, **k):
        self.action_calls += 1
        return super().request_action(*a, **k)


@pytest.fixture()
def spy_client(monkeypatch):
    monkeypatch.setenv("M3_MODE", "real")
    app = create_app({"TESTING": False})
    app.extensions["adapters"]["m3"].set_event_source(lambda: [ev()])
    spy = SpyM5()
    app.extensions["adapters"]["m5"] = spy
    return app.test_client(), spy


@pytest.mark.parametrize("action", ["freeze", "verify", "kill", "isolate", "thaw"])
def test_m3_alert_actions_are_refused_by_m6_before_m5_is_called(spy_client, action):
    c, spy = spy_client
    aid = next(a["id"] for a in c.get(f"{V1}/alerts?page_size=100").get_json()["items"] if a["source"] == "m3-events")
    res = c.post(f"{V1}/alerts/{aid}/action", json={"action": action})
    assert res.status_code == 409 and res.get_json()["error"]["code"] == "RESPONSE_NOT_ASSESSED"
    assert spy.action_calls == 0  # M5 was never asked
    assert c.get(f"{V1}/alerts/{aid}").get_json()["response_state"] == "Not assessed"


def test_m3_alert_override_is_refused_and_m5_not_called(spy_client):
    c, spy = spy_client
    aid = next(a["id"] for a in c.get(f"{V1}/alerts?page_size=100").get_json()["items"] if a["source"] == "m3-events")
    res = c.post(f"{V1}/alerts/{aid}/override", json={"reason": "valid reason"})
    assert res.status_code == 409 and spy.action_calls == 0


def test_m2_response_workflow_is_unaffected_when_m3_is_real(spy_client):
    c, spy = spy_client
    res = c.post(f"{V1}/alerts/A-2038/action", json={"action": "isolate"})
    assert res.status_code == 200 and res.get_json()["alert"]["response_state"] == "Isolated" and spy.action_calls == 1


def test_api_honey_page_labels_sample_status_and_hides_running_watcher(client):
    body = client.get(f"{V1}/honey-files").get_json()
    assert body["summary"]["watcher_status"] == "Unavailable (sample data)" and body["summary"]["status_source"] == "mock"
    assert body["meta"]["status_source"] == "mock" and "not live M3" in body["meta"]["status_note"]


def test_api_without_transport_reports_m3_down_but_keeps_other_alerts(monkeypatch):
    monkeypatch.setenv("M3_MODE", "real")
    c = create_app({"TESTING": False}).test_client()
    body = c.get(f"{V1}/alerts?page_size=100").get_json()
    assert "m3" in body["meta"]["unavailable"] and body["total"] > 0 and not any(a["source"] == "m3-events" for a in body["items"])
    rows = {r["module"]: r for r in c.get(f"{V1}/integrations/status").get_json()["components"]}
    assert rows["M3"]["mode"] == "real" and rows["M3"]["status"] == "Failed"
    assert c.get(f"{V1}/honey-files").status_code == 200  # status page stays on mock data