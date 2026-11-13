"""Real M4 adapter. FAKE-HTTP tests: a local stand-in for M4 that speaks M4's documented endpoints
(GET /health, GET /indicators, POST /enrich/m6). Live tests against the real M4 are in test_m4_live.py."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import create_app
from app.integrations.base import IntegrationTimeout, IntegrationUnavailable, MalformedResponse
from app.integrations.m4.real import DEFAULT_URL, RealM4

V1 = "/api/v1"
SHA = "9f2cc3d6f7864d23c4d75cb404558a81d69369e303cbe12c4fbdf337e41a2b7c"


def ind(value="203.0.113.9", rep="Malicious", alert="A-2041", status="enriched", typ="IP address"):
    return {"indicator": value, "type": typ, "reputation": rep, "source": "abuse.ch ThreatFox", "related_alert": alert,
            "last_checked": "2026-11-12T10:00:00+00:00", "notes": "Context only; the detection decision is made by M2/M3.", "enrichment_status": status}


class FakeM4:
    """routes: (METHOD, path-without-query) -> (status, body | bytes). Requests are recorded."""

    def __init__(self):
        self.routes, self.requests, self.delay = {}, [], 0
        self.live(True)
        outer = self

        class H(BaseHTTPRequestHandler):
            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                outer.requests.append((self.command, self.path, body))
                time.sleep(outer.delay)
                status, payload = outer.routes.get((self.command, self.path.split("?")[0]), (404, {"error": "no route"}))
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status); self.end_headers(); self.wfile.write(raw)

            do_GET = do_POST = _serve

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def live(self, keys=True, mode="live"):
        self.routes[("GET", "/health")] = (200, {"status": "ok", "mode": mode, "abusech_key": "set" if keys else "missing", "otx_key": "set" if keys else "missing"})

    def indicators(self, items, is_mock=False):
        self.routes[("GET", "/indicators")] = (200, {"items": items, "meta": {"is_mock": is_mock, "role": "enrichment only"}})


@pytest.fixture()
def fake():
    f = FakeM4()
    yield f
    f.server.shutdown()


@pytest.fixture()
def m4(fake):
    return RealM4(fake.url)


# ---------------------------------------------------------------- health
def test_health_connected_only_when_live_with_both_keys(fake, m4):
    assert m4.health()["status"] == "Connected" and m4.kind == "real"


def test_health_warns_for_mock_mode_and_missing_keys(fake, m4):
    fake.live(keys=True, mode="MOCK")
    h = m4.health()
    assert h["status"] == "Warning" and "MOCK" in h["detail"]
    fake.live(keys=False)
    assert m4.health()["status"] == "Warning" and "key" in m4.health()["detail"]


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"status": "down"}', b'{"status": "ok", "mode": "weird"}'])
def test_health_bad_payload_is_malformed(fake, m4, payload):
    fake.routes[("GET", "/health")] = (200, payload)
    with pytest.raises(MalformedResponse):
        m4.health()


def test_unreachable_m4_is_unavailable():
    with pytest.raises(IntegrationUnavailable):
        RealM4("http://127.0.0.1:9", timeout=1).health()


def test_slow_m4_is_a_timeout(fake):
    fake.delay = 1.0
    with pytest.raises(IntegrationTimeout):
        RealM4(fake.url, timeout=0.2).health()


@pytest.mark.parametrize("status", [500, 502, 503])
def test_server_errors_are_unavailable(fake, m4, status):
    fake.routes[("GET", "/indicators")] = (status, {"error": "x"})
    with pytest.raises(IntegrationUnavailable):
        m4.list_indicators()


# ---------------------------------------------------------------- list_indicators
def test_list_returns_m4_indicators_unchanged_and_asks_for_100(fake, m4):
    items = [ind(), ind(SHA, "Suspicious", typ="SHA-256", status="no_data")]
    fake.indicators(items)
    assert m4.list_indicators() == items
    assert ("GET", "/indicators?limit=100", None) in fake.requests


def test_list_remembers_whether_m4_says_its_data_is_mock(fake, m4):
    fake.indicators([ind()], is_mock=True)
    m4.list_indicators()
    assert m4.last_is_mock is True
    fake.indicators([ind()], is_mock=False)
    m4.list_indicators()
    assert m4.last_is_mock is False


def test_empty_list_is_fine(fake, m4):
    fake.indicators([])
    assert m4.list_indicators() == []


@pytest.mark.parametrize("body", [[], {"items": "x", "meta": {}}, {"items": []}, {"meta": {}}, {"items": [], "meta": []}])
def test_list_with_wrong_shape_is_malformed(fake, m4, body):
    fake.routes[("GET", "/indicators")] = (200, body)
    with pytest.raises(MalformedResponse):
        m4.list_indicators()


def test_invalid_items_are_skipped_and_counted_but_all_invalid_is_an_error(fake, m4):
    fake.indicators([ind(), {"indicator": "x"}, "junk"])
    assert len(m4.list_indicators()) == 1 and m4.skipped == 2
    fake.indicators([{"indicator": "x"}])
    with pytest.raises(MalformedResponse):
        m4.list_indicators()


# ---------------------------------------------------------------- enrich
@pytest.mark.parametrize("value,typ", [(SHA, "hash"), ("d" * 32, "hash"), ("d" * 40, "hash"), ("203.0.113.9", "ip"),
                                       ("2001:db8::1", "ip"), ("evil.example.org", "domain")])
def test_enrich_sends_the_right_type_and_a_lookup_alert_id(fake, m4, value, typ):
    fake.routes[("POST", "/enrich/m6")] = (200, ind(value))
    assert m4.enrich(value)["indicator"] == value
    assert fake.requests[-1] == ("POST", "/enrich/m6", {"alert_id": "m6-lookup", "type": typ, "value": value})


@pytest.mark.parametrize("status", [400, 422])
def test_enrich_returns_none_when_m4_refuses_the_indicator(fake, m4, status):
    fake.routes[("POST", "/enrich/m6")] = (status, {"error": "bad"})
    assert m4.enrich("not an indicator!") is None


def test_enrich_blank_makes_no_request(fake, m4):
    assert m4.enrich("  ") is None and fake.requests == []


def test_enrich_malformed_answer(fake, m4):
    fake.routes[("POST", "/enrich/m6")] = (200, {"indicator": "x"})
    with pytest.raises(MalformedResponse):
        m4.enrich("203.0.113.9")
    fake.routes[("POST", "/enrich/m6")] = (500, {})
    with pytest.raises(IntegrationUnavailable):
        m4.enrich("203.0.113.9")


def test_enrich_failed_lookup_is_shown_as_unavailable_not_clean(fake, m4):
    fake.routes[("POST", "/enrich/m6")] = (200, ind("203.0.113.9", "Unknown", None, "unavailable"))
    r = m4.enrich("203.0.113.9")
    assert r["reputation"] == "Unknown" and r["enrichment_status"] == "unavailable"


# ---------------------------------------------------------------- configuration and role
def test_defaults_and_bad_timeout():
    assert RealM4()._base == DEFAULT_URL == "http://127.0.0.1:5004"
    with pytest.raises(ValueError):
        RealM4("http://x", timeout="abc")


def test_m4_adapter_has_no_response_or_containment_capability():
    assert not any(hasattr(RealM4, n) for n in ("request_action", "freeze", "isolate", "kill", "thaw"))


# ---------------------------------------------------------------- through the M6 API (M4 real, everything else mock)
@pytest.fixture()
def api(fake, monkeypatch):
    monkeypatch.setenv("M4_MODE", "real")
    monkeypatch.setenv("M4_BASE_URL", fake.url)
    fake.indicators([ind("203.0.113.9", "Malicious", "A-2041"), ind("evil.example.org", "Suspicious", "A-2041", typ="Domain")], is_mock=False)
    fake.routes[("POST", "/enrich/m6")] = (200, ind("203.0.113.9"))
    return create_app({"TESTING": False}).test_client()


def test_api_threat_intel_list_is_live_and_not_flagged_mock(api):
    body = api.get(f"{V1}/threat-intelligence").get_json()
    assert [i["indicator"] for i in body["items"]] == ["203.0.113.9", "evil.example.org"]
    assert body["meta"] == {"is_mock": False, "role": "enrichment only"}


def test_api_flags_data_as_mock_when_m4_itself_runs_mock_providers(api, fake):
    fake.indicators([ind()], is_mock=True)
    assert api.get(f"{V1}/threat-intelligence").get_json()["meta"]["is_mock"] is True


def test_api_limit_still_applies(api):
    assert len(api.get(f"{V1}/threat-intelligence?limit=1").get_json()["items"]) == 1


def test_api_single_indicator_and_not_found(api, fake):
    assert api.get(f"{V1}/threat-intelligence/203.0.113.9").get_json()["reputation"] == "Malicious"
    fake.routes[("POST", "/enrich/m6")] = (400, {"error": "bad"})
    assert api.get(f"{V1}/threat-intelligence/nothing.here").status_code == 404


def test_api_alert_detail_lists_related_m4_indicators(api):
    d = api.get(f"{V1}/alerts/A-2041").get_json()
    assert d["indicators"] == ["203.0.113.9", "evil.example.org"] and d["enrichment_status"] == "ok"


def test_api_alert_page_still_loads_when_m4_is_down(api, fake):
    fake.routes[("GET", "/indicators")] = (500, {})
    res = api.get(f"{V1}/alerts/A-2041")
    assert res.status_code == 200 and res.get_json()["indicators"] == [] and res.get_json()["enrichment_status"] == "unavailable"
    assert api.get(f"{V1}/threat-intelligence").status_code == 503


def test_api_integration_status_reports_m4_live_warning_and_failed(api, fake):
    row = lambda: {r["module"]: r for r in api.get(f"{V1}/integrations/status").get_json()["components"]}["M4"]
    assert row()["mode"] == "real" and row()["status"] == "Connected"
    fake.live(keys=True, mode="MOCK")
    api.post(f"{V1}/integrations/check", json={"module": "m4"})
    assert row()["status"] == "Warning" and "MOCK" in row()["detail"]
    fake.routes[("GET", "/health")] = (500, {})
    api.post(f"{V1}/integrations/check", json={"module": "m4"})
    assert row()["status"] == "Failed"


def test_malicious_threat_intel_cannot_trigger_containment(api):
    """A malicious M4 reputation for A-2038's indicator changes nothing: response state belongs to M5."""
    before = api.get(f"{V1}/alerts/A-2038").get_json()
    api.get(f"{V1}/threat-intelligence")
    after = api.get(f"{V1}/alerts/A-2038").get_json()
    assert (before["response_state"], before["verification_state"]) == (after["response_state"], after["verification_state"]) == ("Frozen", "Verifying")


def test_default_mode_is_still_mock(monkeypatch):
    monkeypatch.delenv("M4_MODE", raising=False)
    app = create_app({"TESTING": False})
    assert app.extensions["adapters"]["m4"].kind == "mock"
    assert app.test_client().get(f"{V1}/threat-intelligence").get_json()["meta"]["is_mock"] is True


# ---------------------------------------------------------------- registry
def test_registry_builds_real_m4_only_when_asked_and_leaves_other_modules_alone():
    from app.config import Config
    from app.integrations.registry import build_adapters
    cfg = Config().INTEGRATIONS
    cfg["m4"] = {"mode": "real", "base_url": "http://127.0.0.1:5004"}
    ad = build_adapters(cfg)
    assert ad["m4"].kind == "real" and isinstance(ad["m4"], RealM4)
    assert all(ad[m].kind == "mock" for m in ("m1", "m2", "m3", "m5"))  # nothing else switched by M4


def test_registry_default_m4_is_mock_and_m5_real_is_still_refused():
    from app.config import Config
    from app.integrations.registry import build_adapters
    assert build_adapters(Config().INTEGRATIONS)["m4"].kind == "mock"
    cfg = Config().INTEGRATIONS
    cfg["m5"] = {"mode": "real", "base_url": ""}
    with pytest.raises(NotImplementedError):
        build_adapters(cfg)