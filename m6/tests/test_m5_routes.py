"""Read-only M5 routes and the Integration Status overlay. MOCKED M5 transport (M5's real gateway code over a fake store)."""
import pytest

from app import create_app
from app.services.m5_service import M5Link
from m5_fake_endpoint import KEY, FakeEndpoint, flaky, install_aicm_stub, make_gateway

V1 = "/api/v1"
CASE = "case-1"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    install_aicm_stub(monkeypatch)
    for name in ("M5_LINK_ENABLED", "M5_SSH_HOST"):
        monkeypatch.delenv(name, raising=False)  # tests must not depend on your .env


@pytest.fixture()
def ep():
    e = FakeEndpoint()
    e.store.add_case(CASE)
    e.store.add_operation(CASE, "op-1")
    e.store.risk_event(CASE, {"score": 42, "level": "Suspicious"})
    return e


def client_with(link=None):
    app = create_app({"TESTING": False})
    if link is not None:
        app.extensions["m5_link"] = link
    return app.test_client()


@pytest.fixture()
def api(tmp_path, ep):
    return client_with(M5Link(gateway=make_gateway(tmp_path, ep)))


def rows(client, method="get", **kw):
    res = getattr(client, method)(f"{V1}/integrations/" + ("status" if method == "get" else "check"), **kw)
    assert res.status_code == 200
    return {r["module"]: r for r in res.get_json()["components"]}


# ------------------------------------------------------------------ switched off / not configured: M6 behaves as before
def test_default_is_off_and_says_so():
    c = client_with()
    h = c.get(f"{V1}/m5/health").get_json()
    assert h["enabled"] is False and h["status"] == "Not configured" and "M5_LINK_ENABLED" in h["detail"]
    res = c.get(f"{V1}/m5/cases")
    assert res.status_code == 503 and res.get_json()["error"]["code"] == "M5_NOT_CONFIGURED"


def test_off_means_the_integration_status_is_exactly_as_before():
    m5 = rows(client_with())["M5"]
    assert m5["endpoint"] == "/api/response" and m5["status"] == "Stubbed" and m5["mode"] == "mock" and "gateway" not in m5


def test_enabled_without_settings_lists_what_is_missing_and_stays_a_clear_503():
    link = M5Link(env={"M5_LINK_ENABLED": "true", "M5_SSH_HOST": "m5.example.test"})
    c = client_with(link)
    h = c.get(f"{V1}/m5/health").get_json()
    assert h["status"] == "Not configured" and "M5_SSH_USER" in h["detail"] and "M5_GATEWAY_KEY_FILE" in h["detail"]
    res = c.get(f"{V1}/m5/cases")
    assert res.status_code == 503 and "M5_AGENT_ID" in res.get_json()["error"]["message"]


def test_settings_from_the_environment_build_the_gateway(tmp_path, ep):
    key = tmp_path / "gw.key"
    key.write_bytes(KEY)
    key.chmod(0o600)
    env = {"M5_LINK_ENABLED": "true", "M5_SSH_HOST": "m5.example.test", "M5_SSH_USER": "m6svc", "M5_SSH_IDENTITY_FILE": str(tmp_path / "id"),
           "M5_SSH_KNOWN_HOSTS_FILE": str(tmp_path / "kh"), "M5_GATEWAY_KEY_FILE": str(key), "M5_AGENT_ID": "001", "M6_DATA_DIR": str(tmp_path / "d")}
    from app.integrations.m5.gateway import M5Gateway
    from app.integrations.m5.state_store import M6Store
    link = M5Link(env=env, factory=lambda cfg: M5Gateway(cfg, M6Store(cfg.data_dir), transport=ep.transport))
    assert client_with(link).get(f"{V1}/m5/cases").get_json()["items"][0]["case_id"] == CASE


def test_an_unsafe_key_file_is_reported_without_leaking_it(tmp_path):
    key = tmp_path / "gw.key"
    key.write_bytes(KEY)
    key.chmod(0o644)
    env = {"M5_LINK_ENABLED": "true", "M5_SSH_HOST": "h", "M5_SSH_USER": "u", "M5_SSH_IDENTITY_FILE": "i", "M5_SSH_KNOWN_HOSTS_FILE": "k",
           "M5_GATEWAY_KEY_FILE": str(key), "M5_AGENT_ID": "001"}
    res = client_with(M5Link(env=env)).get(f"{V1}/m5/cases")
    assert res.status_code == 503 and KEY.decode() not in res.get_data(as_text=True)


# ------------------------------------------------------------------ the read-only routes
def test_cases_and_case_detail_are_passed_through_from_m5(api):
    body = api.get(f"{V1}/m5/cases").get_json()
    assert [c["case_id"] for c in body["items"]] == [CASE] and body["meta"] == {"source": "m5-gateway", "is_mock": False, "read_only": True}
    d = api.get(f"{V1}/m5/cases/{CASE}").get_json()
    assert d["case"]["case_id"] == CASE and d["latest_risk_decision"] == {"score": 42, "level": "Suspicious"}
    assert d["process_operations"][0]["operation_id"] == "op-1" and d["resource_operations"] == [] and d["meta"]["read_only"] is True


def test_timeline_and_risk_decisions(api):
    t = api.get(f"{V1}/m5/cases/{CASE}/timeline").get_json()
    assert [e["event_type"] for e in t["items"]] == ["case.created", "risk.decided"]
    assert [e["event_type"] for e in api.get(f"{V1}/m5/cases/{CASE}/timeline?after=1").get_json()["items"]] == ["risk.decided"]
    r = api.get(f"{V1}/m5/cases/{CASE}/risk-decisions").get_json()
    assert [e["event_type"] for e in r["items"]] == ["risk.decided"] and r["items"][0]["details"]["decision"]["score"] == 42


def test_unknown_case_is_a_404(api):
    for path in ("", "/timeline", "/risk-decisions"):
        res = api.get(f"{V1}/m5/cases/ghost{path}")
        assert res.status_code == 404 and res.get_json()["error"]["code"] == "M5_NOT_FOUND"


@pytest.mark.parametrize("path", ["/m5/cases?limit=0", "/m5/cases?limit=101", "/m5/cases?limit=x", "/m5/cases?offset=-1",
                                  f"/m5/cases/{CASE}/timeline?after=-5", f"/m5/cases/{CASE}/risk-decisions?limit=1000"])
def test_bad_query_parameters_are_400(api, path):
    res = api.get(V1 + path)
    assert res.status_code == 400 and res.get_json()["error"]["code"] == "INVALID_PARAMETER"


def test_case_ids_with_control_characters_are_refused_before_calling_m5(tmp_path, ep):
    c = client_with(M5Link(gateway=make_gateway(tmp_path, ep)))
    res = c.get(f"{V1}/m5/cases/bad%00id")
    assert res.status_code == 400 and res.get_json()["error"]["code"] == "INVALID_CASE_ID" and ep.count("get_case") == 0


def test_m5_unavailable_is_a_clear_503_not_fake_data(tmp_path, ep):
    c = client_with(M5Link(gateway=make_gateway(tmp_path, ep, transport=flaky(ep, before=9, methods=("list_cases", "get_case")))))
    res = c.get(f"{V1}/m5/cases")
    assert res.status_code == 503 and res.get_json()["error"]["code"] == "M5_TRANSPORT_UNCERTAIN" and "items" not in res.get_json()


def test_there_is_no_route_that_can_send_an_action_to_m5(api):
    app = api.application
    m5_rules = [r for r in app.url_map.iter_rules() if "/m5" in r.rule]
    assert m5_rules and all(r.methods <= {"GET", "HEAD", "OPTIONS"} for r in m5_rules)
    assert not any("action" in r.rule or "override" in r.rule for r in m5_rules)
    assert api.post(f"{V1}/m5/cases", json={}).status_code == 405
    assert api.post(f"{V1}/m5/cases/{CASE}/action", json={"action": "kill"}).status_code in (404, 405)


# ------------------------------------------------------------------ health and the Integration Status overlay
def test_health_reports_the_gateway_and_stored_events(tmp_path, ep):
    gw = make_gateway(tmp_path, ep)
    h = client_with(M5Link(gateway=gw)).get(f"{V1}/m5/health").get_json()
    assert h["status"] == "Connected" and h["enabled"] is True and h["events_stored"] == 0 and h["meta"]["read_only"] is True


def test_status_row_for_m5_shows_the_gateway_and_leaves_other_rows_alone(tmp_path, ep):
    baseline = rows(client_with())
    live = rows(client_with(M5Link(gateway=make_gateway(tmp_path, ep))))
    assert live["M5"]["endpoint"] == "SSH gateway (read-only): Connected" and live["M5"]["status"] == "Stubbed" and live["M5"]["mode"] == "mock"
    assert live["M5"]["gateway"]["status"] == "Connected" and "still use the M5 mock" in live["M5"]["detail"]
    for module in ("M1", "M2", "M3", "M4", "M6"):
        assert {k: v for k, v in live[module].items() if k != "last_check"} == {k: v for k, v in baseline[module].items() if k != "last_check"}


def test_a_failing_gateway_turns_the_m5_row_to_warning_and_nothing_else(tmp_path, ep):
    c = client_with(M5Link(gateway=make_gateway(tmp_path, ep, transport=flaky(ep, before=9, methods=("health",)))))
    r = rows(c)
    assert r["M5"]["status"] == "Warning" and r["M5"]["gateway"]["status"] == "Failed" and r["M5"]["endpoint"].endswith("Failed")
    assert r["M4"]["status"] == "Stubbed"


def test_status_page_does_not_open_an_ssh_session_on_every_load(tmp_path, ep):
    now = [0.0]
    c = client_with(M5Link(gateway=make_gateway(tmp_path, ep), ttl=30, clock=lambda: now[0]))
    rows(c), rows(c), rows(c)
    assert ep.count("health") == 1
    now[0] = 31
    rows(c)
    assert ep.count("health") == 2


def test_the_check_button_for_m5_asks_m5_again_but_other_checks_do_not(tmp_path, ep):
    c = client_with(M5Link(gateway=make_gateway(tmp_path, ep)))
    rows(c)
    assert ep.count("health") == 1
    rows(c, "post", json={"module": "m1"})
    assert ep.count("health") == 1
    rows(c, "post", json={"module": "m5"})
    assert ep.count("health") == 2


def test_alert_screens_are_unaffected_even_when_m5_is_down(tmp_path, ep):
    c = client_with(M5Link(gateway=make_gateway(tmp_path, ep, transport=flaky(ep, before=99, methods=("health", "list_cases", "get_case")))))
    res = c.get(f"{V1}/alerts?page_size=100")
    assert res.status_code == 200 and res.get_json()["total"] > 0
    a = c.get(f"{V1}/alerts/A-2038").get_json()
    assert (a["response_state"], a["verification_state"]) == ("Frozen", "Verifying")  # still M6's existing M5 mock
