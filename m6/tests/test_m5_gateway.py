"""M6 -> M5 gateway layer. MOCKED M5 transport: M5's real gateway code runs over a fake store; no real SSH, no real machine."""
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from app.integrations.base import ActionRejected, IntegrationUnavailable, MalformedResponse
from app.integrations.m5.gateway import (ACTIONS, M5BadRequest, M5Forbidden, M5Gateway, M5NotFound, M5RequestExpired,
                                          M5TransportUncertain)
from app.integrations.m5.gateway_config import M5ConfigError, M5GatewayConfig, read_key
from app.integrations.m5.state_store import M6Store
from app.integrations.m5.vendor import ai_rdr_m6 as lib
from m5_fake_endpoint import AGENT, KEY, FakeEndpoint, flaky, install_aicm_stub, make_config, make_gateway

CASE = "case-1"
TARGET = {"pid": 4242, "start_ticks": 99, "boot_id": "boot-1"}
REASON = "Analyst reviewed the process tree and requests this step"


@pytest.fixture(autouse=True)
def _aicm(monkeypatch):
    install_aicm_stub(monkeypatch)


@pytest.fixture()
def ep():
    e = FakeEndpoint()
    e.store.add_case(CASE)
    e.store.add_operation(CASE, "op-1")
    e.store.risk_event(CASE, {"score": 42, "level": "Suspicious", "matrix": "m5-risk-matrix-v1"})
    return e


@pytest.fixture()
def gw(tmp_path, ep):
    return make_gateway(tmp_path, ep)


# ------------------------------------------------------------------ configuration
ENV = {"M5_SSH_HOST": "m5.example.test", "M5_SSH_USER": "m6svc", "M5_SSH_IDENTITY_FILE": "/k/id", "M5_SSH_KNOWN_HOSTS_FILE": "/k/kh",
       "M5_GATEWAY_KEY_FILE": "/k/gw.key", "M5_AGENT_ID": "001"}


def test_config_reads_environment_with_safe_defaults():
    c = M5GatewayConfig.from_env({**ENV, "ANALYST_NAME": "Dana"})
    assert (c.host, c.user, c.port, c.agent_id, c.issuer, c.timeout) == ("m5.example.test", "m6svc", 22, "001", "m6-backend", 45.0)
    assert c.analyst_id == "Dana" and c.analyst_roles == ("analyst",) and c.service_id == "m6-backend"


def test_config_lists_every_missing_setting():
    with pytest.raises(M5ConfigError) as err:
        M5GatewayConfig.from_env({"M5_SSH_HOST": "h"})
    for name in ("M5_SSH_USER", "M5_SSH_IDENTITY_FILE", "M5_SSH_KNOWN_HOSTS_FILE", "M5_GATEWAY_KEY_FILE", "M5_AGENT_ID"):
        assert name in str(err.value)


@pytest.mark.parametrize("bad", [{"M5_SSH_PORT": "0"}, {"M5_SSH_PORT": "x"}, {"M5_TIMEOUT": "1"}, {"M5_TIMEOUT": "500"},
                                 {"M5_ANALYST_ROLES": "connector"}, {"M5_ANALYST_ROLES": "root"}, {"M5_ANALYST_ROLES": "analyst,connector"}])
def test_config_rejects_unsafe_values(bad):
    with pytest.raises(M5ConfigError):
        M5GatewayConfig.from_env({**ENV, **bad})


def test_empty_roles_setting_means_the_least_privileged_default():
    assert M5GatewayConfig.from_env({**ENV, "M5_ANALYST_ROLES": ""}).analyst_roles == ("analyst",)


def test_key_file_must_be_private_regular_and_long_enough(tmp_path):
    good = tmp_path / "k"
    good.write_bytes(KEY)
    good.chmod(0o600)
    assert read_key(str(good)) == KEY
    good.chmod(0o644)
    with pytest.raises(M5ConfigError):
        read_key(str(good))
    short = tmp_path / "s"
    short.write_bytes(b"x" * 10)
    short.chmod(0o600)
    with pytest.raises(M5ConfigError):
        read_key(str(short))
    link = tmp_path / "link"
    good.chmod(0o600)
    link.symlink_to(good)
    with pytest.raises(M5ConfigError):
        read_key(str(link))
    with pytest.raises(M5ConfigError) as err:
        read_key(str(tmp_path / "missing"))
    assert KEY.decode() not in str(err.value)


def test_missing_ssh_files_are_a_config_error_not_a_crash(tmp_path):
    with pytest.raises(M5ConfigError):
        M5Gateway(make_config(tmp_path), M6Store(tmp_path / "d"))  # real SSHTransport requested, identity/known_hosts files absent


def test_real_ssh_transport_keeps_m5s_security_properties(tmp_path):
    (tmp_path / "id").write_text("x")
    (tmp_path / "known_hosts").write_text("x")
    gw = M5Gateway(make_config(tmp_path, port=2222), M6Store(tmp_path / "d"))
    t = gw._transport
    assert isinstance(t, lib.SSHTransport)
    cmd = " ".join(t.command)
    assert "StrictHostKeyChecking=yes" in cmd and "BatchMode=yes" in cmd and "StrictHostKeyChecking=no" not in cmd
    assert "UserKnownHostsFile=" + str(tmp_path / "known_hosts") in cmd and "-p 2222" in cmd and t.command[-1] == lib.SSHTransport.COMMAND
    assert t.command[-2] == "m6svc@m5.example.test" and t.timeout == 45.0


def test_invalid_ssh_destination_is_a_config_error(tmp_path):
    (tmp_path / "id").write_text("x")
    (tmp_path / "known_hosts").write_text("x")
    with pytest.raises(M5ConfigError):
        M5Gateway(make_config(tmp_path, host="bad host; rm -rf /"), M6Store(tmp_path / "d"))


# ------------------------------------------------------------------ reads
def test_health_and_status(gw):
    h = gw.health()
    assert h["gateway_ready"] is True and h["agent_id"] == AGENT and set(h["manual_actions"]) == set(ACTIONS)
    assert gw.status()["status"] == "Connected" and "not observed" in gw.status()["detail"]


def test_status_warns_when_agent_id_differs(tmp_path):
    other = FakeEndpoint(agent_id="999")
    g = M5Gateway(make_config(tmp_path, agent_id="999"), M6Store(tmp_path / "d"), transport=other.transport)
    g.config = make_config(tmp_path, agent_id="999")
    assert g.status()["status"] == "Connected"
    g.config = make_config(tmp_path, agent_id="001")
    assert g.status()["status"] == "Warning"


def test_case_list_and_detail_use_m5s_real_structures(gw):
    cases = gw.list_cases()
    assert cases["agent_id"] == AGENT and [c["case_id"] for c in cases["items"]] == [CASE] and cases["items"][0]["lifecycle"] == "open"
    d = gw.get_case(CASE)
    assert d["case"]["case_id"] == CASE and d["case"]["last_sequence"] >= 2
    assert d["latest_risk_decision"] == {"score": 42, "level": "Suspicious", "matrix": "m5-risk-matrix-v1"}
    assert [o["operation_id"] for o in d["process_operations"]] == ["op-1"] and d["process_operations"][0]["target"]["pid"] == 4242
    assert d["resource_operations"] == [] and d["operation_count"] == 1 and d["operations_truncated"] is False


def test_timeline_and_risk_decisions(gw):
    t = gw.timeline(CASE)
    assert [e["event_type"] for e in t["items"]] == ["case.created", "risk.decided"] and t["next_after"] == t["items"][-1]["case_sequence"]
    assert gw.timeline(CASE, after=1)["items"][0]["event_type"] == "risk.decided"
    r = gw.risk_decisions(CASE)
    assert [e["event_type"] for e in r["items"]] == ["risk.decided"] and r["items"][0]["details"]["decision"]["score"] == 42


def test_unknown_case_is_not_found(gw):
    for call in (gw.get_case, gw.timeline, gw.risk_decisions):
        with pytest.raises(M5NotFound):
            call("nope")


def test_reads_use_a_service_principal_with_read_permission(gw, ep):
    gw.list_cases(), gw.get_case(CASE)
    assert {p for _, p in ep.calls} == {"service"}


# ------------------------------------------------------------------ gateway communication failures
def test_unreachable_ssh_is_controlled(tmp_path, ep):
    g = make_gateway(tmp_path, ep, transport=flaky(ep, before=1, methods=("list_cases",)))
    with pytest.raises(M5TransportUncertain) as err:
        g.list_cases()
    assert isinstance(err.value, IntegrationUnavailable) and err.value.status == 503


@pytest.mark.parametrize("garbage", ["not json", ""])
def test_unreadable_gateway_answers_are_malformed(tmp_path, garbage):
    g = M5Gateway(make_config(tmp_path), M6Store(tmp_path / "d"), transport=lambda message: garbage)
    with pytest.raises(MalformedResponse):
        g.health()


@pytest.mark.parametrize("unsigned", ["[]", "{}", '{"ok": true}', '{"ok": true, "result": {}, "signature": "00"}'])
def test_answers_without_a_valid_signature_are_never_trusted(tmp_path, unsigned):
    g = M5Gateway(make_config(tmp_path), M6Store(tmp_path / "d"), transport=lambda message: unsigned)
    with pytest.raises(IntegrationUnavailable) as err:
        g.health()
    assert "authenticate" in err.value.message


def test_response_signed_with_a_different_key_is_rejected(tmp_path, ep):
    other = FakeEndpoint(key=b"z" * 40)
    g = M5Gateway(make_config(tmp_path), M6Store(tmp_path / "d"), transport=other.transport)  # endpoint expects another key
    with pytest.raises(IntegrationUnavailable) as err:
        g.health()
    assert "authenticate" in err.value.message and KEY.decode() not in err.value.message


def test_gateway_disabled_on_the_endpoint_is_reported(tmp_path, ep):
    ep.runtime.config["m6_gateway"]["enabled"] = False
    with pytest.raises(IntegrationUnavailable) as err:
        make_gateway(tmp_path, ep).health()
    assert "disabled" in err.value.message


def test_expired_request_is_reported_as_expired(tmp_path, ep):
    old = lambda: datetime.now(timezone.utc) - timedelta(minutes=10)  # M6's clock is far behind M5's
    with pytest.raises(M5RequestExpired):
        make_gateway(tmp_path, ep, clock=old).list_cases()


# ------------------------------------------------------------------ analyst actions: happy path and request shape
def test_freeze_reads_latest_sequence_and_sends_exact_m5_fields(gw, ep):
    seq = ep.store.db.execute("SELECT last_sequence FROM cases").fetchone()[0]
    out = gw.submit_action(CASE, "freeze", REASON, target=TARGET)
    assert out["status"] == "completed" and out["completion_verified"] is True and out["request_id"] and out["idempotency_key"].startswith("m6-")
    case_id, action, params = ep.executed[0]
    assert (case_id, action) == (CASE, "freeze") and params["target"] == TARGET and params["expected_sequence"] == seq
    assert params["idempotency_key"] == out["idempotency_key"]
    assert out["request_id"] == lib.request_identity(AGENT, {"type": "user", "id": "analyst.one"}, out["idempotency_key"])
    assert [p for m, p in ep.calls if m == "request_action"] == ["user"]  # an analyst identity, never the service one


def test_sequence_comes_from_the_case_at_submit_time_not_from_the_past(gw, ep):
    gw.submit_action(CASE, "verify", REASON, operation_id="op-1")
    ep.store.event(CASE, "response.state_changed")  # the case moves on
    latest = ep.store.db.execute("SELECT last_sequence FROM cases").fetchone()[0]
    gw.submit_action(CASE, "verify", REASON, operation_id="op-1")
    assert ep.executed[-1][2]["expected_sequence"] == latest and ep.executed[0][2]["expected_sequence"] < latest


def test_every_new_action_gets_a_new_idempotency_key(gw):
    a = gw.submit_action(CASE, "verify", REASON, operation_id="op-1")
    b = gw.submit_action(CASE, "verify", REASON, operation_id="op-1")
    assert a["idempotency_key"] != b["idempotency_key"] and a["request_id"] != b["request_id"]


def test_isolate_and_approve_containment_are_different_actions(tmp_path, ep):
    g = make_gateway(tmp_path, ep, roles=("responder",))
    g.submit_action(CASE, "isolate", REASON, operation_id="op-1")
    g.submit_action(CASE, "approve_containment", REASON, operation_id="op-1")
    assert [a for _, a, _ in ep.executed] == ["isolate", "approve_containment"]
    assert {"isolate", "approve_containment", "kill"} <= set(ACTIONS) and len(ACTIONS) == 7


def test_undo_uses_resource_key(gw, ep):
    gw.submit_action(CASE, "undo", REASON, resource_key="host:isolate")
    assert ep.executed[0][2]["resource_key"] == "host:isolate" and "operation_id" not in ep.executed[0][2]


def test_action_status_can_be_read_later(gw):
    out = gw.submit_action(CASE, "thaw", REASON, operation_id="op-1")
    again = gw.action_status(out["idempotency_key"])
    assert again["status"] == "completed" and again["request_id"] == out["request_id"]
    assert gw.get_action(out["request_id"])["actor"] == {"type": "user", "id": "analyst.one"}
    with pytest.raises(M5NotFound):
        gw.get_action("00000000-0000-0000-0000-000000000000")


def test_failed_execution_is_reported_as_failed_never_as_success(tmp_path, ep):
    def boom(state, case_id, action, params):
        raise ValueError("process is gone")
    ep.gateway._execute = boom
    out = make_gateway(tmp_path, ep).submit_action(CASE, "verify", REASON, operation_id="op-1")
    assert out["status"] == "failed" and out["completion_verified"] is False and out["error"]["code"] == "conflict"


# ------------------------------------------------------------------ validation, roles, permissions
@pytest.mark.parametrize("kwargs", [
    dict(action="format-disk", reason=REASON), dict(action="freeze", reason="short"), dict(action="freeze", reason="x" * 2000),
    dict(action="freeze", reason="onewordreason"), dict(action="freeze", reason="   "), dict(action="freeze", reason=None, target=TARGET),
    dict(action="freeze", reason=REASON),                                           # freeze without a target
    dict(action="freeze", reason=REASON, target={"pid": 1}),                        # incomplete identity
    dict(action="freeze", reason=REASON, target={**TARGET, "extra": 1}),
    dict(action="freeze", reason=REASON, target={**TARGET, "pid": "4242"}),
    dict(action="verify", reason=REASON, target=TARGET),                            # only freeze takes a target
    dict(action="verify", reason=REASON, resource_key="k"),                         # resource_key is undo-only
    dict(action="undo", reason=REASON),                                             # undo needs a resource_key
    dict(action="undo", reason=REASON, resource_key="k", operation_id="op-1"),
])
def test_invalid_requests_are_refused_before_anything_is_sent(gw, ep, kwargs):
    kwargs = dict(kwargs)
    with pytest.raises(M5BadRequest):
        gw.submit_action(CASE, kwargs.pop("action"), kwargs.pop("reason"), **kwargs)
    assert ep.count("request_action") == 0 and ep.count("get_case") == 0 and ep.executed == []


@pytest.mark.parametrize("roles,action,allowed", [
    (("viewer",), "freeze", False), (("viewer",), "verify", False), (("analyst",), "kill", False), (("analyst",), "isolate", False),
    (("analyst",), "approve_containment", False), (("analyst",), "freeze", True), (("analyst",), "undo", True),
    (("responder",), "kill", True), (("responder",), "approve_containment", True), (("responder",), "isolate", True)])
def test_m6_checks_the_analysts_role_before_contacting_m5(tmp_path, ep, roles, action, allowed):
    g = make_gateway(tmp_path, ep, roles=roles)
    extra = {"target": TARGET} if action == "freeze" else {"resource_key": "k"} if action == "undo" else {"operation_id": "op-1"}
    if allowed:
        assert g.submit_action(CASE, action, REASON, **extra)["status"] == "completed"
    else:
        with pytest.raises(M5Forbidden):
            g.submit_action(CASE, action, REASON, **extra)
        assert ep.count("request_action") == 0 and ep.executed == []


def test_m5_enforces_roles_itself_even_if_m6_were_bypassed(ep):
    base = dict(case_id=CASE, action="kill", reason=REASON, idempotency_key="k-bypass-1", expected_sequence=0, operation_id="op-1")
    analyst = lib.M5Client(ep.transport, KEY, AGENT, {"type": "user", "id": "a", "roles": ["analyst"]})
    with pytest.raises(lib.GatewayError) as err:
        analyst.call("request_action", **base)
    assert err.value.code == "forbidden"
    service = lib.M5Client(ep.transport, KEY, AGENT, {"type": "service", "id": "m6-backend", "roles": ["connector"]})
    with pytest.raises(lib.GatewayError) as err:
        service.call("request_action", **base)  # a service identity cannot act as an analyst
    assert err.value.code == "forbidden"
    with pytest.raises(lib.GatewayError) as err:
        analyst.outbox()  # an analyst identity cannot deliver events
    assert err.value.code == "forbidden"
    assert ep.executed == []


def test_the_browser_cannot_choose_roles_or_principals(gw):
    import inspect
    names = set(inspect.signature(gw.submit_action).parameters)
    assert names == {"case_id", "action", "reason", "operation_id", "target", "resource_key"}


# ------------------------------------------------------------------ conflicts and M5 refusals
def test_stale_case_is_a_conflict_and_nothing_executes(tmp_path, ep):
    inner = ep.transport

    def moves_case_after_the_read(message):  # the case changes between M6's read and M5's check
        if json.loads(message)["method"] == "request_action":
            ep.store.event(CASE, "response.state_changed")
        return inner(message)
    g = make_gateway(tmp_path, ep, transport=moves_case_after_the_read)
    with pytest.raises(ActionRejected) as err:
        g.submit_action(CASE, "verify", REASON, operation_id="op-1")
    assert "Case changed" in err.value.message and ep.executed == []
    assert g.store.get_intent(next(iter(_keys(g))))["status"] == "rejected"


def _keys(g):
    with g.store._db() as db:
        return [r[0] for r in db.execute("SELECT idempotency_key FROM m5_action_intents")]


def test_closed_case_is_refused(tmp_path, ep):
    ep.store.add_case("closed-1", lifecycle="closed")
    with pytest.raises(ActionRejected):
        make_gateway(tmp_path, ep).submit_action("closed-1", "verify", REASON, operation_id="op-1")
    assert ep.executed == []


def test_unknown_case_is_refused_before_sending(gw, ep):
    with pytest.raises(M5NotFound):
        gw.submit_action("ghost", "verify", REASON, operation_id="op-1")
    assert ep.count("request_action") == 0


def test_reusing_an_idempotency_key_for_a_different_action_is_refused(ep):
    client = lib.M5Client(ep.transport, KEY, AGENT, {"type": "user", "id": "a", "roles": ["responder"]})
    seq = ep.store.db.execute("SELECT last_sequence FROM cases").fetchone()[0]
    first = dict(reason=REASON, idempotency_key="same-key-123", expected_sequence=seq, operation_id="op-1")
    client.request_action(CASE, "verify", **first)
    with pytest.raises(lib.GatewayError) as err:
        client.request_action(CASE, "thaw", **first)
    assert err.value.code == "conflict" and "different action" in str(err.value)
    assert [a for _, a, _ in ep.executed] == ["verify"]


# ------------------------------------------------------------------ idempotency and uncertain transport outcomes
def test_answer_lost_after_m5_acted_is_resolved_by_status_not_by_repeating(tmp_path, ep):
    g = make_gateway(tmp_path, ep, transport=flaky(ep, after=1))
    out = g.submit_action(CASE, "freeze", REASON, target=TARGET)
    assert out["status"] == "completed" and out["completion_verified"] is True  # learned from get_action()
    assert len(ep.executed) == 1 and ep.count("request_action") == 1 and ep.count("get_action") == 1


def test_request_that_never_reached_m5_is_reported_and_can_be_retried_safely(tmp_path, ep):
    g = make_gateway(tmp_path, ep, transport=flaky(ep, before=1))
    out = g.submit_action(CASE, "freeze", REASON, target=TARGET)
    assert out["status"] == "not_received" and out["retry_allowed"] is True and ep.executed == []
    retried = g.retry_action(out["idempotency_key"])
    assert retried["status"] == "completed" and retried["request_id"] == out["request_id"]
    assert len(ep.executed) == 1 and ep.executed[0][2]["idempotency_key"] == out["idempotency_key"]
    again = g.retry_action(out["idempotency_key"])  # a second retry must not repeat the effect
    assert again["status"] == "completed" and len(ep.executed) == 1 and ep.count("request_action") == 1


def test_retry_reuses_the_original_sequence_even_if_the_case_moved_on(tmp_path, ep):
    g = make_gateway(tmp_path, ep, transport=flaky(ep, before=1))
    out = g.submit_action(CASE, "verify", REASON, operation_id="op-1")
    original = g.store.get_intent(out["idempotency_key"])["params"]["expected_sequence"]
    ep.store.event(CASE, "response.state_changed")
    with pytest.raises(ActionRejected):  # M5 refuses a stale request: the analyst must look again and start a NEW action
        g.retry_action(out["idempotency_key"])
    assert g.store.get_intent(out["idempotency_key"])["params"]["expected_sequence"] == original and ep.executed == []


def test_when_status_cannot_be_checked_the_outcome_is_unknown_and_nothing_is_resent(tmp_path, ep):
    g = make_gateway(tmp_path, ep, transport=flaky(ep, after=2, methods=("request_action", "get_action")))
    out = g.submit_action(CASE, "freeze", REASON, target=TARGET)
    assert out["status"] == "unknown" and out["retry_allowed"] is False and len(ep.executed) == 1
    assert ep.count("request_action") == 1


def test_retry_when_still_unreachable_does_not_resend(tmp_path, ep):
    g = make_gateway(tmp_path, ep, transport=flaky(ep, before=1, methods=("request_action",)))
    out = g.submit_action(CASE, "freeze", REASON, target=TARGET)
    g2 = make_gateway(tmp_path, ep, transport=flaky(ep, before=5, methods=("get_action", "request_action")))
    assert g2.retry_action(out["idempotency_key"])["status"] == "unknown" and ep.executed == []


def test_intent_survives_an_m6_restart(tmp_path, ep):
    g = make_gateway(tmp_path, ep, transport=flaky(ep, before=1))
    out = g.submit_action(CASE, "freeze", REASON, target=TARGET)
    restarted = make_gateway(tmp_path, ep)  # new process, same data dir
    assert restarted.retry_action(out["idempotency_key"])["status"] == "completed" and len(ep.executed) == 1


def test_expired_request_never_executes_and_is_reported_not_received(tmp_path, ep):
    old = lambda: datetime.now(timezone.utc) - timedelta(minutes=10)
    g = make_gateway(tmp_path, ep, clock=old)
    ep.store.db.execute("SELECT 1")
    # reads would also fail with the skewed clock, so only the action path is exercised through a pre-read made with a good clock
    good = make_gateway(tmp_path, ep)
    latest = good.get_case(CASE)["case"]["last_sequence"]
    key = "m6-expired-test"
    params = {"case_id": CASE, "action": "verify", "reason": REASON, "operation_id": "op-1", "expected_sequence": latest, "idempotency_key": key}
    g.store.save_intent(key, g._user().action_id(key), "analyst.one", CASE, "verify", params)
    out = g._send(key, g._user().action_id(key), CASE, "verify", params)
    assert ep.executed == [] and out["status"] in ("unknown", "not_received")


def test_retry_of_an_unknown_or_foreign_key_is_not_found(gw):
    with pytest.raises(M5NotFound):
        gw.retry_action("m6-does-not-exist")
    with pytest.raises(M5NotFound):
        gw.retry_action("bad key!")
    with pytest.raises(M5NotFound):
        gw.action_status("m6-does-not-exist")


def test_no_secret_material_in_errors_or_state(tmp_path, ep, gw):
    out = gw.submit_action(CASE, "freeze", REASON, target=TARGET)
    blob = json.dumps(out) + open(gw.store.path, "rb").read().decode("latin-1")
    assert KEY.decode() not in blob and "signature" not in json.dumps(out)
