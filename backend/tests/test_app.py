"""Flask endpoint integration tests, using FakeHostController via create_app().
No live infra: the Flask test client calls in-process."""

import pytest

from backend.app import create_app
from backend.tests.fakes import FakeHostController


@pytest.fixture
def client(tmp_path):
    controller = FakeHostController()
    app = create_app(
        controller=controller,
        audit_log_path=tmp_path / "audit.jsonl",
        allow_list_path=tmp_path / "critical_assets.yml",
    )
    app.config["TESTING"] = True
    with app.test_client() as c:
        c.fake_controller = controller  # stash for assertions
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_trigger_medium_auto_executes(client):
    resp = client.post(
        "/api/arm/trigger",
        json={"host": "airdr-target", "entity": "app-e1", "risk_tier": "medium", "process_id": 1},
    )
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["status"] == "executed"
    assert client.fake_controller.calls  # something actually ran


def test_trigger_critical_pending_then_approve(client):
    trigger_resp = client.post(
        "/api/arm/trigger",
        json={"host": "airdr-target", "entity": "app-e2", "risk_tier": "critical", "process_id": 2},
    )
    body = trigger_resp.get_json()
    assert body["status"] == "pending_approval"
    action_id = body["action_id"]
    assert client.fake_controller.calls == []

    approve_resp = client.post(f"/api/actions/{action_id}/approve")
    approve_body = approve_resp.get_json()
    assert approve_resp.status_code == 200
    assert approve_body["status"] == "executed"
    assert client.fake_controller.calls  # actually ran now

    listing = client.get("/api/actions").get_json()["actions"]
    assert any(a["action_id"] == action_id and a["status"] == "executed" for a in listing)


def test_trigger_high_pending_then_deny(client):
    trigger_resp = client.post(
        "/api/arm/trigger",
        json={"host": "airdr-target", "entity": "app-e3", "risk_tier": "high", "indicator": "1.2.3.4"},
    )
    action_id = trigger_resp.get_json()["action_id"]

    deny_resp = client.post(f"/api/actions/{action_id}/deny")
    assert deny_resp.get_json()["status"] == "denied"
    assert client.fake_controller.calls == []


def test_undo_endpoint(client):
    trigger_resp = client.post(
        "/api/arm/trigger",
        json={"host": "airdr-target", "entity": "app-e4", "signals": ["honeyfile"]},
    )
    action_id = trigger_resp.get_json()["action_id"]
    client.post(f"/api/actions/{action_id}/approve")

    undo_resp = client.post(f"/api/actions/{action_id}/undo")
    undo_body = undo_resp.get_json()
    assert undo_resp.status_code == 200
    assert undo_body["status"] == "undone"
    by_action = {r["action"]: r["status"] for r in undo_body["undo_results"]}
    assert by_action["isolate_host"] == "reversed"
    assert by_action["notify_and_open_case"] == "not_reversible"


def test_approve_unknown_action_id_is_404(client):
    resp = client.post("/api/actions/does-not-exist/approve")
    assert resp.status_code == 404
    assert resp.get_json()["status"] == "not_found"


def test_list_actions_filter_by_status(client):
    client.post(
        "/api/arm/trigger",
        json={"host": "airdr-target", "entity": "app-e5", "risk_tier": "medium", "process_id": 5},
    )
    client.post(
        "/api/arm/trigger",
        json={"host": "airdr-target", "entity": "app-e6", "risk_tier": "critical", "process_id": 6},
    )

    pending = client.get("/api/actions?status=pending_approval").get_json()["actions"]
    executed = client.get("/api/actions?status=executed").get_json()["actions"]
    assert len(pending) == 1
    assert len(executed) == 1


def test_default_action_store_none_without_env_vars(monkeypatch):
    """create_app() must fall back to InMemoryActionStore (via ARM's own
    default) when the AIRDR_OPENSEARCH_* env vars aren't set - local
    dev/tests should never need real OpenSearch credentials."""
    from backend.app import _default_action_store

    monkeypatch.delenv("AIRDR_OPENSEARCH_HOST", raising=False)
    monkeypatch.delenv("AIRDR_OPENSEARCH_USER", raising=False)
    monkeypatch.delenv("AIRDR_OPENSEARCH_PASSWORD", raising=False)
    assert _default_action_store() is None


def test_default_action_store_built_when_env_vars_present(monkeypatch):
    from backend.app import _default_action_store
    from backend.arm import OpenSearchActionStore

    monkeypatch.setenv("AIRDR_OPENSEARCH_HOST", "airdr-siem.example")
    monkeypatch.setenv("AIRDR_OPENSEARCH_USER", "irdp-writer")
    monkeypatch.setenv("AIRDR_OPENSEARCH_PASSWORD", "secret")
    store = _default_action_store()
    assert isinstance(store, OpenSearchActionStore)
    assert store.host == "airdr-siem.example"


def test_create_app_uses_explicit_action_store_over_env(monkeypatch, tmp_path):
    """A test (or a caller) passing action_store= explicitly must win over
    whatever the environment says - app.py pops it out of arm_kwargs rather
    than double-passing it to ARM()."""
    from backend.app import create_app
    from backend.arm import InMemoryActionStore
    from backend.tests.fakes import FakeHostController

    monkeypatch.setenv("AIRDR_OPENSEARCH_HOST", "should-not-be-used.example")
    monkeypatch.setenv("AIRDR_OPENSEARCH_USER", "x")
    monkeypatch.setenv("AIRDR_OPENSEARCH_PASSWORD", "y")

    explicit_store = InMemoryActionStore()
    app = create_app(
        controller=FakeHostController(),
        action_store=explicit_store,
        audit_log_path=tmp_path / "audit.jsonl",
        allow_list_path=tmp_path / "critical_assets.yml",
    )
    assert app.config["ARM"].store is explicit_store
