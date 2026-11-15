"""OPTIONAL compatibility check against M5's REAL gateway and REAL CaseStore (SQLite), with only the response execution replaced.
Skipped unless M5_SOURCE_DIR points at the folder that contains M5's ai_rdr_*.py files, for example:
  M5_SOURCE_DIR=/path/to/m5 python3 -m pytest tests/test_m5_real_code.py -v
This is NOT a test of a real endpoint: no SSH, no real response action, no machine is touched."""
import contextlib
import os
import sys

import pytest

SRC = os.environ.get("M5_SOURCE_DIR", "").strip()
pytestmark = pytest.mark.skipif(not SRC, reason="set M5_SOURCE_DIR to run the M5 real-code compatibility test")

if SRC:
    sys.path.insert(0, SRC)

from app.integrations.base import ActionRejected  # noqa: E402
from app.integrations.m5.delivery import EventDelivery  # noqa: E402
from app.integrations.m5.vendor import ai_rdr_m6 as lib  # noqa: E402
from m5_fake_endpoint import AGENT, KEY, make_gateway  # noqa: E402

REASON = "Analyst reviewed the process tree and requests this step"


class RealStoreRuntime:
    def __init__(self, store):
        self.store, self.actor, self.request_id = store, None, None
        self.config = {"agent_id": AGENT, "m6_gateway": {"enabled": True}}

    def boot_id(self):
        return "boot-1"

    @contextlib.contextmanager
    def transaction(self):
        yield {"cases": {}, "resources": {}}


class Endpoint:
    def __init__(self, tmp_path):
        from ai_rdr_aicm import CaseStore
        self.store = CaseStore(tmp_path / "m5" / "cases.sqlite3")
        self.gateway = lib.M6Gateway(RealStoreRuntime(self.store), KEY)
        self.executed = []
        self.gateway._execute = lambda state, case_id, action, params: self.executed.append((case_id, action)) or {"operation_id": "op-1"}

    def transport(self, message):
        import json
        return lib.canonical(self.gateway.handle(json.loads(message)))


@pytest.fixture()
def ep(tmp_path):
    e = Endpoint(tmp_path)
    actor = {"type": "service", "id": "m5-test"}
    e.store.create_case(actor=actor, title="Suspicious encryption burst", severity="high", case_id="case-1")
    e.store.append_event("case-1", "risk.decided", actor=actor, details={"decision": {"score": 42, "level": "Suspicious"}})
    with e.store.connection() as db:
        db.execute("INSERT INTO operations VALUES('op-1','case-1','process_tree','FROZEN','{\"pid\":4242}','{}','2026-11-13T00:00:00Z')")
    return e


def test_reads_match_the_real_store(tmp_path, ep):
    gw = make_gateway(tmp_path, ep)
    assert gw.health()["gateway_ready"] is True
    assert [c["case_id"] for c in gw.list_cases()["items"]] == ["case-1"]
    detail = gw.get_case("case-1")
    assert detail["latest_risk_decision"] == {"score": 42, "level": "Suspicious"} and detail["process_operations"][0]["operation_id"] == "op-1"
    assert [e["event_type"] for e in gw.timeline("case-1")["items"]] == ["case.created", "risk.decided"]
    assert gw.risk_decisions("case-1")["items"][0]["details"]["decision"]["level"] == "Suspicious"


def test_action_flow_uses_real_sequence_checks_and_idempotency(tmp_path, ep):
    gw = make_gateway(tmp_path, ep)
    out = gw.submit_action("case-1", "verify", REASON, operation_id="op-1")
    assert out["status"] == "completed" and ep.executed == [("case-1", "verify")]
    assert gw.retry_action(out["idempotency_key"])["status"] == "completed" and len(ep.executed) == 1
    seq_before = gw.get_case("case-1")["case"]["last_sequence"]
    inner = ep.transport

    def stale(message):
        if '"request_action"' in message:
            ep.store.append_event("case-1", "case.note_added", actor={"type": "service", "id": "m5-test"})
        return inner(message)
    with pytest.raises(ActionRejected):
        make_gateway(tmp_path, ep, transport=stale).submit_action("case-1", "verify", REASON, operation_id="op-1")
    assert len(ep.executed) == 1 and gw.get_case("case-1")["case"]["last_sequence"] > seq_before


def test_outbox_delivery_against_the_real_store(tmp_path, ep):
    gw = make_gateway(tmp_path, ep)
    report = EventDelivery(gw, gw.store).poll_once()
    assert report["stored"] == 2 and report["acknowledged"] == 2 and ep.store.pending_events() == []
    assert EventDelivery(gw, gw.store).poll_once()["fetched"] == 0


def test_read_only_routes_against_the_real_store(tmp_path, ep):
    from app import create_app
    from app.services.m5_service import M5Link
    app = create_app({"TESTING": False})
    app.extensions["m5_link"] = M5Link(gateway=make_gateway(tmp_path, ep))
    c = app.test_client()
    base = "/api/v1/m5"
    assert c.get(f"{base}/health").get_json()["status"] == "Connected"
    assert [x["case_id"] for x in c.get(f"{base}/cases").get_json()["items"]] == ["case-1"]
    detail = c.get(f"{base}/cases/case-1").get_json()
    assert detail["latest_risk_decision"] == {"score": 42, "level": "Suspicious"} and detail["meta"]["read_only"] is True
    assert [e["event_type"] for e in c.get(f"{base}/cases/case-1/timeline").get_json()["items"]] == ["case.created", "risk.decided"]
    assert len(c.get(f"{base}/cases/case-1/risk-decisions").get_json()["items"]) == 1
    assert c.get(f"{base}/cases/ghost").status_code == 404
