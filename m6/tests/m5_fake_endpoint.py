"""A stand-in for the M5 endpoint for automated tests.

It runs M5's REAL M6Gateway class (request signing, expiry, principals, role permissions, parameter rules, response signing)
over a small fake runtime and an in-memory store. Only the response EXECUTION is faked (`executed` records what M5 would have
done), so no test can touch a process, a firewall or a real machine."""
import contextlib
import hashlib
import json
import sqlite3
import sys
import types
import uuid
from datetime import datetime, timezone

from app.integrations.m5.gateway import M5Gateway
from app.integrations.m5.gateway_config import M5GatewayConfig
from app.integrations.m5.state_store import M6Store
from app.integrations.m5.vendor import ai_rdr_m6 as lib

KEY = b"k" * 40
AGENT = "001"
SCHEMA = """
CREATE TABLE cases (case_id TEXT PRIMARY KEY, title TEXT, severity TEXT, lifecycle TEXT, disposition TEXT, assignee TEXT,
 created_at TEXT, updated_at TEXT, closed_at TEXT, closure_reason TEXT, duplicate_of TEXT, version INTEGER, last_sequence INTEGER DEFAULT 0);
CREATE TABLE operations (operation_id TEXT PRIMARY KEY, case_id TEXT, kind TEXT, status TEXT, target TEXT, details TEXT, updated_at TEXT);
CREATE TABLE audit_events (event_id TEXT PRIMARY KEY, case_id TEXT, sequence INTEGER, event_type TEXT, recorded_at TEXT, payload TEXT);
CREATE TABLE outbox (event_id TEXT PRIMARY KEY, acknowledged_at TEXT);
"""


class Conflict(ValueError):
    """Same role as ai_rdr_aicm.Conflict in M5."""


def install_aicm_stub(monkeypatch):
    module = types.ModuleType("ai_rdr_aicm")
    module.Conflict = Conflict
    monkeypatch.setitem(sys.modules, "ai_rdr_aicm", module)


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class FakeStore:
    def __init__(self):
        self.db = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    @contextlib.contextmanager
    def connection(self):
        yield self.db

    @contextlib.contextmanager
    def transaction(self):
        yield self.db

    def add_case(self, case_id, lifecycle="open", severity="high"):
        self.db.execute("INSERT INTO cases VALUES(?,?,?,?,?,NULL,?,?,NULL,NULL,NULL,1,0)",
                        (case_id, "AI-RDR incident " + case_id, severity, lifecycle, "undetermined", now(), now()))
        return self.event(case_id, "case.created", {"type": "service", "id": "m5"}, details={"severity": severity})

    def add_operation(self, case_id, operation_id, status="FROZEN", kind="process_tree", target=None):
        self.db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?)", (operation_id, case_id, kind, status,
                        json.dumps(target or {"pid": 4242, "start_ticks": 99, "boot_id": "boot-1"}), json.dumps({"score": 7}), now()))

    def event(self, case_id, event_type, actor=None, *, request_id=None, operation_id=None, phase="completed",
              outcome="success", details=None, event_id=None, **_):
        if case_id is None:
            seq = self.db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM audit_events WHERE case_id IS NULL").fetchone()[0]
        else:
            seq = self.db.execute("SELECT last_sequence FROM cases WHERE case_id=?", (case_id,)).fetchone()[0] + 1
        e = {"schema_version": 1, "event_id": event_id or str(uuid.uuid4()), "case_id": case_id, "case_sequence": seq,
             "event_type": event_type, "actor": actor or {"type": "service", "id": "m5"}, "request_id": request_id,
             "operation_id": operation_id, "phase": phase, "outcome": outcome, "occurred_at": now(), "recorded_at": now(),
             "details": details or {}}
        self.db.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (e["event_id"], case_id, seq, event_type, now(), json.dumps(e)))
        if case_id is not None:
            self.db.execute("UPDATE cases SET last_sequence=?,updated_at=? WHERE case_id=?", (seq, now(), case_id))
        self.db.execute("INSERT INTO outbox(event_id) VALUES(?)", (e["event_id"],))
        return e

    def risk_event(self, case_id, decision):
        return self.event(case_id, "risk.decided", details={"decision": decision})

    # ---- the store API M5's gateway calls (behaviour copied from M5's CaseStore)
    def list_cases(self, limit=100, offset=0):
        return [dict(r) for r in self.db.execute("SELECT * FROM cases ORDER BY created_at,case_id LIMIT ? OFFSET ?", (limit, offset))]

    def timeline(self, case_id, after=0, limit=100):
        return [json.loads(r[0]) for r in self.db.execute(
            "SELECT payload FROM audit_events WHERE case_id IS ? AND sequence>? ORDER BY sequence LIMIT ?", (case_id, after, limit))]

    def append_event(self, case_id, event_type, *, actor, **attrs):
        return self.event(case_id, event_type, actor, **attrs)

    def begin_analyst_request(self, case_id, request_id, body, *, actor, executor, expected_sequence):
        fingerprint = hashlib.sha256(lib.canonical(body).encode()).hexdigest()
        prior = self.db.execute("SELECT payload FROM audit_events WHERE event_id=?", ("m6:" + request_id + ":requested",)).fetchone()
        if prior:
            event = json.loads(prior["payload"])
            if event["case_id"] != case_id or event["actor"] != actor or event["details"]["fingerprint"] != fingerprint:
                raise Conflict("Idempotency key reused with a different action")
            return False
        case = self.db.execute("SELECT lifecycle,last_sequence FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if case is None:
            raise KeyError(case_id)
        if case["lifecycle"] == "closed":
            raise Conflict("Reopen the incident before an analyst action")
        if type(expected_sequence) is not int or case["last_sequence"] != expected_sequence:
            raise Conflict("Case changed; refresh its timeline before acting")
        self.event(case_id, "analyst.requested", actor, request_id=request_id, event_id="m6:" + request_id + ":requested",
                   phase="requested", outcome="unknown", details={"request": body, "fingerprint": fingerprint, "executor": executor})
        return True

    def analyst_request(self, request_id):
        ids = tuple("m6:" + request_id + ":" + p for p in ("requested", "started", "completed", "failed"))
        rows = self.db.execute("SELECT payload FROM audit_events WHERE event_id IN (?,?,?,?)", ids).fetchall()
        events = {json.loads(r["payload"])["event_type"]: json.loads(r["payload"]) for r in rows}
        first = events.get("analyst.requested")
        if first is None:
            raise KeyError(request_id)
        done = events.get("analyst.completed") or events.get("analyst.failed")
        status = "completed" if "analyst.completed" in events else "failed" if done else "uncertain"
        return {"request_id": request_id, "case_id": first["case_id"], "action": first["details"]["request"]["action"],
                "actor": first["actor"], "executor": first["details"]["executor"], "status": status,
                "completion_verified": status == "completed",
                "last_phase": "completed" if done else "started" if "analyst.started" in events else "requested",
                "result": done["details"].get("result") if done else None, "error": done["details"].get("error") if done else None,
                "may_have_effects": "analyst.started" in events, "recorded_at": (done or first)["recorded_at"]}

    def pending_events(self, limit=100):
        return [json.loads(r[0]) for r in self.db.execute(
            "SELECT a.payload FROM audit_events a JOIN outbox o ON o.event_id=a.event_id WHERE o.acknowledged_at IS NULL "
            "ORDER BY a.case_id,a.sequence LIMIT ?", (limit,))]

    def acknowledge(self, event_ids):
        for event_id in event_ids:
            if not self.db.execute("UPDATE outbox SET acknowledged_at=COALESCE(acknowledged_at,?) WHERE event_id=?", (now(), event_id)).rowcount:
                raise KeyError(event_id)


class FakeRuntime:
    def __init__(self, store, agent_id=AGENT, gateway_config=None):
        self.store, self.actor, self.request_id = store, None, None
        self.config = {"agent_id": agent_id, "m6_gateway": {"enabled": True, **(gateway_config or {})}}

    def boot_id(self):
        return "boot-1"

    @contextlib.contextmanager
    def transaction(self):
        yield {"cases": {}, "resources": {}}


class FakeEndpoint:
    def __init__(self, key=KEY, agent_id=AGENT, clock=None, gateway_config=None):
        self.store = FakeStore()
        self.runtime = FakeRuntime(self.store, agent_id, gateway_config)
        self.gateway = lib.M6Gateway(self.runtime, key, **({"clock": clock} if clock else {}))
        self.executed, self.calls = [], []
        self.gateway._execute = self._execute  # replace ONLY the execution of a response action

    def _execute(self, state, case_id, action, params):
        self.executed.append((case_id, action, {k: v for k, v in params.items() if k != "reason"}))
        return {"operation_id": params.get("operation_id") or "op-1", "process_state": "REVIEW"}

    def transport(self, message):
        packet = json.loads(message)
        self.calls.append((packet["method"], packet["principal"]["type"]))
        return lib.canonical(self.gateway.handle(packet))

    def count(self, method):
        return sum(1 for m, _ in self.calls if m == method)


def flaky(endpoint, *, before=0, after=0, methods=("request_action",)):
    """Transport that fails like a dropped/timed-out SSH session: `before` = request never reaches M5, `after` = M5 acts
    but the answer is lost."""
    state = {"before": before, "after": after}

    def transport(message):
        method = json.loads(message)["method"]
        if method in methods and state["before"] > 0:
            state["before"] -= 1
            raise lib.GatewayError("transport_uncertain", "SSH unavailable; check action status before retrying")
        out = endpoint.transport(message)
        if method in methods and state["after"] > 0:
            state["after"] -= 1
            raise lib.GatewayError("transport_uncertain", "SSH unavailable; check action status before retrying")
        return out
    return transport


def make_config(tmp_path, roles=("analyst",), key=KEY, **overrides):
    key_file = tmp_path / "gateway.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    values = dict(host="m5.example.test", user="m6svc", identity_file=str(tmp_path / "id"), known_hosts_file=str(tmp_path / "known_hosts"),
                  key_file=str(key_file), agent_id=AGENT, analyst_id="analyst.one", analyst_roles=tuple(roles), data_dir=str(tmp_path / "data"))
    values.update(overrides)
    return M5GatewayConfig(**values)


def make_gateway(tmp_path, endpoint, roles=("analyst",), transport=None, clock=None, **overrides):
    config = make_config(tmp_path, roles, **overrides)
    return M5Gateway(config, M6Store(config.data_dir), transport=transport or endpoint.transport, clock=clock)
