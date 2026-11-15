"""M5 event delivery: outbox() -> stored in M6 -> acknowledge(). MOCKED M5 transport (M5's real gateway code, fake store)."""
import json
import sqlite3

import pytest

from app.integrations.base import IntegrationUnavailable, MalformedResponse
from app.integrations.m5.delivery import EventDelivery
from app.integrations.m5.gateway import M5Forbidden
from app.integrations.m5.state_store import M6Store
from app.integrations.m5.vendor import ai_rdr_m6 as lib
from m5_fake_endpoint import AGENT, KEY, FakeEndpoint, flaky, install_aicm_stub, make_gateway


@pytest.fixture(autouse=True)
def _aicm(monkeypatch):
    install_aicm_stub(monkeypatch)


@pytest.fixture()
def ep():
    e = FakeEndpoint()
    e.store.add_case("case-1")
    e.store.add_case("case-2")
    e.store.risk_event("case-1", {"score": 5})
    return e  # 3 events in the outbox: two case.created and one risk.decided


@pytest.fixture()
def gw(tmp_path, ep):
    return make_gateway(tmp_path, ep)


def pending(ep):
    return len(ep.store.pending_events(1000))


def test_events_are_stored_then_acknowledged(gw, ep):
    report = EventDelivery(gw, gw.store).poll_once()
    assert report == {"fetched": 3, "stored": 3, "duplicates": 0, "invalid": 0, "conflicts": 0, "acknowledged": 3, "ack_error": None}
    assert gw.store.count_events() == 3 and pending(ep) == 0
    assert [e["event_type"] for e in gw.store.events_for_case("case-1")] == ["case.created", "risk.decided"]
    assert EventDelivery(gw, gw.store).poll_once()["fetched"] == 0  # nothing left


def test_an_event_is_acknowledged_only_after_it_is_stored(tmp_path, ep):
    store = M6Store(tmp_path / "d")
    seen = []
    inner = ep.transport

    def spy(message):
        packet = json.loads(message)
        if packet["method"] == "acknowledge":
            seen.append((len(packet["params"]["event_ids"]), store.count_events()))  # events already in M6's database at ack time
        return inner(message)
    gw = make_gateway(tmp_path, ep, transport=spy)
    gw.store = store
    EventDelivery(gw, store).poll_once()
    assert seen == [(3, 3)]


def test_a_storage_failure_acknowledges_nothing_and_loses_nothing(gw, ep, monkeypatch):
    def broken(events):
        raise sqlite3.OperationalError("disk full")
    monkeypatch.setattr(gw.store, "save_events", broken)
    with pytest.raises(sqlite3.OperationalError):
        EventDelivery(gw, gw.store).poll_once()
    assert ep.count("acknowledge") == 0 and pending(ep) == 3
    monkeypatch.undo()
    assert EventDelivery(gw, gw.store).poll_once()["acknowledged"] == 3 and pending(ep) == 0  # recovered on the next poll


def test_save_is_all_or_nothing(tmp_path):
    store = M6Store(tmp_path / "d")
    good = {"schema_version": 1, "event_id": "e1", "case_id": "c", "case_sequence": 1, "event_type": "x"}
    bad = {"schema_version": 1, "event_id": "e2", "case_id": "c", "case_sequence": 2}  # no event_type
    with pytest.raises(Exception):
        store.save_events([good, bad])
    assert store.count_events() == 0


def test_lost_acknowledgement_means_redelivery_without_duplicates(tmp_path, ep):
    gw = make_gateway(tmp_path, ep, transport=flaky(ep, before=1, methods=("acknowledge",)))
    first = EventDelivery(gw, gw.store).poll_once()
    assert first["stored"] == 3 and first["acknowledged"] == 0 and first["ack_error"] and pending(ep) == 3
    second = EventDelivery(gw, gw.store).poll_once()
    assert second["duplicates"] == 3 and second["stored"] == 0 and second["acknowledged"] == 3 and pending(ep) == 0
    assert gw.store.count_events() == 3


def test_unreachable_m5_stops_cleanly(tmp_path, ep):
    gw = make_gateway(tmp_path, ep, transport=flaky(ep, before=1, methods=("outbox",)))
    with pytest.raises(IntegrationUnavailable):
        EventDelivery(gw, gw.store).poll_once()
    assert gw.store.count_events() == 0


def test_changed_content_for_a_known_event_id_is_never_overwritten_or_acknowledged(tmp_path, ep):
    gw = make_gateway(tmp_path, ep)
    store = gw.store
    event = ep.store.pending_events(1)[0]
    store.save_events([{**event, "details": {"tampered": True}}])  # M6 already holds different content under this id
    report = EventDelivery(gw, store).poll_once()
    assert report["conflicts"] == 1 and report["stored"] == 2 and report["acknowledged"] == 2
    assert ep.store.db.execute("SELECT acknowledged_at FROM outbox WHERE event_id=?", (event["event_id"],)).fetchone()[0] is None
    assert store.events_for_case(event["case_id"])[0]["details"] == {"tampered": True}


def test_malformed_events_are_skipped_not_acknowledged(tmp_path, ep):
    class Odd:
        def outbox(self, limit=100):
            return {"items": [{"event_id": "x"}, "junk", {"schema_version": 2, "event_id": "y", "event_type": "t"},
                              {"schema_version": 1, "event_id": "ok", "event_type": "t", "case_id": None, "case_sequence": 1}]}

        def acknowledge(self, ids):
            self.acked = ids
    odd = Odd()
    store = M6Store(tmp_path / "d")
    report = EventDelivery(odd, store).poll_once()
    assert report["invalid"] == 3 and report["stored"] == 1 and odd.acked == ["ok"]


@pytest.mark.parametrize("answer", [{}, {"items": "no"}, []])
def test_malformed_outbox_answer(tmp_path, answer):
    class Bad:
        def outbox(self, limit=100):
            return answer
    with pytest.raises(MalformedResponse):
        EventDelivery(Bad(), M6Store(tmp_path / "d")).poll_once()


def test_acknowledgements_are_sent_in_chunks_of_at_most_100(tmp_path):
    ep = FakeEndpoint()
    ep.store.add_case("big")
    for _ in range(149):
        ep.store.event("big", "response.state_changed")
    gw = make_gateway(tmp_path, ep)
    delivery = EventDelivery(gw, gw.store)
    assert delivery.poll_once(limit=100)["acknowledged"] == 100
    assert delivery.poll_once(limit=100)["acknowledged"] == 50 and pending(ep) == 0


def test_delivery_uses_the_service_principal_and_an_analyst_cannot_deliver(gw, ep):
    EventDelivery(gw, gw.store).poll_once()
    assert {p for m, p in ep.calls if m in ("outbox", "acknowledge")} == {"service"}
    analyst = lib.M5Client(ep.transport, KEY, AGENT, {"type": "user", "id": "a", "roles": ["analyst"]})
    with pytest.raises(lib.GatewayError) as err:
        analyst.acknowledge(["anything"])
    assert err.value.code == "forbidden"
    viewer_service = lib.M5Client(ep.transport, KEY, AGENT, {"type": "service", "id": "svc", "roles": ["viewer"]})
    with pytest.raises(lib.GatewayError):
        viewer_service.outbox()  # a service identity without the 'deliver' permission is refused too


def test_events_survive_an_m6_restart(tmp_path, ep):
    EventDelivery(make_gateway(tmp_path, ep), M6Store(tmp_path / "data")).poll_once()
    assert M6Store(tmp_path / "data").count_events() == 3
