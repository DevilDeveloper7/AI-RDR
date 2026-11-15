"""Event delivery from M5 to M6: outbox() -> save in M6 -> acknowledge().

Rules enforced here:
  * events are fetched with the SERVICE principal (role 'connector'); M5 refuses outbox/acknowledge for a user identity;
  * an event is acknowledged only AFTER M6 has durably stored it (or already holds an identical copy);
  * if storing fails nothing is acknowledged, so M5 keeps the events and delivers them again;
  * if the acknowledgement fails the stored events are harmless: the next poll re-delivers them and they are recognised as duplicates;
  * an event id that arrives again with DIFFERENT content is never overwritten and never acknowledged.
"""
from ..base import IntegrationError

ACK_CHUNK = 100  # M5 accepts 1-100 ids per acknowledge call


def _valid(e):
    return (isinstance(e, dict) and e.get("schema_version") == 1 and isinstance(e.get("event_id"), str) and e["event_id"].strip()
            and isinstance(e.get("event_type"), str) and e["event_type"] and (e.get("case_id") is None or isinstance(e["case_id"], str))
            and (e.get("case_sequence") is None or (type(e["case_sequence"]) is int and e["case_sequence"] >= 0)))


class EventDelivery:
    def __init__(self, gateway, store):
        self.gateway, self.store = gateway, store

    def poll_once(self, limit=100):
        report = {"fetched": 0, "stored": 0, "duplicates": 0, "invalid": 0, "conflicts": 0, "acknowledged": 0, "ack_error": None}
        raw = self.gateway.outbox(limit)
        items = raw.get("items") if isinstance(raw, dict) else None
        if not isinstance(items, list):
            from ..base import MalformedResponse
            raise MalformedResponse("M5 outbox returned an unexpected response.")
        report["fetched"] = len(items)
        events = [e for e in items if _valid(e)]
        report["invalid"] = len(items) - len(events)
        if not events:
            return report
        outcome = self.store.save_events(events)  # raises on a storage failure -> nothing below runs -> nothing is acknowledged
        report["stored"] = sum(v == "new" for v in outcome.values())
        report["duplicates"] = sum(v == "duplicate" for v in outcome.values())
        report["conflicts"] = sum(v == "conflict" for v in outcome.values())
        ackable = [event_id for event_id, v in outcome.items() if v in ("new", "duplicate")]
        for i in range(0, len(ackable), ACK_CHUNK):
            chunk = ackable[i:i + ACK_CHUNK]
            try:
                self.gateway.acknowledge(chunk)
            except IntegrationError as exc:
                report["ack_error"] = exc.message  # events stay in M5's outbox and will be re-delivered
                break
            report["acknowledged"] += len(chunk)
        return report
