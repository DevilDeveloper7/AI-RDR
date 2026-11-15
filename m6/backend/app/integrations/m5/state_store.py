"""M6's own durable state for the M5 link (stdlib sqlite3, one file in M6_DATA_DIR).

  m5_events          every M5 audit event M6 has received. An event is acknowledged to M5 ONLY after it is in here.
  m5_action_intents  every analyst action M6 intends to send, saved BEFORE it is sent, so a crash or a timeout can be
                     resolved by asking M5 about the same request instead of guessing.
"""
import contextlib
import hashlib
import json
import os
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS m5_events (
 event_id TEXT PRIMARY KEY, case_id TEXT, case_sequence INTEGER, event_type TEXT NOT NULL,
 recorded_at TEXT, fingerprint TEXT NOT NULL, payload TEXT NOT NULL, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS m5_events_case ON m5_events(case_id, case_sequence);
CREATE TABLE IF NOT EXISTS m5_action_intents (
 idempotency_key TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL, case_id TEXT NOT NULL,
 action TEXT NOT NULL, params TEXT NOT NULL, status TEXT NOT NULL, result TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
"""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class M6Store:
    def __init__(self, directory, filename="m6-state.sqlite3"):
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / filename
        if not self.path.exists():
            os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600))
        with self._db() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(_SCHEMA)

    @contextlib.contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    # ------------------------------------------------------------------ events
    def save_events(self, events):
        """Store events in ONE transaction. Returns {event_id: 'new' | 'duplicate' | 'conflict'}.
        'duplicate' = already stored with identical content; 'conflict' = same id, different content (never overwritten)."""
        result = {}
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                for e in events:
                    body = canonical(e)
                    fingerprint = hashlib.sha256(body.encode()).hexdigest()
                    row = db.execute("SELECT fingerprint FROM m5_events WHERE event_id=?", (e["event_id"],)).fetchone()
                    if row is None:
                        db.execute("INSERT INTO m5_events(event_id,case_id,case_sequence,event_type,recorded_at,fingerprint,payload) "
                                   "VALUES(?,?,?,?,?,?,?)", (e["event_id"], e.get("case_id"), e.get("case_sequence"),
                                                             e["event_type"], e.get("recorded_at"), fingerprint, body))
                        result[e["event_id"]] = "new"
                    else:
                        result[e["event_id"]] = "duplicate" if row["fingerprint"] == fingerprint else "conflict"
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return result

    def events_for_case(self, case_id, after=0, limit=100):
        with self._db() as db:
            rows = db.execute("SELECT payload FROM m5_events WHERE case_id IS ? AND case_sequence>? ORDER BY case_sequence LIMIT ?",
                              (case_id, after, limit)).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def count_events(self):
        with self._db() as db:
            return db.execute("SELECT COUNT(*) FROM m5_events").fetchone()[0]

    # ------------------------------------------------------------------ action intents
    def save_intent(self, key, request_id, user_id, case_id, action, params):
        with self._db() as db:
            db.execute("INSERT INTO m5_action_intents(idempotency_key,request_id,user_id,case_id,action,params,status) VALUES(?,?,?,?,?,?,'prepared')",
                       (key, request_id, user_id, case_id, action, canonical(params)))

    def get_intent(self, key):
        with self._db() as db:
            row = db.execute("SELECT * FROM m5_action_intents WHERE idempotency_key=?", (key,)).fetchone()
        return self._intent(row)

    def update_intent(self, key, status, result=None):
        with self._db() as db:
            db.execute("UPDATE m5_action_intents SET status=?,result=?,updated_at=CURRENT_TIMESTAMP WHERE idempotency_key=?",
                       (status, canonical(result) if result is not None else None, key))

    @staticmethod
    def _intent(row):
        if row is None:
            return None
        item = dict(row)
        item["params"] = json.loads(item["params"])
        item["result"] = json.loads(item["result"]) if item["result"] else None
        return item
