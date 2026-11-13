"""REAL M3 adapter: normalises M3 honeyfile events into M6's honey-file trigger contract.

IMPORTANT - EVENT TRANSPORT NOT CONNECTED YET
M3 currently has no API or OpenSearch writer (events exist only as console output / in-process Alert
objects), and no transport has been agreed. This adapter therefore does NOT fetch anything by itself.
It takes an `event_source`: a function that returns a list of raw M3 event dicts. Until one is supplied,
M3_MODE=real reports M3 as Failed ("not connected") and shows NO M3 alerts. It never falls back to mock alerts.

Raw M3 event (decoy_registry / m3_checkpoint3.Alert): decoy_id, path, operation, event_flags, time, details.
  time     local wall-clock "YYYY-MM-DD HH:MM:SS" with NO timezone. M6 keeps it as an ISO string WITHOUT a "Z"
           and labels it "timezone not provided by M3". No timezone is assumed or added.
  alert_id M3 sends no event ID (decoy_id identifies the decoy, not the event). M6 derives "A-M3-<12 hex>" from a
           SHA-1 of decoy_id|path|operation|time|event_flags|details (details as key-sorted JSON), so the same event
           always gets the same ID and events differing only in details (e.g. a different rename target) get different IDs.
  host / process  M3 supplies neither (inotify has no PID) -> "Unattributed".
  severity / response state  belong to M5 Risk Fusion -> severity stays None (shown as "Unrated").
M3 exposes no registry/watcher status feed, so the Honey Files status page keeps the existing SAMPLE data, labelled
as mock (status_source="mock") with the watcher status "Unavailable (sample data)". It is never shown as live M3 information.
"""
import copy
import hashlib
import json
import os
from datetime import datetime, timezone

from ...mock import load_json
from ..base import IntegrationError, IntegrationTimeout, IntegrationUnavailable, MalformedResponse
from . import M3Adapter

SOURCE = "m3-events"
UNATTRIBUTED = "Unattributed"
OPERATIONS = ("READ", "WRITE", "DELETE", "RENAME", "MOVE_OUT", "MOVE_IN")
TZ_MISSING = "not provided by M3"


def _flag(f):
    if isinstance(f, bool) or not isinstance(f, (str, int)) or f == "":
        raise ValueError("bad event flag")
    return str(f)


def _timestamp(value):
    """M3 'time' -> (iso string, timezone note). Naive times stay naive; nothing is assumed."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("missing time")
    text = value.strip()
    try:
        dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))  # only for a future writer that sends an offset
    if dt.tzinfo is None:
        return dt.strftime("%Y-%m-%dT%H:%M:%S"), TZ_MISSING
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "UTC (converted from the offset sent by the source)"


def normalize_event(raw):
    """One raw M3 event -> M6 trigger dict (contracts.TRIGGER plus source/m3). Raises ValueError if unusable."""
    if not isinstance(raw, dict):
        raise ValueError("event is not an object")
    decoy_id, path, op, flags, details = raw.get("decoy_id"), raw.get("path"), raw.get("operation"), raw.get("event_flags"), raw.get("details")
    if not (isinstance(decoy_id, str) and decoy_id and isinstance(path, str) and path):
        raise ValueError("missing decoy_id or path")
    if op not in OPERATIONS:
        raise ValueError("unknown operation")
    if not isinstance(flags, list):
        raise ValueError("event_flags is not a list")
    if details is not None and not isinstance(details, (dict, str)):
        raise ValueError("bad details")
    flag_names = [_flag(f) for f in flags]
    ts, tz_note = _timestamp(raw.get("time"))
    details_repr = json.dumps(details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)  # key order never matters
    ident = "|".join([decoy_id, path, op, str(raw.get("time")), ",".join(flag_names), details_repr])
    file_name = os.path.basename(path) or path
    return {
        "alert_id": "A-M3-" + hashlib.sha1(ident.encode("utf-8")).hexdigest()[:12],
        "severity": None,  # M5 Risk Fusion owns severity and risk classification
        "host": UNATTRIBUTED, "process": UNATTRIBUTED,  # M3 provides neither
        "honey_file": path,
        "event": ", ".join(flag_names) or op,
        "activity": f"Registered honeyfile {decoy_id} triggered: {op} on {file_name}",
        "timestamp": ts,
        "high_confidence": False,  # M3 asserts no confidence level; M5 decides risk
        "source": SOURCE,
        "m3": {"decoy_id": decoy_id, "path": path, "file_name": file_name, "operation": op, "event_flags": flag_names,
               "details": copy.deepcopy(details) if details else {}, "time_raw": raw.get("time"), "timestamp_timezone": tz_note,
               "raw": copy.deepcopy(raw)},
    }


class RealM3(M3Adapter):
    kind = "real"

    def __init__(self, base_url="", event_source=None):
        self._source = event_source  # callable() -> list of raw M3 event dicts; supplied once the transport exists
        self.skipped = 0  # raw events ignored in the last read because they were malformed

    def set_event_source(self, event_source):
        self._source = event_source

    def _events(self):
        if self._source is None:
            raise IntegrationUnavailable("M3 event transport is not connected yet (M3 has no API or OpenSearch writer). No M3 alerts are shown.")
        try:
            raw = self._source()
        except IntegrationError:
            raise
        except TimeoutError:
            raise IntegrationTimeout("The M3 event source did not answer in time.")
        except (OSError, ConnectionError):
            raise IntegrationUnavailable("The M3 event source is not reachable.")
        if not isinstance(raw, list):
            raise MalformedResponse("The M3 event source returned something that is not a list of events.")
        out, self.skipped = [], 0
        for r in raw:
            try:
                out.append(normalize_event(r))
            except (ValueError, TypeError, OverflowError):
                self.skipped += 1
        if raw and not out:
            raise MalformedResponse("M3 events were received, but none were valid.")
        return out

    def health(self):
        n = len(self._events())
        note = "Honey-file status page uses mock data (M3 exposes no registry or watcher status)."
        if self.skipped:
            return {"status": "Warning", "detail": f"{n} M3 events read, {self.skipped} malformed ignored. {note}"}
        return {"status": "Connected", "detail": f"{n} M3 honeyfile events read. {note}"}

    def list_triggers(self):
        return sorted(self._events(), key=lambda t: t["timestamp"], reverse=True)  # newest first (wall-clock order for naive times)

    def list_honey_files(self):
        """Status page data: M3 provides no registry/watcher feed, so this is the existing SAMPLE data, labelled as mock.
        The watcher status is unknown, so it is NOT reported as running."""
        data = load_json("honey_files.json")
        return {"items": copy.deepcopy(data["items"]), "activity": copy.deepcopy(data["activity"]),
                "watcher_status": "Unavailable (sample data)", "status_source": "mock",
                "status_note": "M3 provides no registry or watcher status feed; items and activity are provisional sample data, not live M3 information."}