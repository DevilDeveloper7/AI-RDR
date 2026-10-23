"""M6 alert logic.

An alert is *assembled* here from what each module owns:
  M2 detection (ML)  or  M3 trigger (honey file)   -> what was detected
  M1 normalized events                              -> evidence
  M5 response case                                  -> response state, verification state, response history
  M4 enrichment                                     -> related indicators (context only, never required)
  M6 itself                                         -> analyst status (Open / Acknowledged)
M6 requests response actions; the M5 adapter decides the result and owns the response state.
"""
import copy
import math
from datetime import datetime, timedelta, timezone

from ..errors import ApiError
from ..integrations import contracts as C
from ..integrations.base import IntegrationError, MalformedResponse

ML, HONEY = "ML Behavioural Detection", "Honey-File Trigger"
_BEHAVIOURAL = ("behavioural.features", "syscall.summary", "fim.modified_burst")
_LIST_FIELDS = ("id", "severity", "detection_type", "host", "process", "activity", "timestamp",
                "response_state", "verification_state", "status", "source", "confidence")


def _parse(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_iso():
    return _iso(datetime.now(timezone.utc))


class AlertService:
    def __init__(self, adapters, analyst_name, seed):
        self._a = adapters  # same dict the app holds, so adapters can be swapped (tests, real modules)
        self.analyst = analyst_name
        self.meta = {"is_mock": True, "reference_time": seed["meta"]["reference_time"]}
        self._acknowledged = set(seed["acknowledged"])  # analyst status is owned by M6
        self._ack_log = []

    # ---------------------------------------------------------------- assembling alerts
    def _sources(self):
        """Detections from M2 and honey-file triggers from M3, each fetched independently.

        The two paths do not depend on each other: if one module is unavailable the other still
        works, and the failure is reported (meta.unavailable), never hidden. Returns (alerts, failures).
        """
        base, down = {}, {}
        for key, fetch in (("m2", self._ml_alerts), ("m3", self._honey_alerts)):
            try:
                base.update(fetch())
            except IntegrationError as exc:
                down[key] = exc
        if down and not base:
            raise next(iter(down.values()))  # nothing to show at all
        return base, down

    def _ml_alerts(self):
        base = {}
        for d in self._a["m2"].list_detections():
            C.validate_detection(d)
            base[d["alert_id"]] = {"id": d["alert_id"], "severity": d["severity"], "detection_type": ML, "host": d["host"],
                                   "process": d["process"], "activity": d["activity"], "timestamp": d["timestamp"],
                                   "confidence": d["confidence"], "source": "mock", "_src": d}
        return base

    def _honey_alerts(self):  # independent path: M3 -> M6, never through M2
        base = {}
        for t in self._a["m3"].list_triggers():
            C.validate_trigger(t)
            base[t["alert_id"]] = {"id": t["alert_id"], "severity": t["severity"], "detection_type": HONEY, "host": t["host"],
                                   "process": t["process"], "activity": t["activity"], "timestamp": t["timestamp"],
                                   "confidence": None, "honey_file": t["honey_file"], "source": "mock", "_src": t}
        return base

    def _compose(self, base, case):
        if case is None:
            raise MalformedResponse(f"M5 has no response case for {base['id']}.")
        item = {k: v for k, v in base.items() if k != "_src"}
        item.update(response_state=case["response_state"], verification_state=case["verification_state"],
                    status="Acknowledged" if base["id"] in self._acknowledged else "Open")
        return item

    def _all(self):
        base, down = self._sources()
        cases = {}
        for c in self._a["m5"].list_cases():
            C.validate_case(c)
            cases[c["alert_id"]] = c
        items = sorted((self._compose(b, cases.get(i)) for i, b in base.items()), key=lambda a: a["timestamp"], reverse=True)
        return items, sorted(down)

    def _require(self, alert_id):
        sources, down = self._sources()
        base = sources.get(alert_id)
        if not base:
            if down:  # it may belong to the module that is unavailable, so do not claim it does not exist
                raise next(iter(down.values()))
            raise ApiError("ALERT_NOT_FOUND", f"Alert {alert_id} was not found.", 404)
        return base

    def _case(self, alert_id):
        case = self._a["m5"].get_case(alert_id)
        return C.validate_case(case) if case else None

    # ---------------------------------------------------------------- reads
    def get(self, alert_id):
        base = self._require(alert_id)
        item = self._compose(base, self._case(alert_id))
        events, evidence_status = self._behavioural_events(base)
        item["summary"] = self._summary(item)
        item["evidence"] = self._evidence(base, events)
        item["evidence_status"] = evidence_status
        item["timeline"] = self._timeline(item, base, events, self._case(alert_id))
        item["indicators"], item["enrichment_status"] = self._indicators(alert_id)
        return item

    def _behavioural_events(self, base):
        """M1 events behind an ML alert. M1 being down must not break the alert page."""
        if base["detection_type"] != ML:
            return [], "ok"
        t = _parse(base["timestamp"])
        try:
            events = [C.validate_event(e) for e in self._a["m1"].list_events(host=base["host"], since=_iso(t - timedelta(seconds=3)), until=_iso(t + timedelta(seconds=1)))]
        except IntegrationError:
            return [], "unavailable"
        return [e for e in events if e["event_type"] in _BEHAVIOURAL and e["details"].get("process") == base["process"]], "ok"

    def _indicators(self, alert_id):
        """M4 enrichment is context only: if M4 fails, the alert still loads."""
        try:
            items = [C.validate_indicator(i) for i in self._a["m4"].list_indicators()]
        except IntegrationError:
            return [], "unavailable"
        return [i["indicator"] for i in items if i["related_alert"] == alert_id], "ok"

    @staticmethod
    def _summary(item):
        if item["detection_type"] == HONEY:
            return (f"A honey file on {item['host']} was accessed. Honey-file interaction is a high-confidence signal "
                    "and was sent directly to response without ML scoring.")
        if item["response_state"] == "Thawed":
            return (f"Behavioural activity on {item['host']} exceeded the detection threshold. "
                    f"The process was released ({item['verification_state'].lower()}).")
        return (f"Behavioural activity on {item['host']} exceeded the configured ransomware detection threshold. "
                "The process wrote and renamed files at a rate far above baseline.")

    @staticmethod
    def _evidence(base, events):
        if base["detection_type"] == HONEY:
            t = base["_src"]
            return [{"label": "Trigger", "value": "Honey file opened / modified (inotify)"}, {"label": "File", "value": t["honey_file"]},
                    {"label": "Event", "value": t["event"]}, {"label": "Model stage", "value": "Bypassed (fast path)"}]
        return [{"label": k, "value": v} for e in events for k, v in e["details"].items() if k != "process"]

    @staticmethod
    def _timeline(item, base, events, case):
        src = base["_src"]
        if item["detection_type"] == ML:
            rows = ([{"timestamp": events[0]["timestamp"], "event": "Telemetry received"}] if events else []) + [
                {"timestamp": src["timestamp"], "event": "Behavioural anomaly detected"},
                {"timestamp": src["threshold_exceeded_at"], "event": "ML threshold exceeded"}]
        else:
            rows = [{"timestamp": src["timestamp"], "event": "Honey-file event received (inotify)"},
                    {"timestamp": src["timestamp"], "event": "Fast-path alert created"}]
        rows += case["history"]  # response events come from M5
        out = [{"timestamp": r["timestamp"], "event": r["event"], "pending": False, "hot": r["event"] == "Process frozen"} for r in rows]
        if item["response_state"] == "Frozen":
            out.append({"timestamp": None, "event": "Isolation, if verification confirms", "pending": True, "hot": False})
        return out

    def events_for_alert(self, alert_id):
        """Normalized M1 events on the alert's host around the alert time (not shown in the UI yet)."""
        base = self._require(alert_id)
        t = _parse(base["timestamp"])
        events = [C.validate_event(e) for e in self._a["m1"].list_events(host=base["host"], since=_iso(t - timedelta(seconds=10)), until=_iso(t + timedelta(seconds=10)))]
        return {"alert_id": alert_id, "items": events, "meta": {"is_mock": True}}

    def summary(self, items):
        a = items
        return {"active": sum(x["response_state"] == "Frozen" for x in a),
                "critical": sum(x["severity"] == "Critical" and x["response_state"] == "Frozen" for x in a),
                "open": sum(x["status"] == "Open" for x in a), "total": len(a)}

    def facets(self, items):
        order = lambda present, ref: [x for x in ref if x in present]
        return {"hosts": sorted({x["host"] for x in items}),
                "severities": order({x["severity"] for x in items}, C.SEVERITIES),
                "detection_types": sorted({x["detection_type"] for x in items}),
                "response_states": order({x["response_state"] for x in items}, C.RESPONSE_STATES)}

    def list(self, severity=None, detection_type=None, response_state=None, host=None,
             range_minutes=None, q=None, page=1, page_size=20):
        everything, unavailable = self._all()
        ref = _parse(self.meta["reference_time"])
        needle = (q or "").strip().lower()

        def match(a):
            if severity and a["severity"] != severity: return False
            if detection_type and a["detection_type"] != detection_type: return False
            if response_state and a["response_state"] != response_state: return False
            if host and a["host"] != host: return False
            if range_minutes and (ref - _parse(a["timestamp"])).total_seconds() > range_minutes * 60: return False
            if needle and needle not in " ".join((a["id"], a["host"], a["process"], a["detection_type"])).lower(): return False
            return True

        items = [a for a in everything if match(a)]
        pages = max(1, math.ceil(len(items) / page_size))
        page = min(page, pages)
        window = items[(page - 1) * page_size: page * page_size]
        return {"items": [{k: a[k] for k in _LIST_FIELDS} for a in window], "total": len(items), "page": page,
                "page_size": page_size, "pages": pages, "summary": self.summary(everything), "facets": self.facets(everything),
                "meta": {"is_mock": True, "reference_time": self.meta["reference_time"], "unavailable": unavailable}}

    def shap(self, alert_id):
        base = self._require(alert_id)
        if base["detection_type"] != ML:
            raise ApiError("SHAP_NOT_APPLICABLE", "SHAP applies to ML detections only. Honey-file alerts bypass the ML stage.", 404)
        data = self._a["m2"].get_shap(alert_id)
        if not data:
            raise ApiError("SHAP_NOT_AVAILABLE", f"No SHAP explanation is available for {alert_id}.", 404)
        C.validate_shap(data)
        return {"alert_id": alert_id, "severity": base["severity"], "host": base["host"], **data}

    def recent_activity(self, limit):
        audit = [C.validate_audit(a) for a in self._a["m5"].list_audit(50)]  # M5's audit trail + M6's own acknowledgements
        merged = sorted(audit + self._ack_log, key=lambda r: r["timestamp"], reverse=True)[:limit]
        return {"items": copy.deepcopy(merged), "meta": {"is_mock": True}}

    # ---------------------------------------------------------------- analyst actions
    def acknowledge(self, alert_id):
        self._require(alert_id)
        if alert_id not in self._acknowledged:
            self._acknowledged.add(alert_id)
            self._ack_log.append({"timestamp": _now_iso(), "event": "Analyst acknowledgement", "detail": self.analyst, "alert_id": alert_id})
        return {"alert": self.get(alert_id), "acknowledged_by": self.analyst}

    def request_action(self, alert_id, action, reason=None, override=False):
        base = self._require(alert_id)
        m5 = self._a["m5"]
        result = C.validate_action_result(m5.request_action(
            alert_id, action, {"host": base["host"], "process": base["process"]}, self.analyst, reason, analyst_override=override))
        if override or action in ("kill", "isolate"):
            self._acknowledged.add(alert_id)
        return {"alert": self.get(alert_id), "requested_by": self.analyst, "executor": f"M5 ({m5.kind} adapter)", "result": result}

    def override(self, alert_id, reason):
        self._require(alert_id)
        case = self._case(alert_id)
        if not case or case["response_state"] != "Frozen":
            raise ApiError("INVALID_STATE", "Only a frozen process can be overridden.", 409)
        return self.request_action(alert_id, "thaw", reason, override=True)
