"""Data contracts for what crosses each adapter boundary.

PROVISIONAL / M6 STUB: these describe what M6 expects. They are not agreed with M1-M5 yet.
Services validate every adapter result here, so a real adapter that returns
something unexpected produces a controlled 502 instead of a broken screen.
"""
from .base import MalformedResponse

NONE = type(None)
SEVERITIES = ("Critical", "High", "Medium")
RESPONSE_STATES = ("Frozen", "Isolated", "Thawed")
ACTIONS = ("freeze", "verify", "kill", "isolate", "thaw")

# field -> allowed type(s). Extra fields are tolerated.
EVENT = {"event_id": str, "timestamp": str, "source": str, "event_type": str, "host": str, "details": dict}                      # M1
DETECTION = {"alert_id": str, "severity": str, "host": str, "process": str, "activity": str, "timestamp": str,
             "threshold_exceeded_at": str, "prediction": str, "confidence": (int, float)}                                         # M2
SHAP = {"model": str, "ransomware_likelihood": (int, float), "explained_at": str, "summary": str, "features": list}           # M2
TRIGGER = {"alert_id": str, "severity": str, "host": str, "process": str, "honey_file": str, "event": str,
           "activity": str, "timestamp": str, "high_confidence": bool}                                                           # M3
HONEY_ITEM = {"host": str, "file": str, "location": str, "status": str, "last_event": (str, NONE), "alert_id": (str, NONE)}    # M3
INDICATOR = {"indicator": str, "type": str, "reputation": str, "source": str, "related_alert": (str, NONE),
             "last_checked": str, "notes": str, "enrichment_status": str}                                                         # M4
CASE = {"alert_id": str, "response_state": str, "verification_state": str, "history": list}                                       # M5
ACTION_RESULT = {"alert_id": str, "action": str, "result": str, "response_state": str, "verification_state": str, "timestamp": str}  # M5
AUDIT = {"timestamp": str, "event": str, "detail": str, "alert_id": str}                                                          # M5


def _check(name, payload, spec):
    if not isinstance(payload, dict):
        raise MalformedResponse(f"{name} returned something that is not an object.")
    for field, types in spec.items():
        if field not in payload or not isinstance(payload[field], types) or (types is str and not payload[field]):
            raise MalformedResponse(f"{name} returned a malformed response (bad or missing '{field}').")
    return payload


def validate_event(e):
    return _check("M1", e, EVENT)


def validate_detection(d):
    _check("M2", d, DETECTION)
    if d["severity"] not in SEVERITIES:
        raise MalformedResponse("M2 returned an unknown severity.")
    return d


def validate_shap(s):
    _check("M2", s, SHAP)
    if not all(isinstance(f, dict) and isinstance(f.get("feature"), str) and isinstance(f.get("value"), (int, float)) for f in s["features"]):
        raise MalformedResponse("M2 returned a malformed SHAP response (bad feature list).")
    return s


def validate_trigger(t):
    _check("M3", t, TRIGGER)
    if t["severity"] not in SEVERITIES:
        raise MalformedResponse("M3 returned an unknown severity.")
    return t


def validate_honey_item(i):
    return _check("M3", i, HONEY_ITEM)


def validate_indicator(i):
    return _check("M4", i, INDICATOR)


def validate_case(c):
    _check("M5", c, CASE)
    if c["response_state"] not in RESPONSE_STATES:
        raise MalformedResponse("M5 returned an unknown response state.")
    if not all(isinstance(h, dict) and isinstance(h.get("timestamp"), str) and isinstance(h.get("event"), str) for h in c["history"]):
        raise MalformedResponse("M5 returned a malformed response history.")
    return c


def validate_action_result(r):
    _check("M5", r, ACTION_RESULT)
    if r["response_state"] not in RESPONSE_STATES:
        raise MalformedResponse("M5 returned an unknown response state.")
    return r


def validate_audit(a):
    return _check("M5", a, AUDIT)
