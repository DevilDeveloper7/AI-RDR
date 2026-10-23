"""Input validation helpers. Everything from a request goes through these."""
import re

from flask import request

from ..errors import ApiError

ALERT_ID_RE = re.compile(r"^A-\d{1,6}$")
ACTIONS = ("freeze", "verify", "kill", "isolate", "thaw")
SEVERITIES = ("Critical", "High", "Medium")
DETECTION_TYPES = ("ML Behavioural Detection", "Honey-File Trigger")
RESPONSE_STATES = ("Frozen", "Isolated", "Thawed")
MODULES = ("m1", "m2", "m3", "m4", "m5", "m6")


def alert_id(value):
    if not ALERT_ID_RE.match(value or ""):
        raise ApiError("INVALID_ALERT_ID", "Alert ID must look like A-1234.", 400)
    return value


def action(value):
    if value not in ACTIONS:
        raise ApiError("INVALID_ACTION", f"Action must be one of: {', '.join(ACTIONS)}.", 400)
    return value


def json_body(required=False):
    body = request.get_json(silent=True)
    if body is None and not required:
        return {}
    if not isinstance(body, dict):
        raise ApiError("INVALID_BODY", "Request body must be a JSON object.", 400)
    return body


def int_arg(name, default, lo, hi):
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ApiError("INVALID_PARAMETER", f"'{name}' must be an integer.", 400)
    if not lo <= value <= hi:
        raise ApiError("INVALID_PARAMETER", f"'{name}' must be between {lo} and {hi}.", 400)
    return value


def choice_arg(name, allowed):
    value = request.args.get(name) or None
    if value is not None and value not in allowed:
        raise ApiError("INVALID_PARAMETER", f"'{name}' must be one of: {', '.join(allowed)}.", 400)
    return value


def reason(value):
    text = (value or "").strip() if isinstance(value, str) else ""
    if not 3 <= len(text) <= 500:
        raise ApiError("INVALID_REASON", "A reason of 3-500 characters is required.", 400)
    return text
