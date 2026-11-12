"""REAL M4 adapter: reads live threat-intelligence enrichment from M4's HTTP service.

M4 (m4/, Flask, default http://127.0.0.1:5004) already answers in M6's INDICATOR
shape, so this adapter only does the HTTP call and turns failures into the
controlled errors M6 understands. Standard library only (no new dependency).

  list_indicators() -> GET  /indicators?limit=100   (recent answers, newest first)
  enrich(indicator) -> POST /enrich/m6              (alert_id "m6-lookup": M4 does
                                                     not list it as an alert's indicator)
  health()          -> GET  /health

Enrichment is context only. A failed or missing lookup is never turned into
"Clean": M4 reports it as enrichment_status "unavailable" / "no_data".
"""
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request

from ..base import (IntegrationError, IntegrationTimeout, IntegrationUnavailable,
                    MalformedResponse)
from . import M4Adapter

DEFAULT_BASE_URL = "http://127.0.0.1:5004"
LOOKUP_ALERT_ID = "m6-lookup"
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def classify(indicator):
    """('hash'|'ip'|'domain', value) for an indicator string, or None."""
    value = (indicator or "").strip()
    if _HEX.match(value) and len(value) in (32, 40, 64):
        return "hash", value.lower()
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if "." in value and not value.endswith("."):
        return "domain", value.lower()
    return None


class RealM4(M4Adapter):
    kind = "real"

    def __init__(self, base_url="", timeout=5.0, limit=100):
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.limit = limit

    # ------------------------------------------------------------------ HTTP
    def _call(self, method, path, body=None):
        """Return (status, parsed JSON). Raises IntegrationError subclasses."""
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        except (socket.timeout, TimeoutError):
            raise IntegrationTimeout("M4 did not answer in time.") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise IntegrationTimeout("M4 did not answer in time.") from None
            raise IntegrationUnavailable("M4 is not reachable.") from None
        except OSError:
            raise IntegrationUnavailable("M4 is not reachable.") from None
        if status >= 500:
            raise IntegrationUnavailable(f"M4 returned HTTP {status}.")
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            raise MalformedResponse("M4 returned invalid JSON.") from None
        return status, payload

    # --------------------------------------------------------------- adapter
    def health(self):
        try:
            status, body = self._call("GET", "/health")
        except IntegrationError as exc:
            return {"status": "Failed", "detail": exc.message}
        if status != 200 or not isinstance(body, dict) or body.get("status") != "ok":
            return {"status": "Warning", "detail": "M4 answered, but its health response is unexpected."}
        if body.get("mode") != "live":
            return {"status": "Warning", "detail": "M4 is running in MOCK mode: answers are sample data."}
        missing = [name for name in ("abusech_key", "otx_key") if body.get(name) != "set"]
        if missing:
            return {"status": "Warning", "detail": "M4 is running, but a provider key is missing: "
                    + ", ".join(m.replace("_key", "") for m in missing) + "."}
        return {"status": "Connected", "detail": "M4 threat intelligence is live."}

    def list_indicators(self):
        status, body = self._call("GET", f"/indicators?limit={self.limit}")
        if status != 200 or not isinstance(body, dict) or not isinstance(body.get("items"), list):
            raise MalformedResponse("M4 returned an unexpected indicator list.")
        return body["items"]

    def enrich(self, indicator):
        kind = classify(indicator)
        if kind is None:
            return None
        status, body = self._call("POST", "/enrich/m6", {"alert_id": LOOKUP_ALERT_ID,
                                                          "type": kind[0], "value": kind[1]})
        if status in (400, 422):          # M4 refused the indicator: nothing to show
            return None
        if status != 200 or not isinstance(body, dict):
            raise MalformedResponse("M4 returned an unexpected enrichment response.")
        return body
