"""REAL M4 adapter: reads threat-intelligence context from the M4 Flask service over HTTP.

M4 endpoints used (verified in the M4 source, m4_threat_intel/app.py):
  GET  /health           -> {"status": "ok", "mode": "MOCK"|"live", "abusech_key": "set"|"missing", "otx_key": ...}
  GET  /indicators?limit -> {"items": [INDICATOR, ...], "meta": {"is_mock": bool, "role": "enrichment only"}}
  POST /enrich/m6        -> one INDICATOR record. Body {"alert_id", "type": "hash"|"ip"|"domain", "value"}.
                            400 = M4 rejected the indicator.
M4 already answers in M6's INDICATOR shape, so nothing is translated here. M4 has no authentication and listens on
127.0.0.1:5004 by default; M6 only reads from it.

M4 is context only. This adapter has no response/containment path, and M4 reputation never authorises an action.

Configuration (environment):
  M4_MODE=real                 select this adapter (default is mock)
  M4_BASE_URL                  default http://127.0.0.1:5004
  M4_TIMEOUT                   seconds per request, default 10
"""
import ipaddress
import json
import os
import re
import socket
from urllib import error, request
from urllib.parse import quote

from .. import contracts as C
from ..base import IntegrationTimeout, IntegrationUnavailable, MalformedResponse
from . import M4Adapter

DEFAULT_URL = "http://127.0.0.1:5004"
LOOKUP_ALERT_ID = "m6-lookup"  # M4 does not remember lookups made under this id, so they never show up as an alert's indicator
LIST_LIMIT = 100  # M6's /threat-intelligence accepts at most 100
_HASH = re.compile(r"^[0-9A-Fa-f]+$")


def _indicator_type(value):
    """M4 request type for a bare indicator string: hash, ip or domain (M4 validates it again)."""
    v = value.strip()
    if len(v) in (32, 40, 64) and _HASH.match(v):
        return "hash"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        return "domain"


class RealM4(M4Adapter):
    kind = "real"

    def __init__(self, base_url="", timeout=None):
        self._base = (base_url or "").strip().rstrip("/") or DEFAULT_URL
        try:
            self._timeout = float(timeout if timeout is not None else os.environ.get("M4_TIMEOUT", "10"))
        except ValueError:
            raise ValueError("M4_TIMEOUT must be a number of seconds.")
        self.last_is_mock = True  # what M4 said about its own data in the last /indicators answer (unknown -> mock)
        self.skipped = 0  # items ignored in the last list because they broke the INDICATOR contract

    # ------------------------------------------------------------------ transport
    def _call(self, method, path, body=None, soft=()):
        """Returns (status, parsed JSON). Statuses listed in `soft` come back instead of raising (parsed body may be None)."""
        data = json.dumps(body).encode() if body is not None else None
        req = request.Request(self._base + path, data=data, method=method,
                              headers={"Accept": "application/json", **({"Content-Type": "application/json"} if data else {})})
        try:
            with request.urlopen(req, timeout=self._timeout) as res:
                status, raw = res.status, res.read()
        except error.HTTPError as exc:
            if exc.code in soft:
                return exc.code, None
            raise IntegrationUnavailable(f"M4 returned HTTP {exc.code}.")
        except (socket.timeout, TimeoutError):
            raise IntegrationTimeout("M4 did not answer in time.")
        except error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise IntegrationTimeout("M4 did not answer in time.")
            raise IntegrationUnavailable("M4 is not reachable. Is it running (python -m m4_threat_intel.app)?")
        except (OSError, ValueError):
            raise IntegrationUnavailable("M4 is not reachable.")
        try:
            return status, json.loads(raw)
        except ValueError:
            raise MalformedResponse("M4 returned a response that is not JSON.")

    # ------------------------------------------------------------------ M4Adapter
    def health(self):
        _, h = self._call("GET", "/health")
        if not isinstance(h, dict) or h.get("status") != "ok" or h.get("mode") not in ("MOCK", "live"):
            raise MalformedResponse("M4 /health returned an unexpected response.")
        if h["mode"] == "MOCK":
            return {"status": "Warning", "detail": "M4 is reachable but running in MOCK provider mode: indicators are lab data, not real threat intelligence."}
        missing = [name for name, key in (("abuse.ch", "abusech_key"), ("OTX", "otx_key")) if h.get(key) != "set"]
        if missing:
            return {"status": "Warning", "detail": f"M4 is live but the API key for {', '.join(missing)} is missing, so lookups are incomplete."}
        return {"status": "Connected", "detail": "M4 is live with both threat-intelligence keys set. Enrichment is context only."}

    def list_indicators(self):
        _, body = self._call("GET", f"/indicators?limit={LIST_LIMIT}")
        items, meta = (body.get("items"), body.get("meta")) if isinstance(body, dict) else (None, None)
        if not isinstance(items, list) or not isinstance(meta, dict):
            raise MalformedResponse("M4 /indicators returned an unexpected response (need 'items' and 'meta').")
        self.last_is_mock = bool(meta.get("is_mock", True))
        good, self.skipped = [], 0
        for item in items:
            try:
                good.append(C.validate_indicator(item))
            except MalformedResponse:
                self.skipped += 1
        if items and not good:
            raise MalformedResponse("M4 returned indicators, but none matched M6's indicator contract.")
        return good

    def enrich(self, indicator):
        if not isinstance(indicator, str) or not indicator.strip():
            return None
        value = indicator.strip()
        status, item = self._call("POST", "/enrich/m6", {"alert_id": LOOKUP_ALERT_ID, "type": _indicator_type(value), "value": value}, soft=(400, 422))
        if status in (400, 422):
            return None  # M4 refused the indicator (not a hash, IP or domain)
        return C.validate_indicator(item)