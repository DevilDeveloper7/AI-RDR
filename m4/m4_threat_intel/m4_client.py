"""Client helper for other modules (M5 case manager, M6 dashboard).

    from m4_threat_intel.m4_client import enrich
    ti = enrich("hash", sha256, alert_id="A-1001")

Always returns a contract-shaped dict and NEVER raises. If M4 is down, slow
or broken, the result is verdict "unknown" with `error` set: never "clean".

How M5 should use the verdict (threat intelligence is CONTEXT, not the
deciding signal; response is decided by M2/M3, Final Doc section 10):
  malicious  -> attach to the case and raise its priority in the analyst view
  suspicious -> attach as supporting context
  unknown    -> attach as "no intelligence"; do NOT treat as safe
  clean      -> locally allowlisted; still do not override an M2/M3 detection
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

DEFAULT_M4_URL = "http://127.0.0.1:5004"


def unknown_result(alert_id: str, ioc_type: str, value: str, error: str) -> Dict[str, Any]:
    return {"alert_id": alert_id, "type": ioc_type, "value": value, "verdict": "unknown",
            "score": 0, "sources": [], "tags": [], "cached": False, "error": error,
            "details": [], "latency_ms": 0.0,
            "enriched_at": datetime.now(timezone.utc).isoformat()}


def enrich(ioc_type: str, value: str, alert_id: str, timeout: float = 5.0,
           base_url: str = DEFAULT_M4_URL, session: Optional[Any] = None) -> Dict[str, Any]:
    """Synchronous lookup through M4's /enrich. Never raises."""
    http = session or requests
    try:
        resp = http.post(base_url.rstrip("/") + "/enrich", timeout=timeout,
                         json={"alert_id": alert_id, "type": ioc_type, "value": value})
    except requests.Timeout:
        return unknown_result(alert_id, ioc_type, value, "M4 timeout")
    except requests.RequestException as exc:
        return unknown_result(alert_id, ioc_type, value, f"M4 unreachable ({type(exc).__name__})")
    if resp.status_code != 200:
        return unknown_result(alert_id, ioc_type, value, f"M4 returned HTTP {resp.status_code}")
    try:
        body = resp.json()
    except ValueError:
        return unknown_result(alert_id, ioc_type, value, "M4 returned invalid JSON")
    if not isinstance(body, dict) or body.get("verdict") not in (
            "malicious", "suspicious", "unknown", "clean"):
        return unknown_result(alert_id, ioc_type, value, "M4 returned an unexpected response")
    return body


def enrich_for_m5(ioc_type: str, value: str, alert_id: str, timeout: float = 5.0,
                  base_url: str = DEFAULT_M4_URL, session: Optional[Any] = None,
                  allow_synthetic: bool = False) -> Optional[Dict[str, Any]]:
    """Lookup and return the record for M5's bundle["threat_intel"] (never raises).

    Returns None for md5/sha1/domain (M5 has no contract for them): add nothing
    to the bundle. If M4 is down the record has status "unavailable".
    """
    from .m5_adapter import to_m5_record
    return to_m5_record(enrich(ioc_type, value, alert_id, timeout, base_url, session),
                        allow_synthetic=allow_synthetic)
