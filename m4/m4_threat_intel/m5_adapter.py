"""Translate an M4 enrichment result into the record M5 (risk scoring) accepts.

M5 reads `threat_intel` records from the alert bundle (ai_rdr_risk.py):

  status in unavailable | no_match | stale  -> recorded, contribution 0
  status == "match" AND malicious is True   -> weight 55, but ONLY if
      * provider is a non-empty string
      * indicator_type is "sha256" or "ip"
      * indicator equals the bundle's sha256 / src_ip
      * checked_at is timezone-aware ISO and -30 <= now - checked_at <= 900 s
  anything else                              -> invalid_ti_contract error

Mapping rules (threat intelligence is CONTEXT, never proof of safety):

  M4 malicious                      -> match   (malicious: true)
  M4 suspicious / clean / unknown   -> no_match (M4 verdict kept in m4_verdict)
  M4 unknown WITH error             -> unavailable (lookup failed; not "no match")
  md5 / sha1 / domain               -> None (M5 cannot consume them)
  synthetic (mock) data             -> unavailable unless allow_synthetic=True

`checked_at` is the ORIGINAL `enriched_at`; it is not refreshed on cache hits,
so a cached answer older than M5's 900 s window is correctly rejected by M5.
`timestamp` is deliberately NOT set (M5 uses it for a different freshness rule).
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Services that make up the "abuse.ch" provider (see enricher._hit_sources).
_ABUSECH_NAMES = {"abusech", "abuse.ch", "malwarebazaar", "urlhaus", "threatfox",
                  "yaraify", "sslbl", "feodotracker"}
_M5_INDICATOR_TYPES = ("sha256", "ip")


def _indicator_type(ioc_type: Any, value: Any) -> Optional[str]:
    """'sha256' or 'ip' when M5 can consume the indicator, else None."""
    if ioc_type == "ip":
        return "ip"
    if ioc_type == "hash" and isinstance(value, str) and len(value) == 64:
        return "sha256"
    return None


def _provider(sources: Any) -> str:
    names = {str(s).lower() for s in sources or [] if str(s).strip()}
    real = {s for s in names if not s.startswith("mock")}
    families = set()
    for name in real or names:
        bare = name[5:] if name.startswith("mock_") else name
        if bare in _ABUSECH_NAMES:
            families.add("abuse.ch")
        elif bare == "otx":
            families.add("otx")
        else:
            families.add(bare)
    return "+".join(sorted(families)) if families else "m4"


def _is_synthetic(result: Dict[str, Any]) -> bool:
    sources = [str(s).lower() for s in result.get("sources") or []]
    return "MOCK-DATA" in (result.get("tags") or []) or any(s.startswith("mock") for s in sources)


def _checked_at(result: Dict[str, Any]) -> str:
    """The original enrichment time as a Z-suffixed, timezone-aware ISO string."""
    raw = result.get("enriched_at")
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if parsed.tzinfo is None:                      # M5 rejects naive times
            parsed = parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        parsed = datetime.now(timezone.utc)            # unusable time: treat as fresh-now
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def to_m5_record(result: Dict[str, Any], *, allow_synthetic: bool = False) -> Optional[Dict[str, Any]]:
    """Return the M5 `threat_intel` record for one M4 result, or None.

    None means M5 has no contract for this indicator type (md5, sha1, domain);
    the caller must not put anything in the bundle for it.
    """
    kind = _indicator_type(result.get("type"), result.get("value"))
    if kind is None:
        return None

    verdict = result.get("verdict")
    synthetic = _is_synthetic(result)
    record: Dict[str, Any] = {
        "provider": _provider(result.get("sources")),
        "indicator_type": kind,
        "indicator": result.get("value"),
        "checked_at": _checked_at(result),
        "m4_verdict": verdict,
        "score": result.get("score", 0),
        "sources": list(result.get("sources") or []),
        "tags": list(result.get("tags") or []),
        "cached": bool(result.get("cached")),
        "alert_id": result.get("alert_id"),
    }
    if synthetic:
        record["synthetic"] = True

    if synthetic and not allow_synthetic:
        record.update(status="unavailable", reason="synthetic_data_not_allowed")
    elif result.get("error") and verdict != "malicious":
        record.update(status="unavailable", reason="lookup_failed", error=result["error"])
    elif verdict == "malicious":
        record.update(status="match", malicious=True)
    else:
        record.update(status="no_match", malicious=False)
    return record


def unavailable_record(ioc_type: str, value: str, alert_id: str, reason: str) -> Optional[Dict[str, Any]]:
    """Record for 'M4 could not be asked at all' (down, timeout, HTTP error)."""
    kind = _indicator_type(ioc_type, value)
    if kind is None:
        return None
    return {"provider": "m4", "indicator_type": kind, "indicator": value,
            "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "unavailable", "reason": reason, "m4_verdict": "unknown",
            "alert_id": alert_id}
