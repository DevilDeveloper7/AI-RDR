"""Translate an M4 enrichment result into the INDICATOR record M6 shows.

M6 contract (m6/backend/app/integrations/contracts.py, INDICATOR): indicator,
type, reputation, source, related_alert (str or None), last_checked, notes,
enrichment_status. Enrichment is context only, never the detection decision.

  M4 verdict -> reputation: malicious Malicious | suspicious Suspicious |
                            clean Clean | unknown Unknown
  enrichment_status: "unavailable" when the lookup failed (error set and the
                     verdict is not malicious), "enriched" when a source
                     answered or the allowlist matched, else "no_data".
"""
from typing import Any, Dict, Optional

from .m5_adapter import _checked_at, _is_synthetic
from .recent import NOT_LOGGED_PREFIX

_HASH_LABELS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_REPUTATION = {"malicious": "Malicious", "suspicious": "Suspicious",
               "clean": "Clean", "unknown": "Unknown"}
_SOURCE_LABELS = {
    "malwarebazaar": "abuse.ch MalwareBazaar", "urlhaus": "abuse.ch URLhaus",
    "threatfox": "abuse.ch ThreatFox", "abusech": "abuse.ch", "otx": "AlienVault OTX",
    "local_allowlist": "Internal allowlist",
}


def _type_label(ioc_type: Any, value: Any) -> str:
    if ioc_type == "ip":
        return "IP address"
    if ioc_type == "domain":
        return "Domain"
    return _HASH_LABELS.get(len(value) if isinstance(value, str) else 0, "Hash")


def _source_label(sources: Any) -> str:
    labels = []
    for name in sources or []:
        name = str(name)
        mock = name.startswith("mock_")
        label = _SOURCE_LABELS.get(name[5:] if mock else name, name)
        labels.append(label + (" (mock)" if mock else ""))
    return ", ".join(labels) if labels else "M4 threat intelligence"


def _notes(result: Dict[str, Any], verdict: str) -> str:
    score = result.get("score", 0)
    tags = ", ".join(str(t) for t in result.get("tags") or [] if t != "MOCK-DATA")
    if verdict == "malicious":
        text = f"Reported malicious by threat intelligence (score {score})."
    elif verdict == "suspicious":
        text = f"Low-confidence suspicious reputation (score {score})."
    elif verdict == "clean":
        text = "On the local allowlist."
    else:
        text = "No reputation data returned. This is not proof that the indicator is safe."
    if tags:
        text += f" Tags: {tags}."
    if verdict == "unknown":      # e.g. "non-routable IP: not sent to external services"
        local = [d["note"] for d in result.get("details") or []
                 if isinstance(d, dict) and d.get("note")]
        if local:
            text += f" {local[0][0].upper()}{local[0][1:]}."
    if result.get("error"):
        text += f" Lookup incomplete: {result['error']}."
    if _is_synthetic(result):
        text += " MOCK DATA."
    return text + " Context only; the detection decision is made by M2/M3."


def to_m6_indicator(result: Dict[str, Any]) -> Dict[str, Any]:
    verdict = result.get("verdict") if result.get("verdict") in _REPUTATION else "unknown"
    failed = bool(result.get("error")) and verdict != "malicious"
    if failed:
        status = "unavailable"
    elif result.get("sources") or verdict == "clean":
        status = "enriched"
    else:
        status = "no_data"
    alert_id: Optional[str] = result.get("alert_id")
    related = alert_id if (isinstance(alert_id, str) and alert_id.strip()
                           and not alert_id.startswith(NOT_LOGGED_PREFIX)) else None
    return {
        "indicator": result.get("value"),
        "type": _type_label(result.get("type"), result.get("value")),
        "reputation": _REPUTATION[verdict],
        "source": _source_label(result.get("sources")),
        "related_alert": related,
        "last_checked": _checked_at(result),
        "notes": _notes(result, verdict),
        "enrichment_status": status,
    }
