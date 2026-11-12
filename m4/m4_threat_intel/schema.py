"""Interface contract, indicator validation and shared data types for M4.

Contract (agreed with M1/M5/M6; see docs/interface_contract.md):

    Request : {"alert_id": str, "type": "hash"|"ip"|"domain", "value": str}
    Response: {"alert_id", "type", "value",
               "verdict": "malicious"|"suspicious"|"unknown"|"clean",
               "score": 0-100, "sources": [str], "tags": [str],
               "cached": bool, "error": str|null, "details": [...],
               "latency_ms": float, "enriched_at": ISO-8601}

"unknown" means "no evidence either way" (not found OR lookup failed).
It is NOT the same as "clean", which only comes from the local allowlist.
"""
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# --- Constants ---------------------------------------------------------------
INDICATOR_TYPES = ("hash", "ip", "domain")

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_UNKNOWN = "unknown"
VERDICT_CLEAN = "clean"
VERDICTS = (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_UNKNOWN, VERDICT_CLEAN)

# Outcome of one provider lookup.
STATUS_HIT = "hit"      # the source knows this indicator as bad
STATUS_MISS = "miss"    # the source answered: not found
STATUS_ERROR = "error"  # the lookup failed (timeout, HTTP error, bad JSON, no key...)

HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256"}
MAX_ALERT_ID_LENGTH = 200

_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidIndicator(ValueError):
    """Raised for a malformed request or indicator."""


# --- Validation / normalisation ------------------------------------------------
def normalize(ioc_type: Any, value: Any) -> str:
    """Return the canonical form of an indicator or raise InvalidIndicator.

    Canonical forms let the cache and the allowlist match regardless of case,
    whitespace, IPv6 abbreviation or a trailing dot.
    """
    if ioc_type not in INDICATOR_TYPES:
        raise InvalidIndicator(f"type must be one of: {', '.join(INDICATOR_TYPES)}")
    if not isinstance(value, str) or not value.strip():
        raise InvalidIndicator("value must be a non-empty string")
    value = value.strip()

    if ioc_type == "hash":
        value = value.lower()
        if len(value) not in HASH_KINDS or not _HEX.match(value):
            raise InvalidIndicator("hash must be hex MD5, SHA-1 or SHA-256")
        return value

    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise InvalidIndicator("not a valid IPv4/IPv6 address") from None

    value = value.lower().rstrip(".")
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or not all(_DOMAIN_LABEL.match(x) for x in labels):
        raise InvalidIndicator("not a valid domain name")
    if labels[-1].isdigit():
        raise InvalidIndicator("looks like an IP address; use type 'ip'")
    return value


def hash_kind(value: str) -> str:
    """'md5', 'sha1' or 'sha256' for an already-normalised hash."""
    return HASH_KINDS[len(value)]


def is_non_routable(ip: str) -> bool:
    """True if the address must never be sent to an external service.

    Covers private, loopback, link-local, carrier-grade NAT, multicast,
    reserved and unspecified addresses. Categories are checked explicitly
    because `is_global` alone counts multicast as global and its exact ranges
    differ between Python versions.
    """
    addr = ipaddress.ip_address(ip)
    return (
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def parse_request(data: Any) -> Tuple[str, str, str]:
    """Validate a request body; return (alert_id, type, normalised value)."""
    if not isinstance(data, dict):
        raise InvalidIndicator("body must be a JSON object")
    alert_id = data.get("alert_id")
    if not isinstance(alert_id, str) or not alert_id.strip():
        raise InvalidIndicator("alert_id must be a non-empty string")
    if len(alert_id) > MAX_ALERT_ID_LENGTH:
        raise InvalidIndicator("alert_id is too long")
    ioc_type = data.get("type")
    return alert_id, ioc_type, normalize(ioc_type, data.get("value"))


# --- Provider result -----------------------------------------------------------
@dataclass
class ProviderResult:
    provider: str
    status: str                       # STATUS_HIT / STATUS_MISS / STATUS_ERROR
    score: int = 0                    # 0-100, meaningful only for a hit
    tags: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    context_only: bool = False        # set by the enricher from the provider class

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProviderError(Exception):
    """A lookup failed. The message is safe to show and to log (no secrets)."""
