"""abuse.ch provider: MalwareBazaar, ThreatFox and URLhaus (PRIMARY source).

Routing:
  hash      -> MalwareBazaar, then ThreatFox (ThreatFox skipped for SHA-1)
  ip/domain -> ThreatFox, then URLhaus

Combining the services:
  any hit             -> hit (score = max, tags merged)
  no hit, any error   -> error (we cannot claim "not found" if a service failed)
  otherwise           -> miss

API formats: see docs/api_notes.md. Every detail marked UNVERIFIED there is
handled so that a wrong guess produces an error, never a false "not found".
"""
from typing import Any, Dict, List, Optional

from ..config import (
    MALWAREBAZAAR_HIT_SCORE, MAX_TAGS_PER_PROVIDER, THREATFOX_DEFAULT_SCORE,
    URLHAUS_OFFLINE_SCORE, URLHAUS_ONLINE_SCORE,
)
from ..http import HttpClient, ProviderError, json_object
from ..schema import STATUS_ERROR, STATUS_HIT, STATUS_MISS, ProviderResult, hash_kind
from .base import Provider

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"   # UNVERIFIED path

FOUND_STATUS = "ok"
# UNVERIFIED: "not found" query_status names. Any other value -> error.
MALWAREBAZAAR_NOT_FOUND = {"hash_not_found"}
THREATFOX_NOT_FOUND = {"no_result"}
URLHAUS_NOT_FOUND = {"no_results"}


def _hit(score: int, tags: List[str], **fields: Any) -> Dict[str, Any]:
    return {"status": STATUS_HIT, "score": score, "tags": tags, **fields}


def _miss() -> Dict[str, Any]:
    return {"status": STATUS_MISS}


def _string_list(value: Any) -> List[str]:
    """Keep only non-empty strings from a list; anything else -> []."""
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def _add_tags(tags: List[str], *new: Optional[str]) -> None:
    for tag in new:
        if isinstance(tag, str) and tag.strip() and tag.strip() not in tags:
            tags.append(tag.strip())


def _records(body: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    """The list of result records under `key`; error if it has the wrong shape."""
    records = body.get(key)
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise ProviderError(f"unexpected '{key}' in response")
    return records


def _not_found_or_error(service: str, status: Any, not_found: set) -> Dict[str, Any]:
    if status in not_found:
        return _miss()
    raise ProviderError(f"{service}: unexpected query_status {status!r}")


def _confidence(record: Dict[str, Any]) -> Optional[int]:
    try:
        return max(0, min(100, int(record.get("confidence_level"))))
    except (TypeError, ValueError):
        return None


class AbuseChProvider(Provider):
    name = "abusech"
    supported_types = frozenset({"hash", "ip", "domain"})

    def __init__(self, auth_key: Optional[str], http: Optional[HttpClient] = None):
        self._auth_key = auth_key
        self._http = http or HttpClient()

    def _lookup(self, ioc_type: str, value: str) -> ProviderResult:
        if not self._auth_key:
            return self.error("ABUSECH_AUTH_KEY is not set")   # no network call

        if ioc_type == "hash":
            services = [("malwarebazaar", self._malwarebazaar)]
            if hash_kind(value) != "sha1":   # ThreatFox search_hash: MD5/SHA-256 only
                services.append(("threatfox", self._threatfox_hash))
        else:
            services = [("threatfox", self._threatfox_ioc), ("urlhaus", self._urlhaus)]

        per_service: Dict[str, Dict[str, Any]] = {}
        for service, query in services:
            try:
                per_service[service] = query(value)
            except ProviderError as exc:
                per_service[service] = {"status": STATUS_ERROR, "error": str(exc)}
        return self._combine(per_service)

    def _combine(self, per_service: Dict[str, Dict[str, Any]]) -> ProviderResult:
        hits = {s: r for s, r in per_service.items() if r["status"] == STATUS_HIT}
        errors = [f"{s}: {r['error']}" for s, r in per_service.items()
                  if r["status"] == STATUS_ERROR]
        error = "; ".join(errors) or None

        if hits:
            tags: List[str] = []
            for r in hits.values():
                _add_tags(tags, *r["tags"])
            return ProviderResult(
                provider=self.name, status=STATUS_HIT,
                score=max(r["score"] for r in hits.values()),
                tags=tags[:MAX_TAGS_PER_PROVIDER],
                details={"services": per_service, "hit_services": list(hits)},
                error=error,   # partial failure is reported, the hit is kept
            )
        status = STATUS_ERROR if errors else STATUS_MISS
        return ProviderResult(provider=self.name, status=status,
                              details={"services": per_service}, error=error)

    # --- headers / requests ---------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        return {"Auth-Key": self._auth_key}

    def _post_form(self, url: str, data: Dict[str, str]) -> Dict[str, Any]:
        return json_object(self._http.request("POST", url, headers=self._headers(), data=data))

    def _post_json(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return json_object(self._http.request("POST", url, headers=self._headers(), json=payload))

    # --- MalwareBazaar --------------------------------------------------------
    def _malwarebazaar(self, value: str) -> Dict[str, Any]:
        body = self._post_form(MALWAREBAZAAR_URL, {"query": "get_info", "hash": value})
        status = body.get("query_status")
        if status != FOUND_STATUS:
            return _not_found_or_error("malwarebazaar", status, MALWAREBAZAAR_NOT_FOUND)
        records = _records(body, "data")
        if not records:
            raise ProviderError("malwarebazaar: 'ok' but no data")
        sample = records[0]
        tags: List[str] = []
        _add_tags(tags, sample.get("signature"), *_string_list(sample.get("tags")))
        return _hit(MALWAREBAZAAR_HIT_SCORE, tags,
                    signature=sample.get("signature"),
                    file_type=sample.get("file_type"),
                    first_seen=sample.get("first_seen"))

    # --- ThreatFox ------------------------------------------------------------
    def _threatfox_hash(self, value: str) -> Dict[str, Any]:
        body = self._post_json(THREATFOX_URL, {"query": "search_hash", "hash": value})
        return self._threatfox_parse(body)

    def _threatfox_ioc(self, value: str) -> Dict[str, Any]:
        body = self._post_json(THREATFOX_URL,
                               {"query": "search_ioc", "search_term": value, "exact_match": True})
        return self._threatfox_parse(body)

    def _threatfox_parse(self, body: Dict[str, Any]) -> Dict[str, Any]:
        status = body.get("query_status")
        if status != FOUND_STATUS:
            return _not_found_or_error("threatfox", status, THREATFOX_NOT_FOUND)
        records = _records(body, "data")
        if not records:
            raise ProviderError("threatfox: 'ok' but no data")
        tags: List[str] = []
        confidences = []
        for rec in records:
            _add_tags(tags, rec.get("malware_printable"), rec.get("threat_type"),
                      *_string_list(rec.get("tags")))
            conf = _confidence(rec)
            if conf is not None:
                confidences.append(conf)
        score = max(confidences) if confidences else THREATFOX_DEFAULT_SCORE
        return _hit(score, tags, ioc_count=len(records),
                    confidence_level=max(confidences) if confidences else None)

    # --- URLhaus --------------------------------------------------------------
    def _urlhaus(self, value: str) -> Dict[str, Any]:
        body = self._post_form(URLHAUS_HOST_URL, {"host": value})
        status = body.get("query_status")
        if status != FOUND_STATUS:
            return _not_found_or_error("urlhaus", status, URLHAUS_NOT_FOUND)
        urls = _records(body, "urls")
        if not urls:
            return _miss()
        online = sum(1 for u in urls if u.get("url_status") == "online")
        tags: List[str] = []
        for u in urls:
            _add_tags(tags, u.get("threat"), *_string_list(u.get("tags")))
        score = URLHAUS_ONLINE_SCORE if online else URLHAUS_OFFLINE_SCORE
        return _hit(score, tags, url_count=len(urls), urls_online=online)
