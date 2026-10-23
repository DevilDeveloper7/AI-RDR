import re

from ..errors import ApiError
from ..integrations import contracts as C

_SAFE = re.compile(r"^[A-Za-z0-9.:_\-…]{1,128}$")


def list_indicators(m4, limit=None):
    items = [C.validate_indicator(i) for i in m4.list_indicators()]
    return {"items": items[:limit] if limit else items, "meta": {"is_mock": True, "role": "enrichment only"}}


def get_indicator(m4, indicator):
    if not _SAFE.match(indicator or ""):
        raise ApiError("INVALID_INDICATOR", "Indicator contains unsupported characters.", 400)
    item = m4.enrich(indicator)
    if item:
        C.validate_indicator(item)
    if not item:
        raise ApiError("INDICATOR_NOT_FOUND", "No enrichment is available for this indicator.", 404)
    return item
