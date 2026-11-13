import re

from ..errors import ApiError
from ..integrations import contracts as C

_SAFE = re.compile(r"^[A-Za-z0-9.:_\-…]{1,128}$")


def _is_mock(m4):
    """Mock adapter -> mock. Real adapter -> what M4 itself reports (M4 can run in MOCK provider mode); unknown counts as mock."""
    return getattr(m4, "kind", "mock") == "mock" or bool(getattr(m4, "last_is_mock", True))


def list_indicators(m4, limit=None):
    items = [C.validate_indicator(i) for i in m4.list_indicators()]  # call first: a real adapter learns M4's is_mock from this answer
    return {"items": items[:limit] if limit else items, "meta": {"is_mock": _is_mock(m4), "role": "enrichment only"}}


def get_indicator(m4, indicator):
    if not _SAFE.match(indicator or ""):
        raise ApiError("INVALID_INDICATOR", "Indicator contains unsupported characters.", 400)
    item = m4.enrich(indicator)
    if item:
        C.validate_indicator(item)
    if not item:
        raise ApiError("INDICATOR_NOT_FOUND", "No enrichment is available for this indicator.", 404)
    return item