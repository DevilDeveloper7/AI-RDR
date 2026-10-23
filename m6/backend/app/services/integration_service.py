from datetime import datetime, timezone

from ..errors import ApiError
from ..integrations.base import IntegrationError


class IntegrationService:
    """Status of M1-M5 from each adapter's health(). M6 reports itself as Connected."""

    def __init__(self, data, adapters, integrations_config):
        self._rows = data["components"]
        self._tests = data["recent_tests"]
        self._adapters, self._cfg = adapters, integrations_config
        self._last_check = {r["module"]: r["last_check"] for r in self._rows}
        self._health = {}

    def _health_of(self, module):
        try:
            return self._adapters[module].health()
        except IntegrationError as exc:
            return {"status": "Failed", "detail": exc.message}

    def _probe(self, module):
        self._health[module] = self._health_of(module)
        self._last_check[module.upper()] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def status(self):
        rows = []
        for r in self._rows:
            m = r["module"].lower()
            if m == "m6":
                state, mode = {"status": "Connected"}, "self"
            else:
                if m not in self._health:
                    self._health[m] = self._health_of(m)
                state, mode = self._health[m], self._cfg[m]["mode"]
            rows.append({**r, "last_check": self._last_check[r["module"]], "status": state["status"],
                         "detail": state.get("detail", ""), "mode": mode, "provisional": m != "m6"})
        return {"components": rows, "recent_tests": self._tests, "meta": {"is_mock": True}}

    def check(self, module=None):
        if module is not None and module not in self._adapters:
            raise ApiError("INVALID_MODULE", "Module must be one of m1-m5.", 400)
        for m in ([module] if module else list(self._adapters)):
            self._probe(m)
        return self.status()
