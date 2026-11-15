"""M6's READ-ONLY view of M5, plus the Integration Status overlay.

Nothing here can send an action to M5. Analyst actions stay blocked until M6 has analyst authentication and an agreed
alert-to-case mapping (see docs/integration/m5-gateway.md).

The link is OFF unless M5_LINK_ENABLED=true. When it is off or not configured M6 behaves exactly as before and says so.
"""
import os
import threading
import time

from ..integrations.base import IntegrationError
from ..integrations.m5.gateway import M5Gateway
from ..integrations.m5.gateway_config import M5ConfigError, M5GatewayConfig
from ..integrations.m5.state_store import M6Store

_ON = ("1", "true", "yes", "on")


class M5NotConfigured(IntegrationError):
    code, status = "M5_NOT_CONFIGURED", 503


class M5Link:
    def __init__(self, env=None, gateway=None, factory=None, ttl=30.0, clock=time.monotonic):
        self._env = os.environ if env is None else env
        self._gateway, self._factory, self._ttl, self._clock = gateway, factory, ttl, clock
        self._lock = threading.Lock()
        self._cached = None  # (time, health dict)

    # ------------------------------------------------------------------ state
    @property
    def enabled(self):
        return self._gateway is not None or (self._env.get("M5_LINK_ENABLED") or "").strip().lower() in _ON

    def gateway(self):
        if self._gateway is not None:
            return self._gateway
        if not self.enabled:
            raise M5NotConfigured("The M5 link is switched off. Set M5_LINK_ENABLED=true and the M5_* settings in .env (see docs/integration/m5-gateway.md).")
        with self._lock:
            if self._gateway is None:
                try:
                    config = M5GatewayConfig.from_env(self._env)
                    self._gateway = self._factory(config) if self._factory else M5Gateway(config, M6Store(config.data_dir))
                except M5ConfigError as exc:
                    raise M5NotConfigured(str(exc))
        return self._gateway

    def health(self, refresh=False):
        """{'enabled', 'status', 'detail', 'events_stored'}: status is Connected, Warning, Failed or Not configured. Cached briefly
        so that opening the Integration Status page does not open an SSH session every time."""
        if not self.enabled:
            return {"enabled": False, "status": "Not configured", "detail": "The M5 link is switched off (M5_LINK_ENABLED).", "events_stored": None}
        now = self._clock()
        if not refresh and self._cached and now - self._cached[0] < self._ttl:
            return self._cached[1]
        try:
            gateway = self.gateway()
            state = gateway.status()
            try:
                stored = gateway.store.count_events()
            except Exception:  # a broken local database must not hide the M5 answer
                stored = None
            result = {"enabled": True, **state, "events_stored": stored}
        except M5NotConfigured as exc:
            result = {"enabled": True, "status": "Not configured", "detail": exc.message, "events_stored": None}
        except IntegrationError as exc:
            result = {"enabled": True, "status": "Failed", "detail": exc.message, "events_stored": None}
        self._cached = (now, result)
        return result


def overlay_status(payload, link, refresh=False):
    """Adds the M5 SSH-gateway state to the M5 row of /integrations/status. Rows for M1-M4 and M6 are never touched, and nothing
    changes while the link is off. The M5 row stays 'Stubbed' (the alert screens still use the M5 mock) unless the link is broken."""
    if not link.enabled:
        return payload
    h = link.health(refresh=refresh)
    rows = []
    for row in payload["components"]:
        if row["module"] == "M5":
            row = {**row, "endpoint": f"SSH gateway (read-only): {h['status']}", "gateway": h,
                   "detail": f"M5 gateway link: {h['status']}. {h['detail']} The alert screens still use the M5 mock."}
            if h["status"] in ("Warning", "Failed"):
                row["status"] = "Warning"
        rows.append(row)
    return {**payload, "components": rows}
