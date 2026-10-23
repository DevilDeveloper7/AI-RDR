"""M6 configuration, read from environment variables (see .env.example)."""
import os

MODULES = ("m1", "m2", "m3", "m4", "m5")
VALID_MODES = ("mock", "real")


def _csv(value):
    return [item.strip() for item in value.split(",") if item.strip()]


class Config:
    def __init__(self):
        self.APP_ENV = os.environ.get("APP_ENV", "development")
        self.API_PREFIX = "/api/v1"
        self.CORS_ORIGINS = _csv(
            os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
        )
        # There is no login in M6 scope; this name is recorded on analyst actions.
        self.ANALYST_NAME = os.environ.get("ANALYST_NAME", "Muhammad Alam")

        # PROVISIONAL / M6 STUB: every module defaults to its built-in mock.
        self.INTEGRATIONS = {}
        for module in MODULES:
            prefix = module.upper()
            mode = os.environ.get(f"{prefix}_MODE", "mock").strip().lower()
            if mode not in VALID_MODES:
                raise ValueError(f"{prefix}_MODE must be one of {VALID_MODES}, got '{mode}'")
            self.INTEGRATIONS[module] = {
                "mode": mode,
                "base_url": os.environ.get(f"{prefix}_BASE_URL", "").strip(),
            }
