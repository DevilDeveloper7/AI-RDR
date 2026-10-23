from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS

from .config import Config
from .errors import register_error_handlers
from .integrations.registry import build_adapters
from .mock import load_json
from .services.alert_service import AlertService
from .services.integration_service import IntegrationService
from .routes import register_routes

# Optional .env in the repo root (never committed).
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def create_app(config_overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config())
    if config_overrides:
        app.config.update(config_overrides)

    if app.config["CORS_ORIGINS"]:
        CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

    # Adapters (mock for now) and the M6 service layer.
    adapters = build_adapters(app.config["INTEGRATIONS"])
    app.extensions["adapters"] = adapters
    app.extensions["alert_service"] = AlertService(adapters, app.config["ANALYST_NAME"], load_json("m6_seed.json"))
    app.extensions["integration_service"] = IntegrationService(
        load_json("integrations.json"), adapters, app.config["INTEGRATIONS"])

    register_routes(app)
    register_error_handlers(app)
    return app
