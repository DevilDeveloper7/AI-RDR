from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify

bp = Blueprint("health", __name__)


@bp.get("/health")
def health():
    """M6 liveness only. It says nothing about M1-M5 (see /integrations/status)."""
    return jsonify(
        status="ok",
        service="ai-rdr-m6",
        api_version="v1",
        environment=current_app.config["APP_ENV"],
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
