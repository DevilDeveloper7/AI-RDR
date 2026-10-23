from flask import Blueprint, current_app, jsonify

from ..schemas import validation as v
from ..services import intel_service

bp = Blueprint("intel", __name__)


@bp.get("/threat-intelligence")
def list_indicators():
    return jsonify(intel_service.list_indicators(current_app.extensions["adapters"]["m4"], v.int_arg("limit", None, 1, 100)))


@bp.get("/threat-intelligence/<path:indicator>")
def get_indicator(indicator):
    return jsonify(intel_service.get_indicator(current_app.extensions["adapters"]["m4"], indicator))
