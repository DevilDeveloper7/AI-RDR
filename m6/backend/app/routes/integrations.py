from flask import Blueprint, current_app, jsonify

from ..errors import ApiError
from ..schemas import validation as v
from ..services.m5_service import M5Link, overlay_status

bp = Blueprint("integrations", __name__)


def _svc():
    return current_app.extensions["integration_service"]


def _m5_link():
    return current_app.extensions.setdefault("m5_link", M5Link())


@bp.get("/integrations/status")
def status():
    return jsonify(overlay_status(_svc().status(), _m5_link()))


@bp.post("/integrations/check")
def check():
    module = v.json_body().get("module")
    if module is not None and (not isinstance(module, str) or module.lower() not in v.MODULES[:5]):
        raise ApiError("INVALID_MODULE", "Module must be one of m1-m5.", 400)
    refresh = module is None or module.lower() == "m5"  # a check of M5 (or of everything) really asks the M5 gateway again
    return jsonify(overlay_status(_svc().check(module.lower() if module else None), _m5_link(), refresh=refresh))