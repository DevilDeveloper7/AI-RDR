from flask import Blueprint, current_app, jsonify

from ..errors import ApiError
from ..schemas import validation as v

bp = Blueprint("integrations", __name__)


def _svc():
    return current_app.extensions["integration_service"]


@bp.get("/integrations/status")
def status():
    return jsonify(_svc().status())


@bp.post("/integrations/check")
def check():
    module = v.json_body().get("module")
    if module is not None and (not isinstance(module, str) or module.lower() not in v.MODULES[:5]):
        raise ApiError("INVALID_MODULE", "Module must be one of m1-m5.", 400)
    return jsonify(_svc().check(module.lower() if module else None))
