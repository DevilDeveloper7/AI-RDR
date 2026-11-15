"""READ-ONLY browser routes for M5 data, passed through unchanged from the M5 gateway.

There is deliberately NO route here that sends an action to M5: M6 has no analyst authentication yet and no agreed mapping from
alerts to M5 cases. Like every other M6 route these have no login, so they work only when the M5 link is switched on in .env.
"""
import re

from flask import Blueprint, current_app, jsonify

from ..errors import ApiError
from ..schemas import validation as v
from ..services.m5_service import M5Link

bp = Blueprint("m5", __name__)
_CASE_ID = re.compile(r"^[^\x00-\x1f\x7f/\\]{1,256}$")  # M5's own rule: 1-256 characters, no control characters
_META = {"source": "m5-gateway", "is_mock": False, "read_only": True}


def _link():
    return current_app.extensions.setdefault("m5_link", M5Link())


def _case_id(value):
    if not _CASE_ID.match(value or ""):
        raise ApiError("INVALID_CASE_ID", "Case ID must be 1-256 characters without control characters.", 400)
    return value


def _wrap(result):
    return jsonify({**result, "meta": _META} if isinstance(result, dict) else {"data": result, "meta": _META})


@bp.get("/m5/health")
def health():
    return jsonify({**_link().health(refresh=False), "meta": {**_META, "note": "Case lookups only; analyst actions are not connected."}})


@bp.get("/m5/cases")
def cases():
    return _wrap(_link().gateway().list_cases(limit=v.int_arg("limit", 100, 1, 100), offset=v.int_arg("offset", 0, 0, 100000)))


@bp.get("/m5/cases/<case_id>")
def case(case_id):
    return _wrap(_link().gateway().get_case(_case_id(case_id), limit=v.int_arg("limit", 100, 1, 100)))


@bp.get("/m5/cases/<case_id>/timeline")
def timeline(case_id):
    return _wrap(_link().gateway().timeline(_case_id(case_id), after=v.int_arg("after", 0, 0, 10**9), limit=v.int_arg("limit", 100, 1, 100)))


@bp.get("/m5/cases/<case_id>/risk-decisions")
def risk_decisions(case_id):
    return _wrap(_link().gateway().risk_decisions(_case_id(case_id), after=v.int_arg("after", 0, 0, 10**9), limit=v.int_arg("limit", 100, 1, 100)))
