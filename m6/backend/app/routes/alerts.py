from flask import Blueprint, current_app, jsonify, request

from ..schemas import validation as v

bp = Blueprint("alerts", __name__)


def _svc():
    return current_app.extensions["alert_service"]


@bp.get("/alerts")
def list_alerts():
    return jsonify(_svc().list(
        severity=v.choice_arg("severity", v.SEVERITIES),
        detection_type=v.choice_arg("detection_type", v.DETECTION_TYPES),
        response_state=v.choice_arg("response_state", v.RESPONSE_STATES),
        host=(request.args.get("host") or None),
        range_minutes=v.int_arg("range_minutes", None, 1, 525600),
        q=(request.args.get("q") or "")[:100],
        page=v.int_arg("page", 1, 1, 10000),
        page_size=v.int_arg("page_size", 20, 1, 100),
    ))


@bp.get("/alerts/<alert_id>")
def get_alert(alert_id):
    return jsonify(_svc().get(v.alert_id(alert_id)))


@bp.get("/alerts/<alert_id>/events")
def get_events(alert_id):
    return jsonify(_svc().events_for_alert(v.alert_id(alert_id)))


@bp.get("/alerts/<alert_id>/shap")
def get_shap(alert_id):
    return jsonify(_svc().shap(v.alert_id(alert_id)))


@bp.post("/alerts/<alert_id>/acknowledge")
def acknowledge(alert_id):
    return jsonify(_svc().acknowledge(v.alert_id(alert_id)))


@bp.post("/alerts/<alert_id>/override")
def override(alert_id):
    body = v.json_body(required=True)
    return jsonify(_svc().override(v.alert_id(alert_id), v.reason(body.get("reason"))))


@bp.post("/alerts/<alert_id>/action")
def action(alert_id):
    body = v.json_body(required=True)
    reason = v.reason(body["reason"]) if body.get("reason") else None
    return jsonify(_svc().request_action(v.alert_id(alert_id), v.action(body.get("action")), reason))


@bp.get("/response-activity")
def response_activity():
    return jsonify(_svc().recent_activity(v.int_arg("limit", 6, 1, 50)))
