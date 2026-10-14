"""
Flask app exposing the ARM API (planning/arm-playbooks-spec.md).

Meant to eventually replace the placeholder Flask app currently deployed via
Ansible on `airdr-detect` (`ansible-devops-staff`'s `setup_airdr_detect.yml`,
which embeds its app.py inline in a `content:` block) - that deployment/
Ansible change is a separate, later phase and explicitly out of scope here.
This file only needs to be correct, importable, and runnable standalone,
which it is: `python -m backend.app` starts it with harmless demo defaults
and no live infra contacted unless a trigger actually names a reachable host.

Routes:
  POST /api/arm/trigger              - synthetic trigger payload (S4 of the
                                        spec): {risk_tier, entity, host,
                                        signals, process_id, ...}
  POST /api/actions/<action_id>/approve
  POST /api/actions/<action_id>/deny
  POST /api/actions/<action_id>/undo
  GET  /api/actions[?status=...]     - list pending/executed/... actions
  GET  /health
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request

from .arm import ARM, ActionStore, OpenSearchActionStore
from .host_controller import HostController, SSHHostController


def _default_controller() -> HostController:
    # Demo-scope defaults, overridable via environment variables - see
    # host_controller.py's module docstring for why SSH (not a production
    # in-guest agent) is used here at all. No real credentials are embedded:
    # nothing connects anywhere until a trigger names a reachable host and an
    # action actually runs.
    return SSHHostController(
        ssh_user=os.environ.get("AIRDR_SSH_USER", "ansible-user"),
        ssh_key_path=os.environ.get("AIRDR_SSH_KEY_PATH", "~/.ssh/id_ed25519"),
    )


def _default_action_store() -> Optional[ActionStore]:
    # Only returns a real OpenSearchActionStore when all 3 env vars are
    # present - otherwise None, which lets ARM's own constructor fall back
    # to InMemoryActionStore (e.g. local dev/tests never need to set these).
    # See arm.py's OpenSearchActionStore docstring for why this exists at
    # all: InMemoryActionStore silently loses every pending-approval record
    # on a process restart, found live 2026-09-29.
    host = os.environ.get("AIRDR_OPENSEARCH_HOST")
    username = os.environ.get("AIRDR_OPENSEARCH_USER")
    password = os.environ.get("AIRDR_OPENSEARCH_PASSWORD")
    if not (host and username and password):
        return None
    return OpenSearchActionStore(
        host=host,
        username=username,
        password=password,
        port=int(os.environ.get("AIRDR_OPENSEARCH_PORT", "9200")),
    )


def create_app(
    controller: Optional[HostController] = None,
    arm_instance: Optional[ARM] = None,
    **arm_kwargs: Any,
) -> Flask:
    """Build the Flask app. Tests should pass a fake `controller` (see
    backend/tests/fakes.py) and/or an explicit `arm_instance`, and should
    always pass `audit_log_path=`/`allow_list_path=` pointing at a tmp_path so
    test runs don't write into the real backend/ package directory."""
    app = Flask(__name__)
    action_store = arm_kwargs.pop("action_store", None) or _default_action_store()
    arm = arm_instance or ARM(
        controller=controller or _default_controller(), action_store=action_store, **arm_kwargs
    )
    app.config["ARM"] = arm

    @app.post("/api/arm/trigger")
    def trigger() -> Any:
        payload: Dict[str, Any] = request.get_json(force=True, silent=True) or {}
        result = arm.handle_trigger(payload)
        status_code = 400 if result.get("status") == "rejected" else 200
        return jsonify(result), status_code

    @app.post("/api/actions/<action_id>/approve")
    def approve(action_id: str) -> Any:
        result = arm.approve(action_id)
        return jsonify(result), 404 if result.get("status") == "not_found" else 200

    @app.post("/api/actions/<action_id>/deny")
    def deny(action_id: str) -> Any:
        result = arm.deny(action_id)
        return jsonify(result), 404 if result.get("status") == "not_found" else 200

    @app.post("/api/actions/<action_id>/undo")
    def undo(action_id: str) -> Any:
        result = arm.undo(action_id)
        return jsonify(result), 404 if result.get("status") == "not_found" else 200

    @app.get("/api/actions")
    def list_actions() -> Any:
        status_filter = request.args.get("status")
        records = arm.list_actions()
        if status_filter:
            records = [r for r in records if r["status"] == status_filter]
        return jsonify({"actions": records})

    @app.get("/health")
    def health() -> Any:
        return jsonify({"status": "ok"})

    return app


if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
