"""
The 8 atomic ARM actions from SDD Table 6.4.1b.

Each function takes a `HostController` plus target info and returns a uniform
result dict: `{action, target, status, timestamp, reversible[, detail]}`.
Exceptions raised by the controller are caught here and turned into
`status="failed"` rather than propagating - playbooks.py/arm.py decide what to
do with a failed step (currently: keep going and let each step report its own
status; a stricter production version might halt a playbook on first
failure).

Note the asymmetry with `HostController`: that ABC has 7 abstract forward
methods (isolate/terminate_process/block_ip_hash/quarantine_file/
lock_directory/snapshot/update_policy). `notify_and_open_case` - Table
6.4.1b's 8th action - is NOT a host action at all (SDD: "Alert SOC and hand to
AICM"), so it doesn't call anything on the controller; it still takes a
`controller` argument purely for signature uniformity across all 8 catalogue
actions. It now calls AICM for real (task 4.6; backend/aicm.py) instead of
being a stub - see its own docstring below for how playbook_id/entity are
recovered without touching backend/playbooks.py's step definitions (out of
scope for that task).
"""

from __future__ import annotations

import datetime
import re
from typing import Any, Callable, Dict, Optional

from . import aicm
from .host_controller import HostController

_PLAYBOOK_ID_PREFIX = re.compile(r"^(PB-\d+)")


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _run(
    action_name: str,
    target: Dict[str, Any],
    reversible: Optional[bool],
    fn: Callable[..., Any],
    *args,
    **kwargs,
) -> Dict[str, Any]:
    try:
        fn(*args, **kwargs)
        return {
            "action": action_name,
            "target": target,
            "status": "success",
            "timestamp": now_iso(),
            "reversible": reversible,
            "detail": {},
        }
    except Exception as exc:  # noqa: BLE001 - deliberately broad: any controller
        # failure (SSH error, hypervisor API error, ...) becomes a failed result
        # record rather than an unhandled exception taking down the caller.
        return {
            "action": action_name,
            "target": target,
            "status": "failed",
            "timestamp": now_iso(),
            "reversible": reversible,
            "detail": {"error": str(exc)},
        }


def isolate_host(controller: HostController, host: str) -> Dict[str, Any]:
    return _run("isolate_host", {"host": host}, True, controller.isolate, host)


def terminate_process(controller: HostController, host: str, pid: int) -> Dict[str, Any]:
    # No reverse - SDD Table 6.4.1b marks this action non-reversible. Do not
    # add one; see NON_REVERSIBLE_ACTIONS below and arm.py's undo().
    return _run(
        "terminate_process", {"host": host, "pid": pid}, False, controller.terminate_process, host, pid
    )


def block_ip_hash(controller: HostController, host: str, value: str) -> Dict[str, Any]:
    return _run(
        "block_ip_hash", {"host": host, "value": value}, True, controller.block_ip_hash, host, value
    )


def quarantine_file(controller: HostController, host: str, path: str) -> Dict[str, Any]:
    return _run(
        "quarantine_file", {"host": host, "path": path}, True, controller.quarantine_file, host, path
    )


def lock_directory(controller: HostController, host: str, path: str) -> Dict[str, Any]:
    return _run(
        "lock_directory", {"host": host, "path": path}, True, controller.lock_directory, host, path
    )


def snapshot_target(controller: HostController, host: str) -> Dict[str, Any]:
    # Handled separately from _run() because controller.snapshot() returns a
    # snapshot_id we need to keep (for remove_snapshot()/restore later), not
    # just a success/fail signal.
    target = {"host": host}
    try:
        snapshot_id = controller.snapshot(host)
        return {
            "action": "snapshot_target",
            "target": target,
            "status": "success",
            "timestamp": now_iso(),
            "reversible": True,
            "detail": {"snapshot_id": snapshot_id},
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "action": "snapshot_target",
            "target": target,
            "status": "failed",
            "timestamp": now_iso(),
            "reversible": True,
            "detail": {"error": str(exc)},
        }


def update_policy(controller: HostController, host: str, rule: str) -> Dict[str, Any]:
    return _run("update_policy", {"host": host, "rule": rule}, True, controller.update_policy, host, rule)


def notify_and_open_case(
    controller: HostController,
    host: str,
    message: str,
    priority: str = "normal",
    entity: Optional[str] = None,
) -> Dict[str, Any]:
    """Not a HostController action (see module docstring) - calls
    `aicm.open_or_update_case()` for real (task 4.6) instead of the old
    stub. `reversible=None` represents Table 6.4.1b's "n/a" reversibility
    (notifying can't be un-notified).

    **Two disclosed gaps, both a consequence of backend/playbooks.py's step
    definitions being out of scope for task 4.6 to edit** (every call site
    - `_pb01_steps()`..`_pb04_steps()` - passes only `host`/`message`/
    `priority`, same as before this task):
      - `playbook_id`: every playbook's message literally starts with its
        own id ("PB-01 Ransomware Containment triggered", etc. - confirmed
        against all 4 call sites in playbooks.py), so it's recovered here
        by parsing that prefix rather than threading a new required
        argument through playbooks.py's closures.
      - `entity`: risk_fusion's own fused `entity` (typically `host:pid`)
        isn't available at this call site either - only `host` is. `entity`
        defaults to `host` when not explicitly passed, which is what every
        current real call site gets; a future caller with the richer entity
        string on hand can pass it explicitly once playbooks.py threads it
        through (a separate, later wiring task).
    """
    playbook_id_match = _PLAYBOOK_ID_PREFIX.match(message)
    playbook_id = playbook_id_match.group(1) if playbook_id_match else None

    case = aicm.open_or_update_case(
        entity=entity or host,
        host=host,
        trigger={"priority": priority, "message": message},
        playbook_id=playbook_id,
    )

    return {
        "action": "notify_and_open_case",
        "target": {"host": host, "message": message, "priority": priority},
        "status": "success",
        "timestamp": now_iso(),
        "reversible": None,
        "detail": {"case_id": case.case_id},
    }


# ---------------------------------------------------------------------------
# Undo support: reversal handlers for the 6 reversible actions, keyed by the
# `action` name used in result dicts above. arm.py's undo() uses this to
# dispatch, so it doesn't need to know the target/detail shape of every
# action.
# ---------------------------------------------------------------------------

def _reverse_isolate_host(controller: HostController, result: Dict[str, Any]) -> None:
    controller.release_host(result["target"]["host"])


def _reverse_block_ip_hash(controller: HostController, result: Dict[str, Any]) -> None:
    controller.unblock_ip_hash(result["target"]["host"], result["target"]["value"])


def _reverse_quarantine_file(controller: HostController, result: Dict[str, Any]) -> None:
    controller.unquarantine_file(result["target"]["host"], result["target"]["path"])


def _reverse_lock_directory(controller: HostController, result: Dict[str, Any]) -> None:
    controller.unlock_directory(result["target"]["host"], result["target"]["path"])


def _reverse_snapshot_target(controller: HostController, result: Dict[str, Any]) -> None:
    controller.remove_snapshot(result["target"]["host"], result["detail"].get("snapshot_id"))


def _reverse_update_policy(controller: HostController, result: Dict[str, Any]) -> None:
    controller.remove_policy(result["target"]["host"], result["target"]["rule"])


REVERSAL_HANDLERS: Dict[str, Callable[[HostController, Dict[str, Any]], None]] = {
    "isolate_host": _reverse_isolate_host,
    "block_ip_hash": _reverse_block_ip_hash,
    "quarantine_file": _reverse_quarantine_file,
    "lock_directory": _reverse_lock_directory,
    "snapshot_target": _reverse_snapshot_target,
    "update_policy": _reverse_update_policy,
}

# terminate_process: SDD marks it explicitly non-reversible - no handler, and
# arm.py's undo() must report this honestly rather than silently no-opping.
# notify_and_open_case: reversibility "n/a" - can't un-notify.
NON_REVERSIBLE_ACTIONS = frozenset({"terminate_process", "notify_and_open_case"})
