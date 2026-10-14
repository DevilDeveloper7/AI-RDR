"""
PB-01 through PB-04, SDD Table 6.4.1c, as ordered sequences over actions.py.

Each playbook is built from a synthetic trigger payload (the same shape
`POST /api/arm/trigger` accepts - see app.py/arm.py): a dict with at least
`host`, plus playbook-specific fields (`process_id`, `target_paths`,
`indicator`/`source_ip`/`source_hash`, `file_path`). Fields not present in a
given trigger are simply skipped (e.g. PB-01 without a `process_id` won't
include a terminate_process step) rather than failing - triggers are
synthetic/hand-crafted in this phase (arm-playbooks-spec.md S4), so playbooks
must tolerate partial payloads.

`Playbook.build_steps(trigger)` returns an ordered list of `PlaybookStep`s;
each step's `run(controller)` calls the matching actions.py function and
returns one result dict. Whether a playbook actually executes automatically
or waits for approval is decided by arm.py's hard-coded approval gate, NOT by
anything in this module - see arm.py's module docstring for why that's
deliberate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List

from . import actions
from .host_controller import HostController


@dataclass
class PlaybookStep:
    action_name: str
    run: Callable[[HostController], Dict[str, Any]]


@dataclass
class Playbook:
    id: str
    name: str
    build_steps: Callable[[Dict[str, Any]], List[PlaybookStep]]


def _pb01_steps(trigger: Dict[str, Any]) -> List[PlaybookStep]:
    """
    PB-01 - Ransomware Containment (Critical risk / confirmed encryption).

    SDD's literal sequence is "isolate host -> kill process -> lock & snapshot
    predicted directories -> block source -> open case". Taken literally, that
    is a bug: if "isolate" means a full network cutoff, step 2 (a remote
    process kill) becomes impossible - the very channel needed to issue it
    would already be gone. This implementation uses the quarantine-bridge
    fix documented in task-breakdown.md S4.5 and arm-playbooks-spec.md instead:
    `HostController.isolate()` moves the host to a restricted bridge/firewall
    state that still carries the agent control channel, not a full cutoff -
    so kill process (and the lock/snapshot/block steps after it) can still
    reach the host. The *order* below is therefore the same as the SDD's
    table; what changed is what `isolate` means, at the HostController-
    implementation level (see host_controller.py's isolate() docstrings on
    SSHHostController).
    """
    host = trigger["host"]
    steps: List[PlaybookStep] = [
        PlaybookStep("isolate_host", lambda c, h=host: actions.isolate_host(c, h)),
    ]

    pid = trigger.get("process_id")
    if pid is not None:
        steps.append(
            PlaybookStep("terminate_process", lambda c, h=host, p=pid: actions.terminate_process(c, h, p))
        )

    for path in trigger.get("target_paths", []) or []:
        steps.append(PlaybookStep("lock_directory", lambda c, h=host, p=path: actions.lock_directory(c, h, p)))

    steps.append(PlaybookStep("snapshot_target", lambda c, h=host: actions.snapshot_target(c, h)))

    source = trigger.get("source_ip") or trigger.get("source_hash") or trigger.get("indicator")
    if source:
        steps.append(
            PlaybookStep("block_ip_hash", lambda c, h=host, v=source: actions.block_ip_hash(c, h, v))
        )

    steps.append(
        PlaybookStep(
            "notify_and_open_case",
            lambda c, h=host: actions.notify_and_open_case(
                c, h, "PB-01 Ransomware Containment triggered", priority="critical"
            ),
        )
    )
    return steps


def _pb02_steps(trigger: Dict[str, Any]) -> List[PlaybookStep]:
    """
    PB-02 - Suspicious Behaviour (Medium risk / ML anomaly).

    SDD sequence: "back up predicted targets -> throttle process ->
    prioritised alert -> await confirmation".

    Two scope notes:
    - "Throttle process" is not one of Table 6.4.1b's 8 atomic actions. It's
      mapped onto `update_policy` here (pushing a resource-throttling rule)
      rather than `terminate_process`, since throttling deliberately keeps the
      process alive - killing it would make this playbook indistinguishable
      from PB-01/03's containment actions, which is wrong for a Medium-risk,
      not-yet-confirmed anomaly.
    - "Await confirmation" is not an atomic action either - it's the resulting
      case state after the 3 actions below run (this playbook auto-executes
      per arm.py's hard-coded gate, then the opened case sits for analyst
      review). AICM (task 4.6) would model that case-state transition;
      it isn't built yet, so there's no 4th step to call here.
    """
    host = trigger["host"]
    pid = trigger.get("process_id")
    return [
        PlaybookStep("snapshot_target", lambda c, h=host: actions.snapshot_target(c, h)),
        PlaybookStep(
            "update_policy",
            lambda c, h=host, p=pid: actions.update_policy(c, h, f"throttle_process:{p}"),
        ),
        PlaybookStep(
            "notify_and_open_case",
            lambda c, h=host: actions.notify_and_open_case(
                c, h, "PB-02 Suspicious Behaviour - prioritised alert", priority="medium"
            ),
        ),
    ]


def _pb03_steps(trigger: Dict[str, Any]) -> List[PlaybookStep]:
    """PB-03 - Known-Bad Indicator (High risk / X-Force hit).
    SDD sequence: "block IP/hash -> quarantine file -> isolate host -> notify
    analyst" - implemented in that literal order (no ordering bug here, since
    nothing after isolate needs the pre-isolation network state)."""
    host = trigger["host"]
    steps: List[PlaybookStep] = []

    indicator = trigger.get("indicator") or trigger.get("source_ip") or trigger.get("source_hash")
    if indicator:
        steps.append(
            PlaybookStep("block_ip_hash", lambda c, h=host, v=indicator: actions.block_ip_hash(c, h, v))
        )

    file_path = trigger.get("file_path")
    if file_path:
        steps.append(
            PlaybookStep("quarantine_file", lambda c, h=host, p=file_path: actions.quarantine_file(c, h, p))
        )

    steps.append(PlaybookStep("isolate_host", lambda c, h=host: actions.isolate_host(c, h)))
    steps.append(
        PlaybookStep(
            "notify_and_open_case",
            lambda c, h=host: actions.notify_and_open_case(
                c, h, "PB-03 Known-Bad Indicator triggered", priority="high"
            ),
        )
    )
    return steps


def _pb04_steps(trigger: Dict[str, Any]) -> List[PlaybookStep]:
    """PB-04 - Honey-File Trigger (any honey-file access; deterministic,
    highest confidence). SDD sequence: "immediate isolation -> open
    high-priority case" - just those two steps, no ordering concerns."""
    host = trigger["host"]
    return [
        PlaybookStep("isolate_host", lambda c, h=host: actions.isolate_host(c, h)),
        PlaybookStep(
            "notify_and_open_case",
            lambda c, h=host: actions.notify_and_open_case(
                c, h, "PB-04 Honey-File Trigger - high-priority case opened", priority="critical"
            ),
        ),
    ]


PB_01 = Playbook(id="PB-01", name="Ransomware Containment", build_steps=_pb01_steps)
PB_02 = Playbook(id="PB-02", name="Suspicious Behaviour", build_steps=_pb02_steps)
PB_03 = Playbook(id="PB-03", name="Known-Bad Indicator", build_steps=_pb03_steps)
PB_04 = Playbook(id="PB-04", name="Honey-File Trigger", build_steps=_pb04_steps)

PLAYBOOKS: Dict[str, Playbook] = {p.id: p for p in (PB_01, PB_02, PB_03, PB_04)}
