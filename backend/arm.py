"""
ARM orchestrator (SDD S6.4.1; task-breakdown.md S4.5; planning/arm-playbooks-
spec.md).

Owns, in order, for every incoming trigger:
  1. playbook selection (select_playbook, per Tables 6.4.1a/6.4.1c)
  2. action_id generation + idempotency dedupe
  3. rate limiting (token bucket per entity)
  4. the critical-asset allow-list check
  5. the approval gate (this section's docstring below)
  6. audit logging of every step above

**The approval gate is a HARD requirement, not a configurable default**
(arm-playbooks-spec.md S3): PB-01, PB-03, and PB-04 must always produce a
`pending_approval` record and never execute automatically, regardless of what
Table 6.4.1a's default tiering says ("Automatic" for High/Critical) - this
project's own standing recommendation (task-breakdown.md S4.5) is to start
more conservative than the SDD defaults until real false-positive numbers
(S3.5) justify loosening it. PB-02 alone (backup + throttle, both reversible/
low-blast-radius) auto-executes, matching the SDD's Medium-tier "Automatic +
analyst review".

`ARM.handle_trigger()` below implements this as a literal
`playbook.id == "PB-02"` check - NOT a field read off `Playbook` or any
constructor/config flag - specifically so it cannot be silently loosened by
changing a config value elsewhere. Loosening this requires editing this
function (and, per the spec, justifying it with real evaluation numbers
first). Do not "fix" this for testing convenience: the test suite
(backend/tests/test_arm.py) exercises the gate directly, including
approve/deny of the resulting pending_approval records.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml

from . import actions, aicm, playbooks
from .host_controller import HostController

DEFAULT_ALLOW_LIST_PATH = Path(__file__).resolve().parent / "critical_assets.yml"
DEFAULT_AUDIT_LOG_PATH = Path(__file__).resolve().parent / "audit_log.jsonl"

# The one playbook allowed to auto-execute. A literal module-level constant,
# not something callers can override via ARM(...) kwargs - see module
# docstring.
_AUTO_EXECUTE_PLAYBOOK_ID = "PB-02"


def compute_action_id(playbook_id: str, entity: str, host: str, trigger_timestamp: str) -> str:
    """action_id = sha256(playbook_id + entity + host + trigger_timestamp)[:16]
    (arm-playbooks-spec.md's idempotency design). `trigger_timestamp` is
    expected to come from the *trigger payload* (the originating detection
    event's timestamp), not be freshly generated on every call - that's what
    lets a redelivered/retried trigger (e.g. Wazuh re-sending the same alert)
    naturally dedupe to the same action_id. If a caller omits
    trigger_timestamp, ARM falls back to "now", which means retries without an
    explicit timestamp will NOT dedupe - documented, not silently wrong."""
    raw = f"{playbook_id}{entity}{host}{trigger_timestamp}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Idempotency / action-record store. Pluggable so a real audit-index-backed
# store (task 4.1's ai-rdr-response-audit-* OpenSearch mappings) can replace
# this later without changing ARM's orchestration logic - InMemoryActionStore
# is not hardcoded as the only option, just the default while those mappings
# don't exist yet.
# ---------------------------------------------------------------------------


class ActionStore:
    """Abstract store for action records, keyed by action_id."""

    def get(self, action_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def put(self, record: Dict[str, Any]) -> None:
        raise NotImplementedError

    def all(self) -> List[Dict[str, Any]]:
        raise NotImplementedError


class InMemoryActionStore(ActionStore):
    """Default store: a process-local dict, guarded by a lock. Fine at ARM's
    current single-process scale (task-breakdown.md S4.5's own note that no
    Redis/broker is needed here). Swap for an OpenSearch-backed ActionStore
    once task 4.1 lands, by implementing the same get/put/all interface."""

    def __init__(self) -> None:
        self._records: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def get(self, action_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._records.get(action_id)

    def put(self, record: Dict[str, Any]) -> None:
        with self._lock:
            self._records[record["action_id"]] = record

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._records.values())


class OpenSearchActionStore(ActionStore):
    """Persistent `ActionStore` backed by a dedicated OpenSearch index on
    `airdr-siem`'s indexer.

    **Why this exists**: `InMemoryActionStore` silently loses every pending-
    approval record and action history entry on a process restart - found
    live on 2026-09-29 when an unrelated IRDP deployment restarted
    `airdr-flask` and wiped 3 queued records with no error or trace (see
    `planning/arm-deployment-progress.md`'s "Known limitation" section).
    This is the fix that section pointed at.

    **Deliberately NOT `ai-rdr-response-audit-*`, despite that index looking
    like the obvious target** - that index is the SDD's *immutable,
    append-only* per-event log (one row per playbook_selected/approved/
    executed/undone event), which is already exactly what `AuditLog` above
    produces (its own docstring already calls out swapping its local-JSONL
    writes for a real `ai-rdr-response-audit-*` writer as a separate, later
    step - not done here, a smaller follow-up on its own). What this class
    needs is the opposite shape: one *mutable* record per `action_id`,
    read back and overwritten in place as its status changes
    (pending_approval -> executed -> undone) - a current-state store, not a
    log. Reusing the audit-log index for this would mean either duplicating
    documents per state change (breaking the "one row per action_id"
    get/put semantics `InMemoryActionStore` already has) or writing update-
    in-place documents into an index the SDD explicitly calls immutable.
    Uses its own index (`ai-rdr-arm-action-state` by default) instead - a
    deliberate, disclosed addition beyond the SDD's literal 7 indices, same
    category of judgment call `backend/irdp/normalize.py` already made for
    `ai-rdr-normalized-events-*`'s denormalized convenience fields.

    One document per `action_id` (used as `_id`, so `put()` on an existing
    action_id is an overwrite/update - matching `InMemoryActionStore`'s own
    dict-keyed-by-action_id semantics exactly)."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 9200,
        index: str = "ai-rdr-arm-action-state",
        verify_ssl: bool = False,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.index = index
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"https://{self.host}:{self.port}/{path}"

    def get(self, action_id: str) -> Optional[Dict[str, Any]]:
        resp = requests.get(
            self._url(f"{self.index}/_doc/{action_id}"),
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()["_source"]

    def put(self, record: Dict[str, Any]) -> None:
        resp = requests.put(
            self._url(f"{self.index}/_doc/{record['action_id']}"),
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=self.timeout,
            json=record,
        )
        resp.raise_for_status()

    def all(self) -> List[Dict[str, Any]]:
        resp = requests.post(
            self._url(f"{self.index}/_search"),
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=self.timeout,
            json={"size": 10000, "query": {"match_all": {}}},
        )
        resp.raise_for_status()
        return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


class TokenBucket:
    """Simple in-memory token bucket, keyed by an arbitrary string (ARM uses
    the trigger's `entity`, i.e. host+process per arm-playbooks-spec.md).
    Refill model is intentionally simple (full refill every `period` seconds,
    not gradual leak) - enough to enforce "at most `capacity` playbook
    invocations per entity per `period` seconds" without needing Redis at
    ARM's single-process scale."""

    def __init__(self, capacity: int = 1, period: float = 60.0):
        self.capacity = capacity
        self.period = period
        self._state: Dict[str, tuple] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (self.capacity, now))
            if now - last >= self.period:
                tokens = self.capacity
                last = now
            if tokens <= 0:
                self._state[key] = (tokens, last)
                return False
            tokens -= 1
            self._state[key] = (tokens, last)
            return True


def load_allow_list(path: Path) -> Dict[str, List[str]]:
    """Static allow-list of host/path patterns that can never be auto-executed
    against, regardless of tier (arm-playbooks-spec.md's allow-list design).
    Missing file -> empty allow-list (nothing extra gated), so a fresh
    checkout without a customized critical_assets.yml still behaves
    sensibly."""
    if not path.exists():
        return {"hosts": [], "paths": []}
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return {"hosts": list(data.get("hosts") or []), "paths": list(data.get("paths") or [])}


def host_is_allow_listed(host: str, allow_list: Dict[str, List[str]]) -> bool:
    return any(fnmatch.fnmatch(host, pattern) for pattern in allow_list.get("hosts", []))


class AuditLog:
    """Append-only JSON-lines audit log - the explicit local-file interim
    arm-playbooks-spec.md calls for (task 4.1's ai-rdr-response-audit-*
    OpenSearch mappings don't exist yet); same pattern the earlier e2e smoke
    test used (planning/e2e-smoke-test-progress.md). Swap for a real
    OpenSearch writer once those mappings land - callers only depend on
    `.write(event_dict)`."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: Dict[str, Any]) -> None:
        record = {"logged_at": actions.now_iso(), **event}
        with self._lock:
            with open(self.path, "a") as f:
                f.write(json.dumps(record, default=str) + "\n")


def select_playbook(trigger: Dict[str, Any]) -> Optional[playbooks.Playbook]:
    """Select a playbook purely from the trigger payload, per Tables 6.4.1a
    (tier -> mode) and 6.4.1c (trigger -> playbook):

    - A honey-file signal always routes to PB-04, regardless of risk_tier -
      Table 6.4.1c gives PB-04 its own trigger ("any honey-file access"),
      distinct from PB-01's "critical risk / confirmed encryption" even
      though both sit at the Critical tier in Table 6.4.1a.
    - Otherwise, risk_tier maps directly: critical -> PB-01, high -> PB-03,
      medium -> PB-02.
    - Low tier has no playbook of its own - Table 6.4.1a's Low-tier action is
      "increase monitoring; log; enrich case" (already just passive logging),
      so `None` is returned and the caller logs the trigger without invoking
      any playbook, rather than inventing a stub PB-00.
    """
    signals = trigger.get("signals") or []
    if trigger.get("honeyfile_triggered") or "honeyfile" in signals:
        return playbooks.PB_04

    tier = (trigger.get("risk_tier") or "").strip().lower()
    if tier == "critical":
        return playbooks.PB_01
    if tier == "high":
        return playbooks.PB_03
    if tier == "medium":
        return playbooks.PB_02
    return None


class ARM:
    def __init__(
        self,
        controller: HostController,
        action_store: Optional[ActionStore] = None,
        rate_limiter: Optional[TokenBucket] = None,
        allow_list_path: Optional[Path] = None,
        audit_log_path: Optional[Path] = None,
    ):
        self.controller = controller
        self.store = action_store or InMemoryActionStore()
        self.rate_limiter = rate_limiter or TokenBucket(capacity=1, period=60.0)
        self.allow_list = load_allow_list(Path(allow_list_path or DEFAULT_ALLOW_LIST_PATH))
        self.audit = AuditLog(Path(audit_log_path or DEFAULT_AUDIT_LOG_PATH))

    def handle_trigger(self, trigger: Dict[str, Any]) -> Dict[str, Any]:
        host = trigger.get("host")
        entity = trigger.get("entity") or host
        if not host or not entity:
            return {"status": "rejected", "reason": "trigger missing required 'host' (and/or 'entity')"}

        playbook = select_playbook(trigger)
        if playbook is None:
            self.audit.write({"event": "trigger_logged_only", "trigger": trigger})
            return {
                "status": "logged_only",
                "reason": "no playbook for this trigger (Low tier is passive-log-only per Table 6.4.1a)",
            }

        # trigger_timestamp is part of the idempotency key on purpose - see
        # compute_action_id()'s docstring.
        trigger_timestamp = trigger.get("trigger_timestamp") or actions.now_iso()
        action_id = compute_action_id(playbook.id, entity, host, trigger_timestamp)

        existing = self.store.get(action_id)
        if existing is not None:
            # Dedupe before consuming a rate-limit token: a redelivered/
            # retried trigger is the "same" event, not a new invocation.
            self.audit.write({"event": "trigger_deduped", "action_id": action_id})
            return {"status": "deduped", "action_id": action_id, "existing_status": existing["status"]}

        if not self.rate_limiter.allow(entity):
            self.audit.write(
                {"event": "trigger_rate_limited", "entity": entity, "playbook_id": playbook.id}
            )
            return {"status": "rate_limited", "reason": f"rate limit exceeded for entity {entity!r}"}

        # Allow-list is checked before the approval-gate decision below, not
        # instead of it (arm-playbooks-spec.md): an allow-listed host forces
        # pending_approval even for PB-02, which would otherwise auto-execute.
        allow_listed = host_is_allow_listed(host, self.allow_list)

        record: Dict[str, Any] = {
            "action_id": action_id,
            "playbook_id": playbook.id,
            "playbook_name": playbook.name,
            "entity": entity,
            "host": host,
            "trigger": trigger,
            "trigger_timestamp": trigger_timestamp,
            "created_at": actions.now_iso(),
            "status": "pending_approval",
            "results": [],
            "allow_listed": allow_listed,
        }

        auto_execute = (playbook.id == _AUTO_EXECUTE_PLAYBOOK_ID) and not allow_listed

        self.store.put(record)
        self.audit.write(
            {
                "event": "playbook_selected",
                "action_id": action_id,
                "playbook_id": playbook.id,
                "auto_execute": auto_execute,
                "allow_listed": allow_listed,
            }
        )

        if auto_execute:
            self._execute(record)
            return {
                "status": "executed",
                "action_id": action_id,
                "playbook_id": playbook.id,
                "results": record["results"],
            }

        return {"status": "pending_approval", "action_id": action_id, "playbook_id": playbook.id}

    def _execute(self, record: Dict[str, Any]) -> None:
        playbook = playbooks.PLAYBOOKS[record["playbook_id"]]
        steps = playbook.build_steps(record["trigger"])
        results = [step.run(self.controller) for step in steps]
        record["results"] = results
        record["status"] = "executed"
        record["executed_at"] = actions.now_iso()
        self.store.put(record)
        self.audit.write({"event": "playbook_executed", "action_id": record["action_id"], "results": results})
        self._update_case(results)

    def _update_case(self, results: List[Dict[str, Any]]) -> None:
        """The shared post-execution AICM hook (task 4.6; SDD pseudocode's
        trailing `AICM.update_case(case, actions_taken)` line) - called once,
        from `_execute()` alone, so both the auto-execute path
        (`handle_trigger()` -> `_execute()`) and the approval path
        (`approve()` -> `_execute()`) go through this exact same call, never
        duplicated logic. `case_id` comes from whichever step's result was
        `notify_and_open_case`'s own result dict - every one of PB-01
        through PB-04 includes that step (Table 6.4.1c; confirmed directly
        against backend/playbooks.py's 4 `_pbXX_steps()` functions), so this
        is always present for a real playbook run. A result list that
        somehow lacks it (future playbook, hand-built test trigger with no
        notify step) is a no-op here, not an error - this hook is additive,
        never load-bearing for ARM's own orchestration."""
        case_id = next(
            (r["detail"]["case_id"] for r in results if r.get("action") == "notify_and_open_case"),
            None,
        )
        if case_id is None:
            return
        aicm.update_case(case_id, results)

    def approve(self, action_id: str) -> Dict[str, Any]:
        record = self.store.get(action_id)
        if record is None:
            return {"status": "not_found", "action_id": action_id}
        if record["status"] != "pending_approval":
            return {
                "status": "error",
                "action_id": action_id,
                "reason": f"action is '{record['status']}', not pending_approval",
            }
        self._execute(record)
        self.audit.write({"event": "action_approved", "action_id": action_id})
        return {"status": "executed", "action_id": action_id, "results": record["results"]}

    def deny(self, action_id: str) -> Dict[str, Any]:
        record = self.store.get(action_id)
        if record is None:
            return {"status": "not_found", "action_id": action_id}
        if record["status"] != "pending_approval":
            return {
                "status": "error",
                "action_id": action_id,
                "reason": f"action is '{record['status']}', not pending_approval",
            }
        record["status"] = "denied"
        record["denied_at"] = actions.now_iso()
        self.store.put(record)
        self.audit.write({"event": "action_denied", "action_id": action_id})
        return {"status": "denied", "action_id": action_id}

    def undo(self, action_id: str) -> Dict[str, Any]:
        record = self.store.get(action_id)
        if record is None:
            return {"status": "not_found", "action_id": action_id}
        if record["status"] != "executed":
            return {
                "status": "error",
                "action_id": action_id,
                "reason": f"action is '{record['status']}', nothing executed to undo",
            }

        undo_results: List[Dict[str, Any]] = []
        for result in record["results"]:
            name = result["action"]
            if result["status"] != "success":
                undo_results.append(
                    {"action": name, "status": "skipped", "reason": "original action did not succeed"}
                )
                continue
            if name in actions.NON_REVERSIBLE_ACTIONS:
                # Honest "not reversible" response, per arm-playbooks-spec.md -
                # never fake a reverse for terminate_process/notify_and_open_case.
                undo_results.append(
                    {
                        "action": name,
                        "status": "not_reversible",
                        "reason": "SDD Table 6.4.1b marks this action non-reversible",
                    }
                )
                continue
            handler = actions.REVERSAL_HANDLERS.get(name)
            if handler is None:
                undo_results.append(
                    {"action": name, "status": "unknown", "reason": "no reversal handler registered"}
                )
                continue
            try:
                handler(self.controller, result)
                undo_results.append({"action": name, "status": "reversed"})
            except Exception as exc:  # noqa: BLE001
                undo_results.append({"action": name, "status": "failed", "reason": str(exc)})

        record["status"] = "undone"
        record["undone_at"] = actions.now_iso()
        record["undo_results"] = undo_results
        self.store.put(record)
        self.audit.write({"event": "action_undone", "action_id": action_id, "undo_results": undo_results})
        return {"status": "undone", "action_id": action_id, "undo_results": undo_results}

    def list_actions(self) -> List[Dict[str, Any]]:
        return self.store.all()
