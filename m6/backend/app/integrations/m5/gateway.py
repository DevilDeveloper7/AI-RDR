"""M6's side of the M6 -> M5 link: M5Client over restricted SSH (no REST server exists on M5).

  M6 backend -> M5Gateway (this file) -> M5Client + SSHTransport (supplied by M5, vendored unchanged) -> M5 gateway.

M5 stays authoritative for risk decisions, authorization and execution. This class only submits an analyst's request and
reports what M5 says. It never kills, freezes, isolates or decides anything itself, and it never reports success before M5 has.
The signing key and SSH key stay on this server; nothing here is meant to reach a browser.
"""
import os
import re
import uuid

from ..base import ActionRejected, IntegrationError, IntegrationTimeout, IntegrationUnavailable, MalformedResponse
from .gateway_config import M5ConfigError, read_key
from .vendor import ai_rdr_m6 as lib

ACTIONS = lib.MANUAL_ACTIONS  # freeze verify kill isolate thaw undo approve_containment (exact M5 names)
_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_UNCERTAIN = ("transport_uncertain", "expired", "unavailable", "response_too_large")  # M5 may or may not have acted


class M5Forbidden(IntegrationError):
    code, status = "M5_FORBIDDEN", 403


class M5NotFound(IntegrationError):
    code, status = "M5_NOT_FOUND", 404


class M5BadRequest(IntegrationError):
    code, status = "M5_BAD_REQUEST", 400


class M5RequestExpired(IntegrationTimeout):
    code, status = "M5_REQUEST_EXPIRED", 504


class M5TransportUncertain(IntegrationUnavailable):
    code, status = "M5_TRANSPORT_UNCERTAIN", 503


def _translate(exc):
    """lib.GatewayError (what M5 or the transport said) -> a controlled M6 error. Messages never carry secrets or packets."""
    code, message = exc.code, str(exc)
    if code == "transport_uncertain":
        return M5TransportUncertain("The SSH link to M5 failed or timed out; the outcome of a request may be unknown.")
    if code == "conflict":
        return ActionRejected(message)
    if code == "forbidden":
        return M5Forbidden(message)
    if code == "not_found":
        return M5NotFound(message)
    if code == "bad_request":
        return M5BadRequest(message)
    if code == "expired":
        return M5RequestExpired("M5 refused the request as expired (check the clocks of M6 and the M5 endpoint).")
    if code == "unauthenticated":
        return IntegrationUnavailable("M5 could not authenticate the gateway request (check M5_GATEWAY_KEY_FILE and M5_AGENT_ID).")
    if code == "disabled":
        return IntegrationUnavailable("The M5 gateway is disabled on the endpoint (m6_gateway.enabled).")
    return IntegrationUnavailable("M5 could not complete the request.")


class M5Gateway:
    kind = "real"

    def __init__(self, config, store, *, transport=None, clock=None):
        self.config, self.store = config, store
        self._key = read_key(config.key_file)
        if transport is None:
            for label, path in (("M5_SSH_IDENTITY_FILE", config.identity_file), ("M5_SSH_KNOWN_HOSTS_FILE", config.known_hosts_file)):
                if not os.path.isfile(path):
                    raise M5ConfigError(f"{label} does not point to a file.")
            try:  # fixed remote command, BatchMode, StrictHostKeyChecking=yes: all enforced inside M5's SSHTransport
                transport = lib.SSHTransport(config.host, config.user, config.identity_file, port=config.port,
                                             known_hosts_file=config.known_hosts_file, timeout=config.timeout)
            except ValueError as exc:
                raise M5ConfigError(str(exc))
        self._transport = transport
        self._clock = clock
        self._service = self._client({"type": "service", "id": config.service_id, "roles": ["connector"]})

    # ------------------------------------------------------------------ clients
    def _client(self, principal):
        extra = {"clock": self._clock} if self._clock else {}
        return lib.M5Client(self._transport, self._key, self.config.agent_id, principal, issuer=self.config.issuer, **extra)

    def _user(self):
        """The authenticated analyst. Taken from M6's server-side configuration only, never from a request."""
        return self._client({"type": "user", "id": self.config.analyst_id, "roles": list(self.config.analyst_roles)})

    @staticmethod
    def _guard(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except lib.GatewayError as exc:
            raise _translate(exc)
        except (ValueError, KeyError, TypeError, AttributeError):  # unreadable JSON / wrong envelope from the far end
            raise MalformedResponse("M5 returned a response that could not be read.")

    # ------------------------------------------------------------------ reads (service principal, 'read' permission)
    def health(self):
        return self._guard(self._service.call, "health")  # M5Client has no health() wrapper; call() is its public method

    def status(self):
        """Integration Status row: Connected / Warning. Failure raises (the caller shows Failed)."""
        h = self.health()
        if not isinstance(h, dict) or h.get("gateway_ready") is not True or h.get("agent_id") != self.config.agent_id:
            return {"status": "Warning", "detail": "M5 answered but its gateway is not ready or reports a different agent id."}
        return {"status": "Connected", "detail": f"M5 gateway ready on agent {h['agent_id']} (worker status is not observed by the gateway)."}

    def list_cases(self, limit=100, offset=0):
        return self._guard(self._service.list_cases, limit=limit, offset=offset)

    def get_case(self, case_id, limit=100):
        return self._guard(self._service.get_case, case_id, limit=limit)

    def timeline(self, case_id, after=0, limit=100):
        return self._guard(self._service.timeline, case_id, after=after, limit=limit)

    def risk_decisions(self, case_id, after=0, limit=100):
        return self._guard(self._service.risk_decisions, case_id, after=after, limit=limit)

    def get_action(self, request_id):
        return self._guard(self._service.get_action, request_id)

    # ------------------------------------------------------------------ event delivery (service principal, 'deliver' permission)
    def outbox(self, limit=100):
        return self._guard(self._service.outbox, limit)

    def acknowledge(self, event_ids):
        return self._guard(self._service.acknowledge, list(event_ids))

    # ------------------------------------------------------------------ analyst actions
    def submit_action(self, case_id, action, reason, *, operation_id=None, target=None, resource_key=None):
        """Start ONE new intended action. Reads the latest case first, takes expected_sequence from it, makes a fresh idempotency
        key, saves the intent, then sends it. Returns the outcome dict (see _outcome)."""
        params = self._validate(case_id, action, reason, operation_id, target, resource_key)
        latest = self.get_case(case_id)  # raises M5NotFound / unavailable: nothing is sent in that case
        sequence = (latest.get("case") or {}).get("last_sequence") if isinstance(latest, dict) else None
        if type(sequence) is not int:
            raise MalformedResponse("M5 returned a case without a usable sequence number.")
        key = "m6-" + uuid.uuid4().hex
        params = {**params, "expected_sequence": sequence, "idempotency_key": key}
        request_id = self._user().action_id(key)
        self.store.save_intent(key, request_id, self.config.analyst_id, case_id, action, params)  # BEFORE sending
        return self._send(key, request_id, case_id, action, params)

    def retry_action(self, idempotency_key):
        """Safe retry of the SAME intended action: asks M5 first; only if M5 has no record is the identical request re-sent."""
        intent = self.store.get_intent(idempotency_key) if _KEY.match(idempotency_key or "") else None
        if intent is None or intent["user_id"] != self.config.analyst_id:
            raise M5NotFound("No such action request from this analyst.")
        known = self._status_or_none(intent["request_id"])
        if known == "unreachable":
            return self._outcome(intent, None, "unknown", retry_allowed=False)
        if known is not None:
            return self._finish(intent, known)
        return self._send(intent["idempotency_key"], intent["request_id"], intent["case_id"], intent["action"], intent["params"])

    def action_status(self, idempotency_key):
        intent = self.store.get_intent(idempotency_key) if _KEY.match(idempotency_key or "") else None
        if intent is None or intent["user_id"] != self.config.analyst_id:
            raise M5NotFound("No such action request from this analyst.")
        return self._finish(intent, self.get_action(intent["request_id"]))

    # ------------------------------------------------------------------ internals
    def _validate(self, case_id, action, reason, operation_id, target, resource_key):
        if action not in ACTIONS:
            raise M5BadRequest("Unknown action. M5 actions: " + ", ".join(ACTIONS))
        permissions = {p for role in self.config.analyst_roles for p in lib.ROLE_PERMISSIONS.get(role, [])}
        if action not in permissions:  # early refusal; M5 re-checks with its own endpoint policy and stays authoritative
            raise M5Forbidden(f"Your M5 role does not permit '{action}'.")
        if not isinstance(case_id, str) or not case_id.strip() or len(case_id) > 256 or any(ord(c) < 32 for c in case_id):
            raise M5BadRequest("Invalid case id.")
        text = reason.strip() if isinstance(reason, str) else ""
        if not 10 <= len(text) <= 1024 or len(text.split()) < 2 or any(ord(c) < 32 for c in text):
            raise M5BadRequest("A meaningful reason is required (at least 10 characters and 2 words).")
        params = {"case_id": case_id, "action": action, "reason": text}
        if action == "undo":
            if target is not None or operation_id is not None or not isinstance(resource_key, str) or not resource_key.strip():
                raise M5BadRequest("Undo needs a resource_key (and no target or operation_id).")
            params["resource_key"] = resource_key
        else:
            if resource_key is not None:
                raise M5BadRequest("resource_key is only valid for undo.")
            if action == "freeze":
                ok = (isinstance(target, dict) and set(target) == {"pid", "start_ticks", "boot_id"}
                      and all(type(target[k]) is int and not isinstance(target[k], bool) and target[k] >= 0 for k in ("pid", "start_ticks"))
                      and isinstance(target["boot_id"], str) and target["boot_id"].strip())
                if not ok:
                    raise M5BadRequest("Freeze needs a complete process identity: pid, start_ticks and boot_id.")
                params["target"] = {k: target[k] for k in ("pid", "start_ticks", "boot_id")}
            elif target is not None:
                raise M5BadRequest("Only freeze takes a target; other actions use an existing operation_id.")
            if operation_id is not None:
                if not isinstance(operation_id, str) or not operation_id.strip() or len(operation_id) > 256:
                    raise M5BadRequest("Invalid operation id.")
                params["operation_id"] = operation_id
        return params

    def _send(self, key, request_id, case_id, action, params):
        rest = {k: v for k, v in params.items() if k not in ("case_id", "action")}
        try:
            record = self._guard(self._user().request_action, case_id, action, **rest)
        except (M5TransportUncertain, M5RequestExpired, MalformedResponse) as exc:
            return self._resolve_uncertain(key, request_id, case_id, action, params, exc)
        except IntegrationUnavailable as exc:  # M5 said 'unavailable': it may have started work
            return self._resolve_uncertain(key, request_id, case_id, action, params, exc)
        except IntegrationError:
            self.store.update_intent(key, "rejected")  # M5 evaluated and refused it (forbidden / conflict / bad request ...)
            raise
        return self._finish(self.store.get_intent(key), record)

    def _status_or_none(self, request_id):
        """M5's record for this request, None if M5 has none, or 'unreachable' if M5 cannot be asked right now."""
        try:
            return self.get_action(request_id)
        except M5NotFound:
            return None
        except IntegrationError:
            return "unreachable"

    def _resolve_uncertain(self, key, request_id, case_id, action, params, exc):
        """The outcome of the send is unknown. NEVER re-send here: ask M5 about this exact request first."""
        intent = self.store.get_intent(key)
        known = self._status_or_none(request_id)
        if known == "unreachable":
            self.store.update_intent(key, "unknown")
            return self._outcome(intent, None, "unknown", retry_allowed=False)
        if known is None:
            self.store.update_intent(key, "not_received")  # M5 has no record: it never got the request
            return self._outcome(intent, None, "not_received", retry_allowed=True)
        return self._finish(intent, known)

    def _finish(self, intent, record):
        if not isinstance(record, dict) or record.get("request_id") != intent["request_id"] or record.get("status") not in ("completed", "failed", "uncertain"):
            raise MalformedResponse("M5 returned an action record that does not match the request.")
        self.store.update_intent(intent["idempotency_key"], record["status"], record)
        return self._outcome(intent, record, record["status"], retry_allowed=False)

    @staticmethod
    def _outcome(intent, record, status, retry_allowed):
        record = record or {}
        return {"idempotency_key": intent["idempotency_key"], "request_id": intent["request_id"], "case_id": intent["case_id"],
                "action": intent["action"], "status": status, "retry_allowed": retry_allowed,
                "completion_verified": bool(record.get("completion_verified")), "may_have_effects": record.get("may_have_effects"),
                "last_phase": record.get("last_phase"), "result": record.get("result"), "error": record.get("error")}
