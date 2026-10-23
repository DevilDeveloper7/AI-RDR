import copy
import re
from datetime import datetime, timezone

from ...mock import load_json
from ..base import ActionRejected
from . import M5Adapter

_HISTORY = {"freeze": "Process frozen", "verify": "Verification started", "kill": "Process killed",
            "isolate": "Isolation initiated", "thaw": "Process thawed"}
_AUDIT = {"freeze": "Freeze", "verify": "Verification started", "kill": "Kill", "isolate": "Isolation", "thaw": "Thaw"}


class MockM5(M5Adapter):
    """MOCK M5. Simulates the response workflow in memory. It executes nothing on any host."""

    kind = "mock"

    def __init__(self):
        data = load_json("m5_cases.json")
        self._cases = {c["alert_id"]: c for c in copy.deepcopy(data["cases"])}
        self._audit = copy.deepcopy(data["audit"])

    def health(self):
        return {"status": "Stubbed", "detail": "Mock adapter. No real response is executed."}

    def list_cases(self):
        return copy.deepcopy(list(self._cases.values()))

    def get_case(self, alert_id):
        case = self._cases.get(alert_id)
        return copy.deepcopy(case) if case else None

    def list_audit(self, limit=50):
        return copy.deepcopy(self._audit[:limit])

    def request_action(self, alert_id, action, target, actor, reason=None, analyst_override=False):
        case = self._cases.get(alert_id)
        if case is None:
            raise ActionRejected(f"M5 has no response case for {alert_id}.")
        current = case["response_state"]
        if action == "freeze":
            new = ("Frozen", "Verifying")
        elif current != "Frozen":
            raise ActionRejected(f"'{action}' is not valid while the process is {current}.")
        elif action == "verify":
            new = ("Frozen", "Verifying")
        elif action in ("kill", "isolate"):  # PROVISIONAL: both end in "Isolated" until M5 defines them
            new = ("Isolated", "Confirmed")
        elif action == "thaw":
            new = ("Thawed", "Analyst override" if analyst_override else "False positive")
        else:
            raise ActionRejected(f"Unknown action '{action}'.")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        case["response_state"], case["verification_state"] = new
        case["history"].append({"timestamp": now, "event": _HISTORY[action]})
        pid = re.search(r"PID \d+", target.get("process", ""))
        where = f"{target.get('host', '')} · {pid.group(0)}" if pid else target.get("host", "")
        if analyst_override:
            self._audit.insert(0, {"timestamp": now, "event": "Analyst override → Thaw", "detail": f"{actor} · {(reason or '')[:60]}", "alert_id": alert_id})
        else:
            self._audit.insert(0, {"timestamp": now, "event": _AUDIT[action], "detail": where, "alert_id": alert_id})
        return {"alert_id": alert_id, "action": action, "result": "accepted",
                "response_state": new[0], "verification_state": new[1], "timestamp": now}
