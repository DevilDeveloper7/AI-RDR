from ..base import BaseAdapter


class M5Adapter(BaseAdapter):
    """M5: automated response (ARM + AICM), case record and audit trail.

    Workflow: Detection -> Freeze -> Verify -> (confirmed) Kill or Isolate, or (false positive) Thaw.
    M6 *requests* actions; M5 decides and executes them and owns the response state.

    PROVISIONAL / M6 STUB. Kill and Isolate are separate actions until M5 says otherwise.
    """

    module = "m5"

    def list_cases(self):
        """All response cases (see contracts.CASE)."""
        raise NotImplementedError

    def get_case(self, alert_id):
        """One case, or None."""
        raise NotImplementedError

    def request_action(self, alert_id, action, target, actor, reason=None, analyst_override=False):
        """Request freeze|verify|kill|isolate|thaw. `target` = {"host", "process"}.

        Return contracts.ACTION_RESULT, or raise ActionRejected if the action is not allowed in the current state.
        """
        raise NotImplementedError

    def list_audit(self, limit=50):
        """Audit trail entries (see contracts.AUDIT), newest first."""
        raise NotImplementedError
