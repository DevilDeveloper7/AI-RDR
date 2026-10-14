"""
Fakes shared across backend/tests/. No SSH keys, hypervisor credentials,
OpenSearch credentials, or network access are needed to run backend/tests/ -
that's the point.

FakeHostController - an in-memory HostController that just records calls,
used instead of SSHHostController (backend/
host_controller.py; task 4.5/ARM tests).

FakeEventSource / FakeEventWriter - the same in-memory-recording pattern for
IRDP (backend/irdp/; task 4.1): FakeEventSource holds a plain list of
RawEvents and filters by the same `timestamp > since_checkpoint` rule a real
WazuhEventSource would apply; FakeEventWriter just appends every document it
was asked to write into 3 lists, one per ai-rdr-* shape, for tests to
inspect.

FakeThreatIntelClient / FakeTriggerSender - the same in-memory-recording
pattern for Risk Fusion (backend/risk_fusion.py; task 4.4):
FakeThreatIntelClient returns a pre-seeded `ThreatIntelResult` (default:
no match) and records every `indicators` dict it was asked to look up;
FakeTriggerSender just records every `fuse()`-result dict it was asked to
send, like FakeHostController's "just record the call" pattern.

FakeM2Client - the same pattern for M2 (backend/m2_client.py; task
m2-integration): returns a pre-seeded `M2Result` (default: a benign,
no-alert result) on every call, and records every `(events, run_id)` call
so tests can assert on exactly what a caller submitted - matching
FakeThreatIntelClient's own convention, including living here rather than
alongside `M2Client`/`RealM2Client` in `backend/m2_client.py` itself.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from backend.host_controller import HostController
from backend.irdp.event_source import RawEvent, WazuhEventSource
from backend.irdp.writer import EventWriter
from backend.m2_client import M2Client, M2Result
from backend.risk_fusion import ThreatIntelClient, ThreatIntelResult, TriggerSender


class FakeHostController(HostController):
    def __init__(self) -> None:
        self.calls: List[Tuple[str, tuple]] = []
        self._snapshot_counter = 0
        self._backup_counter = 0
        self.fail_on: set = set()  # action names to raise on, for failure-path tests
        # PathPredict test fixture (task 3.4): (host, path) -> entry names,
        # seeded by tests before calling list_directory(). Unseeded lookups
        # return [] rather than raising, matching a real empty directory.
        self.directories: Dict[Tuple[str, str], List[str]] = {}

    def _record(self, name: str, *args) -> None:
        self.calls.append((name, args))
        if name in self.fail_on:
            raise RuntimeError(f"simulated failure in {name}")

    # ---- forward actions ----
    def isolate(self, host):
        self._record("isolate", host)

    def terminate_process(self, host, pid):
        self._record("terminate_process", host, pid)

    def block_ip_hash(self, host, value):
        self._record("block_ip_hash", host, value)

    def quarantine_file(self, host, path):
        self._record("quarantine_file", host, path)

    def lock_directory(self, host, path):
        self._record("lock_directory", host, path)

    def snapshot(self, host):
        self._record("snapshot", host)
        self._snapshot_counter += 1
        return f"fake-snap-{self._snapshot_counter}"

    def update_policy(self, host, rule):
        self._record("update_policy", host, rule)

    # ---- PathPredict-only additions (task 3.4) ----
    def list_directory(self, host, path):
        self._record("list_directory", host, path)
        return list(self.directories.get((host, path), []))

    def backup_file(self, host, path):
        self._record("backup_file", host, path)
        self._backup_counter += 1
        backup_id = f"fake-file-backup-{self._backup_counter}"
        return {
            "backup_id": backup_id,
            "source_path": path,
            "backup_path": f"/fake/backups/{backup_id}",
        }

    # ---- reverse actions ----
    def release_host(self, host):
        self._record("release_host", host)

    def unblock_ip_hash(self, host, value):
        self._record("unblock_ip_hash", host, value)

    def unquarantine_file(self, host, path):
        self._record("unquarantine_file", host, path)

    def unlock_directory(self, host, path):
        self._record("unlock_directory", host, path)

    def remove_snapshot(self, host, snapshot_id):
        self._record("remove_snapshot", host, snapshot_id)

    def remove_policy(self, host, rule):
        self._record("remove_policy", host, rule)

    def remove_backup(self, host, backup_id):
        self._record("remove_backup", host, backup_id)


class FakeEventSource(WazuhEventSource):
    """In-memory WazuhEventSource for IRDP tests. Holds a plain list of
    canned RawEvents; `poll()` returns everything strictly newer than
    `since_checkpoint` by plain string comparison of the ISO-8601
    timestamp - the same watermark rule pipeline.run_once()/checkpoint.py
    use, so tests exercise the real checkpoint-advancement logic, not a
    shortcut."""

    def __init__(self, events: Optional[List[RawEvent]] = None) -> None:
        self.events: List[RawEvent] = list(events or [])

    def add_events(self, events: List[RawEvent]) -> None:
        self.events.extend(events)

    def poll(self, since_checkpoint: Optional[str]) -> List[RawEvent]:
        if since_checkpoint is None:
            return list(self.events)
        return [e for e in self.events if e.timestamp > since_checkpoint]


class FakeEventWriter(EventWriter):
    """In-memory EventWriter for IRDP tests - records every document it was
    asked to write into 4 lists, one per ai-rdr-* shape, matching
    FakeHostController's "just record the call" pattern."""

    def __init__(self) -> None:
        self.raw_wazuh_logs: List[Dict[str, Any]] = []
        self.fs_events: List[Dict[str, Any]] = []
        self.normalized_events: List[Dict[str, Any]] = []
        self.ml_detections: List[Dict[str, Any]] = []

    def write_raw_wazuh_log(self, doc: Dict[str, Any]) -> None:
        self.raw_wazuh_logs.append(doc)

    def write_fs_event(self, doc: Dict[str, Any]) -> None:
        self.fs_events.append(doc)

    def write_normalized_event(self, doc: Dict[str, Any]) -> None:
        self.normalized_events.append(doc)

    def write_ml_detection(self, doc: Dict[str, Any]) -> None:
        self.ml_detections.append(doc)


class FakeThreatIntelClient(ThreatIntelClient):
    """In-memory ThreatIntelClient for Risk Fusion tests. Returns whatever
    `ThreatIntelResult` it was seeded with (default: `matched=False`, i.e. a
    clean/no-op lookup) on every call, and records each `indicators` dict it
    was asked to look up so tests can assert on what a caller actually
    submitted."""

    def __init__(self, result: Optional[ThreatIntelResult] = None) -> None:
        self.result = result if result is not None else ThreatIntelResult(matched=False, source="fake")
        self.calls: List[Dict[str, Any]] = []

    def lookup(self, indicators: Dict[str, Any]) -> ThreatIntelResult:
        self.calls.append(indicators)
        return self.result


class FakeTriggerSender(TriggerSender):
    """In-memory TriggerSender for Risk Fusion tests - records every `fuse()`
    result dict it was asked to send, matching FakeHostController's/
    FakeEventWriter's "just record the call" pattern."""

    def __init__(self) -> None:
        self.sent: List[Dict[str, Any]] = []

    def send(self, fused: Dict[str, Any]) -> Dict[str, Any]:
        self.sent.append(fused)
        return {"status": "fake_sent", "risk_tier": fused["risk_tier"]}


class FakeM2Client(M2Client):
    """In-memory `M2Client` for tests (task m2-integration). Returns
    whatever `M2Result` it was seeded with (default: a benign, no-alert
    result) on every call, and records each `(events, run_id)` call so
    tests can assert on exactly what a caller submitted - matches
    `FakeThreatIntelClient`'s own convention."""

    def __init__(self, result: Optional[M2Result] = None) -> None:
        self.result = result if result is not None else M2Result(
            prediction="benign",
            ransomware_probability=0.0,
            threshold=0.5,
            alert=False,
            model_name="fake",
            feature_version="fake-1.0",
            explanation=[],
        )
        self.calls: List[Tuple[List[RawEvent], str]] = []

    def score(self, events: Sequence[RawEvent], run_id: str) -> Optional[M2Result]:
        self.calls.append((list(events), run_id))
        return self.result
