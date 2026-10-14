"""
RawEvent + the WazuhEventSource abstraction (analogous to
backend/host_controller.py's HostController pattern: one ABC, one real
implementation parameterized by host/credentials but never exercised live in
this phase, and a fake used by every test - see backend/tests/fakes.py).

Correction 1 (see backend/irdp/__init__.py's package docstring): every
fs-shaped field here (`auditd_syscall`) is populated from auditd, never
inotify - this project's honey-file detection path (task-breakdown.md S2.2)
is auditd rules 100100 (read/write access, audit key `airdr_honeyfile_
access`) and 100103 (rename), read via Wazuh's logcollector, not a Linux
inotify watch.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

# The two custom Wazuh rule IDs task-breakdown.md S2.2 documents as the real,
# live-verified honey-file detection path (100100 = read/write via the
# airdr_honeyfile_access audit key, MITRE T1486; 100103 = rename, added
# separately because Wazuh's built-in auditd decoder collapses a rename's
# PATH group before a single rule could see both old/new names). Any alert
# carrying one of these rule IDs is the deterministic honey-file trigger -
# REQ-1.1's bypass-everything-else path.
HONEY_FILE_RULE_IDS = frozenset({"100100", "100103"})


@dataclass(frozen=True)
class RawEvent:
    """One event as read off the Wazuh indexer, before normalization.

    `kind` says which raw index this event's own record belongs in:
      - "wazuh_alert": a Wazuh rule match -> ai-rdr-raw-wazuh-logs-* shape.
        This includes honey-file alerts (rule_id in HONEY_FILE_RULE_IDS) -
        those are *also* file-system events (see normalize.to_fs_event_doc),
        but they arrive at this pipeline as Wazuh alerts, not as separate raw
        audit.log reads, because Wazuh's own logcollector+custom-rule
        pipeline is what turns the auditd record into an alert in the first
        place (task-breakdown.md S2.2's real, deployed detection path).
      - "fs_event": a raw auditd/FIM-sourced record read independently of any
        Wazuh rule match (e.g. a direct audit.log tail/whodata read) ->
        ai-rdr-fs-events-* shape.

    Fields are a superset of both ai-rdr-raw-wazuh-logs-*'s and
    ai-rdr-fs-events-*'s SDD-listed primary fields; each normalizer function
    in normalize.py reads only the subset relevant to the document it
    builds.
    """

    kind: str  # "wazuh_alert" | "fs_event"
    timestamp: str  # ISO-8601 UTC, e.g. "2026-09-29T00:00:00Z" - zero-padded
    # so plain string comparison sorts/checkpoints correctly (see
    # checkpoint.py's docstring for the tradeoff this implies).
    host_id: str
    honey_file_triggered: bool = False

    # ai-rdr-raw-wazuh-logs-* fields (only meaningful when kind=="wazuh_alert")
    agent_id: Optional[str] = None
    host_name: Optional[str] = None
    rule_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    process_name: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    raw_message: Optional[str] = None

    # ai-rdr-fs-events-* fields (SDD names, verbatim)
    event_id: Optional[str] = None
    file_path: Optional[str] = None
    process_id: Optional[int] = None
    user_id: Optional[str] = None

    # Internal only - never written to any document directly. The raw
    # auditd operation this event represents ("read", "write", "rename",
    # "delete"). Used by normalize.py to (a) map onto the SDD's
    # inotify-flavored event_mask STRING label for the fs-events doc
    # (Correction 1), and (b) infer a Tier-1 event_type for the ML-facing
    # bitmask (Correction 2) - both are pragmatic mappings this pipeline
    # owns, not values pulled from any upstream system.
    auditd_syscall: Optional[str] = None


class WazuhEventSource(ABC):
    """Abstract source of new RawEvents from a Wazuh manager's
    indexer/API. `poll()` must be side-effect-free with respect to what
    "new" means - it takes the last-processed checkpoint explicitly rather
    than tracking its own read position, so the same source object can be
    re-polled with a different checkpoint (e.g. after a restart that lost
    in-memory state) and still behave correctly.
    """

    @abstractmethod
    def poll(self, since_checkpoint: Optional[str]) -> List[RawEvent]:
        """Return every RawEvent strictly newer than `since_checkpoint`
        (an opaque token this module treats as a watermark - see
        checkpoint.py), or every event available if `since_checkpoint` is
        None (first-ever run). Must not mutate any state needed to answer
        the same query again - checkpoint advancement is the caller's job
        (pipeline.run_once), not the source's.
        """


class RealWazuhEventSource(WazuhEventSource):
    """Queries `airdr-siem`'s Wazuh indexer (OpenSearch) directly over its
    REST `_search` API for both ordinary Wazuh alerts and auditd-decoded
    events, using a `@timestamp` range filter as the checkpoint boundary.

    Deliberately NOT exercised against real infrastructure in this phase -
    no SSH keys or OpenSearch credentials are available or assumed (task
    instructions). `host`/`username`/`password`/`index_pattern` are plain
    constructor parameters with no embedded secrets; constructing this class
    opens no network connection (mirrors host_controller.py's
    A hypervisor-backed controller: building the client object is always safe,
    only `poll()` needs a reachable indexer). The exact request/response
    shape below is a plausible mapping onto Wazuh's standard alert JSON
    (`rule.id`, `agent.id`, `data.audit.*`, etc.) and task-breakdown.md
    S2.2's documented rule IDs/audit key - it has not been verified against
    a live query in this phase, and a later phase with real credentials
    should treat this as a starting point to verify/adjust, not a proven
    contract.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 9200,
        index_pattern: str = "wazuh-alerts-*",
        verify_ssl: bool = False,
        timeout: float = 10.0,
        page_size: int = 500,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.index_pattern = index_pattern
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.page_size = page_size

    def _search(self, since_checkpoint: Optional[str]) -> dict:
        import requests  # already a backend dependency (host_controller.py's
        # sibling modules use it); imported lazily so this module stays
        # importable with no network access, same convention as
        # host_controller.py's lazy paramiko import.

        time_filter = {"gt": since_checkpoint} if since_checkpoint else {"gte": "now-1y"}
        query = {
            "size": self.page_size,
            "sort": [{"@timestamp": "asc"}],
            "query": {"range": {"@timestamp": time_filter}},
        }
        url = f"https://{self.host}:{self.port}/{self.index_pattern}/_search"
        resp = requests.get(
            url,
            json=query,
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _hit_to_raw_event(hit: dict) -> RawEvent:
        src = hit.get("_source", {})
        rule = src.get("rule", {}) or {}
        agent = src.get("agent", {}) or {}
        data = src.get("data", {}) or {}
        audit = data.get("audit", {}) or {}

        rule_id = str(rule.get("id")) if rule.get("id") is not None else None
        honey_file_triggered = rule_id in HONEY_FILE_RULE_IDS

        # A hit carries real fs-event detail (audit key populated) whenever
        # Wazuh's auditd decoder fired, whether or not a custom rule also
        # matched - that's the Correction-1 auditd path, never inotify.
        has_fs_detail = bool(audit)

        mitre = rule.get("mitre", {}) or {}
        mitre_ids = mitre.get("id") or []
        mitre_technique = mitre_ids[0] if mitre_ids else None

        auditd_syscall = None
        syscall_name = (audit.get("syscall") or "").lower()
        if "read" in syscall_name or audit.get("key") == "airdr_honeyfile_access" and not audit.get("file", {}).get("name", "").endswith("~"):
            auditd_syscall = "read"
        if any(w in syscall_name for w in ("write", "pwrite")):
            auditd_syscall = "write"
        if "rename" in syscall_name:
            auditd_syscall = "rename"
        if any(w in syscall_name for w in ("unlink", "delete")):
            auditd_syscall = "delete"

        return RawEvent(
            kind="wazuh_alert",
            timestamp=src.get("timestamp") or src.get("@timestamp"),
            host_id=agent.get("name") or agent.get("id") or "unknown-host",
            honey_file_triggered=honey_file_triggered,
            agent_id=agent.get("id"),
            host_name=agent.get("name"),
            rule_id=rule_id,
            mitre_technique=mitre_technique,
            process_name=data.get("process", {}).get("name") if isinstance(data.get("process"), dict) else audit.get("exe"),
            src_ip=data.get("srcip"),
            dest_ip=data.get("dstip"),
            raw_message=src.get("full_log"),
            event_id=hit.get("_id"),
            file_path=(audit.get("file", {}) or {}).get("name") if has_fs_detail else None,
            process_id=int(audit.get("pid")) if audit.get("pid") else None,
            user_id=audit.get("auid"),
            auditd_syscall=auditd_syscall if has_fs_detail else None,
        )

    def poll(self, since_checkpoint: Optional[str]) -> List[RawEvent]:
        body = self._search(since_checkpoint)
        hits = body.get("hits", {}).get("hits", [])
        return [self._hit_to_raw_event(hit) for hit in hits]
