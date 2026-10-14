"""
EventWriter - the abstraction pipeline.run_once() writes its 3 document
shapes through (analogous to WazuhEventSource/HostController: one ABC, one
real implementation stubbed for OpenSearch, and a fake used by every test -
see backend/tests/fakes.FakeEventWriter).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class EventWriter(ABC):
    """Three write methods, one per document shape run_once() produces -
    kept as 3 explicit methods rather than one generic `write(index, doc)`
    so callers/tests can't accidentally target the wrong index by passing a
    typo'd string; the index name for each shape is this class's own
    responsibility, not the caller's.
    """

    @abstractmethod
    def write_raw_wazuh_log(self, doc: Dict[str, Any]) -> None:
        """Write one ai-rdr-raw-wazuh-logs-* shaped document."""

    @abstractmethod
    def write_fs_event(self, doc: Dict[str, Any]) -> None:
        """Write one ai-rdr-fs-events-* shaped document."""

    @abstractmethod
    def write_normalized_event(self, doc: Dict[str, Any]) -> None:
        """Write one ai-rdr-normalized-events-* shaped document."""

    @abstractmethod
    def write_ml_detection(self, doc: Dict[str, Any]) -> None:
        """Write one ai-rdr-ml-detections-* shaped document (backend/
        ml_scoring.py's score_events() output - task 4.2, live ML
        inference)."""


class OpenSearchEventWriter(EventWriter):
    """Stub real implementation - bulk-indexes each document via the
    OpenSearch REST `_doc` API against `airdr-siem`'s indexer. Deliberately
    NOT exercised against real infrastructure in this phase - no OpenSearch
    credentials are available or assumed (task instructions). Constructing
    this class opens no network connection; only the write_* methods need a
    reachable indexer, same convention as RealWazuhEventSource/
    host_controller.py's real implementations.

    Index names are parameterized (not hardcoded) so a later phase can point
    this at whatever the real deployed index-template names turn out to be
    without editing this file.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 9200,
        verify_ssl: bool = False,
        raw_wazuh_index_prefix: str = "ai-rdr-raw-wazuh-logs",
        fs_events_index_prefix: str = "ai-rdr-fs-events",
        normalized_index_prefix: str = "ai-rdr-normalized-events",
        ml_detections_index_prefix: str = "ai-rdr-ml-detections",
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl
        self.raw_wazuh_index_prefix = raw_wazuh_index_prefix
        self.fs_events_index_prefix = fs_events_index_prefix
        self.normalized_index_prefix = normalized_index_prefix
        self.ml_detections_index_prefix = ml_detections_index_prefix
        self.timeout = timeout

    def _index_name(self, prefix: str) -> str:
        import datetime

        # Daily-rotating index, matching the `-*` index-pattern convention
        # every ai-rdr-* name in the data dictionary uses.
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y.%m.%d")
        return f"{prefix}-{today}"

    def _index(self, prefix: str, doc: Dict[str, Any]) -> None:
        import requests  # lazy import - see event_source.RealWazuhEventSource

        index = self._index_name(prefix)
        url = f"https://{self.host}:{self.port}/{index}/_doc"
        resp = requests.post(
            url,
            json=doc,
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        resp.raise_for_status()

    def write_raw_wazuh_log(self, doc: Dict[str, Any]) -> None:
        self._index(self.raw_wazuh_index_prefix, doc)

    def write_fs_event(self, doc: Dict[str, Any]) -> None:
        self._index(self.fs_events_index_prefix, doc)

    def write_normalized_event(self, doc: Dict[str, Any]) -> None:
        self._index(self.normalized_index_prefix, doc)

    def write_ml_detection(self, doc: Dict[str, Any]) -> None:
        self._index(self.ml_detections_index_prefix, doc)
