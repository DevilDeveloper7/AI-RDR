"""Background enrichment jobs, so the alert path never waits for lookups.

submit() returns a job id immediately; a thread pool does the lookup.
Statuses: pending -> done | failed. A worker exception sets "failed"
(it never dies silently). The store keeps at most `max_jobs` jobs and
evicts the oldest beyond that.
"""
import threading
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

from .enricher import Enricher

PENDING, DONE, FAILED = "pending", "done", "failed"


class JobManager:
    def __init__(self, enricher: Enricher, workers: int = 4, max_jobs: int = 1000):
        self._enricher = enricher
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="m4-worker")
        self._max_jobs = max_jobs
        self._jobs: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._lock = threading.Lock()
        self.submitted = 0

    def submit(self, alert_id: str, ioc_type: str, value: str) -> str:
        job_id = uuid.uuid4().hex
        with self._lock:
            self._jobs[job_id] = {"job_id": job_id, "alert_id": alert_id, "status": PENDING,
                                  "result": None, "error": None}
            while len(self._jobs) > self._max_jobs:
                self._jobs.popitem(last=False)   # evict the oldest job
            self.submitted += 1
        self._pool.submit(self._run, job_id, alert_id, ioc_type, value)
        return job_id

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def stats(self) -> Dict[str, int]:
        with self._lock:
            counts = {PENDING: 0, DONE: 0, FAILED: 0}
            for job in self._jobs.values():
                counts[job["status"]] += 1
            return {"submitted": self.submitted, "stored": len(self._jobs), **counts}

    def shutdown(self) -> None:
        self._pool.shutdown(wait=True)

    def _run(self, job_id: str, alert_id: str, ioc_type: str, value: str) -> None:
        try:
            result, status, error = self._enricher.enrich(alert_id, ioc_type, value), DONE, None
        except Exception as exc:   # record the failure; never leave a job pending
            result, status, error = None, FAILED, f"enrichment failed: {type(exc).__name__}"
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:   # may have been evicted meanwhile
                job.update(status=status, result=result, error=error)
