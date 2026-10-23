# Integration hand-off: what M6 needs from M1-M5

**Status: PROVISIONAL / M6 STUB.** No teammate has confirmed an interface yet. M1-M5 currently run as mock adapters, so nothing in M6 is connected to a real module. Every method name and payload on this page is M6's proposal and may change once you tell us what your module actually provides.

How the pieces fit is described in [`adapters.md`](adapters.md) and [`../architecture.md`](../architecture.md). M6 requests or reads data through one adapter per module, so connecting your module only means writing that adapter. The React screens and the M6 API do not change.

## 1. What to send us

Please send the following for your module (a short message or a filled-in copy of this table is enough):

| Item | What we need |
|---|---|
| Repository / code | Where your code is (repository URL, branch, or the file to import) |
| Interface | Python function or module M6 can import, **or** an HTTP service (base URL and every endpoint with method) |
| Input format | Parameters each call takes, with types |
| Output format | The exact fields returned, with types and an example |
| Dependencies | What must be installed or running (services, libraries, models, data) |
| Run command | The exact command that starts your module |
| Port / base URL | Port and base URL if it is a service (`M<n>_BASE_URL` in `.env`); please do not give fixed IP addresses |
| Errors and limits | What it returns on failure, how long a call can take (timeouts), rate or size limits |
| Sample request and response | One real request and its real response |
| Time format | Timestamps as ISO 8601 UTC (`2026-09-29T09:41:15Z`) are what M6 expects |
| Security | Whether authentication is needed. M6 adapters do not support authentication yet |

## 2. What M6 expects from each module (PROVISIONAL)

Output shapes are checked by `backend/app/integrations/contracts.py`. The samples below are the **mock** data M6 uses today; replace them with your real sample in your reply. Unmarked fields are required; extra fields are tolerated.

### M1: SIEM and telemetry

Methods: `list_events(host, since, until, limit)`, `get_event(event_id)`. Input: optional host name, ISO timestamps (inclusive), maximum number of events. Output: normalized events, oldest first.

M6 uses the events as alert evidence and for the "Telemetry received" timeline entry. For ML alerts it currently reads events of type `behavioural.features`, `syscall.summary` and `fim.modified_burst` whose `details.process` matches the alert's process and that fall within a few seconds of the detection. Tell us which real event types and fields correspond.

```json
{
  "event_id": "EVT-1971-1",
  "timestamp": "2026-09-28T02:47:24Z",
  "source": "irdp",
  "event_type": "behavioural.features",
  "host": "HOST-03",
  "details": {
    "process": "clamscan (PID 4390)",
    "write_rate": "340 writes/s (baseline 42)",
    "rename_ratio": "0.12 of file operations"
  }
}
```

### M2: behavioural ML and SHAP

Methods: `list_detections()`, `get_shap(alert_id)`. Output: ML detections, and one SHAP explanation per detection (or none). M6 only displays this; it does not train or explain anything.

```json
{
  "alert_id": "A-2041",
  "severity": "Critical",
  "host": "HOST-03",
  "process": "enc_worker.py (PID 4127)",
  "activity": "Mass file write and rename burst",
  "timestamp": "2026-09-29T09:41:14Z",
  "threshold_exceeded_at": "2026-09-29T09:41:15Z",
  "prediction": "ransomware",
  "confidence": 0.94
}
```

SHAP explanation (`features` shortened to two entries):

```json
{
  "model": "XGBoost",
  "ransomware_likelihood": 0.94,
  "explained_at": "2026-09-29T09:41:15Z",
  "summary": "The alert was primarily influenced by unusually high file-write activity and elevated rename operations. Backup-process similarity slightly reduced confidence.",
  "features": [
    {
      "feature": "write_rate",
      "value": 0.42
    },
    {
      "feature": "rename_ratio",
      "value": 0.27
    }
  ]
}
```

### M3: honey-file deception

Methods: `list_honey_files()`, `list_triggers()`. Output: decoy status, recent activity, watcher status, and honey-file trigger alerts. A trigger goes directly to M6 and response; it must not need M2.

Trigger:

```json
{
  "alert_id": "A-2042",
  "severity": "Critical",
  "host": "HOST-03",
  "process": "enc_worker.py (PID 4127)",
  "honey_file": "/home/shared/budget_report.docx",
  "event": "IN_MODIFY, IN_OPEN by PID 4127",
  "activity": "Honey file modified",
  "timestamp": "2026-09-29T09:41:15Z",
  "high_confidence": true
}
```

Decoy status item:

```json
{
  "host": "HOST-03",
  "file": "budget_report.docx",
  "location": "/home/shared/",
  "status": "Triggered",
  "last_event": "2026-09-29T09:41:15Z",
  "alert_id": "A-2042"
}
```

### M4: threat-intelligence enrichment

Methods: `list_indicators()`, `enrich(indicator)`. Output: reputation and context for hashes, IPs and domains. Any provider is fine; M6 does not depend on one. It is context only, never the detection decision.

```json
{
  "indicator": "185.220.101.47",
  "type": "IP address",
  "reputation": "Suspicious",
  "source": "Threat feed (M4)",
  "related_alert": "A-2041",
  "last_checked": "2026-09-29T09:41:17Z",
  "notes": "Outbound connection attempt from HOST-03 shortly before detection. Listed on a public abuse feed.",
  "enrichment_status": "enriched"
}
```

### M5: automated response

Methods: `list_cases()`, `get_case(alert_id)`, `request_action(alert_id, action, target, actor, reason, analyst_override)`, `list_audit(limit)`.

M6 only requests actions: `freeze`, `verify`, `kill`, `isolate`, `thaw` (Kill and Isolate are separate). `target` is `{"host": ..., "process": ...}`. M5 decides, executes, and owns the response state and history. If an action is not allowed in the current state, M5 should reject it (M6 shows this as a 409 and leaves the alert unchanged).

Request (as M6 sends it): `request_action("A-2041", "verify", {"host": "HOST-03", "process": "enc_worker.py (PID 4127)"}, "Muhammad Alam")`

Response:

```json
{
  "alert_id": "A-2041",
  "action": "verify",
  "result": "accepted",
  "response_state": "Frozen",
  "verification_state": "Verifying",
  "timestamp": "2026-10-05T09:16:54Z"
}
```

Case (`history` shortened):

```json
{
  "alert_id": "A-2041",
  "response_state": "Frozen",
  "verification_state": "Verifying",
  "history": [
    {
      "timestamp": "2026-09-29T09:41:15Z",
      "event": "Process frozen"
    },
    {
      "timestamp": "2026-09-29T09:41:16Z",
      "event": "Verification started"
    }
  ]
}
```

Audit entry:

```json
{
  "timestamp": "2026-10-05T09:16:54Z",
  "event": "Verification started",
  "detail": "HOST-03 · PID 4127",
  "alert_id": "A-2041"
}
```

## 3. Questions we need answered

1. Who decides alert severity (`Critical`, `High`, `Medium`), and how?
2. Does the detector assign the alert ID, or should M6?
3. Do Kill and Isolate end in the same response state? What states exist beyond `Frozen`, `Isolated` and `Thawed`?
4. How does M6 reach each module (Python call or HTTP), and what are the timeouts and failure responses?
5. Which M1 event types and fields should be shown as evidence for an ML alert?
6. How is the honey-file watcher status reported (the mock always says `Running`)?

## 4. How M6 connects your module

1. We record your confirmed interface in [`adapters.md`](adapters.md) and remove the PROVISIONAL marking for it.
2. M6 adds `backend/app/integrations/mN/real.py` (a class that returns the shapes above) and registers it in `backend/app/integrations/registry.py`.
3. In `.env` set `MN_MODE=real` and, for an HTTP service, `MN_BASE_URL=<your base URL>`.
4. The adapter's output is checked against the contracts, and `python -m pytest` still has to pass. Integration Status then reflects the module's real health instead of `Stubbed`.

Until step 2 exists, `MN_MODE=real` is refused at startup, and the module stays a mock.
