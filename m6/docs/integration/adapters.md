# M1-M5 adapter boundaries

**Status: PROVISIONAL / M6 STUB. The real M1-M5 interfaces are still pending.**
Every method name, payload and field below is M6's *proposal*. Nothing here has been agreed with the owners of M1-M5.
Until they confirm their interfaces, every module runs as a built-in **mock** (`M1_MODE=mock` ... `M5_MODE=mock`), and the
Integration Status screen shows each one as **Stubbed** with the line **Mock · provisional**. M1-M5 are never reported as Connected.

```
React -> M6 Flask API (/api/v1) -> M6 services -> adapters (integrations/m1 ... m5) -> mock (now) / real module (later)
```

React never talks to M1-M5. Adapters know nothing about Flask or React; they return plain dicts that match `backend/app/integrations/contracts.py`.
Services validate every adapter result against those contracts, so a bad reply becomes a controlled error (502/503/504), never a broken screen.

## Who owns what

| Module | Owns | M6 asks it for | Adapter (interface / mock) |
|---|---|---|---|
| M1 | SIEM + telemetry (Wazuh, auditd/FIM, IRDP normalisation) | Normalized events (evidence, timeline) | `integrations/m1/__init__.py`, `m1/mock.py` |
| M2 | Behavioural ML detection + SHAP | ML detections, SHAP explanation | `m2/` |
| M3 | Honey-file deception (inotify watcher) | Honey-file status, trigger alerts | `m3/` |
| M4 | Threat-intelligence enrichment (provider not final) | Indicator reputation/context | `m4/` |
| M5 | Automated response (ARM + AICM), case record, audit trail | Response state, history; executes requested actions | `m5/` |
| M6 | Dashboard, analyst status (Open/Acknowledged), API, integration | - | `services/`, `routes/` |

M6 does not detect, explain, watch files, call a threat-intel provider, or execute responses.

### How an alert is assembled (`services/alert_service.py`)

| Part of the alert | Comes from |
|---|---|
| ML alert (severity, host, process, confidence) | M2 `list_detections()` |
| Honey-file alert | M3 `list_triggers()` (independent fast path: **never** routed through M2) |
| Evidence, "Telemetry received" | M1 `list_events()` |
| Response state, verification state, response history | M5 `list_cases()` / `get_case()` |
| Related indicators | M4 `list_indicators()` (context only; if M4 fails the alert still loads) |
| Open / Acknowledged | M6 (analyst status) |

## Contracts (PROVISIONAL)

| Contract | Fields |
|---|---|
| M1 event | `event_id, timestamp, source, event_type, host, details{}` |
| M2 detection | `alert_id, severity, host, process, activity, timestamp, threshold_exceeded_at, prediction, confidence` |
| M2 SHAP | `model, ransomware_likelihood, explained_at, summary, features[{feature, value}]` |
| M3 trigger | `alert_id, severity, host, process, honey_file, event, activity, timestamp, high_confidence` |
| M3 honey item | `host, file, location, status, last_event, alert_id` |
| M4 indicator | `indicator, type, reputation, source, related_alert, last_checked, notes, enrichment_status` |
| M5 case | `alert_id, response_state, verification_state, history[{timestamp, event}]` |
| M5 action result | `alert_id, action, result, response_state, verification_state, timestamp` |
| M5 audit entry | `timestamp, event, detail, alert_id` |

Timestamps are ISO 8601 UTC (`2026-09-29T09:41:15Z`). `severity` is `Critical|High|Medium`; `response_state` is `Frozen|Isolated|Thawed`.
Open questions for the module owners: how severity is decided, whether M6 or the detector assigns alert IDs, and whether Kill and Isolate end in the same state.

### Examples (mock data)

These are real outputs of the mock adapters (lists shortened). A real adapter must return the same shapes.

**M1 event**

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

**M2 detection**

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

**M2 SHAP** (`features` shortened)

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

**M3 trigger**

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

**M3 honey item**

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

**M4 indicator**

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

**M5 case** (`history` shortened)

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

**M5 action result**

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

**M5 audit entry**

```json
{
  "timestamp": "2026-10-05T09:16:54Z",
  "event": "Verification started",
  "detail": "HOST-03 · PID 4127",
  "alert_id": "A-2041"
}
```

### Adapter methods (PROVISIONAL)

- **M1:** `list_events(host, since, until, limit)`, `get_event(event_id)`
- **M2:** `list_detections()`, `get_shap(alert_id)`
- **M3:** `list_honey_files()`, `list_triggers()`
- **M4:** `list_indicators()`, `enrich(indicator)`
- **M5:** `list_cases()`, `get_case(alert_id)`, `request_action(alert_id, action, target, actor, reason, analyst_override)`, `list_audit(limit)`
- **All:** `health()` returns `{"status": "Connected|Stubbed|Warning|Failed", "detail": "..."}`

### Response workflow (M5)

`Detection -> Freeze -> Verify -> (confirmed ransomware) Kill or Isolate | (false positive) Thaw`.
Allowed actions: `freeze, verify, kill, isolate, thaw`. Kill and Isolate are separate actions. The mock M5 ends both in `Isolated`
(PROVISIONAL). An analyst override is a Thaw request with `analyst_override=true`.

### Errors

Adapters raise `IntegrationUnavailable` (503), `IntegrationTimeout` (504), `MalformedResponse` (502) or `ActionRejected` (409);
Flask turns them into `{"error": {"code", "message"}}`. How M6 reacts depends on the module:

| Module fails | Result |
|---|---|
| M1 | The alert page still loads; evidence is empty and `evidence_status` is `unavailable`. The events endpoint returns the error. |
| M4 | The alert page still loads; `indicators` is empty and `enrichment_status` is `unavailable`. |
| M2 or M3 (one of them) | The other detection path still works. `GET /alerts` lists the available alerts and names the missing module in `meta.unavailable`. Asking for an alert that needs the missing module returns the error. |
| M2 and M3 | The alert list returns the error. |
| M5 | Alerts cannot show a response state, so the alert list and actions return the error; the alert is left unchanged. |

Results that break the contracts below are rejected with `502 MALFORMED_RESPONSE`.

## Replacing a mock with the real module

What a teammate needs to provide is listed in [`handoff.md`](handoff.md).

1. Get the real endpoint and schema from the module owner and update this file.
2. Add `integrations/mN/real.py` with a class that subclasses the interface and returns the same shapes as the mock.
3. Register it in `integrations/registry.py` (`_REAL`) and set `MN_MODE=real`, `MN_BASE_URL=...` in `.env`.

Services, the API response shapes and the React UI do not change.

## Mock data

`backend/app/mock/`: `m1_events.json`, `m2_detections.json`, `shap.json`, `m3_triggers.json`, `honey_files.json`, `threat_intelligence.json`,
`m5_cases.json`, `m6_seed.json`, `integrations.json`. The files describe one consistent simulated system (same alert IDs, hosts, processes and times
across M1-M5); `tests/test_adapters.py` checks this. All of it is MOCK data, not real module output.
