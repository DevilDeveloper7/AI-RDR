# M6 REST API reference

Base path: `/api/v1`. The API is served by the M6 Flask backend (default `http://127.0.0.1:5001`). The React app reaches it through the Vite dev proxy at `http://localhost:5173/api/v1`.
It is the only interface the frontend uses; the frontend never contacts M1-M5. See [`../architecture.md`](../architecture.md).

All data currently comes from mock adapters (M1-M5 are not connected). Lists are shortened in the examples. All values come from the running mock system, so they are mock data, and values such as action timestamps depend on when the request was made.

## Conventions

- Requests and responses are JSON. Timestamps are ISO 8601 UTC strings such as `2026-09-29T09:41:15Z`.
- Alert IDs match `A-<1 to 6 digits>` (for example `A-2041`).
- There is no authentication. Analyst actions are recorded under the configured `ANALYST_NAME`.
- Every error has the same shape and never contains a stack trace (details are written to the server log only):

```json
{"error": {"code": "ALERT_NOT_FOUND", "message": "Alert A-9999 was not found."}}
```

| Status | Codes | Meaning |
|---|---|---|
| 400 | `INVALID_ALERT_ID`, `INVALID_PARAMETER`, `INVALID_ACTION`, `INVALID_BODY`, `INVALID_REASON`, `INVALID_INDICATOR`, `INVALID_MODULE` | The request is not valid |
| 404 | `ALERT_NOT_FOUND`, `INDICATOR_NOT_FOUND`, `SHAP_NOT_AVAILABLE`, `SHAP_NOT_APPLICABLE`, `NOT_FOUND` | The thing requested does not exist or does not apply |
| 405 | `METHOD_NOT_ALLOWED` | Wrong HTTP method for the path |
| 409 | `INVALID_STATE`, `ACTION_REJECTED` | The action is not allowed in the alert's current response state |
| 500 | `INTERNAL_ERROR` | Unexpected error (generic message) |
| 502 | `MALFORMED_RESPONSE`, `INTEGRATION_ERROR` | An adapter returned something that breaks the data contract |
| 503 | `INTEGRATION_UNAVAILABLE` | An adapter reported that its module is unavailable |
| 504 | `INTEGRATION_TIMEOUT` | An adapter timed out |

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | M6 liveness |
| GET | `/alerts` | Filtered, paged alert list |
| GET | `/alerts/<alert_id>` | One alert with evidence and timeline |
| GET | `/alerts/<alert_id>/events` | Normalized M1 events around the alert |
| GET | `/alerts/<alert_id>/shap` | SHAP explanation (ML alerts only) |
| POST | `/alerts/<alert_id>/acknowledge` | Analyst acknowledgement |
| POST | `/alerts/<alert_id>/override` | Analyst override (requests Thaw) |
| POST | `/alerts/<alert_id>/action` | Request a response action from M5 |
| GET | `/response-activity` | Recent response activity |
| GET | `/honey-files` | Honey-file status |
| GET | `/threat-intelligence` | Enriched indicators |
| GET | `/threat-intelligence/<indicator>` | One enriched indicator |
| GET | `/integrations/status` | Status of M1-M6 |
| POST | `/integrations/check` | Re-check one module or all |

---

### GET `/health`

M6 liveness only. It says nothing about M1-M5 (use `/integrations/status`). No parameters.

Response fields: `status` (`"ok"`), `service` (`"ai-rdr-m6"`), `api_version`, `environment` (from `APP_ENV`), `timestamp`.

`200`

```json
{
  "api_version": "v1",
  "environment": "development",
  "service": "ai-rdr-m6",
  "status": "ok",
  "timestamp": "2026-10-05T09:16:53+00:00"
}
```

---

### GET `/alerts`

Alerts are assembled by M6 from M2 detections or M3 honey-file triggers, M1 events, and M5 response state. They are sorted newest first.

| Parameter | Values | Notes |
|---|---|---|
| `severity` | `Critical`, `High`, `Medium` | optional |
| `detection_type` | `ML Behavioural Detection`, `Honey-File Trigger` | optional |
| `response_state` | `Frozen`, `Isolated`, `Thawed` | optional |
| `host` | host name, exact match | optional |
| `range_minutes` | integer 1-525600 | only alerts newer than this many minutes before `meta.reference_time` |
| `q` | text (first 100 characters used) | case-insensitive match on ID, host, process, detection type |
| `page` | integer 1-10000 | default 1 (a page past the end returns the last page) |
| `page_size` | integer 1-100 | default 20 |

Response fields:

- `items[]`: `id, severity, detection_type, host, process, activity, timestamp, response_state, verification_state, status, source, confidence`. `status` is `Open` or `Acknowledged`. `confidence` is a number for ML alerts and `null` for honey-file alerts.
- `total, page, page_size, pages`.
- `summary` (over all alerts, not just the filtered ones): `active` (Frozen), `critical` (Critical and Frozen), `open` (not acknowledged), `total`.
- `facets`: `hosts, severities, detection_types, response_states` (used to fill the filter lists).
- `meta`: `is_mock`, `reference_time`, `unavailable` (list of modules that could not be read, see below).

Errors: `400 INVALID_PARAMETER`; `502/503/504` if M5 fails, or if both M2 and M3 fail.

Example: `GET /alerts?severity=Critical&page_size=2`

`200`

```json
{
  "facets": {
    "detection_types": [
      "Honey-File Trigger",
      "ML Behavioural Detection"
    ],
    "hosts": [
      "HOST-01",
      "HOST-02"
    ],
    "response_states": [
      "Frozen",
      "Isolated",
      "Thawed"
    ],
    "severities": [
      "Critical",
      "High",
      "Medium"
    ]
  },
  "items": [
    {
      "activity": "Honey file modified",
      "confidence": null,
      "detection_type": "Honey-File Trigger",
      "host": "HOST-03",
      "id": "A-2042",
      "process": "enc_worker.py (PID 4127)",
      "response_state": "Frozen",
      "severity": "Critical",
      "source": "mock",
      "status": "Open",
      "timestamp": "2026-09-29T09:41:15Z",
      "verification_state": "Verifying"
    },
    {
      "activity": "Mass file write and rename burst",
      "confidence": 0.94,
      "detection_type": "ML Behavioural Detection",
      "host": "HOST-03",
      "id": "A-2041",
      "process": "enc_worker.py (PID 4127)",
      "response_state": "Frozen",
      "severity": "Critical",
      "source": "mock",
      "status": "Open",
      "timestamp": "2026-09-29T09:41:14Z",
      "verification_state": "Verifying"
    }
  ],
  "meta": {
    "is_mock": true,
    "reference_time": "2026-09-29T09:44:03Z",
    "unavailable": []
  },
  "page": 1,
  "page_size": 2,
  "pages": 8,
  "summary": {
    "active": 3,
    "critical": 2,
    "open": 3,
    "total": 80
  },
  "total": 16
}
```

**One detection source down.** M2 (ML) and M3 (honey file) are independent paths. If one module is unavailable the other still serves its alerts, and the outage is reported in `meta.unavailable` instead of being hidden. Example with M2 unavailable (produced in a test with a failing adapter; the list contains only honey-file alerts):

`200`

```json
{
  "meta": {
    "is_mock": true,
    "reference_time": "2026-09-29T09:44:03Z",
    "unavailable": [
      "m2"
    ]
  }
}
```

An empty result is a normal `200` with `"items": []`, `"total": 0`, `"pages": 1`.

---

### GET `/alerts/<alert_id>`

The list fields plus: `summary` (plain-language description), `evidence[]` (`label`, `value`), `timeline[]` (`timestamp`, `event`, `pending`, `hot`), `indicators[]` (related M4 indicator values), `evidence_status` and `enrichment_status` (`ok` or `unavailable`). Honey-file alerts also have `honey_file`.

- ML alert evidence comes from M1 events; honey-file alert evidence comes from the M3 trigger and includes `Model stage: Bypassed (fast path)`.
- Timeline response entries come from M5. While the process is Frozen, a final entry with `pending: true` and `timestamp: null` marks the expected next step.
- If M1 or M4 is unavailable, the alert still loads and the matching status says `unavailable` (evidence or indicators are empty).

Errors: `400 INVALID_ALERT_ID`, `404 ALERT_NOT_FOUND`, `502/503/504` when a required module fails.

`200`

```json
{
  "activity": "Mass file write and rename burst",
  "confidence": 0.94,
  "detection_type": "ML Behavioural Detection",
  "enrichment_status": "ok",
  "evidence": [
    {
      "label": "write_rate",
      "value": "1,840 writes/s (baseline 42)"
    },
    {
      "label": "rename_ratio",
      "value": "0.61 of file operations"
    },
    {
      "label": "syscall_frequency",
      "value": "12.4k/s (auditd)"
    }
  ],
  "evidence_status": "ok",
  "host": "HOST-03",
  "id": "A-2041",
  "indicators": [
    "9f2cc3d6f7864d23c4d75cb404558a81d69369e303cbe12c4fbdf337e41a",
    "185.220.101.47"
  ],
  "process": "enc_worker.py (PID 4127)",
  "response_state": "Frozen",
  "severity": "Critical",
  "source": "mock",
  "status": "Open",
  "summary": "Behavioural activity on HOST-03 exceeded the configured ransomware detection threshold. The process wrote and renamed files at a rate far above baseline.",
  "timeline": [
    {
      "event": "Telemetry received",
      "hot": false,
      "pending": false,
      "timestamp": "2026-09-29T09:41:12Z"
    },
    {
      "event": "Behavioural anomaly detected",
      "hot": false,
      "pending": false,
      "timestamp": "2026-09-29T09:41:14Z"
    },
    {
      "event": "ML threshold exceeded",
      "hot": false,
      "pending": false,
      "timestamp": "2026-09-29T09:41:15Z"
    }
  ],
  "timestamp": "2026-09-29T09:41:14Z",
  "verification_state": "Verifying"
}
```

---

### GET `/alerts/<alert_id>/events`

Normalized M1 events for the alert's host within 10 seconds either side of the alert time. The current UI does not display them. Response: `alert_id`, `items[]` (`event_id, timestamp, source, event_type, host, details`), `meta`.

`200`

```json
{
  "alert_id": "A-2041",
  "items": [
    {
      "details": {
        "process": "enc_worker.py (PID 4127)",
        "rename_ratio": "0.61 of file operations",
        "write_rate": "1,840 writes/s (baseline 42)"
      },
      "event_id": "EVT-2041-1",
      "event_type": "behavioural.features",
      "host": "HOST-03",
      "source": "irdp",
      "timestamp": "2026-09-29T09:41:12Z"
    },
    {
      "details": {
        "process": "enc_worker.py (PID 4127)",
        "syscall_frequency": "12.4k/s (auditd)"
      },
      "event_id": "EVT-2041-2",
      "event_type": "syscall.summary",
      "host": "HOST-03",
      "source": "auditd",
      "timestamp": "2026-09-29T09:41:13Z"
    }
  ],
  "meta": {
    "is_mock": true
  }
}
```

---

### GET `/alerts/<alert_id>/shap`

SHAP explanation supplied by M2 (M6 does not calculate it). Response: `alert_id, severity, host, model, ransomware_likelihood, explained_at, summary, features[]` (`feature`, `value`; positive values raise the likelihood).

Errors: `404 SHAP_NOT_APPLICABLE` (honey-file alert: no ML stage), `404 SHAP_NOT_AVAILABLE` (M2 has no explanation for this alert), `400/404` for bad IDs, `502/503/504` if M2 fails. In the mock data only A-2041, A-2039 and A-2038 have SHAP values.

`200`

```json
{
  "alert_id": "A-2041",
  "explained_at": "2026-09-29T09:41:15Z",
  "features": [
    {
      "feature": "write_rate",
      "value": 0.42
    },
    {
      "feature": "rename_ratio",
      "value": 0.27
    },
    {
      "feature": "syscall_frequency",
      "value": 0.21
    }
  ],
  "host": "HOST-03",
  "model": "XGBoost",
  "ransomware_likelihood": 0.94,
  "severity": "Critical",
  "summary": "The alert was primarily influenced by unusually high file-write activity and elevated rename operations. Backup-process similarity slightly reduced confidence."
}
```

Not available:

`404`

```json
{
  "error": {
    "code": "SHAP_NOT_AVAILABLE",
    "message": "No SHAP explanation is available for A-2040."
  }
}
```

---

### POST `/alerts/<alert_id>/acknowledge`

Marks the alert Acknowledged (M6 keeps analyst status). No request body. Repeating the call is harmless. Response: `alert` (the full alert as in the detail endpoint) and `acknowledged_by`.

`200`

```json
{
  "acknowledged_by": "Muhammad Alam",
  "alert": {
    "activity": "Mass file write and rename burst",
    "confidence": 0.94,
    "detection_type": "ML Behavioural Detection",
    "enrichment_status": "ok",
    "evidence": [
      {
        "label": "write_rate",
        "value": "1,840 writes/s (baseline 42)"
      }
    ],
    "evidence_status": "ok",
    "host": "HOST-03",
    "id": "A-2041",
    "indicators": [
      "9f2cc3d6f7864d23c4d75cb404558a81d69369e303cbe12c4fbdf337e41a"
    ],
    "process": "enc_worker.py (PID 4127)",
    "response_state": "Frozen",
    "severity": "Critical",
    "source": "mock",
    "status": "Acknowledged",
    "summary": "Behavioural activity on HOST-03 exceeded the configured ransomware detection threshold. The process wrote and renamed files at a rate far above baseline.",
    "timeline": [
      {
        "event": "Telemetry received",
        "hot": false,
        "pending": false,
        "timestamp": "2026-09-29T09:41:12Z"
      }
    ],
    "timestamp": "2026-09-29T09:41:14Z",
    "verification_state": "Verifying"
  }
}
```

---

### POST `/alerts/<alert_id>/override`

Analyst override: requests **Thaw** from M5 with the analyst flag set, and marks the alert Acknowledged.

Body: `{"reason": "<3 to 500 characters>"}`. Errors: `400 INVALID_REASON`, `400 INVALID_BODY`, `409 INVALID_STATE` (the process is not Frozen), `409 ACTION_REJECTED`, `502/503/504`. Response: `alert`, `requested_by`, `executor`, `result` (the M5 action result).

`200`

```json
{
  "alert": {
    "activity": "Mass file write and rename burst",
    "confidence": 0.66,
    "detection_type": "ML Behavioural Detection",
    "enrichment_status": "ok",
    "evidence": [
      {
        "label": "write_rate",
        "value": "1,030 writes/s (baseline 42)"
      }
    ],
    "evidence_status": "ok",
    "host": "HOST-05",
    "id": "A-2038",
    "indicators": [
      "3ab829c44a2d514e3859c1c4da7c8471d0dfd46600539e9596d20b6277d0"
    ],
    "process": "tar (PID 22014)",
    "response_state": "Thawed",
    "severity": "Medium",
    "source": "mock",
    "status": "Acknowledged",
    "summary": "Behavioural activity on HOST-05 exceeded the detection threshold. The process was released (analyst override).",
    "timeline": [
      {
        "event": "Telemetry received",
        "hot": false,
        "pending": false,
        "timestamp": "2026-09-29T08:57:38Z"
      }
    ],
    "timestamp": "2026-09-29T08:57:40Z",
    "verification_state": "Analyst override"
  },
  "executor": "M5 (mock adapter)",
  "requested_by": "Muhammad Alam",
  "result": {
    "action": "thaw",
    "alert_id": "A-2038",
    "response_state": "Thawed",
    "result": "accepted",
    "timestamp": "2026-10-05T09:16:53Z",
    "verification_state": "Analyst override"
  }
}
```

---

### POST `/alerts/<alert_id>/action`

Requests a response action. M6 only requests; M5 decides and executes. Body: `{"action": "<action>", "reason": "<optional, 3-500 characters>"}` where `action` is one of `freeze`, `verify`, `kill`, `isolate`, `thaw`. Kill and Isolate are separate actions. `kill` and `isolate` also mark the alert Acknowledged.

Errors: `400 INVALID_ACTION`, `400 INVALID_BODY`, `400 INVALID_REASON`, `404 ALERT_NOT_FOUND`, `409 ACTION_REJECTED` (not allowed in the current state; the alert is left unchanged), `502/503/504`.

Mock M5 behaviour (the real M5 may differ): `freeze` is always accepted and gives `Frozen`/`Verifying`; `verify`, `kill`, `isolate` and `thaw` are only accepted while `Frozen`; `verify` gives `Frozen`/`Verifying`; `kill` and `isolate` both give `Isolated`/`Confirmed` (provisional); `thaw` gives `Thawed`/`False positive`.

`200`

```json
{
  "alert": {
    "activity": "Mass file write and rename burst",
    "confidence": 0.94,
    "detection_type": "ML Behavioural Detection",
    "enrichment_status": "ok",
    "evidence": [
      {
        "label": "write_rate",
        "value": "1,840 writes/s (baseline 42)"
      }
    ],
    "evidence_status": "ok",
    "host": "HOST-03",
    "id": "A-2041",
    "indicators": [
      "9f2cc3d6f7864d23c4d75cb404558a81d69369e303cbe12c4fbdf337e41a"
    ],
    "process": "enc_worker.py (PID 4127)",
    "response_state": "Isolated",
    "severity": "Critical",
    "source": "mock",
    "status": "Acknowledged",
    "summary": "Behavioural activity on HOST-03 exceeded the configured ransomware detection threshold. The process wrote and renamed files at a rate far above baseline.",
    "timeline": [
      {
        "event": "Telemetry received",
        "hot": false,
        "pending": false,
        "timestamp": "2026-09-29T09:41:12Z"
      }
    ],
    "timestamp": "2026-09-29T09:41:14Z",
    "verification_state": "Confirmed"
  },
  "executor": "M5 (mock adapter)",
  "requested_by": "Muhammad Alam",
  "result": {
    "action": "isolate",
    "alert_id": "A-2041",
    "response_state": "Isolated",
    "result": "accepted",
    "timestamp": "2026-10-05T09:16:53Z",
    "verification_state": "Confirmed"
  }
}
```

Rejected (isolating a process that was already thawed):

`409`

```json
{
  "error": {
    "code": "ACTION_REJECTED",
    "message": "'isolate' is not valid while the process is Thawed."
  }
}
```

Invalid action:

`400`

```json
{
  "error": {
    "code": "INVALID_ACTION",
    "message": "Action must be one of: freeze, verify, kill, isolate, thaw."
  }
}
```

---

### GET `/response-activity`

Recent response activity: M5's audit trail merged with M6's own acknowledgements, newest first. Parameter: `limit` (1-50, default 6). Response: `items[]` (`timestamp, event, detail, alert_id`), `meta`.

`200`

```json
{
  "items": [
    {
      "alert_id": "A-2041",
      "detail": "HOST-03 · PID 4127",
      "event": "Verification started",
      "timestamp": "2026-09-29T09:41:16Z"
    },
    {
      "alert_id": "A-2042",
      "detail": "HOST-03 · PID 4127",
      "event": "Freeze",
      "timestamp": "2026-09-29T09:41:15Z"
    },
    {
      "alert_id": "A-2039",
      "detail": "HOST-01 · PID 1893",
      "event": "Thaw",
      "timestamp": "2026-09-29T09:22:31Z"
    }
  ],
  "meta": {
    "is_mock": true
  }
}
```

---

### GET `/honey-files`

Honey-file status from M3. Response: `summary` (`watcher_status, total_files, monitored_hosts, total_hosts, healthy, triggered, triggered_hosts, last_interaction`), `items[]` (`host, file, location, status, last_event, alert_id`), `activity[]` (`timestamp, text, hot`), `meta`. `status` is `Protected` or `Triggered`. Errors: `502/503/504` if M3 fails.

`200`

```json
{
  "activity": [
    {
      "hot": true,
      "text": "budget_report.docx modified on HOST-03",
      "timestamp": "2026-09-29T09:41:15Z"
    },
    {
      "hot": false,
      "text": "payroll_q3.xlsx opened on HOST-02",
      "timestamp": "2026-09-29T08:10:02Z"
    }
  ],
  "items": [
    {
      "alert_id": null,
      "file": "invoice_2026.xlsx",
      "host": "HOST-01",
      "last_event": null,
      "location": "/home/shared/",
      "status": "Protected"
    },
    {
      "alert_id": "A-2037",
      "file": "payroll_q3.xlsx",
      "host": "HOST-02",
      "last_event": "2026-09-29T08:10:02Z",
      "location": "/srv/finance/",
      "status": "Triggered"
    }
  ],
  "meta": {
    "is_mock": true
  },
  "summary": {
    "healthy": 4,
    "last_interaction": {
      "host": "HOST-03",
      "time": "2026-09-29T09:41:15Z"
    },
    "monitored_hosts": 6,
    "total_files": 6,
    "total_hosts": 6,
    "triggered": 2,
    "triggered_hosts": [
      "HOST-02",
      "HOST-03"
    ],
    "watcher_status": "Running"
  }
}
```

---

### GET `/threat-intelligence` and `/threat-intelligence/<indicator>`

Enrichment from M4. It is context for alerts, never the detection decision. The list accepts `limit` (1-100). The detail path takes an indicator value (hash, IP or domain; letters, digits and `. : _ - …`, up to 128 characters).

Fields: `indicator, type, reputation, source, related_alert, last_checked, notes, enrichment_status`. `reputation` is `Malicious`, `Suspicious`, `Clean` or `Unknown`; `enrichment_status` is `enriched` or `no_data`. Errors: `400 INVALID_INDICATOR`, `404 INDICATOR_NOT_FOUND`, `502/503/504` if M4 fails.

`200`

```json
{
  "items": [
    {
      "enrichment_status": "enriched",
      "indicator": "9f2cc3d6f7864d23c4d75cb404558a81d69369e303cbe12c4fbdf337e41a",
      "last_checked": "2026-09-29T09:41:17Z",
      "notes": "Hash of enc_worker.py observed on HOST-03. Matches a known ransomware family sample. Context only; the detection decision was made by M2.",
      "related_alert": "A-2041",
      "reputation": "Malicious",
      "source": "Threat feed (M4)",
      "type": "SHA-256"
    },
    {
      "enrichment_status": "enriched",
      "indicator": "185.220.101.47",
      "last_checked": "2026-09-29T09:41:17Z",
      "notes": "Outbound connection attempt from HOST-03 shortly before detection. Listed on a public abuse feed.",
      "related_alert": "A-2041",
      "reputation": "Suspicious",
      "source": "Threat feed (M4)",
      "type": "IP address"
    }
  ],
  "meta": {
    "is_mock": true,
    "role": "enrichment only"
  }
}
```

`200`

```json
{
  "enrichment_status": "enriched",
  "indicator": "185.220.101.47",
  "last_checked": "2026-09-29T09:41:17Z",
  "notes": "Outbound connection attempt from HOST-03 shortly before detection. Listed on a public abuse feed.",
  "related_alert": "A-2041",
  "reputation": "Suspicious",
  "source": "Threat feed (M4)",
  "type": "IP address"
}
```

---

### GET `/integrations/status`

Status of each component, as reported by its adapter's `health()`; M6 reports itself as `Connected`. Component fields: `module, name, interface, endpoint, last_check, status, detail, mode, provisional`. Statuses: `Connected`, `Stubbed`, `Warning`, `Failed`. `mode` is `mock` for M1-M5 today. All five are shown as `Stubbed`; none is reported as Connected.

`endpoint` and `recent_tests` come from `backend/app/mock/integrations.json`. They are placeholder descriptive data (provisional endpoint paths and a static list of sample test results), not live measurements.

`200`

```json
{
  "components": [
    {
      "detail": "Mock adapter with 232 sample events. No real M1 is connected.",
      "endpoint": "/api/events",
      "interface": "Telemetry contract",
      "last_check": "2026-09-29T09:44:02Z",
      "mode": "mock",
      "module": "M1",
      "name": "Monitoring / telemetry",
      "provisional": true,
      "status": "Stubbed"
    }
  ],
  "meta": {
    "is_mock": true
  },
  "recent_tests": [
    {
      "contract": "Telemetry contract",
      "path": "M1 → M2",
      "result": "Stub response",
      "timestamp": "2026-09-29T09:40:01Z"
    }
  ]
}
```

### POST `/integrations/check`

Re-runs the adapter health check for one module or all of them and returns the same structure as `/integrations/status`. Body (optional): `{"module": "m1".."m5"}`; omit `module` (or send `null`) to check all. Error: `400 INVALID_MODULE`. A module whose health check fails is reported as `Failed` rather than failing the request.

`200`

```json
{
  "components": [
    {
      "detail": "Mock adapter with 232 sample events. No real M1 is connected.",
      "endpoint": "/api/events",
      "interface": "Telemetry contract",
      "last_check": "2026-09-29T09:44:02Z",
      "mode": "mock",
      "module": "M1",
      "name": "Monitoring / telemetry",
      "provisional": true,
      "status": "Stubbed"
    }
  ],
  "meta": {
    "is_mock": true
  },
  "recent_tests": [
    {
      "contract": "Telemetry contract",
      "path": "M1 → M2",
      "result": "Stub response",
      "timestamp": "2026-09-29T09:40:01Z"
    }
  ]
}
```
