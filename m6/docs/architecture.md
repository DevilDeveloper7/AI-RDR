# Architecture

AI-RDR is a Linux-based ransomware detection and response platform made of six components. **M6** is the analyst dashboard and the integration layer: it displays and integrates what M1-M5 produce, and it is not a detection engine.

| Component | Role |
|---|---|
| M1 | SIEM and telemetry pipeline (normalized events) |
| M2 | Behavioural ML detection and SHAP explanations |
| M3 | Honey-file deception |
| M4 | Threat-intelligence enrichment |
| M5 | Automated response (ARM and AICM): Freeze, Verify, Kill or Isolate, Thaw |
| M6 | Dashboard, REST API, analyst actions, integration (this repository) |

> **Current status.** M1-M5 are not connected. Each one is represented by a **mock adapter** that serves sample data from JSON files, and every interface to them is **provisional** (proposed by M6, not confirmed by the module owners). Nothing in this repository claims or simulates a real Wazuh, auditd, ML, inotify, threat-intelligence or response deployment.

## Request flow

```
React frontend  (frontend/src)
      |  HTTP, JSON, only through frontend/src/services/api.js
      v
M6 Flask API  /api/v1  (backend/app/routes)
      v
M6 services  (backend/app/services)
      v
M1-M5 adapters  (backend/app/integrations/m1 ... m5)
      v
mock implementations today  /  real modules when their interfaces exist
```

In development the Vite server (port 5173) forwards `/api` to Flask (port 5001), so the browser talks to one address.

## Where things live

| Layer | Location | Responsibility |
|---|---|---|
| Frontend | `frontend/src/pages`, `components`, `hooks`, `services/api.js`, `routes.js`, `styles` | Eight screens (Dashboard, Alerts, Alert Detail, SHAP, Honey Files, Threat Intelligence, Action / Override, Integration Status). Data comes only from the M6 API. |
| App setup | `backend/app/__init__.py`, `config.py`, `errors.py` | Builds the Flask app, reads `.env`, wires adapters and services, turns errors into JSON. |
| Routes | `backend/app/routes/` | Thin HTTP layer: validate input, call a service, return JSON. |
| Validation | `backend/app/schemas/validation.py` | Alert IDs, actions, reasons, query parameters. |
| Services | `backend/app/services/` | M6 logic: `alert_service` (assembles alerts, analyst actions), `honey_service`, `intel_service`, `integration_service`. |
| Adapters | `backend/app/integrations/` | `base.py` (error types), `contracts.py` (data contracts and validators), `registry.py` (chooses mock or real per module), and one package per module (`m1` to `m5`) holding the interface (`__init__.py`) and the mock (`mock.py`). |
| Mock data | `backend/app/mock/*.json` | Sample data used only by the mock adapters. |
| Launcher | `run.sh`, `RUN.command` | Sets up and starts backend and frontend together. |

`backend/app/models/` exists but is empty and unused.

Rules enforced by `tests/test_architecture.py`: the frontend never imports mock data or contacts M1-M5; only `registry.py` imports mock adapters; services and routes never read mock files directly; adapters never import Flask.

## Who owns which data

An alert is assembled by `alert_service` from the module that owns each part:

| Part of an alert | Source |
|---|---|
| ML alert (severity, host, process, confidence) | M2 `list_detections()` |
| Honey-file alert | M3 `list_triggers()` |
| Evidence and the "Telemetry received" timeline entry | M1 `list_events()` |
| Response state, verification state, response history, audit trail | M5 (`list_cases()`, `get_case()`, `list_audit()`) |
| Related indicators | M4 `list_indicators()` |
| Open / Acknowledged | M6 itself |
| SHAP explanation | M2 `get_shap()` |

The honey-file path is independent of ML: an M3 trigger goes straight to M6 and response, and does not pass through M2. If M2 is down, honey-file alerts still work, and the reverse. `GET /alerts` reports the outage in `meta.unavailable`.

**Response workflow.** Detection, then Freeze, then Verify, then either Kill or Isolate (confirmed ransomware) or Thaw (false positive). M6 only *requests* an action through the M5 adapter, and M5 decides the outcome and owns the response state. Kill and Isolate are separate actions. M6 never executes anything on a host.

## Connected, mocked, provisional

| Item | Status |
|---|---|
| React frontend, Flask API, M6 services, validation, error handling, launcher, tests | Implemented and working (real M6 code) |
| Adapter interfaces and data contracts (`integrations/`) | Implemented in M6; **provisional** until teammates confirm them |
| M1, M2, M3, M4, M5 adapters | **Mock only**. `M*_MODE=real` is refused at startup because no real adapter exists |
| `M*_BASE_URL` settings | Read into the configuration; **not used by any adapter yet** |
| All alert, event, SHAP, honey-file, threat-intelligence and response data | **Mock data** |
| Real M1-M5 connections | **None** |

## Failure behaviour

| Situation | Result |
|---|---|
| Invalid input | `400` JSON error |
| Unknown alert or indicator | `404` JSON error |
| Action not allowed in the current response state | `409`, and the alert is left unchanged |
| M1 unavailable | Alert page still loads; `evidence_status: "unavailable"` |
| M4 unavailable | Alert page still loads; `enrichment_status: "unavailable"` |
| M2 or M3 unavailable | The other path still works; `meta.unavailable` names the missing module; requesting an alert that needs the missing module returns `502/503/504` |
| M2 and M3 both unavailable, or M5 unavailable | `502/503/504` JSON error |
| Adapter returns data that breaks the contract | `502 MALFORMED_RESPONSE` |
| Unexpected exception | `500` with a generic message; the stack trace goes to the server log only |

The frontend shows these messages inside the existing cards and offers Retry only for errors where retrying can help.

## State

There is no database. Analyst status (acknowledgements), the mock M5 response cases and audit trail, and integration health are held in memory, and reset when the Flask process restarts.

## Things to know

- Static text from the approved design stays in `frontend/src/config.js`: the environment label ("Production  ·  Linux fleet") and the analyst name shown in the sidebar. Actions are recorded under the backend setting `ANALYST_NAME`.
- On Integration Status, the `endpoint` column and the "Integration test" list come from `backend/app/mock/integrations.json`. They are placeholder data, not live results.
- The honey-file watcher status ("Running") is a constant in the mock M3.
- The Alerts page keeps its filters in the URL (`/alerts?severity=Critical&response_state=Frozen&q=enc_worker`). The top-bar search (alerts only) and the Dashboard summary cards open Alerts through that same URL filter.
- The status line "All core services online" in the sidebar only appears when every component reports `Connected`. With mock adapters it stays hidden.

## Startup

`run.sh` checks Python 3.11+ and Node 18+, creates `.venv` and installs dependencies only when `backend/requirements.txt` or `frontend/package-lock.json` change, then starts Flask and Vite, waits until both respond, and stops both on Ctrl+C. It records the process IDs in `logs/m6.pids` so `./run.sh --stop` (or the next start) can stop leftovers. Logs go to `logs/backend.log` and `logs/frontend.log`.
