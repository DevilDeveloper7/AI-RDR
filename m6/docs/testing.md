# Testing

Everything here runs against the mock adapter layer. No test touches a real M1-M5 module.

## Running the tests

Backend, contract, architecture and launcher tests (from the repository root):

```bash
source .venv/bin/activate
python -m pytest
```

Frontend tests (they call the live API, so start the backend first, for example `python backend/run.py` or `./run.sh`; they only read data):

```bash
cd frontend
npm test
```

## Automated tests

### Backend and launcher (pytest): 104 tests

| File | Tests | What it covers |
|---|---|---|
| `tests/test_health.py` | 4 | Health endpoint, JSON 404 and 405 errors, and that an unexpected error returns a generic message with no stack trace. |
| `tests/test_config.py` | 3 | Configuration defaults (all modules mock), `M*_BASE_URL` handling, rejection of an invalid mode. |
| `tests/test_api.py` | 14 | List shape, paging and filters, bad filters, alert detail, invalid and unknown IDs, SHAP, acknowledge, override, action through M5, invalid action, honey files, threat intelligence, integration status and check. |
| `tests/test_api_contract.py` | 8 | Required fields of every response the React pages rely on, and that every error is JSON with a code and message. |
| `tests/test_workflow_and_errors.py` | 29 | Response workflow paths (verify, kill, isolate, thaw, freeze), rejected transitions leaving state unchanged, invalid requests (parametrized), empty list, filter facets, and controlled failures of each adapter (unavailable, timeout, malformed). Also integration status with a failed module and refusal of `real` mode. |
| `tests/test_adapters.py` | 28 | Contract tests for each mock adapter (M1-M5), rejection of malformed payloads, consistency of the mock data across modules, independence of the honey-file path, service-to-adapter calls (recorded), and non-fatal M1 and M4 failures. |
| `tests/test_end_to_end.py` | 8 | Mock lifecycle through the API: confirmed ransomware, false positive, analyst override, Kill and Isolate as separate actions, new response cycle, honey-file alert handled while M2 is down, ML alerts while M3 is down, and both sources down. |
| `tests/test_architecture.py` | 5 | Layering rules: frontend does not import mock data, only the registry imports mock adapters, services and routes do not read mock files, adapters do not import Flask. Also that the logo SVG files exist and the favicon points to the symbol. |
| `tests/test_launcher.py` | 5 | `run.sh` and `RUN.command` exist and are executable, shell syntax, `--help`, `--check`, unknown option, `--stop` with nothing running. |

### Frontend (Vitest, jsdom): 18 tests in `frontend/src/App.test.jsx`

- Dashboard, Alerts, Alert Detail, SHAP, Honey Files, Threat Intelligence and Integration Status render with data from the API (none is blank).
- Navigation Dashboard to Alert Detail to SHAP and Action; Alerts filter, row summary panel and "Open Alert Detail".
- Integration Status shows five Stubbed components with the "Mock · provisional" line.
- Error and empty states: API unreachable, HTTP 500, malformed reply, unknown alert (no Retry button), invalid alert ID, empty filter result.
- All screens render without React `console.error` output.
- Top bar: no notification button, analyst name shown, the search runs against the alert API on Enter, can be cleared, keeps filters already applied, and shares the Alerts page filter.
- Dashboard summary cards are links that open the matching filtered Alerts view (Critical Alerts = Critical and Frozen; Active Alerts = Frozen; Honey Files and Systems Monitored open Honey Files).
- Alerts table: status and action are separate columns; the logo is shown in the sidebar.

## Verification snapshot

**Snapshot taken on 2026-10-12. It describes the repository at that date and can become outdated after later changes.**

Environment: Linux (Ubuntu-based container), Python 3.12.3, Node v22.22.2. The checks used a clean copy of the repository (no `.venv`, no `node_modules`, no `.env`).

### Automated and scripted checks

| Check | Result |
|---|---|
| `./run.sh --setup-only` on the clean copy (creates `.env` from `.env.example`) | Succeeded; `ANALYST_NAME` was `Muhammad Alam` |
| `python -m pytest` (nothing else running) | **104 passed in 1.50s** |
| `./run.sh --no-browser`, `GET /api/v1/health` through the Vite proxy | `status: "ok"` |
| `npm test` against the launched servers | **18 passed** |
| State-changing UI flow in jsdom: acknowledge from the Alerts panel, override with reason, Kill / Isolate with confirmation, an integration Check, Dashboard counts updated, no React console errors | **Passed** (a temporary test; it is not kept in the repository) |
| Backend log after all of the above | 0 tracebacks, 0 responses with status 5xx |
| Ctrl+C (SIGINT) on the launcher | Exit code 130; no backend or frontend process left |
| Launcher killed with SIGKILL (no cleanup), then started again | The leftover processes were stopped automatically, M6 started normally, none left after stopping |

### Manual checks in a real browser engine

Run with throwaway scripts (not kept in the repository) in a headless Chromium (Qt WebEngine) on Linux against the launched servers, at 1440 px width unless stated:

| Check | Result |
|---|---|
| Top-bar search: type `enc_worker`, press Enter | Opened `/alerts?q=enc_worker`, showed "Showing 1–8 of 8", the Alerts search box showed the same text, the clear button appeared; clearing returned to all 80 alerts |
| Notification button | Not present |
| Sidebar profile | Shows "Muhammad Alam" |
| Dashboard cards (clicked) | Critical Alerts → `/alerts?severity=Critical&response_state=Frozen` (2 results, both selects set); Active Alerts → `/alerts?response_state=Frozen` (3 results); Honey Files and Systems Monitored → `/honey-files` |
| Keyboard | Seven Tab presses reached the Active Alerts card, which showed a 2 px red focus ring; Enter opened the filtered Alerts view |
| Alerts table (20 rows) | All status badges the same width, all Investigate buttons at the same horizontal position and height, none wrapped onto a second line |
| Filter dropdowns | Native arrow removed; 32 px right padding with a 14 px arrow 9 px from the edge (centred in the padding) on all five dropdowns; checked by screenshot at 1440, 1280 and 1100 px |
| 820 px width | The Alerts page's own search box is visible (the top-bar search is hidden at this width, as designed) |
| Logo | Symbol shown in the sidebar (image loaded), favicon points to the symbol SVG; rendered at 256, 32 and 16 px to check legibility |
| Browser console | No warnings or errors during these checks |

Earlier in the same work the end-to-end lifecycle, honey-file independence and adapter failure tests were also run and passed; they are part of the pytest total above.

## Known issue found during verification

`tests/test_launcher.py::test_stop_mode_is_safe_when_nothing_is_running` runs `./run.sh --stop` in the real repository folder. If M6 was started from that same folder with `run.sh`, running the tests stops it and the test fails. When this was observed (2026-10-05), running only that file gave `1 failed, 4 passed in 2.09s`, and the running M6 was stopped. To avoid this, **run `python -m pytest` while M6 is not running from the same folder** (or start the backend manually with `python backend/run.py` for the frontend tests, since that does not create the launcher's PID file). The test has not been changed.

## Not tested and limitations

- The macOS launcher (`RUN.command` double-click) and the automatic browser opening were **not tested**; the launcher was verified on Linux only. Fonts differ between this Linux environment and macOS, so exact text widths (for example how much of a search placeholder is visible) can differ.
- The automated frontend tests run in jsdom, which has no layout engine. Layout and styling were checked by hand in a headless Chromium on Linux (see above), not on macOS, and not in Safari or Firefox.
- The frontend tests need a running backend and cover reading and navigation; state-changing flows are covered by the backend tests and by the temporary check above.
- No real M1-M5 module exists in the repository, so nothing about real integration, performance, or load has been tested. `M*_MODE=real` is refused at startup.
- The mock data is simulated and says nothing about detection quality.
- Windows is not supported (WSL is expected to work but was not tested).
