# AI-RDR · M6 Dashboard and Integration

## QUICK START

1. Open the repository folder.
2. Start it:
   - **macOS:** double-click **`RUN.command`** (or run `./RUN.command` in Terminal).
   - **macOS / Linux:** run **`./run.sh`** in a terminal.
3. The first run sets everything up automatically (about a minute), then opens **http://localhost:5173** in your browser.
4. Press **Ctrl+C** in the terminal window to stop both the backend and the frontend.

Later runs skip the setup and start in a few seconds.

You only need **Python 3.11+** and **Node.js 18+** installed. On macOS: `brew install python@3.12 node@20`. On Ubuntu: `sudo apt install python3 python3-venv python3-pip nodejs npm`.

If a launcher will not start:
- *"Permission denied"* → `chmod +x run.sh RUN.command`, or run `bash run.sh`.
- *macOS says the file cannot be opened (downloaded zip)* → right-click `RUN.command` → **Open** → **Open** (first time only).
- *"Port 5001 / 5173 is already in use"* → usually an earlier M6 is still running (for example the terminal or the VS Code Code Runner "Stop" button killed the launcher without stopping its servers). Run `./run.sh --stop`, then start again. The launcher also does this automatically on the next start. If something else owns the port: `kill $(lsof -ti :5001)`, or change `PORT` in `.env`.
- Run the launcher in a real terminal (the VS Code integrated terminal, Terminal.app, or `RUN.command`), not in the Code Runner output panel, so Ctrl+C can stop everything cleanly.
- Logs are written to `logs/backend.log` and `logs/frontend.log`.

Launcher options: `./run.sh --check` (only check Python/Node), `./run.sh --setup-only`, `./run.sh --no-browser`, `./run.sh --stop` (stop an M6 left running).

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Design, request flow, who owns which data, what is connected, mocked or provisional |
| [`docs/api/README.md`](docs/api/README.md) | Every `/api/v1` endpoint with parameters, responses, errors and real examples |
| [`docs/integration/adapters.md`](docs/integration/adapters.md) | M1-M5 adapter boundaries, data contracts and examples |
| [`docs/integration/handoff.md`](docs/integration/handoff.md) | What teammates must provide to connect their module |
| [`docs/testing.md`](docs/testing.md) | Tests, how to run them, a dated verification snapshot and known limitations |

## What M6 is

AI-RDR (AI-Driven Ransomware Detection and Response) is a Linux-based ransomware detection and response platform.
**M6** is the analyst dashboard plus the integration layer. It displays and integrates what the other modules produce; it is not the detection engine.

| Module | Role | Status in this repo |
|---|---|---|
| M1 | SIEM and telemetry pipeline | PROVISIONAL / M6 STUB (mock adapter) |
| M2 | Behavioural ML detection + SHAP | PROVISIONAL / M6 STUB (mock adapter) |
| M3 | Honey-file deception | PROVISIONAL / M6 STUB (mock adapter) |
| M4 | Threat-intelligence enrichment | PROVISIONAL / M6 STUB (mock adapter) |
| M5 | Automated response (ARM + AICM) | PROVISIONAL / M6 STUB (mock adapter) |
| M6 | Dashboard and integration | This repository |

**All data you see is MOCK data.** No real M1-M5 interface has been confirmed yet, and nothing here is real Wazuh, M2, M3, M4 or M5 output.

## Addresses

| What | URL |
|---|---|
| Application (React) | http://localhost:5173 |
| Backend (Flask) | http://127.0.0.1:5001 |
| API health | http://127.0.0.1:5001/api/v1/health |

(The backend uses port 5001 because macOS uses 5000 for AirPlay Receiver.)

## Manual startup (for development and debugging)

First time, from the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env
cd frontend && npm install && cd ..
```

Terminal 1 (backend):

```bash
source .venv/bin/activate
python backend/run.py
```

Terminal 2 (frontend):

```bash
cd frontend
npm run dev
```

## Configuration

Settings are environment variables, read from `.env` in the repository root (copy `.env.example`; never commit `.env`).

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | Environment name shown by `/api/v1/health` |
| `FLASK_DEBUG` | `0` | `1` turns on Flask debug mode (not for shared use) |
| `HOST`, `PORT` | `127.0.0.1`, `5001` | Backend address (also read by `run.sh`) |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Allowed browser origins |
| `ANALYST_NAME` | `Muhammad Alam` | Name recorded on acknowledgements, overrides and actions |
| `M1_MODE` to `M5_MODE` | `mock` | `mock` (built-in) or `real` (not implemented; refused at startup) |
| `M1_BASE_URL` to `M5_BASE_URL` | empty | Reserved for real modules; not used by any adapter yet |

Frontend (`frontend/.env.example`): `VITE_API_BASE_URL` (default `/api/v1`) and `VITE_DEV_API_TARGET` (default `http://127.0.0.1:5001`). Launcher: `M6_FRONTEND_PORT` (default `5173`) and `NO_BROWSER=1`.

## Architecture

```
React (frontend)  ->  M6 Flask API (/api/v1)  ->  M6 services  ->  adapters  ->  mock data (now) / real M1-M5 (later)
```

- React only talks to the M6 API (`frontend/src/services/api.js`). It never reads mock files and never contacts M1-M5.
- Routes (`backend/app/routes/`) are thin and call services (`backend/app/services/`).
- Services talk to M1-M5 only through adapter interfaces (`backend/app/integrations/base.py`).
- `backend/app/integrations/m1/` ... `m5/` each hold the adapter interface (`__init__.py`) and its mock (`mock.py`, reads `backend/app/mock/*.json`). Data crossing the boundary is checked against `integrations/contracts.py`.
- `backend/app/integrations/registry.py` chooses the adapter for each module from `M1_MODE` ... `M5_MODE` in `.env`.
- Alerts are assembled from the modules that own the data: M2 detections or M3 honey-file triggers (an independent path, never through M2), M1 events as evidence, and M5 for response state. See `docs/integration/adapters.md`.
- M6 **requests** response actions (`freeze`, `verify`, `kill`, `isolate`, `thaw`); the M5 adapter decides the outcome. M6 does not implement M5, compute SHAP, watch files, or call a threat-intel provider.
- Alert state changes (acknowledge, override, actions) are kept in memory and reset when Flask restarts. There is no database.

### Replacing a mock with a real module later

1. Get the real interface (endpoint, schema) from the module owner and record it in `docs/integration/adapters.md`.
2. Add `integrations/m2/real.py` (for example) returning the same shapes as the mock.
3. Register it in `registry.py` and set `M2_MODE=real`, `M2_BASE_URL=...` in `.env`.

No React page, component or API response shape changes. Until that is done, `M*_MODE=real` is refused at startup.

## Integration status

M1-M5 are **not connected**. Each is a mock adapter serving sample data, and every interface to them is **provisional** (proposed by M6, not confirmed by the module owners). Integration Status shows them as *Stubbed* with "Mock · provisional" and never as Connected. What M6 needs from teammates to connect a real module is in [`docs/integration/handoff.md`](docs/integration/handoff.md).

## API endpoints (`/api/v1`)

Full reference with parameters, responses and examples: [`docs/api/README.md`](docs/api/README.md).

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | M6 liveness |
| GET | `/alerts` | Alert list. Filters: `severity`, `detection_type`, `response_state`, `host`, `range_minutes`, `q`, `page`, `page_size`. Also returns `summary` and `facets` |
| GET | `/alerts/<id>` | One alert with evidence and timeline |
| GET | `/alerts/<id>/events` | Normalized M1 events around the alert (not shown in the UI yet) |
| GET | `/alerts/<id>/shap` | SHAP explanation via the M2 adapter (ML alerts only) |
| POST | `/alerts/<id>/acknowledge` | Analyst acknowledgement |
| POST | `/alerts/<id>/override` | Analyst override (`{"reason": "..."}`); requests Thaw from M5 |
| POST | `/alerts/<id>/action` | Request `freeze`, `verify`, `kill`, `isolate` or `thaw` from M5 |
| GET | `/response-activity` | Recent response activity (`limit`) |
| GET | `/honey-files` | Honey-file status via the M3 adapter |
| GET | `/threat-intelligence` and `/threat-intelligence/<indicator>` | Enrichment via the M4 adapter (context only) |
| GET | `/integrations/status` | Status of M1-M6 from the adapters |
| POST | `/integrations/check` | Re-check one module (`{"module": "m2"}`) or all |

Errors are always JSON: `{"error": {"code": "...", "message": "..."}}` with a proper HTTP status (400 invalid input, 404 not found, 409 action not allowed in the current state, 502/503/504 integration problems, 500 unexpected). Stack traces are only written to the server log.

## Tests

Backend and launcher tests (from the repo root):

```bash
source .venv/bin/activate
python -m pytest
```

Run the tests while M6 is not running from this folder with `run.sh` (one launcher test uses `./run.sh --stop`; see [`docs/testing.md`](docs/testing.md)).

Frontend tests (they use the live API, so start the backend first, for example with `python backend/run.py`):

```bash
cd frontend
npm test
```

## Project structure

```
RUN.command            one-click start for macOS (double-click)
run.sh                 one-click start for macOS and Linux
README.md
.env.example           configuration template (copy to .env; never commit .env)
backend/app/           Flask app: routes/, services/, integrations/ (base, contracts, registry, m1..m5), schemas/, mock/ (JSON data)
frontend/src/         React app: pages/, components/, services/, hooks/, styles/, utils/
tests/                 Backend, architecture and launcher tests (pytest)
docs/architecture.md   Design, data ownership and current status
docs/api/              M6 REST API reference
docs/testing.md        Tests, verification snapshot, limitations
docs/reference/        The two approved HTML prototypes (visual reference)
docs/integration/      M1-M5 adapter boundaries and contracts (all PROVISIONAL / M6 STUB; real interfaces still pending)
```
