# Phase 4 notes (Week 4): reliability

## What was built and why
- `cache.py`: SQLite cache.
  - One connection shared by the workers behind a lock (thread-safe).
  - Each entry has its own expiry time; the clock is injectable for tests.
  - `get / set / purge_expired / close / stats()` with hit/miss counters.
  - `set()` refuses any payload with an error. That is the second safety net; the enricher is the first.
- Caching in `enricher.py`:
  - found → 24 h; not found → 1 h; errors (including partial failures) → never.
  - Allowlist and private-IP answers aren't cached: they're local, and allowlist edits should apply immediately.
  - A cached answer returns `cached: true` with the **current** request's `alert_id`. `enriched_at` keeps the original lookup time, so you can see how old it is.
- `ratelimit.py`:
  - `TokenBucket` (rate, burst, max wait; injectable clock and sleep).
  - `request_with_retry()`:
    - takes a token first
    - uses a timeout
    - retries 429/500/502/503/504 and network errors with backoff 1, 2, 4… s (capped at 30)
    - honours a numeric `Retry-After` (capped at 30 s)
    - fails immediately on 401/403 ("authentication failed: check API key")
    - accepts extra statuses (OTX 404)
    - raises `ProviderError` when it gives up
  - Both providers use it through `HttpClient`.
  - The limits (1 request/s, burst 2 per provider; 3 retries) are **conservative defaults**, because neither provider's exact limit could be verified.
- `jobs.py` + `app.py`:
  - `POST /enrich/async` validates first (400 on bad input), then returns 202 with a `job_id`.
  - A thread pool does the work; `GET /enrich/jobs/<id>` reports pending/done/failed (404 if unknown).
  - The job store is capped at 1000 jobs; the oldest is evicted first.
  - A worker exception marks the job `failed` with a message, so it never dies silently.
  - `GET /stats` shows cache and job counters.
- `providers/mock.py` + `data/mock_iocs.json`: **MOCK mode** (`M4_MOCK_PROVIDERS=1`) for offline demos.
  - Canned answers for fake indicators.
  - Every result is labelled `mock_*` and tagged `MOCK-DATA`, and `/health` reports `"mode": "MOCK"`.
  - This is not threat intelligence; it only exists so the pipeline can be shown without keys.
- `shutdown_app()`: closes workers, the cache and the HTTP sessions, so there are no leaks.

## Tests
`.venv/bin/python -W error::ResourceWarning -m unittest discover -s tests -t .` → **84 tests, OK, 0.39 s** (gate: < 5 s). No real sleeping: fake clocks are used.

## Real run by Claude Code (server in MOCK mode, no keys)
| Step | Result |
|---|---|
| sync `mock-c2.example` (A1) | malicious, 90, sources `mock_abusech, mock_otx`, `cached: false` |
| same again (A2) | same verdict, **`cached: true`, `alert_id: A2`** |
| async `8.8.4.4` (A3) | 202 + job_id → poll → `done`, **suspicious 40 (OTX-only mock, not malicious)** |
| `/stats` | cache: 2 entries, 1 hit / 2 misses; jobs: 1 submitted, 1 done |

## UNVERIFIED
- Real provider rate limits and `Retry-After` format. The numeric form is handled; the HTTP-date form falls back to normal backoff.
- Live behaviour under real 429s: not exercised (no network access to the providers).
