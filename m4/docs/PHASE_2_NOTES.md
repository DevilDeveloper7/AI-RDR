# Phase 2 notes (Week 2): API formats, interface, stub

## What was built and why
- `docs/api_notes.md`: URL, method, auth, body and response fields for each service, each marked ✅ confirmed / ⚠️ partially confirmed / ❌ UNVERIFIED.
  - **Limitation:** the build environment's network policy blocked the abuse.ch and OTX websites.
  - OTX was verified from AlienVault's **official Python SDK source** on GitHub.
  - abuse.ch was only partly confirmed, through search extracts of the official pages and third-party docs, so several abuse.ch details stay UNVERIFIED until you run the scripts below with your key.
- `scripts/curl_examples.sh`, `scripts/try_abusech.py`, `scripts/try_otx.py`: manual checks with your own key. Keys come from environment variables only. Timeouts, non-200 responses, non-JSON and a missing key are handled. They print the raw JSON and a one-line summary. They deliberately do not use M4's parsers, so you see the API's real answer.
- `providers/base.py`: the `Provider` interface. `lookup()` **never raises**: any exception becomes `status="error"`.
- `providers/abusech.py`, `providers/otx.py`: skeletons returning `error: not implemented`.
- `app.py`: `POST /enrich` returns a contract-shaped STUB (`unknown` plus a STUB error), `GET /health`, and 400 on bad input.

## Tests
`.venv/bin/python -m unittest discover -s tests -t .` → 16 tests, OK.
Real run by Claude Code: started `python -m m4_threat_intel.app`.
- A curl of a domain returned a contract-shaped `unknown` STUB response.
- An invalid IP returned HTTP 400.

## Commands for you (with your real keys)
```bash
export ABUSECH_AUTH_KEY=...   # from https://auth.abuse.ch
export OTX_API_KEY=...        # from your OTX profile page
scripts/curl_examples.sh <sha256-of-a-known-sample> 8.8.8.8 example.com
.venv/bin/python scripts/try_abusech.py hash <sha256>
.venv/bin/python scripts/try_otx.py ip 8.8.8.8
```
What to expect (UNVERIFIED until you run it):
- **abuse.ch:** JSON containing `"query_status"`. `"ok"` with a `data`/`urls` list for known indicators, and a not-found status otherwise.
- **OTX:** HTTP 200 with `pulse_info.pulses` for known indicators, or 404 if unknown.

**Paste the outputs (remove your key) to Claude Code. The parsers will be adjusted if anything differs.**
Use a hash of a well-known sample, taken from the MalwareBazaar website or a report. Only the hash is needed: never download the file.

## UNVERIFIED
See the ❌ rows in `docs/api_notes.md`: the not-found `query_status` names, the URLhaus `/host/` path and body, the MalwareBazaar fields, ThreatFox `ip:port` matching, and the rate limits.
