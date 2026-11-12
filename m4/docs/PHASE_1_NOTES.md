# Phase 1 notes (Week 1): decide and freeze

## What was built and why
- `m4_threat_intel/config.py`: all settings come from environment variables. Keys are never printed (`repr` hides them, and a test checks this). The thresholds (80 malicious / 30 suspicious) and the per-source scores are named constants, labelled as design choices to tune with measured data. A start-up assertion guarantees `OTX_MAX_SCORE < MALICIOUS_THRESHOLD`, so OTX alone can never reach "malicious".
- `m4_threat_intel/schema.py`: the contract (in the docstring), input validation and normalisation, `is_non_routable()`, verdict/status constants and the `ProviderResult` type. Normalising inputs means the cache and allowlist match no matter how a value was written.
- `is_non_routable()` checks private, loopback, link-local, CGNAT, multicast, reserved and unspecified addresses explicitly, because Python's `is_global` alone counts multicast (e.g. 224.0.0.1) as global. That was found by a test in the draft.
- `tests/__init__.py` blocks all network sockets, so no test can reach the internet.
- Docs: `interface_contract.md`, `indicator_sources.md`, `section9_provider_decision.md`.

## Tests
`.venv/bin/python -m unittest discover -s tests -t .` → 11 tests, OK.

## Assumptions
- One indicator per request (as in the contract). An alert with several indicators sends several requests.

## UNVERIFIED / to confirm
- All Wazuh field paths: no sample alert yet (`indicator_sources.md`, marked TO CONFIRM WITH M1).
- Free-tier terms of abuse.ch and OTX: re-verify before submission.

## Changes from the earlier draft (`m4_enrichment`)
- OTX cap is now 60 (was 50). Thresholds are now score-based (80/30) per the master prompt. The not-found TTL is now 1 h (was 6 h). The package was renamed to `m4_threat_intel`.
