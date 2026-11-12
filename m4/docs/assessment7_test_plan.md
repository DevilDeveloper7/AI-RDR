# Assessment 7: M4 unit and integration test plan

## Objectives
1. Show that M4 follows its safety rules (the non-negotiable rules R1–R11 in the project brief).
2. Show that M4 is robust: provider failures, slow services, bad data and M4 outages never break alert handling.
3. Plan the Week 7 measurements of M4's usefulness, with pass criteria to be agreed.

## How to run
```bash
.venv/bin/python -W error::ResourceWarning -m unittest discover -s tests -t . -v
.venv/bin/python scripts/e2e_smoke.py        # end-to-end, MOCK providers
```

## Test inventory (requirement → tests)
| Requirement | Tests (file → test names) |
|---|---|
| R1 not found / failed = `unknown`, never `clean` | `test_enricher`: not_found_is_unknown_not_clean, failure_is_never_clean · `test_app`: without_keys_result_is_unknown_with_error_never_clean · `test_otx`: validation_is_miss_never_clean · `test_integration`: failures_are_unknown_never_clean |
| R1 `clean` only from the allowlist | `test_enricher`: allowlist_is_clean_without_calls · `test_abusech`/`test_enricher`: provider cannot produce clean (only hit/miss/error exist) |
| R2 errors never cached | `test_cache`: refuses_errors, errors_are_never_cached, partial_failure_not_cached |
| R3 OTX alone never malicious | `test_enricher`: otx_alone_is_never_malicious · `test_otx`: hit_score_formula_and_cap · startup assertion in `config.py` |
| R4 private IPs never sent out | `test_enricher`: private_ip_makes_zero_provider_calls · `test_schema`: non_routable · `test_integration`: only_public_ips_extracted |
| R5 never blocks alert handling | `test_app`: async_does_not_wait_for_slow_provider, worker_exception_marks_job_failed · `test_integration`: survives_m4_down_slow_or_erroring, main_never_fails |
| R6 keys from the environment only, never logged | `test_schema`: repr_never_shows_keys · `test_integration`: log_contains_no_secret · missing key → no network call (`test_abusech`, `test_otx`) |
| R8 no invented formats | unexpected statuses/fields → error: `test_abusech`: unexpected_query_status_is_error_not_miss, ok_with_bad_data_is_error · `test_otx`: missing_pulse_info_is_error |
| R9 offline tests | the `tests/__init__.py` socket guard fails any test that opens a connection |
| Input validation | `test_schema` (hashes, IPs, domains, requests) · `test_app`: invalid_input_is_400, async_bad_input_is_400_and_not_queued |
| Provider parsing | `test_abusech` (17 tests), `test_otx` (10 tests) |
| Rate limit / retry | `test_ratelimit` (14 tests): burst, throttle, refill, timeout, backoff, Retry-After, give-up, no retry on 401/403 |
| Cache | `test_cache`: TTL, purge, stats, thread safety, 2nd lookup = zero provider calls, current alert_id |
| Integration | `test_integration` (Wazuh script and M5 client) · `scripts/e2e_smoke.py` |

## Planned Week 7 measurements (live, with real keys, lab network)
| Measurement | Method | Pass criterion |
|---|---|---|
| Detection rate on known-bad hashes | Labelled set of SHA-256s of **known public samples** (hashes only, from public reports/MalwareBazaar listings; no downloads), sent through M4 | **TO BE DECIDED by Kiana with supervisor** |
| False-positive rate | Hashes of benign files (e.g. Ubuntu system binaries) and popular benign domains: share of `malicious`/`suspicious` | **TO BE DECIDED** |
| Lab-sample coverage | Share of the lab's own ransomware-simulation artefacts found in any feed (expected to be low: novel samples are not in public feeds) | Report only |
| Latency | `latency_ms` p50/p95 for uncached and cached lookups | **TO BE DECIDED** |
| Cache hit rate | `/stats` over a replayed alert stream | Report only |
| Robustness | Kill M4 / block the network during an alert replay; check Wazuh and M5 keep working | Must not break alert handling |

The labelled set goes in `data/labelled.csv` (git-ignored). Results go in `results/` (git-ignored).

## Risks
- abuse.ch format details are UNVERIFIED (`docs/api_notes.md`). A mismatch shows up as `unknown` + error, not as wrong verdicts. Fix it with one real curl run.
- Free-tier rate limits and terms can change. M4 throttles itself conservatively.
- Low coverage on novel or lab ransomware is expected. M4 is context, not detection.
- The Wazuh field names for IPs are unconfirmed, and the integration hasn't been run on the real manager yet.
- M4 has no authentication and must stay on localhost or the isolated lab network.
