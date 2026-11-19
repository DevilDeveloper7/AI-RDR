# Assessment 7: M4 unit and integration test plan

## Objectives
1. Show that M4 follows its safety rules (the non-negotiable rules R1–R11 in the project brief).
2. Show that M4 is robust: provider failures, slow services, bad data and M4 outages never break alert handling.
3. Plan the Week 7 measurements of M4's usefulness, with pass criteria to be agreed.

Status (2026-11-19): **all tests implemented and passing** (170 tests, `OK`, run on the student's Mac).

## How to run
```bash
python3 -m unittest discover -s tests -t .           # 170 offline tests (needs -t .)
python3 scripts/e2e_demo.py                          # Wazuh script -> M4 -> M5 -> M6, MOCK providers
python3 scripts/e2e_demo.py --live http://127.0.0.1:5004 --alert results/candidates/alerts/001_Akira.json
```
The 4 M5 cross-checks in `test_m5_adapter` are skipped when `../m5` is not beside `m4`.

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
| Integration | `test_integration` (Wazuh script and M5 client; incl. Falco-style dotted keys `falco_dotted_keys`, `falco_nested_keys`, `duplicate_ip_sent_once`) · `scripts/e2e_smoke.py`, `scripts/e2e_demo.py` |
| Circuit breaker | `test_resilience`: opens_after_two_network_failures_and_stops_calling_the_provider, closes_after_the_cooldown_and_a_good_answer_resets_it, http_errors_and_misses_do_not_open_it, only_consecutive_failures_count, unsupported_type_is_not_counted, breaker_can_be_switched_off, stats_show_skipped_providers |
| Cache fallback | `test_resilience`: unwritable_cache_folder_does_not_stop_m4 (M4 runs with `cache=None`, `/stats` shows `cache: null`) |
| M5 adapter (`/enrich/m5`, `enrich_for_m5`) | `test_m5_adapter` (34 tests): malicious_hash_is_a_match, malicious_ip_is_a_match, non_malicious_verdicts_are_no_match_never_a_match, unknown_with_error_is_unavailable_not_no_match, types_m5_cannot_use_return_none, synthetic_is_never_a_match_by_default, checked_at_is_original_enriched_at_and_aware, cached_hit_keeps_original_checked_at, unsupported_types_are_422, m4_down_gives_unavailable, timeout_gives_unavailable, and cross-checks against the real `RiskMatrix`: fresh_match_counts_with_weight_55, freshness_boundaries, boundaries_agree_with_the_mirror, no_match_unavailable_and_synthetic_never_score |
| M6 adapter (`/enrich/m6`, `/indicators`) | `test_m6_adapter` (20 tests): every_verdict, status_enriched_no_data_unavailable, unknown_is_never_presented_as_clean, mock_data_is_labelled, m6_own_lookup_is_not_a_related_alert, newest_first_dedupe_and_cap, indicators_lists_recent_answers_newest_first, limit_validation, enrich_m6_bad_input_is_400 |
| Per-alert endpoint (`/alerts/<id>/threat_intel`) | `test_alert_records`: records_for_one_alert_only_and_accepted_by_m5, md5_sha1_and_domain_are_left_out, unknown_alert_gives_an_empty_list_not_an_error · client `threat_intel_for_alert`: returns_records, never_raises |
| Real provider formats | `test_live_fixtures` (recorded real abuse.ch answer, `tests/fixtures/abusech_live_2026-10-18.json`) |

## Measurements (implemented; live, real keys)
| Measurement | Method | Result | Evidence |
|---|---|---|---|
| Detection rate on known-bad hashes | 25 SHA-256s of public ransomware samples (MalwareBazaar metadata only, no downloads) through `scripts/evaluate_http.py` | 100% (25/25). Note: taken from MalwareBazaar itself, so this checks the pipeline, not real-world coverage | `results/summary.md`, `results/results.csv` |
| False-positive rate | 25 benign hashes / domains | 0% (0/25) | `results/summary.md` |
| Lab-sample coverage | Lab's own simulator artefacts | n/a (no lab artefacts yet); expected low, novel samples are not in feeds | `results/summary.md` |
| Latency | `latency_ms`, cold vs cached | cold mean 2070 ms, p95 3076 ms; cached mean 1.9 ms | `results/summary.md` |
| Cache hit rate | warm second pass | 100% | `results/summary.md` |
| End-to-end, mock | `scripts/e2e_demo.py` | ALL CHECKS PASSED (Wazuh script, M4, M5 scoring 55, M6 listing) | `results/e2e_demo_output.txt` (MOCK-DATA) |
| End-to-end, live replay of real ELF ransomware hashes | `scripts/pick_samples.py --m4` then `e2e_demo.py --live` for Akira and LockBit ELF hashes | Both `malicious` (score 95, MalwareBazaar), M5 `ti_match=55`, M6 shows Malicious | `results/candidates/`, `results/e2e_live_output.txt` |
| Robustness | No internet / provider down | `unknown` + error, breaker skips the provider, never `clean` (unit tests above) | `test_resilience`, `test_app` |

Pass criteria for detection / false-positive / latency were not fixed by the supervisor; the numbers are reported as measured.

## Risks
- abuse.ch formats were verified with real keys (2026-10-18 fixture, 2026-11-19 live runs). A future format change shows up as `unknown` + error, not as wrong verdicts.
- Free-tier rate limits and terms can change. M4 throttles itself conservatively.
- Low coverage on novel or lab ransomware is expected. M4 is context, not detection.
- The Wazuh field names for `sha256_after` and for IPs (Wazuh `data.srcip`/`dstip`, Falco `output_fields.fd.rip`/`fd.sip`) are still UNVERIFIED: no real lab alert yet. The integration has not been run on the real manager yet.
- M4 has no authentication and must stay on localhost or the isolated lab network.
