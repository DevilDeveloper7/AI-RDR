# M4 results and limitations

M4 (threat-intelligence enrichment) adds **context** to AI-RDR alerts. It does not
detect ransomware; M2 (ML) and M3 (honey files) do. This page sums up what was
measured and what M4 cannot do. All numbers below come from real runs on
2026-10-18 (evaluation) and 2026-11-19 (tests and end-to-end runs).

## Results
| What | Result | Evidence |
|---|---|---|
| Unit and integration tests | 170 tests, all pass (offline, no network) | `python3 -m unittest discover -s tests -t .` |
| End-to-end, mock | Wazuh script → M4 → M5 (scores 55) → M6 (lists it): ALL CHECKS PASSED | `results/e2e_demo_output.txt` (MOCK-DATA) |
| End-to-end, live | Real ELF ransomware hashes (Akira, LockBit) → M4 `malicious`, score 95, MalwareBazaar → M5 `ti_match=55` → M6 "Malicious" | `results/e2e_live_output.txt` |
| Sample shortlist | 18 ransomware hashes from 9 families checked through live M4, all `malicious`; ELF builds for Akira, LockBit, Babuk, BlackBasta, Royal, Kuiper | `results/candidates/candidates.csv` |
| Detection rate (25 known-bad hashes) | 100% (pipeline check: hashes come from MalwareBazaar itself) | `results/summary.md` |
| False positives (25 benign) | 0% | `results/summary.md` |
| Latency | uncached mean 2.1 s (p95 3.1 s); cached 1.9 ms | `results/summary.md` |

### Malware for the demo (professor's request of 2026-11-18)
Shortlisted (metadata only, nothing downloaded or run on the student's machine):

| Family | File type | SHA-256 | M4 answer |
|---|---|---|---|
| Akira | ELF | `adef929e7c44596ed1cb4c1300826874fc48d6adc9edde45f0cfa45e9792ef42` | malicious, 95, MalwareBazaar |
| LockBit (5.0, Linux) | ELF | `4dc06ecee904b9165fa699b026045c1b6408cc7061df3d2a7bc2b7b4f0879f4d` | malicious, 95, MalwareBazaar |

Only teammate Vadim may place and run samples, and only on the isolated target VM.

## Limitations
1. **Provider rate limits.** abuse.ch and OTX publish only "fair use" for the free
   tier; no exact number was found (`docs/api_notes.md`). M4 limits itself to
   1 request/s, burst 2, per provider (`M4_ABUSECH_RATE`, `M4_OTX_RATE`), retries with
   back-off and honours `Retry-After` (max 30 s). A cold lookup takes about 2 s, so
   M4 is called once per **alert / unique indicator**, never per raw event, and the
   cache (600 s for hits, 300 s for misses; below M5's 900 s freshness window)
   absorbs repeats.
2. **No internet = `unknown`, never `clean`.** The target VM is isolated from the
   internet. If M4 runs where it cannot reach abuse.ch/OTX, every answer is
   `unknown` with an error, and the circuit breaker skips the provider for 30 s after
   2 network failures so alerts are not delayed. `clean` comes only from the local
   allowlist. M5 turns these answers into `unavailable` (0 points). Errors are never cached.
3. **Recent-indicator log is in memory.** `/indicators` and `/alerts/<id>/threat_intel`
   read a list of the last **500** answers kept in memory. An M4 restart empties it
   until new alerts are enriched. The SQLite cache is only a speed-up, not a store.
4. **Mock data is labelled.** With `M4_MOCK_PROVIDERS=1` answers come from
   `data/mock_iocs.json`, are tagged `MOCK-DATA`, `/health` says `"mode": "MOCK"`,
   M5 records carry `"synthetic": true` (and are refused as evidence outside mock
   mode), M6 notes say "MOCK DATA". Mock output is never presented as real intelligence.
5. **Real malware vs simulators.** Real samples are only run by Vadim on the isolated
   target VM. Where a real sample does not run there, the team uses
   **behaviour simulators** (scripts that mass-encrypt or rename test files) to trigger
   M2/M3 detection and M5 response, and proves M4's part with **real hashes** replayed
   as Wazuh alerts (`results/candidates/alerts/*.json`). Why samples may not run:
   - the Linux builds of Akira and LockBit mainly target VMware ESXi and may expect
     ESXi paths, tools or command-line arguments that a plain Ubuntu VM lacks;
   - the VM has no internet, so samples that need a C2 or key server may stop early;
   - most ransomware samples in public feeds are Windows PE files (the default
     "ransomware" tag query returned none in ELF), which cannot run on the Linux target;
   - safety: anything that could escape the lab is not run at all.
   A simulator's own file hash is not in any feed, so M4 correctly answers `unknown`
   for it. This is expected and is **not** a failure: M4 is context, detection comes
   from M2/M3.
6. **Coverage of new ransomware is low by design.** Public feeds know only samples
   already reported. Lab-built or brand-new samples give `unknown`.
7. **Unverified Wazuh/Falco field names.** `integrations/custom-m4-enrich.py` reads
   `syscheck.sha256_after` (inferred) and IPs from `data.srcip`/`data.dstip` and
   Falco's `data.output_fields.fd.rip`/`fd.sip` (guessed). No real lab alert has been
   seen yet. The script is fail-safe: a wrong path extracts nothing and never breaks
   Wazuh. Falco events carry no file hashes; hashes come only from Wazuh FIM.
8. **Supported indicator types for M5.** M5 scores only sha256 and IP. md5, sha1
   and domain are enriched (visible in M6) but `/enrich/m5` answers 422 for them.
9. **No authentication.** M4 listens on `127.0.0.1` by default and must only be
   exposed inside the isolated lab network (`M4_HOST`).
10. **OTX alone is capped at 60** (`suspicious` at most), because OTX pulses are
    community reports, not confirmed samples.
