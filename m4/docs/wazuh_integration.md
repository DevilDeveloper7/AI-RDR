# Wazuh → M4 integration (lab VM)

Wazuh's **integrator** can run a script for every alert that matches an
`<integration>` block. Our script `integrations/custom-m4-enrich.py` reads the
alert, extracts a file hash (and IPs, once confirmed), and sends each to M4's
`POST /enrich/async`. It **never** blocks or breaks alert processing. On any
problem it logs one line and exits 0.

## What is verified and what is not
| Item | Status | Source |
|---|---|---|
| Script arguments: `argv[1]` alert JSON file, `argv[2]` api_key, `argv[3]` hook_url, `argv[4]` "debug" | ✅ | Wazuh v4.9.0 `integrations/virustotal.py` and `slack.py` |
| `<integration>` tags `<name>`, `<hook_url>`, `<api_key>`, `<group>`, `<alert_format>json</alert_format>` | ✅ | config comments in the same official scripts |
| Alert fields `id`, `agent`, `syscheck.path`, `syscheck.md5_after`, `syscheck.sha1_after` | ✅ | `virustotal.py` reads them |
| `syscheck.sha256_after` | ⚠️ inferred (decoder field `sha256`, same `_after` pattern). The script falls back to `sha1_after`/`md5_after`. | `src/analysisd/decoders/syscheck.c` |
| IP field paths (`data.srcip`, `data.dstip`) | ❌ **UNVERIFIED / TODO**: replace with names from M1's real network alert | none |
| Custom names must start with `custom-`; script lives in `/var/ossec/integrations/` | ❌ UNVERIFIED (from memory of the Wazuh docs; the docs site was blocked in the build environment) | none |
| File ownership/permissions and the restart command below | ❌ UNVERIFIED (standard Wazuh practice; check the docs for your version) | none |
| Our Wazuh version | ❌ not provided yet (the scripts above are from v4.9.0) | ask M1 |

**Nothing here was run on a real Wazuh manager.** The script logic is tested
offline (`tests/test_integration.py`) and end-to-end against a local M4 in
MOCK mode (`scripts/e2e_smoke.py`).

## Install steps (on the Wazuh manager VM)
1. **Run M4** on the same VM (simplest: Wazuh reaches it at `127.0.0.1`):
   ```bash
   cd /opt/m4_threat_intel_project
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
   cp .env.example .env && nano .env            # paste your keys; chmod 600 .env
   set -a; . ./.env; set +a
   .venv/bin/python -m m4_threat_intel.app      # listens on 127.0.0.1:5004
   ```
2. **Copy the script** (UNVERIFIED paths and permissions; check for your version):
   ```bash
   sudo cp integrations/custom-m4-enrich.py /var/ossec/integrations/custom-m4-enrich
   sudo chown root:wazuh /var/ossec/integrations/custom-m4-enrich
   sudo chmod 750 /var/ossec/integrations/custom-m4-enrich
   ```
   If `integrations.log` later says the script can't be found, also copy it as
   `custom-m4-enrich.py`.
3. **Add to `/var/ossec/etc/ossec.conf`** (inside `<ossec_config>`):
   ```xml
   <integration>
     <name>custom-m4-enrich</name>
     <hook_url>http://127.0.0.1:5004</hook_url>
     <group>syscheck</group>
     <alert_format>json</alert_format>
   </integration>
   ```
   `<group>syscheck</group>` sends only FIM alerts. Once M1 confirms the
   network-alert fields, add another block or a `<rule_id>` filter for those.
4. **Restart the manager**: `sudo systemctl restart wazuh-manager`
5. **Check it works**: modify a monitored file, then
   ```bash
   sudo tail -f /var/ossec/logs/integrations.log     # expect "custom-m4-enrich: ... queued job ..."
   curl -s http://127.0.0.1:5004/stats
   ```

## Fixing the field names (after M1 sends a real alert)
Open `integrations/custom-m4-enrich.py` and edit `FIELD_PATHS` at the top.
Then add the real alert (with any secrets removed) as a test case in
`tests/test_integration.py` and run the tests.

## Safety notes
- The script uses only the Python standard library and logs no secrets. The `api_key` argument is ignored.
- M4 has **no authentication**. Keep it on `127.0.0.1`, or bind it (`M4_HOST`) only inside the isolated lab network.
- Results are not written back into Wazuh. M5 and M6 read them from M4. Writing back through Wazuh's socket (as `virustotal.py` does) is possible future work.
