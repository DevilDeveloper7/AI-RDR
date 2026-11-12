# Where M4's indicators come from

M4 does not collect telemetry. It receives indicators that M1's pipeline
extracts from alerts. No Wazuh alert sample has been provided yet, so **no
field names are fixed here**. Every field path below must be confirmed with M1
against a real alert from our Wazuh version.

| Indicator | Origin in the system | Alert field path | Notes |
|---|---|---|---|
| File hash (SHA-256 preferred) | Wazuh File Integrity Monitoring (syscheck) event on a created/modified file | **TO CONFIRM WITH M1** | FIM can record file hashes. Which hash fields our configuration enables must be checked in the agent's `ossec.conf` and in a real alert. |
| Hash of a decoy-touching process binary (optional) | M3 honey-file alert, if M3 includes it | **TO CONFIRM WITH M3** | Only if M3's alert carries an executable path/hash |
| Source/destination IP | Network-related events in the IRDP-normalised stream | **TO CONFIRM WITH M1** | Non-routable IPs are dropped by M4 itself |
| Domain | DNS/network events in the normalised stream, if collected | **TO CONFIRM WITH M1** | Network/exfiltration detection is deferred (Final Doc §15), so domains may be rare in the prototype |

## How the field names will be fixed
1. M1 exports one real FIM alert and one network alert (JSON) from the lab VM.
2. The field paths are copied from those samples into `integrations/custom-m4-enrich.py` (the `FIELD_PATHS` adapter).
3. This table is updated and the `TO CONFIRM` markers are removed.
