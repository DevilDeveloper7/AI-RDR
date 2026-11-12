#!/usr/bin/env python3
"""Wazuh custom integration: send indicators from selected alerts to M4.

Wazuh's integrator runs this script once per matching alert, with:
    argv[1] = path of a file holding the alert JSON
    argv[2] = <api_key> from ossec.conf (unused here)
    argv[3] = <hook_url> from ossec.conf = M4 base URL, e.g. http://127.0.0.1:5004
    argv[4] = "debug" (optional)
(Argument order verified against Wazuh v4.9.0's own integrations/virustotal.py
and slack.py. See docs/wazuh_integration.md.)

FAIL-SAFE: this script must never disturb alert processing. Every problem
(M4 down, slow, erroring, odd alert) is logged and the script exits 0.
It uses only the Python standard library and never logs secrets.
"""
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# FIELD ADAPTER: where indicators live inside a Wazuh alert.
#   syscheck.md5_after / syscheck.sha1_after: confirmed (Wazuh's virustotal.py)
#   syscheck.sha256_after: inferred (decoder field "sha256" + the same
#       "_after" pattern). UNVERIFIED: confirm with a real FIM alert from M1.
#   IP paths: TODO / UNVERIFIED. Replace with the real field names from
#       M1's sample network alert. Nothing is extracted until confirmed paths
#       produce a value.
# ---------------------------------------------------------------------------
FIELD_PATHS = {
    "hash": ["syscheck.sha256_after", "syscheck.sha1_after", "syscheck.md5_after"],
    "ip": ["data.srcip", "data.dstip"],   # TODO: UNVERIFIED, confirm with M1
}
ALERT_ID_PATH = "id"                      # confirmed (virustotal.py uses alert['id'])

TIMEOUT_SECONDS = 3
_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
                         "logs", "integrations.log")


def log(message, log_file=None):
    """Append one line to Wazuh's integrations log; never raise."""
    try:
        with open(log_file or _LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"custom-m4-enrich: {message}\n")
    except OSError:
        pass


def get_path(alert, dotted):
    node = alert
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def extract_indicators(alert):
    """Return [(type, value), ...] found in the alert.

    Hash: the FIRST (strongest) valid hash only, SHA-256 preferred.
    IPs: every valid, publicly routable address in the configured paths.
    """
    indicators = []
    for path in FIELD_PATHS["hash"]:
        value = get_path(alert, path)
        if isinstance(value, str) and _HASH_RE.match(value.strip()):
            indicators.append(("hash", value.strip().lower()))
            break
    for path in FIELD_PATHS["ip"]:
        value = get_path(alert, path)
        if not isinstance(value, str):
            continue
        try:
            ip = ipaddress.ip_address(value.strip())
        except ValueError:
            continue
        if ip.is_global and not ip.is_multicast and ("ip", str(ip)) not in indicators:
            indicators.append(("ip", str(ip)))
    return indicators


def post_json(url, payload, timeout=TIMEOUT_SECONDS):
    """POST JSON, return (status_code, parsed_body_or_None). Raises on network errors."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        return exc.code, None


def process_alert(alert, m4_url, post=post_json, log_file=None):
    """Submit each indicator to M4's async endpoint. Never raises.

    Returns a list of (type, value, outcome) for logging/tests.
    """
    outcomes = []
    if not isinstance(alert, dict):
        log("alert is not a JSON object; skipped", log_file)
        return outcomes
    alert_id = str(get_path(alert, ALERT_ID_PATH) or "unknown-alert")
    for ioc_type, value in extract_indicators(alert):
        payload = {"alert_id": alert_id, "type": ioc_type, "value": value}
        try:
            status, body = post(m4_url.rstrip("/") + "/enrich/async", payload)
            if status == 202 and isinstance(body, dict) and body.get("job_id"):
                outcome = f"queued job {body['job_id']}"
            else:
                outcome = f"M4 answered HTTP {status}"
        except Exception as exc:   # M4 down / slow / anything else: log and carry on
            outcome = f"M4 unreachable ({type(exc).__name__})"
        log(f"alert {alert_id} {ioc_type} {value}: {outcome}", log_file)
        outcomes.append((ioc_type, value, outcome))
    return outcomes


def main(argv):
    try:
        if len(argv) < 4:
            log("bad arguments (expected alert file and hook_url)")
            return 0
        with open(argv[1], encoding="utf-8") as fh:
            alert = json.load(fh)
        process_alert(alert, argv[3])
    except Exception as exc:   # fail-safe: never break the integrator
        log(f"error: {type(exc).__name__}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
