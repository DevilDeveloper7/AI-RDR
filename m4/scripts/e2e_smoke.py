"""End-to-end smoke test: synthetic Wazuh alert -> integration script -> M4
(MOCK providers) -> enrichment result. No keys, no malware, no internet.

    .venv/bin/python scripts/e2e_smoke.py

1. Starts M4 in MOCK mode on a free localhost port (in this process).
2. Feeds a SYNTHETIC FIM alert to integrations/custom-m4-enrich.py.
3. Polls the job and prints the enrichment that would be attached.
4. Repeats with M4 stopped, to show the integration survives M4 being down.
"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from werkzeug.serving import make_server  # noqa: E402  (installed with Flask)

from m4_threat_intel.app import create_app, shutdown_app  # noqa: E402
from m4_threat_intel.config import Settings  # noqa: E402

spec = importlib.util.spec_from_file_location("integ", ROOT / "integrations" / "custom-m4-enrich.py")
integ = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integ)

MOCK_BAD_HASH = "1" * 64   # listed in data/mock_iocs.json (fake)
ALERT = {   # SYNTHETIC alert using the FIELD_PATHS names; not a real Wazuh export
    "id": "SMOKE-0001", "agent": {"id": "001", "name": "lab-endpoint"},
    "rule": {"description": "SYNTHETIC: file modified"},
    "syscheck": {"path": "/srv/share/report.docx", "sha256_after": MOCK_BAD_HASH},
    "data": {"srcip": "8.8.4.4"},
}


def main():
    tmp = tempfile.TemporaryDirectory()
    log_file = os.path.join(tmp.name, "integrations.log")
    app = create_app(Settings(cache_path=os.path.join(tmp.name, "c.sqlite3")), mock=True)
    server = make_server("127.0.0.1", 0, app)
    url = f"http://127.0.0.1:{server.server_port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"M4 (MOCK mode) listening on {url}")

    outcomes = integ.process_alert(ALERT, url, log_file=log_file)
    print("Integration outcomes:", outcomes)
    for ioc_type, value, outcome in outcomes:
        job_id = outcome.split()[-1]
        for _ in range(100):
            with urllib.request.urlopen(f"{url}/enrich/jobs/{job_id}", timeout=3) as resp:
                job = json.load(resp)
            if job["status"] != "pending":
                break
            time.sleep(0.05)
        r = job["result"] or {}
        print(f"  {ioc_type} {value[:16]}... -> status={job['status']} verdict={r.get('verdict')} "
              f"score={r.get('score')} sources={r.get('sources')} tags={r.get('tags')}")

    server.shutdown()
    shutdown_app(app)
    print("\nM4 stopped. Sending the same alert again:")
    print("Integration outcomes:", integ.process_alert(ALERT, url, log_file=log_file))
    print("\nintegrations.log:\n" + Path(log_file).read_text())
    tmp.cleanup()


if __name__ == "__main__":
    main()
