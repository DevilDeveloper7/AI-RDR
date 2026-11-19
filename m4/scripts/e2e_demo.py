#!/usr/bin/env python3
"""One-command proof that the whole chain works: Wazuh alert -> M4 -> M5 -> M6.

    python3 scripts/e2e_demo.py                       # offline: M4 starts itself in MOCK mode (fake intel, labelled)
    python3 scripts/e2e_demo.py --live http://127.0.0.1:5004 --alert results/candidates/alerts/001_Akira.json
                                                      # uses your running M4 (real abuse.ch / OTX answers)

Steps (each prints PASS / FAIL):
  1. the Wazuh integration script (integrations/custom-m4-enrich.py) queues the alert's indicators in M4
  2. M4 answers; the records for that alert id are pulled with GET /alerts/<id>/threat_intel
  3. M5 (real ai_rdr_risk.RiskMatrix, if ../m5 is there) scores the bundle: threat_intel must add its weight
  4. M6 (real RealM4 adapter, if ../m6 and its dependencies are there) lists the indicator for the dashboard
No malware is run. The default alert carries a FAKE hash that only the mock data knows.
"""
import argparse, datetime as dt, importlib.util, json, os, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
M4_ROOT = os.path.dirname(HERE)
REPO = os.path.dirname(M4_ROOT)
sys.path.insert(0, M4_ROOT)
import logging
logging.getLogger("werkzeug").setLevel(logging.ERROR)     # no request noise in the demo output

FAKE_ALERT = {"id": "demo-0001", "rule": {"id": "554", "description": "File added (demo)", "level": 7},
              "agent": {"id": "001", "name": "airdr-target"},
              "syscheck": {"path": "/tmp/demo_sample", "event": "added", "sha256_after": "1" * 64},
              "data": {"srcip": "185.220.101.47"}}
results = []


def step(name, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    return ok


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def start_mock_m4():
    from werkzeug.serving import make_server
    from m4_threat_intel.app import create_app
    from m4_threat_intel.config import Settings
    tmp = tempfile.mkdtemp()
    app = create_app(Settings(cache_path=os.path.join(tmp, "cache.sqlite3")), mock=True)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", help="URL of a running M4 (default: start a mock M4 for this demo)")
    ap.add_argument("--alert", help="Wazuh alert JSON file (default: built-in demo alert)")
    a = ap.parse_args()

    alert = json.load(open(a.alert)) if a.alert else FAKE_ALERT
    alert_id = str(alert.get("id", "demo"))
    url = a.live or start_mock_m4()
    print(f"M4 at {url} ({'live' if a.live else 'mock, fake intelligence'}); alert {alert_id}")

    from m4_threat_intel import m4_client
    wazuh = load(os.path.join(M4_ROOT, "integrations", "custom-m4-enrich.py"), "custom_m4_enrich")
    log = os.path.join(tempfile.mkdtemp(), "integrations.log")

    print("1. Wazuh integration script")
    indicators = wazuh.extract_indicators(alert)
    step("indicators found in the alert", bool(indicators), ", ".join(f"{t}={v[:16]}" for t, v in indicators))
    outcomes = wazuh.process_alert(alert, url, log_file=log)
    step("queued in M4", bool(outcomes) and all(o[2].startswith("queued") for o in outcomes),
         "; ".join(o[2] for o in outcomes))

    print("2. M4 records for the alert (M5 format)")
    wanted = sum(1 for t, v in indicators if t == "ip" or len(v) == 64)
    records = []
    for _ in range(100):
        records = m4_client.threat_intel_for_alert(alert_id, base_url=url)
        if len(records) >= wanted:
            break
        time.sleep(0.1)
    step("records received", len(records) >= wanted > 0, f"{len(records)} of {wanted}")
    for r in records:
        print(f"       {r['indicator_type']:<6} {r['indicator'][:20]:<22} M4 verdict={r['m4_verdict']:<10} -> M5 status={r['status']}"
              + ("  (synthetic)" if r.get("synthetic") else ""))

    print("3. M5 risk scoring")
    m5_dir = os.path.join(REPO, "m5")
    if os.path.exists(os.path.join(m5_dir, "ai_rdr_risk.py")):
        sys.path.insert(0, m5_dir)
        try:
            import ai_rdr_risk
            sha = next((v for t, v in indicators if t == "hash" and len(v) == 64), None)
            ip = next((v for t, v in indicators if t == "ip"), None)
            bundle = {"agent_id": "airdr-target", "threat_intel": records}
            bundle.update({k: v for k, v in (("sha256", sha), ("src_ip", ip)) if v})
            now = dt.datetime.now(dt.timezone.utc)
            out = ai_rdr_risk.RiskMatrix().evaluate(bundle, agent_id="airdr-target", case_id=alert_id, now=now)
            ti = [e for e in out["evidence"] if e["source"] == "threat_intel"]
            expect = any(r["status"] == "match" for r in records)
            step("M5 accepted the records", not out.get("invalid_sources"), str(out.get("invalid_sources") or "no invalid sources"))
            points = sum(e["contribution"] for e in ti)
            step("threat intelligence counted" if expect else "no match, so 0 points", (points > 0) == expect,
                 "; ".join(f"{e['reason']}={e['contribution']}" for e in ti))
        except Exception as exc:
            step("M5 ran", False, f"{type(exc).__name__}: {exc}")
    else:
        print("  skipped: ../m5 not found")

    print("4. M6 dashboard adapter")
    m6_dir = os.path.join(REPO, "m6", "backend")
    if os.path.exists(os.path.join(m6_dir, "app", "integrations", "m4", "real.py")):
        sys.path.insert(0, m6_dir)
        try:
            from app.integrations.m4.real import RealM4
            adapter = RealM4(url)
            health = adapter.health()
            items = [i for i in adapter.list_indicators() if i["related_alert"] == alert_id]
            step("M6 lists the indicators for this alert", len(items) >= 1, f"{len(items)} item(s), health={health['status']}")
            for i in items:
                print(f"       {i['type']:<10} {i['indicator'][:20]:<22} {i['reputation']:<10} {i['enrichment_status']}")
        except ImportError as exc:
            print(f"  skipped: M6 dependencies missing ({exc}); run: pip3 install -r m6/backend/requirements.txt")
        except Exception as exc:
            step("M6 adapter ran", False, f"{type(exc).__name__}: {exc}")
    else:
        print("  skipped: ../m6 not found")

    print("\nRESULT:", "ALL CHECKS PASSED" if results and all(results) else "SOMETHING FAILED")
    return 0 if results and all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
