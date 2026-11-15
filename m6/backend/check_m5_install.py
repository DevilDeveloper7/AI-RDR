#!/usr/bin/env python3
"""Checks that the M5 integration files are installed correctly. Changes nothing, sends nothing, needs no M5 connection.

  .venv/bin/python backend/check_m5_install.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

FILES = ["backend/app/integrations/m5/vendor/__init__.py", "backend/app/integrations/m5/vendor/ai_rdr_m6.py",
         "backend/app/integrations/m5/gateway_config.py", "backend/app/integrations/m5/gateway.py",
         "backend/app/integrations/m5/state_store.py", "backend/app/integrations/m5/delivery.py",
         "backend/app/services/m5_service.py", "backend/app/routes/m5.py", "backend/m5_tool.py",
         "tests/m5_fake_endpoint.py", "tests/test_m5_gateway.py", "tests/test_m5_events.py", "tests/test_m5_tool.py",
         "tests/test_m5_routes.py", "tests/test_m5_real_code.py", "docs/integration/m5-gateway.md"]
problems = []


def check(ok, good, bad):
    print(("  OK       " if ok else "  PROBLEM  ") + (good if ok else bad.split("|")[0]))
    if not ok:
        problems.append(bad.split("|")[-1])


print(f"Checking the project in: {ROOT}\n\n1. New files")
for f in FILES:
    check((ROOT / f).is_file(), f, f"{f} is missing|Create {f} (see the installation table).")

print("\n2. The two edited files")
init = (ROOT / "backend/app/routes/__init__.py").read_text() if (ROOT / "backend/app/routes/__init__.py").is_file() else ""
integ = (ROOT / "backend/app/routes/integrations.py").read_text() if (ROOT / "backend/app/routes/integrations.py").is_file() else ""
check("m5" in init.replace("m5_", ""), "backend/app/routes/__init__.py registers the m5 routes",
      "backend/app/routes/__init__.py does NOT mention m5|Replace the whole content of backend/app/routes/__init__.py with the new code, then SAVE (Cmd+S).")
check("overlay_status" in integ and "M5Link" in integ, "backend/app/routes/integrations.py has the M5 status overlay",
      "backend/app/routes/integrations.py does NOT have the M5 overlay|Replace the whole content of backend/app/routes/integrations.py with the new code, then SAVE (Cmd+S).")

print("\n3. The running application")
try:
    from app import create_app
    import app as app_pkg
    flask_app = create_app({"TESTING": False})
    where = Path(app_pkg.__file__).resolve()
    check(ROOT in where.parents, f"Python loads the app from {where.parent}",
          f"Python loads the app from a DIFFERENT folder: {where.parent}|Run the commands from the m6 folder you edited.")
    prefix = flask_app.config["API_PREFIX"]
    rules = sorted(r.rule for r in flask_app.url_map.iter_rules() if "/m5/" in r.rule)
    check(len(rules) == 5, f"5 read-only M5 routes are registered, for example {prefix}/m5/health",
          f"Only {len(rules)} of 5 M5 routes are registered|Fix section 2 above and restart.")
    res = flask_app.test_client().get(f"{prefix}/m5/health")
    body = res.get_json(silent=True) or {}
    check(res.status_code == 200 and "status" in body, f"GET {prefix}/m5/health answers: {body.get('status')} ({body.get('detail', '')[:60]})",
          f"GET {prefix}/m5/health answered HTTP {res.status_code}|Fix sections 1 and 2 above.")
except Exception as exc:  # noqa: BLE001 - this is a diagnostic tool
    check(False, "", f"The application could not start: {type(exc).__name__}: {exc}|Read this error message; it names the file that is wrong.")

print()
if problems:
    print(f"{len(problems)} problem(s). What to do:")
    for n, p in enumerate(dict.fromkeys(problems), 1):
        print(f"  {n}. {p}")
    sys.exit(1)
print("Everything is installed correctly.")
