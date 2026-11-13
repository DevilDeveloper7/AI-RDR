"""LIVE tests: M6's real M4 adapter against a RUNNING M4 service (nothing is faked).
Skipped unless M4_LIVE_URL is set, e.g.  M4_LIVE_URL=http://127.0.0.1:5004 python3 -m pytest tests/test_m4_live.py -v
What they can prove depends on how M4 was started: with M4_MOCK_PROVIDERS=1 M4 answers with lab data
(still a real HTTP integration of the M6 path); only an M4 started with real keys proves real threat-intel data."""
import os

import pytest

from app import create_app
from app.integrations import contracts as C
from app.integrations.m4.real import RealM4

URL = os.environ.get("M4_LIVE_URL", "").strip()
pytestmark = pytest.mark.skipif(not URL, reason="set M4_LIVE_URL to run the live M4 tests")
V1 = "/api/v1"


def test_live_health_is_connected_or_warning():
    h = RealM4(URL).health()
    assert h["status"] in ("Connected", "Warning") and h["detail"]


def test_live_enrich_returns_a_valid_indicator_and_list_follows_the_contract():
    a = RealM4(URL)
    item = a.enrich("203.0.113.9")  # documentation IP (TEST-NET-3): not routable, so M4 never sends it to a provider
    assert item is not None and C.validate_indicator(item)["indicator"] == "203.0.113.9" and item["type"] == "IP address"
    assert item["reputation"] != "Clean"  # only M4's local allowlist may say Clean
    assert all(C.validate_indicator(i) for i in a.list_indicators())
    assert isinstance(a.last_is_mock, bool)


def test_live_invalid_indicator_is_refused_by_m4():
    assert RealM4(URL).enrich("not a valid indicator!") is None


def test_live_through_the_m6_api(monkeypatch):
    monkeypatch.setenv("M4_MODE", "real")
    monkeypatch.setenv("M4_BASE_URL", URL)
    c = create_app({"TESTING": False}).test_client()
    row = {r["module"]: r for r in c.get(f"{V1}/integrations/status").get_json()["components"]}["M4"]
    assert row["mode"] == "real" and row["status"] in ("Connected", "Warning")
    res = c.get(f"{V1}/threat-intelligence/203.0.113.9")
    assert res.status_code == 200 and res.get_json()["indicator"] == "203.0.113.9"
    assert c.get(f"{V1}/threat-intelligence").get_json()["meta"]["role"] == "enrichment only"