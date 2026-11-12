"""Real M4 adapter, tested against a small fake M4 HTTP server (no real M4 needed)."""
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.config import Config
from app.integrations import contracts as C
from app.integrations.base import IntegrationTimeout, IntegrationUnavailable, MalformedResponse
from app.integrations.m4.real import RealM4, classify
from app.integrations.registry import build_adapters

SHA = "a" * 64
INDICATOR = {"indicator": SHA, "type": "SHA-256", "reputation": "Malicious", "source": "abuse.ch MalwareBazaar",
             "related_alert": "A-2041", "last_checked": "2026-10-05T09:16:54Z", "notes": "Context only.",
             "enrichment_status": "enriched"}


@contextmanager
def fake_m4(routes, delay=0.0):
    """routes = {(method, path-prefix): (status, body | raw str)}. Records requests."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def _answer(self, method):
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else None
            seen.append((method, self.path, body))
            time.sleep(delay)
            for (m, prefix), (status, payload) in routes.items():
                if m == method and self.path.startswith(prefix):
                    raw = payload if isinstance(payload, str) else json.dumps(payload)
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(raw.encode())
                    return
            self.send_response(404)
            self.end_headers()

        def do_GET(self):
            self._answer("GET")

        def do_POST(self):
            self._answer("POST")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


def test_classify():
    assert classify(SHA.upper()) == ("hash", SHA)
    assert classify("d" * 32)[0] == "hash" and classify("d" * 40)[0] == "hash"
    assert classify("203.0.113.9") == ("ip", "203.0.113.9")
    assert classify("Evil.Example") == ("domain", "evil.example")
    assert classify("nonsense") is None and classify("") is None and classify(None) is None


def test_list_indicators_follow_the_m6_contract():
    with fake_m4({("GET", "/indicators"): (200, {"items": [INDICATOR]})}) as (url, seen):
        items = RealM4(url).list_indicators()
    assert items == [INDICATOR]
    C.validate_indicator(items[0])
    assert seen[0][1] == "/indicators?limit=100"


def test_enrich_sends_the_lookup_alert_id_and_returns_the_indicator():
    with fake_m4({("POST", "/enrich/m6"): (200, INDICATOR)}) as (url, seen):
        item = RealM4(url).enrich(SHA.upper())
    C.validate_indicator(item)
    assert seen[0][2] == {"alert_id": "m6-lookup", "type": "hash", "value": SHA}


def test_enrich_returns_none_when_m4_refuses_the_indicator():
    with fake_m4({("POST", "/enrich/m6"): (400, {"error": "bad"})}) as (url, _):
        assert RealM4(url).enrich("d" * 32) is None
    assert RealM4("http://127.0.0.1:1").enrich("nonsense") is None      # never even asks M4


def test_m4_down_is_unavailable():
    with pytest.raises(IntegrationUnavailable):
        RealM4("http://127.0.0.1:1", timeout=1).list_indicators()


def test_m4_http_500_is_unavailable():
    with fake_m4({("GET", "/indicators"): (500, {"error": "boom"})}) as (url, _):
        with pytest.raises(IntegrationUnavailable):
            RealM4(url).list_indicators()


def test_slow_m4_is_a_timeout():
    with fake_m4({("GET", "/indicators"): (200, {"items": []})}, delay=1.0) as (url, _):
        with pytest.raises(IntegrationTimeout):
            RealM4(url, timeout=0.2).list_indicators()


def test_bad_json_and_wrong_shapes_are_malformed():
    with fake_m4({("GET", "/indicators"): (200, "not json")}) as (url, _):
        with pytest.raises(MalformedResponse):
            RealM4(url).list_indicators()
    with fake_m4({("GET", "/indicators"): (200, {"items": "nope"}),
                  ("POST", "/enrich/m6"): (200, ["x"])}) as (url, _):
        with pytest.raises(MalformedResponse):
            RealM4(url).list_indicators()
        with pytest.raises(MalformedResponse):
            RealM4(url).enrich(SHA)


@pytest.mark.parametrize("health,status", [
    ({"status": "ok", "mode": "live", "abusech_key": "set", "otx_key": "set"}, "Connected"),
    ({"status": "ok", "mode": "MOCK", "abusech_key": "set", "otx_key": "set"}, "Warning"),
    ({"status": "ok", "mode": "live", "abusech_key": "set", "otx_key": "missing"}, "Warning"),
    ({"status": "weird"}, "Warning"),
])
def test_health_states(health, status):
    with fake_m4({("GET", "/health"): (200, health)}) as (url, _):
        assert RealM4(url).health()["status"] == status


def test_health_failed_when_m4_is_down():
    assert RealM4("http://127.0.0.1:1", timeout=1).health()["status"] == "Failed"


def test_registry_builds_the_real_adapter_for_m4_only():
    cfg = Config().INTEGRATIONS
    cfg["m4"] = {"mode": "real", "base_url": "http://127.0.0.1:5004"}
    adapters = build_adapters(cfg)
    assert isinstance(adapters["m4"], RealM4) and adapters["m4"].kind == "real"
    assert adapters["m1"].kind == "mock"


def test_empty_base_url_means_local_m4():
    assert RealM4("").base_url == "http://127.0.0.1:5004"
