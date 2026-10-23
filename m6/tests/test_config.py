import pytest

from app.config import MODULES, Config


def test_all_modules_default_to_mock(monkeypatch):
    for m in MODULES:
        monkeypatch.delenv(f"{m.upper()}_MODE", raising=False)
        monkeypatch.delenv(f"{m.upper()}_BASE_URL", raising=False)
    cfg = Config()
    assert set(cfg.INTEGRATIONS) == set(MODULES)
    assert all(v == {"mode": "mock", "base_url": ""} for v in cfg.INTEGRATIONS.values())


def test_base_url_is_read_from_environment(monkeypatch):
    monkeypatch.setenv("M2_BASE_URL", "http://example.invalid:9000")
    assert Config().INTEGRATIONS["m2"]["base_url"] == "http://example.invalid:9000"


def test_invalid_mode_is_rejected(monkeypatch):
    monkeypatch.setenv("M3_MODE", "banana")
    with pytest.raises(ValueError):
        Config()
