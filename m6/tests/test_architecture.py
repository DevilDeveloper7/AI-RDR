"""Guards the layering: React -> Flask API -> services -> adapters (mock first)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _files(folder, pattern):
    return [p for p in (ROOT / folder).rglob(pattern) if "node_modules" not in p.parts]


def test_frontend_never_imports_mock_data_or_talks_to_m1_m5():
    for path in _files("frontend/src", "*.js*"):
        if path.name.endswith(".test.jsx"):
            continue
        text = path.read_text(encoding="utf-8")
        assert ".json'" not in text and '.json"' not in text, f"{path} imports a JSON file"
        assert "backend/app/mock" not in text, f"{path} references backend mock data"
        for module in ("M1_BASE_URL", "M2_BASE_URL", "M3_BASE_URL", "M4_BASE_URL", "M5_BASE_URL"):
            assert module not in text


def test_only_the_registry_imports_mock_adapters():
    for path in _files("backend/app", "*.py"):
        if path.name == "registry.py":
            continue
        assert "import Mock" not in path.read_text(encoding="utf-8"), f"{path} imports a mock adapter directly"


def test_services_and_routes_never_read_mock_data_directly():
    for folder in ("backend/app/services", "backend/app/routes"):
        for path in _files(folder, "*.py"):
            assert "load_json" not in path.read_text(encoding="utf-8"), f"{path} reads mock data directly"


def test_adapters_know_nothing_about_flask():
    for path in _files("backend/app/integrations", "*.py"):
        imports = [l for l in path.read_text(encoding="utf-8").splitlines() if l.startswith(("import ", "from "))]
        assert not any("flask" in l.lower() for l in imports), f"{path} must not depend on Flask"




def test_logo_assets_exist_independently_and_are_valid_svg():
    import xml.etree.ElementTree as ET

    brand = ROOT / "frontend/src/assets/brand"
    for name in ("ai-rdr-symbol.svg", "ai-rdr-logo.svg"):
        root = ET.parse(brand / name).getroot()
        assert root.tag.endswith("svg") and root.get("viewBox"), f"{name} is not a usable SVG"
    assert "ai-rdr-symbol.svg" in (ROOT / "frontend/index.html").read_text(encoding="utf-8")  # favicon
