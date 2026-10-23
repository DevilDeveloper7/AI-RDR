"""Loader for the MOCK data files in this folder. Keeps data separate from logic."""
import json
from pathlib import Path

_DIR = Path(__file__).parent


def load_json(name):
    with open(_DIR / name, encoding="utf-8") as fh:
        return json.load(fh)
