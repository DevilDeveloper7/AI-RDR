import copy

from ...mock import load_json
from . import M2Adapter


class MockM2(M2Adapter):
    """MOCK M2. Representative detections and SHAP values from JSON. Not real model output."""

    kind = "mock"

    def __init__(self):
        self._detections = load_json("m2_detections.json")["detections"]
        self._shap = load_json("shap.json")["explanations"]

    def health(self):
        return {"status": "Stubbed", "detail": "Mock adapter. No real M2 model is connected."}

    def list_detections(self):
        return copy.deepcopy(self._detections)

    def get_shap(self, alert_id):
        return copy.deepcopy(self._shap.get(alert_id))
