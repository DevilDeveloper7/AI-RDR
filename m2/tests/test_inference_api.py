from fastapi.testclient import TestClient

from m2_pipeline.api import create_app
from m2_pipeline.inference import InferenceService


class FakeModel:
    def predict_proba(self, rows):
        event_count = rows[0][0]
        probability = 0.9 if event_count >= 2 else 0.1
        return [[1.0 - probability, probability]]


def service() -> InferenceService:
    return InferenceService(
        {
            "model": FakeModel(),
            "threshold": 0.5,
            "feature_names": ["event_count"],
            "feature_version": "test",
        },
        model_name="fake",
        enable_shap=False,
    )


def test_predict_contract_is_alert_only() -> None:
    client = TestClient(create_app(service()))
    response = client.post(
        "/v1/predict",
        json={
            "run_id": "live-1",
            "start": 0.0,
            "end": 5.0,
            "events": [
                {"timestamp": 0.1, "event_type": "openat", "pid": 10},
                {"timestamp": 0.2, "event_type": "write", "pid": 10, "bytes": 4096},
            ],
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["prediction"] == "ransomware"
    assert result["alert"] is True
    assert result["response_mode"] == "alert_only"
    assert result["model_name"] == "fake"
    assert result["explanation"] == []


def test_model_metadata_and_input_validation() -> None:
    client = TestClient(create_app(service()))

    metadata = client.get("/v1/model")
    invalid = client.post("/v1/predict", json={"run_id": "live-1", "events": []})

    assert metadata.status_code == 200
    assert metadata.json()["features"] == ["event_count"]
    assert invalid.status_code == 422
