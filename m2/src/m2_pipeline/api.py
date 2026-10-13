from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .inference import InferenceService
from .schema import NormalizedEvent

DEFAULT_MODEL_PATH = Path("artifacts/models/random_forest.joblib")


class EventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: float
    event_type: str = Field(min_length=1)
    operation: str | None = None
    pid: int | None = None
    ppid: int | None = None
    process_name: str | None = None
    path: str | None = None
    bytes: int | None = Field(default=None, ge=0)


class PredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1)
    start: float | None = None
    end: float | None = None
    top_k: int = Field(default=8, ge=1, le=31)
    events: list[EventInput] = Field(min_length=1)


class ExplanationItem(BaseModel):
    feature: str
    value: float
    shap_value: float
    direction: str


class PredictionResponse(BaseModel):
    prediction: str
    ransomware_probability: float
    threshold: float
    alert: bool
    response_mode: str
    model_name: str
    feature_version: str
    inference_ms: float
    explanation: list[ExplanationItem]


def create_app(service: InferenceService | None = None) -> FastAPI:
    app = FastAPI(
        title="AI-RDR M2 inference",
        version="1.0.0",
        description="Behavioural ransomware scoring; response remains alert-only.",
    )
    state: dict[str, InferenceService | None] = {"service": service}

    def get_service() -> InferenceService:
        if state["service"] is None:
            model_path = Path(
                os.environ.get("AI_RDR_MODEL_PATH", str(DEFAULT_MODEL_PATH))
            )
            if not model_path.exists():
                raise HTTPException(
                    status_code=503,
                    detail=f"Model artifact not found: {model_path}",
                )
            try:
                state["service"] = InferenceService.from_path(model_path)
            except (OSError, RuntimeError, ValueError) as error:
                raise HTTPException(status_code=503, detail=str(error)) from error
        return state["service"]

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "component": "m2-inference"}

    @app.get("/v1/model")
    def model_metadata(
        current: InferenceService = Depends(get_service),
    ) -> dict[str, object]:
        return {
            "model_name": current.model_name,
            "feature_version": current.feature_version,
            "threshold": current.threshold,
            "features": list(current.feature_names),
            "response_mode": "alert_only",
        }

    @app.post("/v1/predict", response_model=PredictionResponse)
    def predict(
        request: PredictionRequest,
        current: InferenceService = Depends(get_service),
    ) -> dict:
        events = [
            NormalizedEvent(
                timestamp=event.timestamp,
                run_id=request.run_id,
                label="unknown",
                event_type=event.event_type.lower(),
                operation=(event.operation or event.event_type).lower(),
                pid=event.pid,
                ppid=event.ppid,
                process_name=event.process_name,
                path=event.path,
                bytes=event.bytes,
                source="live-irdp",
            )
            for event in request.events
        ]
        try:
            result = current.predict(
                events,
                run_id=request.run_id,
                start=request.start,
                end=request.end,
                top_k=request.top_k,
            )
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return result.to_dict()

    return app


app = create_app()


def run() -> None:
    try:
        import uvicorn
    except ImportError as error:
        raise RuntimeError(
            "API dependencies are missing; install with: pip install -e '.[api,ml]'"
        ) from error
    uvicorn.run("m2_pipeline.api:app", host="127.0.0.1", port=8000)
