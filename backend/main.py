from __future__ import annotations

from fastapi import FastAPI, HTTPException

from waveframe_guard import WaveframeGuard

from .models import EvaluateRequest, EvaluateResponse, EventRecord
from .store import EventStore


app = FastAPI(
    title="Waveframe Guard Control Plane",
    version="0.1.0",
    description="Backend API for evaluating and recording AI action enforcement decisions.",
)

store = EventStore(db_path="waveframe_guard.db")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate(request: EvaluateRequest) -> EvaluateResponse:
    """
    Evaluate an action through Waveframe Guard and persist the result.
    """
    try:
        guard = WaveframeGuard(policy=request.policy)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Policy initialization failed: {exc}") from exc

    decision = guard.execute(
        action=request.action,
        actor=request.actor,
        context=request.context,
    )

    event = EventRecord.create(
        actor=request.actor,
        action=request.action,
        context=request.context,
        allowed=decision["allowed"],
        reason=decision["reason"],
        policy=request.policy,
    )

    store.insert_event(event)

    return EvaluateResponse(
        event_id=event.event_id,
        timestamp=event.timestamp,
        allowed=event.allowed,
        reason=event.reason,
    )


@app.get("/events")
def list_events(limit: int = 100) -> list[dict]:
    """
    Return recent enforcement events.
    """
    events = store.list_events(limit=limit)
    return [event.model_dump() for event in events]


@app.get("/events/{event_id}")
def get_event(event_id: str) -> dict:
    """
    Return a single enforcement event by ID.
    """
    event = store.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    return event.model_dump()