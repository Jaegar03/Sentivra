"""POST /api/v1/events, GET /api/v1/events, GET /api/v1/events/{id}."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEvent
from app.services.event_repository import EventRepository
from app.services.pipeline import run_pipeline

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("")
async def ingest_event(
    event: SecurityEvent,
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    findings, assessment = await run_pipeline(event, db=db, registry=registry, actor="events_api")
    return {
        "event_id": event.event_id,
        "findings": [f.model_dump(mode="json") for f in findings],
        "risk_assessment": assessment.model_dump(mode="json"),
    }


@router.get("")
async def list_events(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)) -> list[dict]:
    repo = EventRepository(db)
    rows = repo.list_recent(limit=limit, offset=offset)
    return [repo.to_domain(r).model_dump(mode="json") for r in rows]


@router.get("/{event_id}")
async def get_event(event_id: str, db: Session = Depends(get_db)) -> dict:
    repo = EventRepository(db)
    row = repo.get(event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return repo.to_domain(row).model_dump(mode="json")
