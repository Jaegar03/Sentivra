"""GET /api/v1/alerts, GET /api/v1/alerts/{id}, PATCH /api/v1/alerts/{id}.

Each alert carries its event's source and source type, so every view can
show whether it came from LIVE, SIMULATED or DEMO_DATA input (brief §26).
Status changes are recorded in the audit log.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.audit import service as audit_service
from app.schemas.detection import Severity
from app.security.auth import current_actor, require_scopes
from app.services.alert_repository import AlertRepository
from app.services.event_repository import EventRepository

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

_UNKNOWN_EVENT = {"source": None, "source_type": None, "event_type": None}


class AlertStatusUpdate(BaseModel):
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]
    note: str | None = Field(default=None, max_length=500)


@router.get("", dependencies=[Depends(require_scopes("read"))])
async def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    min_severity: Severity | None = None,
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] | None = None,
    db: Session = Depends(get_db),
) -> list[dict]:
    repo = AlertRepository(db)
    rows = repo.list_recent(limit=limit, offset=offset, min_severity_rank=min_severity.rank if min_severity else 0,
                            status=status)
    events = EventRepository(db).summaries([r.event_id for r in rows])
    return [
        {**repo.to_domain(r).model_dump(mode="json"), "status": r.status,
         "event": events.get(r.event_id, _UNKNOWN_EVENT)}
        for r in rows
    ]


@router.get("/{alert_id}", dependencies=[Depends(require_scopes("read"))])
async def get_alert(alert_id: str, db: Session = Depends(get_db)) -> dict:
    repo = AlertRepository(db)
    row = repo.get(alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    events = EventRepository(db)
    event_row = events.get(row.event_id)
    return {
        **repo.to_domain(row).model_dump(mode="json"),
        "status": row.status,
        "event": events.to_domain(event_row).model_dump(mode="json") if event_row else _UNKNOWN_EVENT,
    }


@router.patch("/{alert_id}", dependencies=[Depends(require_scopes("alerts:write"))])
async def update_alert_status(alert_id: str, update: AlertStatusUpdate, db: Session = Depends(get_db)) -> dict:
    repo = AlertRepository(db)
    row = repo.get(alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    previous = row.status
    repo.set_status(row, update.status)
    audit_service.record(db, actor=current_actor(), action="alert_status_change", resource=f"alert:{alert_id}",
                         detail={"from": previous, "to": update.status, "note": update.note})
    return {"alert_id": alert_id, "status": row.status, "previous_status": previous}
