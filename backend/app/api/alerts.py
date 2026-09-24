"""GET /api/v1/alerts, GET /api/v1/alerts/{id}."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.services.alert_repository import AlertRepository

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    limit: int = 50,
    offset: int = 0,
    min_severity: str | None = None,
    db: Session = Depends(get_db),
) -> list[dict]:
    from app.schemas.detection import Severity

    min_rank = Severity(min_severity).rank if min_severity else 0
    repo = AlertRepository(db)
    rows = repo.list_recent(limit=limit, offset=offset, min_severity_rank=min_rank)
    return [repo.to_domain(r).model_dump(mode="json") for r in rows]


@router.get("/{alert_id}")
async def get_alert(alert_id: str, db: Session = Depends(get_db)) -> dict:
    repo = AlertRepository(db)
    row = repo.get(alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return repo.to_domain(row).model_dump(mode="json")
