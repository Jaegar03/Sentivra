"""GET /api/v1/audit — the append-only audit log, newest first. Read-only:
there is no endpoint that edits or deletes audit rows."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.orm import AuditLogORM

router = APIRouter(prefix="/api/v1", tags=["audit"])


@router.get("/audit")
async def list_audit(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, max_length=128),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(AuditLogORM)
    count = select(func.count()).select_from(AuditLogORM)
    if action:
        stmt = stmt.where(AuditLogORM.action == action)
        count = count.where(AuditLogORM.action == action)
    rows = db.execute(stmt.order_by(AuditLogORM.created_at.desc()).offset(offset).limit(limit)).scalars()
    return {
        "total": db.execute(count).scalar_one(),
        "entries": [
            {"id": r.id, "created_at": r.created_at.isoformat(), "actor": r.actor, "action": r.action,
             "resource": r.resource, "detail": json.loads(r.detail_json or "{}")}
            for r in rows
        ],
    }
