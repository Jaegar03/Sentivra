"""Append-only audit logging. No update/delete is exposed — see
AuditLogORM's docstring and docs/threat-model.md Boundary B."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.models.orm import AuditLogORM


def record(db: Session, *, actor: str, action: str, resource: str, detail: dict[str, Any] | None = None) -> None:
    row = AuditLogORM(
        actor=actor,
        action=action,
        resource=resource,
        detail_json=json.dumps(detail or {}),
    )
    db.add(row)
    db.commit()
