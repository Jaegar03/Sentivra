"""GET /api/v1/health (metrics moved to app.api.metrics).

Health reports the *real* state of every optional engine (brief §32 —
"ClamAV: Available / Not Configured" must be truthful). Metrics reports
operational counters only, never a fabricated ML accuracy number
(brief §33) — model evaluation metrics live in ModelRegistry/model-card.md
instead, tied to a specific evaluation date and dataset.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.core.config import get_settings
from app.detectors.registry import DetectorRegistry
from app.models.orm import EventORM
from app.security.auth import require_scopes

router = APIRouter(prefix="/api/v1", tags=["system"])
# Liveness only (no detail): usable by monitors without credentials.
public_router = APIRouter(prefix="/api/v1", tags=["system"])


@public_router.get("/health/live")
async def live() -> dict:
    return {"status": "ok"}


@router.get("/health", dependencies=[Depends(require_scopes("read"))])
async def health(
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    settings = get_settings()

    try:
        db.execute(select(func.count()).select_from(EventORM))
        db_ok = True
    except Exception:  # noqa: BLE001
        db_ok = False

    engines = {}
    for detector in registry.all():
        availability = await detector.is_available()
        engines[detector.name] = {
            "status": availability.status.value,
            "detail": availability.detail,
            "engine_version": availability.engine_version,
        }

    # Engines referenced by the brief that are not yet wired as detectors
    # in this phase are still reported, honestly, as Not Configured rather
    # than omitted (brief §32).
    for planned_engine in ("Suricata", "Zeek"):
        engines.setdefault(
            planned_engine,
            {
                "status": "Not Configured",
                "detail": f"{planned_engine} integration is planned; see docs/architecture.md §4",
                "engine_version": None,
            },
        )

    return {
        "status": "ok" if db_ok else "degraded",
        "environment": settings.env,
        "database": "ok" if db_ok else "unreachable",
        "engines": engines,
    }
