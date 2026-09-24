"""GET /api/v1/health and GET /api/v1/metrics.

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
from app.models.orm import AlertORM, EventORM

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get("/health")
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


@router.get("/metrics")
async def metrics(db: Session = Depends(get_db)) -> dict:
    event_count = db.execute(select(func.count()).select_from(EventORM)).scalar_one()
    alert_count = db.execute(select(func.count()).select_from(AlertORM)).scalar_one()
    severity_counts = dict(
        db.execute(
            select(AlertORM.severity, func.count()).group_by(AlertORM.severity)
        ).all()
    )
    return {
        "events_total": event_count,
        "alerts_total": alert_count,
        "alerts_by_severity": severity_counts,
        "note": (
            "Operational counters only. Model evaluation metrics (precision/recall/"
            "F1/ROC-AUC) are reported per-model via GET /api/v1/models and "
            "docs/model-card.md, each tied to a dataset and evaluation date — "
            "never as an unqualified accuracy figure (brief §33)."
        ),
    }
