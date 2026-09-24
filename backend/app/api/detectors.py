"""GET /api/v1/detectors — reflects DetectorRegistry directly."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_detector_registry
from app.detectors.registry import DetectorRegistry

router = APIRouter(prefix="/api/v1", tags=["detectors"])


@router.get("/detectors")
async def list_detectors(registry: DetectorRegistry = Depends(get_detector_registry)) -> list[dict]:
    out = []
    for detector in registry.all():
        availability = await detector.is_available()
        out.append(
            {
                "name": detector.name,
                "version": detector.version,
                "category": detector.category.value,
                "applicable_event_types": sorted(t.value for t in detector.applicable_event_types),
                "availability": {
                    "status": availability.status.value,
                    "detail": availability.detail,
                    "engine_version": availability.engine_version,
                },
            }
        )
    return out
