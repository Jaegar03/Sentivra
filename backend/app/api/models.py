"""GET /api/v1/models — reflects ModelRegistry directly (brief §20)."""

from __future__ import annotations

from fastapi import APIRouter

from app.ml.registry import registry as model_registry

router = APIRouter(prefix="/api/v1", tags=["models"])


@router.get("/models")
async def list_models() -> list[dict]:
    return [entry.model_dump() for entry in model_registry.discover()]
