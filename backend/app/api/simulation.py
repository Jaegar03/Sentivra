"""Authenticated API for the Cyber Defense Lab."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.detectors.registry import DetectorRegistry
from app.security.auth import require_scopes
from app.services.local_target import synthetic_search_target
from app.services.simulation import (
    MAX_HISTORY_OFFSET,
    SCENARIO_MAP,
    SimulationCapacityError,
    SimulationConflictError,
    SimulationPersistenceError,
    get_execution,
    list_scenarios,
    recent,
    run_simulation,
    serialize,
    statistics,
)

router = APIRouter(prefix="/api/simulation", tags=["simulation"], dependencies=[Depends(require_scopes("read"))])


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=64)
    mode: Literal["simulation"]
    request_key: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")


@router.get("/scenarios")
async def scenarios(registry: DetectorRegistry = Depends(get_detector_registry)) -> list[dict]:
    return await list_scenarios(registry)


@router.post("/target/reset", dependencies=[Depends(require_scopes("analyze"))])
async def reset_target() -> dict:
    """Reset only the in-memory synthetic target; no Sentivra records are deleted."""
    synthetic_search_target.reset()
    return {"mode": "simulation", "target": synthetic_search_target.endpoint, "reset": True}


@router.post("/run", dependencies=[Depends(require_scopes("analyze"))])
async def run(payload: SimulationRequest, db: Session = Depends(get_db), registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    if payload.scenario_id not in SCENARIO_MAP:
        raise HTTPException(status_code=404, detail="Unknown trusted simulation scenario")
    try:
        return serialize(await run_simulation(db, registry, payload.scenario_id, request_key=payload.request_key))
    except SimulationConflictError as exc:
        raise HTTPException(status_code=409, detail="Request key already identifies a different scenario") from exc
    except SimulationCapacityError as exc:
        raise HTTPException(status_code=429, detail="Simulation capacity reached; try again shortly") from exc
    except (SimulationPersistenceError, SQLAlchemyError) as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Simulation storage is unavailable; retry with the same request key") from exc


@router.get("/runs")
async def runs(limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0, le=MAX_HISTORY_OFFSET), db: Session = Depends(get_db)) -> list[dict]:
    try:
        return [serialize(row) for row in recent(db, limit, offset)]
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Simulation storage is unavailable") from exc


@router.get("/stats")
async def stats(db: Session = Depends(get_db)) -> dict:
    try:
        return statistics(db)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Simulation storage is unavailable") from exc


@router.get("/runs/{execution_id}")
async def run_detail(execution_id: str, db: Session = Depends(get_db)) -> dict:
    try:
        row = get_execution(db, execution_id)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Simulation storage is unavailable") from exc
    if row is None:
        raise HTTPException(status_code=404, detail="Simulation execution not found")
    return serialize(row)
