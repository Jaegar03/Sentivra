"""Shared FastAPI dependencies."""

from __future__ import annotations

from app.core.database import get_db  # re-exported for router convenience
from app.detectors.registry import registry as detector_registry


def get_detector_registry():
    return detector_registry


__all__ = ["get_db", "get_detector_registry"]
