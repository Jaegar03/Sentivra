"""BaseDetector — the one interface every detector implements (brief §17).

A detector that cannot run (engine not installed, model not loaded) must
say so via `is_available()` rather than silently returning a clean result.
`GET /api/v1/detectors` reflects `is_available()` verbatim — it is not a
hardcoded status list (brief §32).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum

from pydantic import BaseModel

from app.events.schema import SecurityEvent, SecurityEventType
from app.schemas.detection import DetectionResult, DetectorCategory


class AvailabilityStatus(StrEnum):
    AVAILABLE = "Available"
    NOT_CONFIGURED = "Not Configured"
    DEGRADED = "Degraded"
    ERROR = "Error"


class DetectorAvailability(BaseModel):
    status: AvailabilityStatus
    detail: str
    engine_version: str | None = None


class BaseDetector(ABC):
    name: str
    version: str
    category: DetectorCategory
    applicable_event_types: frozenset[SecurityEventType]

    def applies_to(self, event: SecurityEvent) -> bool:
        return event.event_type in self.applicable_event_types

    @abstractmethod
    async def is_available(self) -> DetectorAvailability:
        """Must be cheap enough to call on every /detectors request."""

    @abstractmethod
    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        """Analyze one event. Callers should check `applies_to()` first;
        implementations may still return a SAFE result for a non-matching
        event type rather than raising, to keep the aggregator simple."""
