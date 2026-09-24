"""DetectorRegistry — the single place detectors are registered and looked
up by the API layer and the aggregator. Adding a detector means adding one
line here, not touching the API or other detectors (docs/architecture.md §1).
"""

from __future__ import annotations

from app.detectors.base import BaseDetector
from app.events.schema import SecurityEvent


class DetectorRegistry:
    def __init__(self) -> None:
        self._detectors: dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        if detector.name in self._detectors:
            raise ValueError(f"Detector already registered: {detector.name}")
        self._detectors[detector.name] = detector

    def clear(self) -> None:
        self._detectors.clear()

    def get(self, name: str) -> BaseDetector | None:
        return self._detectors.get(name)

    def all(self) -> list[BaseDetector]:
        return list(self._detectors.values())

    def applicable_to(self, event: SecurityEvent) -> list[BaseDetector]:
        return [d for d in self._detectors.values() if d.applies_to(event)]


# Process-wide singleton, populated at app startup (app.main).
registry = DetectorRegistry()
