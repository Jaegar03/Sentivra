"""ModelRegistry — reflects whatever is actually in models/, honestly.

Each model directory under models/<domain>/<name>/ is expected to contain
`metadata.json` (version, training dataset, SHA-256, threshold, eval
metrics, eval date — brief §20) alongside its artifact file. A domain/name
directory with no metadata.json is not a model yet — it is reported as
`trained: false`, never silently skipped and never faked as available.

GET /api/v1/models reflects this registry directly.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.config import get_settings


class ModelMetadata(BaseModel):
    name: str
    domain: str
    version: str
    artifact_filename: str
    sha256: str
    training_dataset: str
    evaluation_metrics: dict[str, float] = Field(default_factory=dict)
    evaluation_date: date | None = None
    threshold: float | None = None
    feature_schema_ref: str | None = None
    notes: str | None = None


class ModelEntry(BaseModel):
    domain: str
    name: str
    trained: bool
    path: str
    metadata: ModelMetadata | None = None
    reason_untrained: str | None = None


class ModelRegistry:
    def __init__(self, models_dir: Path | None = None) -> None:
        self._models_dir = models_dir or get_settings().models_dir

    def discover(self) -> list[ModelEntry]:
        entries: list[ModelEntry] = []
        if not self._models_dir.exists():
            return entries

        for domain_dir in sorted(p for p in self._models_dir.iterdir() if p.is_dir()):
            for model_dir in sorted(p for p in domain_dir.iterdir() if p.is_dir()):
                entries.append(self._inspect(domain_dir.name, model_dir))
        return entries

    def _inspect(self, domain: str, model_dir: Path) -> ModelEntry:
        metadata_path = model_dir / "metadata.json"
        if not metadata_path.exists():
            return ModelEntry(
                domain=domain,
                name=model_dir.name,
                trained=False,
                path=str(model_dir),
                reason_untrained=(
                    "No metadata.json — model has not been trained/registered yet. "
                    "This is expected in the current demonstration build; see "
                    "docs/model-card.md for training status per model."
                ),
            )
        try:
            raw = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata = ModelMetadata(**raw)
        except Exception as exc:  # noqa: BLE001 — surfaced to the operator, not swallowed
            return ModelEntry(
                domain=domain,
                name=model_dir.name,
                trained=False,
                path=str(model_dir),
                reason_untrained=f"metadata.json present but invalid: {exc}",
            )
        return ModelEntry(
            domain=domain,
            name=model_dir.name,
            trained=True,
            path=str(model_dir),
            metadata=metadata,
        )


registry = ModelRegistry()
