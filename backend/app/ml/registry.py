"""ModelRegistry — reflects whatever is actually in models/, honestly.

Each model directory under models/<domain>/<name>/ is expected to contain
`metadata.json` (version, datasets, splits, preprocessing, feature schema,
threshold, calibration, evaluation metrics, evaluation date, SHA-256 —
brief §20) alongside its artifact file. A directory with no metadata.json
is not a model yet. It is reported as `trained: false`, never silently
skipped and never faked as available.

GET /api/v1/models reflects this registry directly.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.core.config import get_settings

ArtifactFormat = Literal["linear_text_npz", "lightgbm_text", "onnx", "joblib"]


class DatasetRef(BaseModel):
    name: str
    role: str                      # "train/calibration/test", "ood_eval", ...
    license: str
    source: str
    sha256: str | None = None
    notes: str | None = None


class ModelMetadata(BaseModel):
    name: str
    domain: str
    version: str
    artifact_filename: str
    artifact_format: ArtifactFormat
    sha256: str
    training_dataset: str                         # one-line summary for UIs
    datasets: list[DatasetRef] = Field(default_factory=list)
    splits: dict[str, int] = Field(default_factory=dict)
    split_method: str | None = None
    preprocessing: dict[str, Any] = Field(default_factory=dict)
    feature_schema: list[str] | None = None
    threshold: float | None = None
    threshold_policy: str | None = None
    calibration: dict[str, Any] | None = None
    evaluation_metrics: dict[str, float] = Field(default_factory=dict)  # headline, test split
    evaluation: dict[str, Any] = Field(default_factory=dict)            # full report
    evaluation_date: date | None = None
    limitations: list[str] = Field(default_factory=list)
    notes: str | None = None


class ModelEntry(BaseModel):
    domain: str
    name: str
    trained: bool
    directory: str                 # relative to the repo, e.g. "models/phishing/url_model"
    metadata: ModelMetadata | None = None
    reason_untrained: str | None = None


class ModelRegistry:
    def __init__(self, models_dir: Path | None = None) -> None:
        self._models_dir = models_dir or get_settings().models_dir

    @property
    def models_dir(self) -> Path:
        return self._models_dir

    def discover(self) -> list[ModelEntry]:
        entries: list[ModelEntry] = []
        if not self._models_dir.exists():
            return entries
        for domain_dir in sorted(p for p in self._models_dir.iterdir() if p.is_dir()):
            for model_dir in sorted(p for p in domain_dir.iterdir() if p.is_dir()):
                entries.append(self._inspect(domain_dir.name, model_dir))
        return entries

    def get(self, domain: str, name: str) -> ModelEntry | None:
        model_dir = self._models_dir / domain / name
        if not model_dir.is_dir():
            return None
        return self._inspect(domain, model_dir)

    def resolve(self, entry: ModelEntry) -> Path:
        return self._models_dir / entry.domain / entry.name

    def _inspect(self, domain: str, model_dir: Path) -> ModelEntry:
        directory = f"{self._models_dir.name}/{domain}/{model_dir.name}"
        metadata_path = model_dir / "metadata.json"
        if not metadata_path.exists():
            return ModelEntry(
                domain=domain,
                name=model_dir.name,
                trained=False,
                directory=directory,
                reason_untrained=(
                    "No metadata.json — this model has not been trained yet. "
                    "See docs/model-card.md for the status of each model."
                ),
            )
        try:
            metadata = ModelMetadata(**json.loads(metadata_path.read_text(encoding="utf-8")))
        except Exception as exc:  # noqa: BLE001 — shown to the operator, not swallowed
            return ModelEntry(
                domain=domain,
                name=model_dir.name,
                trained=False,
                directory=directory,
                reason_untrained=f"metadata.json present but invalid: {exc}",
            )
        return ModelEntry(domain=domain, name=model_dir.name, trained=True, directory=directory, metadata=metadata)


registry = ModelRegistry()
