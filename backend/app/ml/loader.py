"""ModelLoader — the ONLY code path allowed to deserialize a model artifact.

Trust boundary (docs/threat-model.md, Boundary C):
  * Every load is preceded by a SHA-256 check against the hash pinned in
    that model's own metadata.json. Mismatch => refuse to load.
  * Only paths inside the registry's models directory are ever loaded,
    never an uploaded file, a URL, or any user-writable runtime path.
  * The formats Sentivra's own models use can't execute code on load:
    `linear_text_npz` is read with numpy's allow_pickle=False, and
    `lightgbm_text` is LightGBM's plain-text tree dump. `joblib` is
    supported for completeness but no committed model uses it. Like pickle
    it runs code on load, so it is only acceptable for artifacts produced
    and committed by this repo's own training scripts (brief §21).
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any

from app.ml.registry import ModelEntry, ModelRegistry
from app.ml.registry import registry as default_registry


class ModelIntegrityError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ModelLoader:
    def __init__(self, registry: ModelRegistry | None = None) -> None:
        self._registry = registry or default_registry
        self._cache: dict[str, Any] = {}
        self._lock = threading.Lock()

    def load(self, entry: ModelEntry) -> Any:
        if not entry.trained or entry.metadata is None:
            raise ModelIntegrityError(
                f"{entry.domain}/{entry.name} has no trained artifact to load ({entry.reason_untrained})"
            )
        meta = entry.metadata
        cache_key = f"{entry.domain}/{entry.name}@{meta.version}:{meta.sha256}"
        with self._lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

            model_dir = self._registry.resolve(entry).resolve()
            artifact_path = (model_dir / meta.artifact_filename).resolve()
            # artifact_filename comes from metadata.json; make sure it can't
            # point outside the model's own directory ("../../elsewhere").
            if model_dir not in artifact_path.parents:
                raise ModelIntegrityError(f"Artifact path escapes model directory: {meta.artifact_filename}")
            if not artifact_path.is_file():
                raise ModelIntegrityError(f"Artifact file missing: {artifact_path.name}")

            actual = sha256_file(artifact_path)
            if actual != meta.sha256:
                raise ModelIntegrityError(
                    f"SHA-256 mismatch for {entry.domain}/{entry.name}: expected {meta.sha256}, "
                    f"got {actual}. Refusing to load."
                )

            model = self._deserialize(meta.artifact_format, artifact_path, meta.preprocessing)
            self._cache[cache_key] = model
            return model

    @staticmethod
    def _deserialize(fmt: str, path: Path, preprocessing: dict) -> Any:
        if fmt == "linear_text_npz":
            from app.ml.text_model import LinearTextModel, VectorizerSpec

            specs = [VectorizerSpec(**s) for s in preprocessing["vectorizers"]]
            return LinearTextModel.load(path, specs)
        if fmt == "lightgbm_text":
            import lightgbm as lgb

            return lgb.Booster(model_file=str(path))
        if fmt == "onnx":
            import onnxruntime as ort

            return ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        if fmt == "json_baseline":
            import json

            return json.loads(path.read_text(encoding="utf-8"))
        if fmt == "joblib":
            import joblib

            return joblib.load(path)
        raise ModelIntegrityError(f"Unsupported artifact format: {fmt}")


loader = ModelLoader()
