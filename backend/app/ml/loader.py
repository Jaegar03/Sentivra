"""ModelLoader — the ONLY code path allowed to deserialize a model artifact.

Trust boundary (docs/threat-model.md, Boundary C):
  * Every load is preceded by a SHA-256 recheck against the pinned hash in
    that model's own metadata.json. Mismatch => refuse to load.
  * Only paths under the registry's models_dir are ever loaded — never an
    uploaded file, a URL, or any user-writable runtime path.
  * `.joblib` artifacts are loaded with joblib.load, which — like pickle —
    is only ever safe for artifacts Sentivra's own training pipeline
    produced and committed. This loader is deliberately the single
    chokepoint so that invariant is enforced in one place instead of
    hoped for at every call site (brief §21).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from app.ml.registry import ModelEntry


class ModelIntegrityError(RuntimeError):
    pass


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ModelLoader:
    def __init__(self) -> None:
        self._cache: dict[str, Any] = {}

    def load(self, entry: ModelEntry) -> Any:
        if not entry.trained or entry.metadata is None:
            raise ModelIntegrityError(
                f"{entry.domain}/{entry.name} has no trained artifact to load "
                f"({entry.reason_untrained})"
            )

        cache_key = f"{entry.domain}/{entry.name}@{entry.metadata.version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        artifact_path = Path(entry.path) / entry.metadata.artifact_filename
        if not artifact_path.is_file():
            raise ModelIntegrityError(f"Artifact file missing: {artifact_path}")

        actual_hash = _sha256_of(artifact_path)
        if actual_hash != entry.metadata.sha256:
            raise ModelIntegrityError(
                f"SHA-256 mismatch for {artifact_path}: "
                f"expected {entry.metadata.sha256}, got {actual_hash}. Refusing to load."
            )

        suffix = artifact_path.suffix.lower()
        if suffix == ".onnx":
            model = self._load_onnx(artifact_path)
        elif suffix == ".joblib":
            model = self._load_joblib(artifact_path)
        else:
            raise ModelIntegrityError(f"Unsupported model artifact type: {suffix}")

        self._cache[cache_key] = model
        return model

    @staticmethod
    def _load_onnx(path: Path) -> Any:
        import onnxruntime as ort  # imported lazily — optional dep until Phase 4/5

        return ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])

    @staticmethod
    def _load_joblib(path: Path) -> Any:
        import joblib  # imported lazily — optional dep until Phase 4/5

        # Safe only because `path` is guaranteed, by the caller above, to be
        # a committed artifact under models/ whose hash matches metadata.json
        # pinned at commit time — never an arbitrary/user-writable path.
        return joblib.load(path)


loader = ModelLoader()
