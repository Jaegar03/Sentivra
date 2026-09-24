"""ModelLoader trust boundary (docs/threat-model.md, Boundary C): refuses
tampered artifacts, paths that escape the model directory, and untrained
entries."""

from __future__ import annotations

import json
import shutil

import pytest

from app.core.config import REPO_ROOT
from app.ml.loader import ModelIntegrityError, ModelLoader
from app.ml.registry import ModelRegistry


@pytest.fixture()
def model_copy(tmp_path):
    """A private copy of models/network/autoencoder that tests can tamper with."""
    dst = tmp_path / "models" / "network" / "autoencoder"
    shutil.copytree(REPO_ROOT / "models" / "network" / "autoencoder", dst)
    registry = ModelRegistry(tmp_path / "models")
    return registry, ModelLoader(registry), dst


def test_intact_model_loads(model_copy):
    registry, loader, _ = model_copy
    assert loader.load(registry.get("network", "autoencoder")) is not None


def test_tampered_artifact_is_refused(model_copy):
    registry, loader, model_dir = model_copy
    with (model_dir / "model.onnx").open("ab") as f:
        f.write(b"\x00")
    with pytest.raises(ModelIntegrityError, match="SHA-256 mismatch"):
        loader.load(registry.get("network", "autoencoder"))


def test_artifact_path_cannot_escape_model_directory(model_copy):
    registry, loader, model_dir = model_copy
    meta_path = model_dir / "metadata.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["artifact_filename"] = "../../../outside.onnx"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(ModelIntegrityError, match="escapes"):
        loader.load(registry.get("network", "autoencoder"))


def test_untrained_entry_is_refused(tmp_path):
    (tmp_path / "models" / "phishing" / "url_model").mkdir(parents=True)
    registry = ModelRegistry(tmp_path / "models")
    entry = registry.get("phishing", "url_model")
    assert entry.trained is False
    with pytest.raises(ModelIntegrityError):
        ModelLoader(registry).load(entry)


def test_registry_reports_repo_relative_paths_only():
    for entry in ModelRegistry().discover():
        assert not entry.directory.startswith(("/", "\\")) and ":" not in entry.directory
