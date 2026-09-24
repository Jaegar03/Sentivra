"""Shared helpers for training scripts: writing model artifacts and
metadata into models/, and evaluation reports into research/evaluation/.

Every script imports feature code from the backend package (`app`), so the
features a model is trained on are computed by exactly the code that serves
it.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = REPO_ROOT / "models"
EVAL_DIR = REPO_ROOT / "research" / "evaluation"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def environment() -> dict[str, str]:
    import numpy
    import sklearn

    info = {"python": sys.version.split()[0], "platform": platform.platform(),
            "numpy": numpy.__version__, "scikit-learn": sklearn.__version__}
    try:
        import lightgbm

        info["lightgbm"] = lightgbm.__version__
    except ImportError:
        pass
    return info


def write_model(domain: str, name: str, artifact_path: Path, metadata: dict[str, Any]) -> Path:
    """Pin the artifact's SHA-256 into metadata.json next to it."""
    model_dir = MODELS_DIR / domain / name
    assert artifact_path.parent == model_dir, "artifact must already be inside its model directory"
    metadata = {
        **metadata,
        "domain": domain,
        "name": name,
        "artifact_filename": artifact_path.name,
        "sha256": sha256_file(artifact_path),
        "evaluation_date": datetime.now(UTC).date().isoformat(),
    }
    (model_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return model_dir / "metadata.json"


def write_report(subdir: str, report: dict[str, Any]) -> Path:
    out_dir = EVAL_DIR / subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path
