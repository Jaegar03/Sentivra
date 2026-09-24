"""GET /api/v1/rules — inventory of the detection rule packs actually loaded,
including Sigma rules the engine couldn't support and why."""

from __future__ import annotations

import yaml
from fastapi import APIRouter, Depends

from app.api.deps import get_detector_registry
from app.core.config import get_settings
from app.core.rules import attack_index, load_yaml, rules_path
from app.detectors.registry import DetectorRegistry
from app.security.auth import require_scopes

router = APIRouter(prefix="/api/v1", tags=["rules"], dependencies=[Depends(require_scopes("read"))])

_CUSTOM_PACKS = {
    "network_rules.yaml": "NetworkAnomalyDetector",
    "endpoint_rules.yaml": "BehavioralAnomalyDetector",
    "auth_rules.yaml": "LogDetector",
    "sql_injection.yaml": "SQLInjectionDetector (not wired yet)",
}


@router.get("/rules")
async def list_rules(registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    settings = get_settings()
    sigma = registry.get("SigmaDetector")
    yara_dir = settings.yara_rules_dir
    custom = []
    for filename, used_by in _CUSTOM_PACKS.items():
        path = rules_path("custom", filename)
        if not path.exists():
            continue
        item = {"file": f"detection-rules/custom/{filename}", "used_by": used_by}
        try:
            rules = (load_yaml(path) or {}).get("rules", {})
            item["rules"] = sorted(rules) if isinstance(rules, dict) else [r.get("id") for r in rules]
        except yaml.YAMLError as exc:
            # A broken pack is reported, not allowed to take the inventory down.
            item["error"] = f"invalid YAML: {exc}"
        custom.append(item)
    index = attack_index()
    return {
        "yara": {"files": sorted(p.name for p in yara_dir.glob("*.yar*")) if yara_dir.exists() else []},
        "sigma": {
            "loaded": [{"id": r.id, "title": r.title, "level": r.level, "status": r.status, "path": r.path,
                        "logsource": r.logsource, "tags": r.tags} for r in sigma.report.loaded] if sigma else [],
            "unsupported": sigma.report.unsupported if sigma else [],
        },
        "custom": custom,
        "attack_index": {"attack_version": index.get("attack_version"),
                         "techniques": len(index.get("techniques", {}))},
    }
