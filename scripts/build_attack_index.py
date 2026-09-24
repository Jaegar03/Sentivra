"""Build detection-rules/custom/attack_index.json from MITRE's official
ATT&CK Enterprise STIX bundle.

    python scripts/build_attack_index.py [path/to/enterprise-attack.json]

With no path, the bundle is downloaded from the mitre-attack/attack-stix-data
repository. The index holds, per technique ID: name, tactics, and, for
revoked techniques, the replacement ID from ATT&CK's own revoked-by
relationships. Detectors use it to validate mappings and to remap revoked
IDs found in third-party rules (for example Sigma tags that still say
T1070.001, which ATT&CK v19 replaced with T1685.005).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "detection-rules" / "custom" / "attack_index.json"
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# Required by the ATT&CK Terms of Use for any reproduction of ATT&CK content.
NOTICE = (
    "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of "
    "The MITRE Corporation. MITRE hereby grants you a non-exclusive, royalty-free license to use "
    "ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes "
    "is authorized provided that you reproduce MITRE's copyright designation and this license in any "
    "such copy. https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
)


def _external_id(obj: dict) -> str | None:
    return next(
        (r["external_id"] for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
        None,
    )


def main(argv: list[str]) -> int:
    if argv:
        bundle = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    else:
        resp = httpx.get(STIX_URL, timeout=120.0, follow_redirects=True)
        resp.raise_for_status()
        bundle = resp.json()

    objects = bundle["objects"]
    by_stix_id = {o["id"]: o for o in objects}
    collection = next((o for o in objects if o.get("type") == "x-mitre-collection"), {})
    tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objects if o.get("type") == "x-mitre-tactic"}

    revoked_by: dict[str, str] = {}
    for rel in objects:
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "revoked-by":
            src = _external_id(by_stix_id.get(rel["source_ref"], {}))
            dst = _external_id(by_stix_id.get(rel["target_ref"], {}))
            if src and dst:
                revoked_by[src] = dst

    techniques: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        tid = _external_id(obj)
        if not tid:
            continue
        entry = {
            "name": obj["name"],
            "tactics": [tactic_names.get(p["phase_name"], p["phase_name"]) for p in obj.get("kill_chain_phases", [])],
        }
        if obj.get("revoked"):
            entry["revoked_by"] = revoked_by.get(tid)
        if obj.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        techniques[tid] = entry

    # Sub-technique names in STIX omit the parent ("Scheduled Task"); the
    # ATT&CK website shows "Scheduled Task/Job: Scheduled Task". Store the
    # full display name so detections read the way analysts expect.
    for tid, entry in techniques.items():
        if "." in tid and tid.split(".")[0] in techniques:
            entry["name"] = f"{techniques[tid.split('.')[0]]['name']}: {entry['name']}"

    OUT.write_text(
        json.dumps(
            {
                "attack_version": collection.get("x_mitre_version"),
                "source": STIX_URL,
                "notice": NOTICE,
                "techniques": dict(sorted(techniques.items())),
            },
            indent=1,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    active = sum(1 for t in techniques.values() if "revoked_by" not in t and not t.get("deprecated"))
    print(f"ATT&CK v{collection.get('x_mitre_version')}: {len(techniques)} techniques ({active} active) -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
