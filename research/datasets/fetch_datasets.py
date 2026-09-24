"""Download the public datasets used to train and evaluate SENTIVRA's Phase 4
models into research/datasets/raw/ (gitignored).

Nothing in the backend downloads data at runtime. This script runs only when
an operator runs it, and it writes a manifest (raw/MANIFEST.json) with the
source URL, license, retrieval date and SHA-256 of every file, so a trained
model's metadata.json can point to exactly the bytes it was trained on.

    python research/datasets/fetch_datasets.py            # everything
    python research/datasets/fetch_datasets.py deepset    # one source

Sources (licenses verified 2026-09-24):
  * PhiUSIIL Phishing URL Dataset, UCI ML Repository #967       CC BY 4.0
  * deepset/prompt-injections, Hugging Face                     Apache-2.0
  * SecLists Fuzzing/Databases/SQLi payload lists (Miessler)    MIT
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

RAW_DIR = Path(__file__).resolve().parent / "raw"
MANIFEST = RAW_DIR / "MANIFEST.json"

PHIUSIIL_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
DEEPSET_ROWS_URL = "https://datasets-server.huggingface.co/rows"
SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/"
SECLISTS_FILES = (
    "Generic-SQLi.txt",
    "Generic-BlindSQLi.fuzzdb.txt",
    "MySQL.fuzzdb.txt",
    "MSSQL.fuzzdb.txt",
    "Oracle.fuzzdb.txt",
    "MySQL-SQLi-Login-Bypass.fuzzdb.txt",
    "SQLi-Polyglots.txt",
    "quick-SQLi.txt",
    "sqli.auth.bypass.txt",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest() -> dict:
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {}


def _record(manifest: dict, key: str, path: Path, *, source: str, license_: str) -> None:
    manifest[key] = {
        "path": str(path.relative_to(RAW_DIR)),
        "source": source,
        "license": license_,
        "retrieved_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sha256": _sha256(path),
        "size_bytes": path.stat().st_size,
    }


def fetch_phiusiil(client: httpx.Client, manifest: dict) -> None:
    target_dir = RAW_DIR / "phiusiil"
    target_dir.mkdir(parents=True, exist_ok=True)
    zip_path = target_dir / "phiusiil.zip"
    print(f"[phiusiil] downloading {PHIUSIIL_URL}")
    with client.stream("GET", PHIUSIIL_URL) as resp:
        resp.raise_for_status()
        with zip_path.open("wb") as f:
            for chunk in resp.iter_bytes():
                f.write(chunk)
    with zipfile.ZipFile(zip_path) as zf:
        # Only extract the CSV, and never trust member paths (zip-slip):
        # write each member to a flat filename under target_dir.
        for info in zf.infolist():
            if info.filename.lower().endswith(".csv"):
                out = target_dir / Path(info.filename).name
                out.write_bytes(zf.read(info))
                _record(manifest, "phiusiil_csv", out, source=PHIUSIIL_URL, license_="CC BY 4.0")
                print(f"[phiusiil] extracted {out.name} ({out.stat().st_size:,} bytes)")


def fetch_deepset(client: httpx.Client, manifest: dict) -> None:
    target_dir = RAW_DIR / "deepset_prompt_injections"
    target_dir.mkdir(parents=True, exist_ok=True)
    for split in ("train", "test"):
        rows: list[dict] = []
        offset = 0
        while True:
            resp = client.get(
                DEEPSET_ROWS_URL,
                params={
                    "dataset": "deepset/prompt-injections",
                    "config": "default",
                    "split": split,
                    "offset": offset,
                    "length": 100,
                },
            )
            resp.raise_for_status()
            page = resp.json()
            batch = [r["row"] for r in page.get("rows", [])]
            rows.extend(batch)
            offset += len(batch)
            if not batch or offset >= page.get("num_rows_total", 0):
                break
        out = target_dir / f"{split}.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps({"text": row["text"], "label": int(row["label"])}, ensure_ascii=False) + "\n")
        _record(
            manifest,
            f"deepset_{split}",
            out,
            source="https://huggingface.co/datasets/deepset/prompt-injections",
            license_="Apache-2.0",
        )
        print(f"[deepset] {split}: {len(rows)} rows")


def fetch_seclists(client: httpx.Client, manifest: dict) -> None:
    target_dir = RAW_DIR / "seclists_sqli"
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in SECLISTS_FILES:
        url = SECLISTS_BASE + name
        resp = client.get(url)
        resp.raise_for_status()
        out = target_dir / name
        out.write_bytes(resp.content)
        _record(manifest, f"seclists_{name}", out, source=url, license_="MIT")
        print(f"[seclists] {name}: {len(resp.content.splitlines())} lines")


SOURCES = {"phiusiil": fetch_phiusiil, "deepset": fetch_deepset, "seclists": fetch_seclists}


def main(argv: list[str]) -> int:
    wanted = argv or list(SOURCES)
    unknown = [w for w in wanted if w not in SOURCES]
    if unknown:
        print(f"Unknown source(s): {unknown}. Choose from {list(SOURCES)}")
        return 2
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    manifest = _load_manifest()
    with httpx.Client(timeout=120.0, follow_redirects=True) as client:
        for name in wanted:
            SOURCES[name](client, manifest)
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Manifest written to {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
