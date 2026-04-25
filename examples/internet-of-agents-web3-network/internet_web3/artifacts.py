"""Artifact persistence and hashing utilities for the web3 agent scenario."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def now_epoch() -> int:
    return int(time.time())


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_rel(path: Path, repo_root: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"missing {label}: {path}. Run ./scripts/qualify-web3-local.sh first, "
            "or provide the artifact path explicitly."
        )


def tx_hashes_by_id(smoke: Json | None) -> dict[str, str]:
    if not smoke:
        return {}
    return {
        tx["id"]: tx["tx_hash"]
        for tx in smoke.get("transactions", [])
        if isinstance(tx, dict) and tx.get("id") and tx.get("tx_hash")
    }


class ArtifactStore:
    """Writes a reviewable evidence bundle with stable JSON formatting."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def write_json(self, relative_path: str, data: Any) -> Any:
        write_json(self.root / relative_path, data)
        return data

    def copy_json(self, source: Path, relative_path: str) -> Any:
        data = read_json(source)
        return self.write_json(relative_path, data)

    def write_manifest(self) -> None:
        excluded = {"bundle-manifest.json", "run-result.json", "review-result.json"}
        files = sorted(
            path.relative_to(self.root).as_posix()
            for path in self.root.rglob("*")
            if path.is_file() and path.name not in excluded
        )
        self.write_json(
            "bundle-manifest.json",
            {
                "schema": "chio.example.ioa-web3.bundle-manifest.v1",
                "generated_at": now_epoch(),
                "files": files,
                "sha256": {relative: sha256_file(self.root / relative) for relative in files},
            },
        )
