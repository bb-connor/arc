#!/usr/bin/env python3
"""Seal only complete, recomputed, reviewed qualification. No bypass flags."""
import json

from inventory import PHASE, sha
from package_record import build_record


def artifact_paths():
    return sorted((path for path in PHASE.rglob("*") if path.is_file()
                   and path.name != "package-integrity.json" and "__pycache__" not in path.parts),
                  key=lambda path: str(path.relative_to(PHASE)))


def main():
    record = build_record()
    (PHASE / "verification.json").write_text(json.dumps(record, indent=2, allow_nan=False) + "\n")
    artifacts = [{"path": str(path.relative_to(PHASE)), "sha256": sha(path)} for path in artifact_paths()]
    integrity = {"schema": "chio.recovery-p6-package-integrity.v1", "artifacts": artifacts}
    (PHASE / "package-integrity.json").write_text(json.dumps(integrity, indent=2) + "\n")
    print("SEALED P6:", len(record["local_gates"]), "local gates, four complete Linux suites, eight obligations, reviewed source and finite live campaign")


if __name__ == "__main__": main()
