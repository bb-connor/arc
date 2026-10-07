#!/usr/bin/env python3
"""Verify retained P2 source/evidence integrity. Does not rerun implementation tests."""
from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import tomllib
from pathlib import Path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    root = Path.cwd()
    phase = root / "docs/architecture/recoverable-agent-runtime/implementation/p2"
    report = json.loads((phase / "verification.json").read_text())
    inventory_path = phase / report["source"]["inventory"]
    inventory = json.loads(inventory_path.read_text())
    baseline = json.loads((phase / "source-baseline.json").read_text())
    require(sha(inventory_path) == report["source"]["inventory_sha256"], "source inventory drift")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    require(head == report["source_base"] == inventory["source_base"], "source Git base drift")
    for row in inventory["joined_changed_sources"]:
        require(sha(root / row["path"]) == row["sha256"], "source drift: " + row["path"])
    for row in report["phase_documents"] + report["evidence_artifacts"]:
        require(sha(phase / row["path"]) == row["sha256"], "phase artifact drift: " + row["path"])
    for row in report["checks"]:
        if row["required_for_local_phase_acceptance"]:
            require(row["status"] == "passed" and row["exit_code"] == 0, "required gate incomplete")
            require(sha(phase / row["log"]) == row["log_sha256"], "gate evidence drift")
    source = report["source"]
    require(sha(phase / source["p1_verification"]) == source["p1_verification_sha256"]
            == baseline["p1_verification_sha256"], "historical P1 verification drift")
    for archive_name, rows, digest in [
        (source["archive"], inventory["joined_changed_sources"], source["archive_sha256"]),
        (source["p1_baseline_archive"], baseline["p1_sources"], source["p1_baseline_archive_sha256"]),
    ]:
        archive_path = phase / archive_name
        require(sha(archive_path) == digest, "source archive drift")
        with tarfile.open(archive_path, "r:gz") as archive:
            for row in rows:
                content = archive.extractfile(row["path"])
                require(content is not None, "missing archived source")
                require(hashlib.sha256(content.read()).hexdigest() == row["sha256"],
                        "archived source drift: " + row["path"])
    with tarfile.open(phase / source["p1_baseline_archive"], "r:gz") as archive:
        old_lock_file = archive.extractfile("Cargo.lock")
        require(old_lock_file is not None, "missing archived dependency lock")
        old_lock = tomllib.loads(old_lock_file.read().decode())
    new_lock = tomllib.loads((root / "Cargo.lock").read_text())

    def packages(lock: dict) -> dict:
        return {(p["name"], p["version"], p.get("source")): p.get("checksum")
                for p in lock["package"]}

    require(packages(old_lock) == packages(new_lock), "dependency package pins changed")
    coverage = json.loads((phase / report["requirements"]["coverage"]).read_text())
    require(len(report["tasks"]) == 6 and coverage["count"] == len(coverage["requirements"]) == 8,
            "phase task/requirement coverage drift")
    require({r["id"] for r in coverage["requirements"]} == set(report["requirements"]["ids"]),
            "requirement identity drift")
    for row in coverage["requirements"]:
        for entry in row["sources"] + row["acceptance_tests"]:
            require(entry["anchor"] in (root / entry["path"]).read_text(), "coverage anchor drift")
        require(all((phase / name).is_file() for name in row["evidence"]), "missing acceptance evidence")
    require(report["review"]["open_p0_findings"] == report["review"]["open_p1_findings"] == 0,
            "open high-severity phase review finding")
    for name in ["sdks/typescript/node_modules", "sdks/typescript/scripts/node_modules",
                 "sdks/typescript/packages/node-http/node_modules",
                 "sdks/typescript/packages/conformance/node_modules"]:
        require(not (root / name).exists() and not (root / name).is_symlink(),
                "temporary task tooling overlay remains")
    print("PASS P2 package: 6 tasks, 8 obligations, "
          f"{len(inventory['joined_changed_sources'])} joined source hashes, "
          f"{len(baseline['p1_sources'])} retained P1 source hashes; "
          "required gate evidence, archives, coverage and dependency pins intact")


if __name__ == "__main__":
    main()
