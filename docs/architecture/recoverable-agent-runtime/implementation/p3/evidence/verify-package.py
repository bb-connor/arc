#!/usr/bin/env python3
"""Check retained P3 source and evidence integrity without rerunning tests."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tomllib


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    root = Path.cwd()
    phase = root / "docs/architecture/recoverable-agent-runtime/implementation/p3"
    report = json.loads((phase / "verification.json").read_text())
    inventory_path = phase / report["source"]["inventory"]
    inventory = json.loads(inventory_path.read_text())
    baseline_path = phase / "source-baseline.json"
    baseline = json.loads(baseline_path.read_text())
    require(report["status"] == "implemented_locally_verified_and_reviewed", "phase incomplete")
    require(sha(inventory_path) == report["source"]["inventory_sha256"], "inventory drift")
    require(sha(baseline_path) == report["source"]["baseline_sha256"], "baseline drift")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(head == report["source_base"] == inventory["source_base"] == baseline["source_base"],
            "Git source base drift")
    for row in inventory["joined_changed_sources"]:
        require(sha(root / row["path"]) == row["sha256"], "source drift: " + row["path"])
    changed = subprocess.check_output(["git", "diff", "--name-only", "HEAD", "--"], text=True).splitlines()
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], text=True).splitlines()
    current_paths = {path for path in changed + untracked
                     if (root / path).is_file()
                     and not path.startswith("docs/architecture/recoverable-agent-runtime/implementation/")
                     and "node_modules" not in Path(path).parts}
    require(current_paths == {row["path"] for row in inventory["joined_changed_sources"]},
            "joined source path set drift")
    for row in inventory["build_inputs"]:
        require(sha(root / row["path"]) == row["sha256"], "build input drift")
    require(sha(phase / report["source"]["archive"]) == report["source"]["archive_sha256"],
            "current source archive drift")
    require(sha(phase / baseline["archive"]) == baseline["archive_sha256"], "P2 archive drift")
    for name, rows in [(report["source"]["archive"], inventory["joined_changed_sources"]),
                       (baseline["archive"], baseline["p2_sources"])]:
        with tarfile.open(phase / name, "r:gz") as archive:
            if name == report["source"]["archive"]:
                metadata = archive.extractfile(str(inventory_path.relative_to(root)))
                require(metadata is not None and hashlib.sha256(metadata.read()).hexdigest()
                        == report["source"]["inventory_sha256"], "archived inventory drift")
            archived_rows = rows + (inventory["build_inputs"] if name == report["source"]["archive"] else [])
            for row in archived_rows:
                content = archive.extractfile(row["path"])
                require(content is not None, "archived source absent: " + row["path"])
                require(hashlib.sha256(content.read()).hexdigest() == row["sha256"],
                        "archived source drift: " + row["path"])
    for row in baseline["baseline_phase_documents"]:
        require(sha(root / row["path"]) == row["sha256"], "historical P2 evidence drift")
    for name in ["p1", "p2"]:
        require(sha(phase.parent / name / "verification.json") == baseline[name + "_verification_sha256"],
                "historical phase verification drift")
    for row in report["phase_documents"] + report["evidence_artifacts"]:
        require(sha(phase / row["path"]) == row["sha256"], "phase artifact drift: " + row["path"])

    spec = importlib.util.spec_from_file_location("p3_gates", phase / "evidence/run-gates.py")
    require(spec is not None and spec.loader is not None, "missing gate runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    required = [row for row in report["checks"] if row["required_for_local_phase_acceptance"]]
    require({row["id"] for row in required} == set(module.GATES), "required gate identity drift")
    require(len(required) == len(module.GATES), "duplicate required gate")
    for row in report["checks"]:
        require(sha(phase / row["log"]) == row["log_sha256"], "gate log drift")
        retained = json.loads((phase / "evidence" / (row["id"] + ".result.json")).read_text())
        require(all(retained.get(key) == value for key, value in row.items()
                    if key in retained), "gate command/result drift")
        if row["required_for_local_phase_acceptance"]:
            require(row["status"] == "passed" and row["exit_code"] == 0, "required gate failed")
            command, cwd, _ = module.GATES[row["id"]]
            require(row["actual_command"] == command and row["cwd"] == cwd, "gate command drift")

    with tarfile.open(phase / baseline["archive"], "r:gz") as archive:
        content = archive.extractfile("Cargo.lock")
        require(content is not None, "missing P2 dependency lock")
        old_lock = tomllib.loads(content.read().decode())
    current_lock = tomllib.loads((root / "Cargo.lock").read_text())

    def pins(lock: dict) -> dict:
        return {(row["name"], row["version"], row.get("source")): row.get("checksum")
                for row in lock["package"]}

    require(pins(old_lock) == pins(current_lock), "dependency package pins changed")
    coverage = json.loads((phase / report["requirements"]["coverage"]).read_text())
    architecture = json.loads((root / "docs/architecture/recoverable-agent-runtime/requirements.json").read_text())
    ids = {row["id"] for row in architecture["requirements"] if row["phase"] == "P3"}
    require(len(report["tasks"]) == 7 and coverage["count"] == len(coverage["requirements"]) == 15,
            "task or requirement count drift")
    require({row["id"] for row in coverage["requirements"]} == set(report["requirements"]["ids"]) == ids,
            "requirement identity drift")
    for row in report["tasks"] + coverage["requirements"]:
        require(row["status"] == "implemented_locally_verified_and_reviewed", "unverified task")
    for row in coverage["requirements"]:
        for entry in row["sources"] + row["acceptance_tests"]:
            require(entry["anchor"] in (root / entry["path"]).read_text(), "coverage anchor drift")
        require(all((phase / path).is_file() for path in row["evidence"]), "missing coverage evidence")
    reviewed = {row["path"] for row in report["review"]["reviewed_rust_sources"]}
    require(reviewed == set(inventory["authored_rust_phase_sources"]), "source review coverage drift")
    require(report["review"]["all_handwritten_changes_reviewed"]
            and report["review"]["open_p0_findings"] == report["review"]["open_p1_findings"] == 0,
            "open high-severity review finding")
    for row in report["review"]["reviewed_rust_sources"]:
        require(sha(root / row["path"]) == row["sha256"], "reviewed source drift")
    for path in ["sdks/typescript/node_modules", "sdks/typescript/scripts/node_modules",
                 "sdks/typescript/packages/node-http/node_modules",
                 "sdks/typescript/packages/conformance/node_modules"]:
        require(not (root / path).exists() and not (root / path).is_symlink(), "tool overlay remains")
    print(f"PASS P3: 7 tasks, 15 obligations, {len(required)} required gates, "
          f"{len(reviewed)} authored Rust sources reviewed, "
          f"{len(inventory['joined_changed_sources'])} joined source hashes; "
          "archives, historical evidence, coverage and dependency pins intact")


if __name__ == "__main__":
    main()
