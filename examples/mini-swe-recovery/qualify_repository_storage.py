"""Installed repository component: retain a large unchanged tree across small edits."""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import random
import tempfile
import time
from pathlib import Path

from chio_mini_swe.repository_archive import contents, entries, git
from chio_mini_swe.repository_store import Workspace, initialize
from chio_mini_swe.repository_transport import docker


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="chio-repository-storage-"))
    images = json.loads(args.worker_image_file.read_text())
    helper = docker("image", "inspect", images["base"], "--format", "{{.Id}}").decode().strip()
    source = root / "source"
    source.mkdir()
    (source / "payload").mkdir()
    (source / "README").write_text("Repository storage qualification\n")
    generator = random.Random(0)
    expected = {}
    for index in range(24):
        data = generator.randbytes(1024 * 1024)
        name = f"payload/{index:04d}.bin"
        (source / name).write_bytes(data)
        expected[name] = sha(data)
    git("init", "--quiet", cwd=source)
    git("add", "--all", cwd=source)
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@localhost",
        "commit",
        "--quiet",
        "-m",
        "repository storage fixture",
        cwd=source,
    )
    commit = git("rev-parse", "HEAD", cwd=source).decode().strip()
    state = root / "state"
    started = time.monotonic()
    config = initialize(source, commit, images["execution_image"], helper, state, 60)
    assert config["schema"] == "chio.repository.workspace.v2"
    report = {
        "schema": "chio.repository.storage-qualification.v1",
        "private_state": str(root),
        "source_commit": commit,
        "host": {"system": platform.platform(), "machine": platform.machine()},
        "images": {"execution": images["execution_image"], "helper": helper},
        "payload_bytes": 24 * 1024 * 1024,
        "initialization_seconds": time.monotonic() - started,
        "installed_sources_sha256": {
            name: sha(Path(importlib.util.find_spec("chio_mini_swe." + name).origin).read_bytes())
            for name in (
                "repository_archive",
                "repository_store",
                "repository_snapshots",
                "repository_container",
                "repository_transport",
                "repository_wire",
            )
        },
        "limits": [
            "Repository component only; no kernel, agent, model or receipt qualification",
            "Generated incompressible payloads; no coding-quality conclusion",
            "Single trial; timing is diagnostic, not a broad benchmark",
        ],
        "commands": [],
    }
    history = [config["baseline"]]
    for number in range(1, 17):
        with Workspace(state) as workspace:
            assert workspace.status()["snapshot"] == history[-1]
            started = time.monotonic()
            result = workspace.execute("printf x >> marker.txt")
            elapsed = time.monotonic() - started
            status = workspace.status()
            assert result["returncode"] == 0 and not status["interrupted"]
            assert status["revision"] == number
            data = workspace.snapshot(status["snapshot"])
            files = entries(contents(data))
            assert files["marker.txt"][2] == b"x" * number
            assert {name: sha(files[name][2]) for name in expected} == expected
            assert sha(data) == status["snapshot"]
            charged = workspace.snapshot_store.usage()
            assert len(data) > 40 * 1024 * 1024
            assert charged < 64 * 1024 * 1024
            history.append(status["snapshot"])
            report["commands"].append(
                {
                    "sequence": number,
                    "wall_seconds": elapsed,
                    "snapshot_bytes": len(data),
                    "accounted_storage_bytes": charged,
                    "snapshot_sha256": status["snapshot"],
                }
            )
        (args.output / "progress.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report["commands"][-1]), flush=True)
    with Workspace(state) as workspace:
        for number, key in enumerate(history):
            data = workspace.snapshot(key)
            files = entries(contents(data))
            assert sha(data) == key
            assert {name: sha(files[name][2]) for name in expected} == expected
            if number:
                assert files["marker.txt"][2] == b"x" * number
            else:
                assert "marker.txt" not in files
        for row in workspace.db.execute("SELECT * FROM commands").fetchall():
            assert row["status"] == "completed"
            workspace.containers(row).cleanup()
        report["completed_commands"] = workspace.status()["revision"]
    assert not git("status", "--porcelain", cwd=source).strip()
    report.update(history_verified=True, cleanup_verified=True, source_unchanged=True)
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
