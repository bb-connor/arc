#!/usr/bin/env python3
"""Self-test for scripts/check-docker-build-contexts.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SCRIPTS_DIR.parent
SCRIPT = SCRIPTS_DIR / "check-docker-build-contexts.py"


def load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_docker_build_contexts", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parses_manifest_copying_stages(checker: ModuleType) -> None:
    text = """FROM rust:1 AS builder
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY --chown=app:app fixtures/data ./fixtures/data
COPY examples/one/file.json ./examples/one/file.json
COPY --from=other /out/bin ./bin
FROM alpine AS runtime
COPY --from=builder /chio /usr/local/bin/chio
FROM --platform=linux/amd64 rust:1 AS product
COPY deploy/docker/chio-workspace/Cargo.toml ./Cargo.toml
COPY third_party/vendored ./third_party/vendored
"""
    stages = checker.parse_stages(text, Path("Dockerfile"))
    assert [stage.name for stage in stages] == ["builder", "product"], stages
    assert stages[0].manifest_dir == ""
    assert stages[0].copied == ["crates", "fixtures/data", "examples/one/file.json"]
    assert stages[1].manifest_dir == "deploy/docker/chio-workspace"
    assert stages[1].copied == ["third_party/vendored"]


def test_collects_reachable_path_packages_only(checker: ModuleType) -> None:
    root = Path("/repo")
    metadata = {
        "packages": [
            {"id": "app", "name": "app", "source": None, "manifest_path": "/repo/crates/app/Cargo.toml"},
            {
                "id": "vendored",
                "name": "vendored",
                "source": None,
                "manifest_path": "/repo/third_party/vendored/Cargo.toml",
            },
            {"id": "unused", "name": "unused", "source": None, "manifest_path": "/repo/crates/unused/Cargo.toml"},
            {
                "id": "serde",
                "name": "serde",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "manifest_path": "/registry/serde/Cargo.toml",
            },
        ],
        "resolve": {
            "nodes": [
                {"id": "app", "deps": [{"pkg": "serde"}]},
                {"id": "serde", "deps": [{"pkg": "vendored"}]},
                {"id": "vendored", "deps": []},
                {"id": "unused", "deps": []},
            ]
        },
        "workspace_members": ["app"],
    }
    required = checker.reachable_path_packages(metadata, (root,), ["app"])
    assert required == {"crates/app": "app", "third_party/vendored": "vendored"}, required


def test_missing_directories_respects_ancestor_copies(checker: ModuleType) -> None:
    required = {"crates/app": "app", "third_party/vendored": "vendored"}
    assert checker.missing_directories(required, ["crates"]) == [("third_party/vendored", "vendored")]
    assert checker.missing_directories(required, ["crates", "third_party"]) == []
    assert checker.missing_directories(required, ["crates/app", "third_party/vendored"]) == []
    assert checker.missing_directories(required, ["crates", "third_party/vendored-other"]) == [
        ("third_party/vendored", "vendored")
    ]


def run_checker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(REPO_ROOT), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def test_tracked_dockerfiles_cover_their_workspaces() -> None:
    result = run_checker()
    assert result.returncode == 0, result.stdout + result.stderr


def test_missing_vendored_members_fail(scratch: Path) -> None:
    root_stage = scratch / "Dockerfile.root"
    root_stage.write_text(
        "FROM rust:1 AS builder\nCOPY Cargo.toml Cargo.lock ./\nCOPY crates ./crates\nRUN cargo build\n",
        encoding="utf-8",
    )
    result = run_checker("--dockerfile", str(root_stage))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "build context lacks third_party/" in result.stdout, result.stdout

    product_stage = scratch / "Dockerfile.product"
    product_stage.write_text(
        "FROM rust:1 AS builder\n"
        "COPY deploy/docker/chio-workspace/Cargo.toml ./Cargo.toml\n"
        "COPY crates ./crates\n"
        "RUN cargo build\n",
        encoding="utf-8",
    )
    result = run_checker("--dockerfile", str(product_stage))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "build context lacks third_party/" in result.stdout, result.stdout


def main() -> int:
    checker = load_checker()
    test_parses_manifest_copying_stages(checker)
    test_collects_reachable_path_packages_only(checker)
    test_missing_directories_respects_ancestor_copies(checker)
    test_tracked_dockerfiles_cover_their_workspaces()
    with tempfile.TemporaryDirectory(prefix="chio-docker-context-test.") as scratch:
        test_missing_vendored_members_fail(Path(scratch))
    print("check-docker-build-contexts self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
