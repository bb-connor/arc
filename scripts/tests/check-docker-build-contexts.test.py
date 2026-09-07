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
RUN --mount=type=cache,target=/build/target \\
    cargo build --release --locked -p chio-api-protect --bin chio-api-protect \\
 && cargo build --release --locked --package=chio-tee
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
    assert stages[0].packages == ("chio-api-protect", "chio-tee"), stages[0].packages
    assert stages[1].manifest_dir == "deploy/docker/chio-workspace"
    assert stages[1].copied == ["third_party/vendored"]
    assert stages[1].packages == ()


def test_cfg_expressions_follow_an_image_build(checker: ModuleType) -> None:
    assert checker.cfg_holds("unix")
    assert checker.cfg_holds('target_os = "linux"')
    assert checker.cfg_holds('feature = "component"')
    assert checker.cfg_holds("not(windows)")
    assert checker.cfg_holds('any(test, feature = "component")')
    assert not checker.cfg_holds("test")
    assert not checker.cfg_holds("all(test, unix)")
    assert not checker.cfg_holds('target_os = "macos"')
    assert not checker.cfg_holds("any(test, windows)")


def test_embedded_files_skip_sources_an_image_build_never_compiles(checker: ModuleType, scratch: Path) -> None:
    package = scratch / "crates" / "app"
    (package / "src" / "nested").mkdir(parents=True)
    (package / "fixtures").mkdir()
    (package / "src" / "lib.rs").write_text(
        "mod handlers;\n"
        "#[cfg(test)]\n"
        "#[allow(clippy::unwrap_used)]\n"
        "mod tests;\n"
        "#[cfg(all(test, unix))]\n"
        "#[path = \"e2e_support.rs\"]\n"
        "mod e2e;\n"
        "mod nested;\n"
        "pub const MANIFEST: &str = include_str!(\"../../../shared/manifest.json\");\n"
        "#[cfg(test)]\n"
        "mod inline_tests {\n"
        "    const EXAMPLE: &str = include_str!(\"../../../docs/inline-example.json\");\n"
        "}\n",
        encoding="utf-8",
    )
    (package / "src" / "handlers.rs").write_text(
        "pub const SCHEMA: &[u8] = include_bytes!(\n    \"../../../spec/schema.json\"\n);\n"
        "pub const LOCAL: &str = include_str!(\"../fixtures/local.json\");\n",
        encoding="utf-8",
    )
    (package / "src" / "tests.rs").write_text(
        "const EXAMPLE: &str = include_str!(\"../../../docs/example.json\");\n", encoding="utf-8"
    )
    (package / "src" / "e2e_support.rs").write_text(
        "const OTHER: &str = include_str!(\"../../../docs/other.json\");\n", encoding="utf-8"
    )
    (package / "src" / "nested" / "mod.rs").write_text("#[cfg(test)]\nmod cases;\n", encoding="utf-8")
    (package / "src" / "nested" / "cases.rs").write_text(
        "const CASES: &str = include_str!(\"../../../../docs/cases.json\");\n", encoding="utf-8"
    )
    files = checker.embedded_files(package, "app", (scratch,))
    assert files == {
        "shared/manifest.json": "app crates/app/src/lib.rs",
        "spec/schema.json": "app crates/app/src/handlers.rs",
    }, files


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


def test_missing_entries_respect_ancestor_copies(checker: ModuleType) -> None:
    required = {"crates/app": "app", "third_party/vendored": "vendored"}
    assert checker.missing_entries(required, ["crates"]) == [("third_party/vendored", "vendored")]
    assert checker.missing_entries(required, ["crates", "third_party"]) == []
    assert checker.missing_entries(required, ["crates/app", "third_party/vendored"]) == []
    assert checker.missing_entries(required, ["crates", "third_party/vendored-other"]) == [
        ("third_party/vendored", "vendored")
    ]
    embedded = {"formal/tla/model.tla": "validator crates/validator/src/lib.rs"}
    assert checker.missing_entries(embedded, ["formal/tla"]) == []
    assert checker.missing_entries(embedded, ["formal/tla/model.tla"]) == []
    assert checker.missing_entries(embedded, ["formal/tlaplus"]) == list(embedded.items())


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


def test_missing_embedded_sources_fail(scratch: Path) -> None:
    cli_stage = scratch / "Dockerfile.cli"
    cli_stage.write_text(
        "FROM rust:1 AS builder\n"
        "COPY deploy/docker/chio-workspace/Cargo.toml ./Cargo.toml\n"
        "COPY .cargo ./.cargo\n"
        "COPY crates ./crates\n"
        "COPY third_party ./third_party\n"
        "COPY examples ./examples\n"
        "COPY fixtures ./fixtures\n"
        "COPY spec ./spec\n"
        "COPY wit ./wit\n"
        "RUN cargo build --locked -p chio-cli --bin chio\n",
        encoding="utf-8",
    )
    result = run_checker("--dockerfile", str(cli_stage))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "build context lacks formal/tla/RevocationPropagation.tla (embedded by chio-trace-validate" in result.stdout, (
        result.stdout
    )

    tee_stage = scratch / "Dockerfile.tee"
    tee_stage.write_text(
        cli_stage.read_text(encoding="utf-8")
        .replace("COPY deploy/docker/chio-workspace/Cargo.toml ./Cargo.toml", "COPY Cargo.toml Cargo.lock ./")
        .replace("-p chio-cli --bin chio", "--package chio-tee --bin chio-tee")
        + "COPY bench ./bench\nCOPY formal ./formal\nCOPY integrations ./integrations\n"
        "COPY tests ./tests\nCOPY xtask ./xtask\nCOPY sdks ./sdks\nCOPY contracts ./contracts\n",
        encoding="utf-8",
    )
    result = run_checker("--dockerfile", str(tee_stage))
    assert "embedded by" not in result.stdout, result.stdout


def main() -> int:
    checker = load_checker()
    test_parses_manifest_copying_stages(checker)
    test_cfg_expressions_follow_an_image_build(checker)
    test_collects_reachable_path_packages_only(checker)
    test_missing_entries_respect_ancestor_copies(checker)
    test_tracked_dockerfiles_cover_their_workspaces()
    with tempfile.TemporaryDirectory(prefix="chio-docker-context-test.") as scratch:
        test_embedded_files_skip_sources_an_image_build_never_compiles(checker, Path(scratch))
        test_missing_vendored_members_fail(Path(scratch))
        test_missing_embedded_sources_fail(Path(scratch))
    print("check-docker-build-contexts self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
