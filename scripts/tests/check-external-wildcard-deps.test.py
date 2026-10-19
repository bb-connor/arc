#!/usr/bin/env python3
"""Self-test for scripts/check-external-wildcard-deps.py."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-external-wildcard-deps.py"
HEADER = "External wildcard dependency check failed:"


class ExternalWildcardDepsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-wildcard-deps-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)

    def manifest(self, text: str, rel: str = "crates/demo/Cargo.toml") -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "scripts/check-external-wildcard-deps.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_red(self, text: str, *violations: str) -> None:
        self.manifest(text)
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        lines = result.stderr.strip().splitlines()
        self.assertEqual(lines[0], HEADER)
        self.assertEqual(
            lines[1:],
            [f"- crates/demo/Cargo.toml {violation}" for violation in violations],
        )

    def test_green_pinned_local_and_git_dependencies(self) -> None:
        self.manifest(
            """[package]
name = "demo"

[dependencies]
serde = "1.0"
tokio = { version = "1", features = ["rt"] }
shared = { workspace = true }
local = { path = "../local" }
local-wild = { path = "../local", version = "*" }
forked = { git = "https://example.invalid/forked.git" }

[dev-dependencies]
proptest = "1.4"

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[workspace.dependencies]
anyhow = "1"
"""
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "external wildcard dependency check passed")

    def test_green_skipped_directories_are_ignored(self) -> None:
        for rel in ("target/debug/Cargo.toml", ".planning/Cargo.toml", ".git/Cargo.toml"):
            self.manifest('[dependencies]\nserde = "*"\n', rel)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_red_string_wildcard(self) -> None:
        self.assert_red(
            '[dependencies]\nserde = "*"\n',
            "[dependencies] serde: wildcard registry dependency version '*'",
        )

    def test_red_partial_wildcard(self) -> None:
        self.assert_red(
            '[dependencies]\nserde = "1.*"\n',
            "[dependencies] serde: wildcard registry dependency version '1.*'",
        )

    def test_red_table_wildcard_in_each_dependency_kind(self) -> None:
        self.assert_red(
            '[dependencies]\na = { version = "*" }\n'
            '[dev-dependencies]\nb = { version = "*" }\n'
            '[build-dependencies]\nc = { version = "*" }\n',
            "[dependencies] a: wildcard registry dependency version '*'",
            "[dev-dependencies] b: wildcard registry dependency version '*'",
            "[build-dependencies] c: wildcard registry dependency version '*'",
        )

    def test_red_wildcard_in_target_and_workspace_tables(self) -> None:
        self.assert_red(
            "[target.'cfg(unix)'.dependencies]\nlibc = \"*\"\n[workspace.dependencies]\nanyhow = \"*\"\n",
            "[target.cfg(unix).dependencies] libc: wildcard registry dependency version '*'",
            "[workspace.dependencies] anyhow: wildcard registry dependency version '*'",
        )

    def test_red_registry_dependency_without_version(self) -> None:
        self.assert_red(
            '[dependencies]\nserde = { features = ["derive"] }\n',
            "[dependencies] serde: registry dependency is missing an explicit version",
        )

    def test_red_non_string_version(self) -> None:
        self.assert_red(
            "[dependencies]\nserde = { version = 1 }\n",
            "[dependencies] serde: dependency version must be a string",
        )

    def test_red_unsupported_specification(self) -> None:
        self.assert_red(
            "[dependencies]\nserde = 1\n",
            "[dependencies] serde: unsupported dependency specification",
        )


if __name__ == "__main__":
    unittest.main()
