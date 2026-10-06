#!/usr/bin/env python3
"""Constrain cargo-mutants module paths without relaxing evidence path syntax."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "security_adversarial_evidence_paths",
    ROOT / "scripts/check-security-adversarial-evidence.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load adversarial evidence checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class CargoMutantsSourcePaths(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="chio-mutants-paths-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.prefix = "crates/fixture-package"
        self.package = self.root / self.prefix
        (self.package / "src").mkdir(parents=True)
        (self.package / "tests").mkdir()
        (self.package / "src/lib.rs").write_text("pub fn live() {}\n")
        (self.package / "tests/support.rs").write_text("pub fn fixture() {}\n")

    def inventory(self, *paths: str) -> frozenset[str]:
        output = json.dumps(
            [{"package": "fixture-package", "path": path} for path in paths]
        )
        with (
            mock.patch.object(
                CHECKER, "cargo_mutants_executable", return_value=Path("/trusted/tool")
            ),
            mock.patch.object(CHECKER, "require_cargo_mutants_version"),
            mock.patch.object(CHECKER, "cargo_mutants_output", return_value=(output, None)),
        ):
            return CHECKER.cargo_mutants_source_inventory(
                self.root,
                self.package,
                "fixture-package",
                CHECKER.CargoMutantsSourceInventory(),
                {},
            )

    def test_canonical_source_remains_accepted(self) -> None:
        path = f"{self.prefix}/src/lib.rs"
        self.assertEqual(self.inventory(path), frozenset({path}))

    def test_in_package_rust_module_parent_path(self) -> None:
        path = f"{self.prefix}/src/../tests/support.rs"
        self.assertEqual(
            self.inventory(path), frozenset({f"{self.prefix}/tests/support.rs"})
        )

    def test_aliases_do_not_hide_duplicate_source(self) -> None:
        with self.assertRaisesRegex(CHECKER.EvidenceError, "duplicate source inventory"):
            self.inventory(
                f"{self.prefix}/tests/support.rs",
                f"{self.prefix}/src/../tests/support.rs",
            )

    def test_parent_path_cannot_leave_package(self) -> None:
        other = self.root / "crates/other"
        other.mkdir()
        (other / "lib.rs").write_text("pub fn other() {}\n")
        for path in (
            f"{self.prefix}/../other/lib.rs",
            f"{self.prefix}/src/../../other/lib.rs",
            f"{self.prefix}/../../crates/fixture-package/src/lib.rs",
        ):
            with self.subTest(path=path), self.assertRaises(CHECKER.EvidenceError):
                self.inventory(path)

    def test_cancelled_parent_must_be_a_real_directory(self) -> None:
        (self.package / "alias").symlink_to("src", target_is_directory=True)
        for component in ("alias", "missing", "src/lib.rs"):
            path = f"{self.prefix}/{component}/../tests/support.rs"
            with self.subTest(path=path), self.assertRaises(CHECKER.EvidenceError):
                self.inventory(path)

    def test_normalized_source_cannot_be_a_symlink(self) -> None:
        (self.package / "tests/alias.rs").symlink_to("support.rs")
        with self.assertRaises(CHECKER.EvidenceError):
            self.inventory(f"{self.prefix}/src/../tests/alias.rs")

    def test_other_noncanonical_and_non_rust_paths_remain_rejected(self) -> None:
        for path in (
            f"/{self.prefix}/src/../tests/support.rs",
            f"{self.prefix}//src/../tests/support.rs",
            f"{self.prefix}/./src/../tests/support.rs",
            f"{self.prefix}/src/../tests/support.rs/",
            f"{self.prefix}/src/..\\tests/support.rs",
            f"{self.prefix}/src/../tests/support.rs\n",
            f"{self.prefix}/src/../Cargo.toml",
        ):
            with self.subTest(path=path), self.assertRaises(CHECKER.EvidenceError):
                self.inventory(path)

    def test_authoritative_evidence_path_syntax_stays_strict(self) -> None:
        with self.assertRaises(CHECKER.EvidenceError):
            CHECKER.canonical_repository_path(
                f"{self.prefix}/src/../tests/support.rs", "declared evidence path"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
