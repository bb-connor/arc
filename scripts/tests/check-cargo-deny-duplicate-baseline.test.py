#!/usr/bin/env python3
"""Self-test for scripts/check-cargo-deny-duplicate-baseline.py."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-cargo-deny-duplicate-baseline.py"
BASELINE = "scripts/cargo-deny-duplicate-baseline.txt"
DRIFT = "Cargo.lock duplicate-version inventory drifted from baseline."
REFRESH = "Refresh scripts/cargo-deny-duplicate-baseline.txt only after review."


def lockfile(packages: dict[str, list[str]]) -> str:
    return "version = 4\n\n" + "".join(
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n\n'
        for name, versions in packages.items()
        for version in versions
    )


class DuplicateBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-dup-baseline-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)

    def fixture(self, packages: dict[str, list[str]], baseline: str) -> subprocess.CompletedProcess[str]:
        (self.root / "Cargo.lock").write_text(lockfile(packages), encoding="utf-8")
        (self.root / BASELINE).write_text(baseline, encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", "scripts/check-cargo-deny-duplicate-baseline.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_drift(self, result: subprocess.CompletedProcess[str], *diff: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stderr.strip().splitlines(), [DRIFT, REFRESH, *diff])

    def test_green_matches(self) -> None:
        result = self.fixture(
            {"syn": ["1.0.109", "2.0.1"], "serde": ["1.0.0"], "base64": ["0.21.0", "0.22.1"]},
            "base64 0.21.0 0.22.1\nsyn 1.0.109 2.0.1\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "cargo-deny duplicate baseline matches Cargo.lock")

    def test_green_no_duplicates_with_empty_baseline(self) -> None:
        result = self.fixture({"serde": ["1.0.0"]}, "")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_green_versions_sort_numerically(self) -> None:
        result = self.fixture({"hashbrown": ["0.9.1", "0.10.0", "0.2.0"]}, "hashbrown 0.2.0 0.9.1 0.10.0\n")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_red_new_duplicate(self) -> None:
        result = self.fixture({"syn": ["1.0.0", "2.0.0"]}, "")
        self.assert_drift(result, "+ syn 1.0.0 2.0.0")

    def test_red_removed_duplicate(self) -> None:
        result = self.fixture({"syn": ["2.0.0"]}, "syn 1.0.0 2.0.0\n")
        self.assert_drift(result, "- syn 1.0.0 2.0.0")

    def test_red_third_version_changes_line(self) -> None:
        result = self.fixture({"syn": ["1.0.0", "2.0.0", "3.0.0"]}, "syn 1.0.0 2.0.0\n")
        self.assert_drift(result, "+ syn 1.0.0 2.0.0 3.0.0", "- syn 1.0.0 2.0.0")

    def test_red_baseline_with_lexical_version_order(self) -> None:
        result = self.fixture({"hashbrown": ["0.9.1", "0.10.0"]}, "hashbrown 0.10.0 0.9.1\n")
        self.assert_drift(result, "+ hashbrown 0.9.1 0.10.0", "- hashbrown 0.10.0 0.9.1")

    def test_red_baseline_reordered(self) -> None:
        result = self.fixture(
            {"a": ["1.0.0", "2.0.0"], "b": ["1.0.0", "2.0.0"]},
            "b 1.0.0 2.0.0\na 1.0.0 2.0.0\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(DRIFT, result.stderr)


if __name__ == "__main__":
    unittest.main()
