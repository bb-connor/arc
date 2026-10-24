#!/usr/bin/env python3
"""Self-test for scripts/check-proptest-coverage.sh."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-proptest-coverage.sh"
INVARIANTS = re.findall(r'"([^"]+\.rs)::(\w+)"', SCRIPT.read_text(encoding="utf-8"))
FIRST_FILE, FIRST_NAME = INVARIANTS[0]
TOTAL = len(INVARIANTS)


class ProptestCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-proptest-coverage-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)
        self.assertEqual(TOTAL, 16)
        self.assertEqual(len(set(INVARIANTS)), TOTAL)
        for file in {file for file, _ in INVARIANTS}:
            (self.root / file).parent.mkdir(parents=True, exist_ok=True)
            (self.root / file).write_text("", encoding="utf-8")
        for file, name in INVARIANTS:
            self.append(file, f"fn {name}() {{}}\n")

    def append(self, file: str, text: str) -> None:
        with (self.root / file).open("a", encoding="utf-8") as handle:
            handle.write(text)

    def rewrite(self, file: str, text: str) -> None:
        (self.root / file).write_text(text, encoding="utf-8")

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-proptest-coverage.sh"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_red(self, found: int, *missing: str) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(
            result.stdout.strip(),
            f"check-proptest-coverage: {found} of {TOTAL} named invariants present",
        )
        self.assertEqual(
            [line for line in result.stderr.splitlines() if line.strip()][0],
            f"FAIL: {len(missing)} invariant name(s) missing or renamed:",
        )
        self.assertEqual(
            [line.strip() for line in result.stderr.splitlines() if line.startswith("  ")],
            list(missing),
        )

    def test_green(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), f"check-proptest-coverage: {TOTAL} of {TOTAL} named invariants present")

    def test_red_duplicate_invariant_registration(self) -> None:
        script = self.root / "scripts" / SCRIPT.name
        text = script.read_text(encoding="utf-8")
        first = "::".join(INVARIANTS[0])
        second = "::".join(INVARIANTS[1])
        self.assertEqual(text.count(f'"{second}"'), 1)
        script.write_text(text.replace(f'"{second}"', f'"{first}"', 1), encoding="utf-8")
        result = self.run_check()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"FAIL: duplicate invariant registration: {first}\n")

    def test_green_name_inside_proptest_block(self) -> None:
        self.rewrite(FIRST_FILE, f"proptest! {{\n    {FIRST_NAME}(x in 0..1) {{}}\n}}\n")
        for file, name in INVARIANTS[1:]:
            if file == FIRST_FILE:
                self.append(file, f"fn {name}() {{}}\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_red_missing_file(self) -> None:
        file = INVARIANTS[5][0]
        (self.root / file).unlink()
        names = [name for f, name in INVARIANTS if f == file]
        self.assert_red(TOTAL - len(names), *[f"MISSING FILE: {file} (expected to contain {name})" for name in names])

    def test_red_missing_name(self) -> None:
        self.rewrite(FIRST_FILE, "".join(f"fn {n}() {{}}\n" for f, n in INVARIANTS if f == FIRST_FILE and n != FIRST_NAME))
        self.assert_red(TOTAL - 1, f"MISSING NAME: {FIRST_FILE}::{FIRST_NAME}")

    def test_red_renamed_name(self) -> None:
        text = (self.root / FIRST_FILE).read_text(encoding="utf-8")
        self.rewrite(FIRST_FILE, text.replace(f"fn {FIRST_NAME}()", f"fn {FIRST_NAME}_v2()"))
        self.assert_red(TOTAL - 1, f"MISSING NAME: {FIRST_FILE}::{FIRST_NAME}")

    def test_red_name_in_another_file_does_not_count(self) -> None:
        other = INVARIANTS[-1][0]
        self.assertNotEqual(other, FIRST_FILE)
        self.rewrite(FIRST_FILE, "")
        self.append(other, f"fn {FIRST_NAME}() {{}}\n")
        missing = [f"MISSING NAME: {f}::{n}" for f, n in INVARIANTS if f == FIRST_FILE]
        self.assert_red(TOTAL - len(missing), *missing)


if __name__ == "__main__":
    unittest.main()
