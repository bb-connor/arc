#!/usr/bin/env python3
"""Self-test for scripts/check-trj4-no-implementation-backed.sh."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-trj4-no-implementation-backed.sh"
NEEDLE = "implementation" + "_backed"


class RegistryStatusGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-trj4-status-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-trj4-no-implementation-backed.sh"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_green_clean_roots(self) -> None:
        self.write("spec/registries/theorems.yaml", "status: proven\n")
        self.write("formal/Model.tla", "(* proven *)\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            f"registry status gate: no '{NEEDLE}' occurrences under spec/registries formal",
        )

    def test_green_missing_roots(self) -> None:
        self.assertEqual(self.run_check().returncode, 0)

    def test_green_other_directories_are_not_scanned(self) -> None:
        self.write("docs/notes.md", f"status: {NEEDLE}\n")
        self.assertEqual(self.run_check().returncode, 0)

    def test_red_in_each_root(self) -> None:
        for rel in ("spec/registries/theorems.yaml", "formal/proofs/Model.tla"):
            with self.subTest(rel):
                self.write(rel, f"id: T1\nstatus: {NEEDLE}\n")
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                lines = result.stderr.strip().splitlines()
                self.assertEqual(
                    lines[0],
                    f"::error::registry status gate: found '{NEEDLE}' in tracked registry/formal sources.",
                )
                self.assertEqual(
                    lines[1],
                    "Demote these entries to 'proposed' (or 'proven'/'assumed') before merging:",
                )
                self.assertEqual(lines[2], f"{rel}:2:status: {NEEDLE}")
                (self.root / rel).unlink()

    def test_red_reports_hits_from_both_roots(self) -> None:
        self.write("spec/registries/a.yaml", f"{NEEDLE}\n")
        self.write("formal/b.tla", f"x {NEEDLE}\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("spec/registries/a.yaml:1:", result.stderr)
        self.assertIn("formal/b.tla:1:", result.stderr)

    def test_red_match_is_literal_not_a_pattern(self) -> None:
        self.write("formal/c.tla", NEEDLE.upper() + "\n")
        self.assertEqual(self.run_check().returncode, 0)


if __name__ == "__main__":
    unittest.main()
