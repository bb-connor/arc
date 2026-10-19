#!/usr/bin/env python3
"""Self-test for scripts/check-mutants-rationale.sh."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-mutants-rationale.sh"
CRATE_FILE = "crates/core/chio-demo/mutants.toml"


class MutantsRationaleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-mutants-rationale-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q", "--initial-branch=main")
        (self.repo / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.repo / "scripts" / SCRIPT.name)

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def track(self, rel: str, text: str) -> None:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.git("add", "--", rel)

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-mutants-rationale.sh"],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_red(self, *lines: str) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stderr.strip().splitlines(), list(lines))

    def test_green_comment_and_inline_rationales(self) -> None:
        self.track(
            CRATE_FILE,
            'exclude_globs = [\n'
            '    # rationale: generated code\n'
            '    "src/generated.rs",\n'
            '    "src/inline.rs", # rationale: covered elsewhere\n'
            '    "src/other.rs", # rationale: also covered\n'
            ']\n',
        )
        self.track(".cargo/mutants.toml", 'exclude_globs = [\n    # rationale: vendored\n    "vendor/**",\n]\n')
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "mutants rationale check passed for 2 file(s)")

    def test_green_file_without_exclude_globs(self) -> None:
        self.track(CRATE_FILE, 'examine_globs = ["src/**"]\n')
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_green_entries_outside_exclude_globs_need_no_rationale(self) -> None:
        self.track(CRATE_FILE, 'exclude_globs = [\n    # rationale: r\n    "a.rs",\n]\nexamine_globs = [\n    "b.rs",\n]\n')
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_red_no_mutants_files(self) -> None:
        self.assert_red("no mutants.toml files found")

    def test_red_entry_without_rationale(self) -> None:
        self.track(CRATE_FILE, 'exclude_globs = [\n    "src/a.rs",\n]\n')
        self.assert_red(
            f"{CRATE_FILE}:2: exclude_globs entry lacks a rationale comment",
            "mutants rationale check failed with 1 issue(s)",
        )

    def test_red_comment_without_rationale_marker(self) -> None:
        self.track(CRATE_FILE, 'exclude_globs = [\n    # skip this\n    "src/a.rs",\n]\n')
        self.assert_red(
            f"{CRATE_FILE}:3: exclude_globs entry lacks a rationale comment",
            "mutants rationale check failed with 1 issue(s)",
        )

    def test_red_rationale_covers_only_the_next_entry(self) -> None:
        self.track(
            CRATE_FILE,
            'exclude_globs = [\n    # rationale: one\n    "src/a.rs",\n    "src/b.rs",\n]\n',
        )
        self.assert_red(
            f"{CRATE_FILE}:4: exclude_globs entry lacks a rationale comment",
            "mutants rationale check failed with 1 issue(s)",
        )

    def test_red_blank_line_resets_rationale(self) -> None:
        self.track(CRATE_FILE, 'exclude_globs = [\n    # rationale: one\n\n    "src/a.rs",\n]\n')
        self.assert_red(
            f"{CRATE_FILE}:4: exclude_globs entry lacks a rationale comment",
            "mutants rationale check failed with 1 issue(s)",
        )

    def test_red_counts_issues_across_files(self) -> None:
        self.track(CRATE_FILE, 'exclude_globs = [\n    "a.rs",\n    "b.rs",\n]\n')
        self.track(".cargo/mutants.toml", 'exclude_globs = [\n    "c.rs",\n]\n')
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr.strip().splitlines()[-1], "mutants rationale check failed with 3 issue(s)")

    def test_red_tracked_file_missing_from_disk(self) -> None:
        self.track(CRATE_FILE, 'exclude_globs = []\n')
        (self.repo / CRATE_FILE).unlink()
        self.assert_red(
            f"missing tracked mutants.toml file: {CRATE_FILE}",
            "mutants rationale check failed with 1 issue(s)",
        )


if __name__ == "__main__":
    unittest.main()
