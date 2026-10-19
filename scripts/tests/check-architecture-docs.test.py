#!/usr/bin/env python3
"""Self-test for scripts/check-architecture-docs.py."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-architecture-docs.py"
DOC_PATH = "crates/core/chio-demo/ARCHITECTURE.md"

SECTIONS = (
    "# chio-demo\n\n"
    "## Boundary\n\n"
    "This crate owns the demo public surface and does not own persistence.\n"
    "It defines the scope of the demo types.\n\n"
    "## Trust\n\n"
    "Every signed value uses canonical bytes. The invariant is fail-closed:\n"
    "an unverifiable value is rejected and security decisions never default.\n\n"
    "## Verification\n\n"
    "Unit tests cover each rule, a regression suite pins the encodings,\n"
    "and a conformance gate replays the fixtures in smoke runs.\n"
)
WORD_RE = re.compile(r"[A-Za-z0-9_'-]+")
PADDING = " ".join(f"word{index}" for index in range(180)) + "\n"
GOOD = SECTIONS + "\n" + PADDING


class ArchitectureDocsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-architecture-docs-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "--initial-branch=main")
        self.git("config", "user.name", "Docs fixture")
        self.git("config", "user.email", "docs@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        (self.repo / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.repo / "scripts" / SCRIPT.name)
        self.write("README.md", "base\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "base")
        self.git("branch", "base")

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=self.repo, text=True, stderr=subprocess.STDOUT
        ).strip()

    def write(self, rel: str, text: str) -> None:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "scripts/check-architecture-docs.py", *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )

    def commit_change(self) -> None:
        self.git("add", "-A")
        self.git("commit", "-qm", "change")

    def check_changed_doc(self, text: str) -> subprocess.CompletedProcess[str]:
        self.write(DOC_PATH, text)
        self.commit_change()
        return self.run_check("--base-ref", "base")

    def assert_single_error(self, text: str, message: str) -> None:
        result = self.check_changed_doc(text)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stderr.strip(), f"{DOC_PATH}: {message}")

    def test_green_changed_doc(self) -> None:
        result = self.check_changed_doc(GOOD)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "architecture docs check passed (1 files)")

    def test_green_diff_without_architecture_docs(self) -> None:
        self.write("docs/other.md", "x\n")
        self.commit_change()
        result = self.run_check("--base-ref", "base")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "architecture docs check passed (0 files)")

    def test_green_deleted_doc_is_skipped(self) -> None:
        self.write(DOC_PATH, "x\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "add")
        self.git("branch", "-f", "base")
        (self.repo / DOC_PATH).unlink()
        self.commit_change()
        result = self.run_check("--base-ref", "base")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(0 files)", result.stdout)

    def test_green_explicit_path(self) -> None:
        self.write(DOC_PATH, GOOD)
        result = self.run_check(DOC_PATH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(1 files)", result.stdout)

    def test_explicit_paths_ignore_other_file_names(self) -> None:
        self.write("notes.md", "too short\n")
        result = self.run_check("notes.md")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(0 files)", result.stdout)

    def test_red_explicit_path_fails(self) -> None:
        self.write(DOC_PATH, "# tiny\n")
        result = self.run_check(DOC_PATH)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"{DOC_PATH}: has 1 nonblank lines, expected at least 10", result.stderr)

    def test_red_too_few_lines(self) -> None:
        text = " ".join(f"boundary trust verification w{index}" for index in range(200))
        text = "## a\n## b\n## c\n" + text + "\n"
        self.assert_single_error(text, "has 4 nonblank lines, expected at least 10")

    def test_red_too_few_words(self) -> None:
        self.assert_single_error(
            SECTIONS,
            f"has {len(WORD_RE.findall(SECTIONS))} words, "
            "expected at least 180",
        )

    def test_red_no_boundary(self) -> None:
        text = (
            GOOD.replace("boundary", "edge").replace("Boundary", "Edge")
            .replace("scope", "extent").replace("does not own", "leaves").replace("owns", "holds").replace("public surface", "api")
        )
        self.assert_single_error(text, "does not describe a boundary, scope, or public surface")

    def test_red_no_trust(self) -> None:
        text = GOOD
        for word, repl in (
            ("Trust", "Rules"), ("trust", "rules"), ("signed", "marked"),
            ("canonical", "plain"), ("invariant", "habit"), ("fail-closed", "strict"),
            ("security", "safety"), ("authority", "origin"),
        ):
            text = text.replace(word, repl)
        self.assert_single_error(text, "does not describe trust, security, or canonical invariants")

    def test_red_no_verification(self) -> None:
        text = GOOD
        for word, repl in (
            ("Verification", "Checks"), ("verification", "checks"), ("Unit tests", "Unit probes"),
            ("tests", "probes"), ("regression", "pinned"), ("conformance", "fixture"),
            ("gate", "step"), ("smoke", "quick"),
        ):
            text = text.replace(word, repl)
        self.assert_single_error(text, "does not describe verification or test focus")

    def test_red_too_few_h2_sections(self) -> None:
        text = GOOD.replace("## Verification", "### Verification").replace("## Trust", "### Trust")
        self.assert_single_error(text, "has 1 second-level sections, expected at least 3")

    def test_red_reports_every_error_per_file(self) -> None:
        result = self.check_changed_doc("# tiny\n")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(result.stderr.strip().splitlines()), 6)


if __name__ == "__main__":
    unittest.main()
