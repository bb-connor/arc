#!/usr/bin/env python3
"""Self-test for scripts/check-review-slices.py."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-review-slices.py"
WORKFLOW_PATHS = ["docs/**", "scripts/**"]
MANIFEST_PATH = "config/cognition-market-components.json"
WORKFLOW_PATH = ".github/workflows/cognition-market-hosted.yml"
SPEC_DRIFT_PATH = ".github/workflows/spec-drift.yml"
GENERATED_TREE = "sdks/python/chio-sdk-python/src/chio_sdk/_generated"
SCHEMA = "chio.cognition-market.components.v1"
UNREADABLE = "review-slice error: cannot read cognition-market component ownership:"


def workflow_text(paths: list[str], occurrences: int = 2) -> str:
    return "".join(f'      - "{path}"\n' * occurrences for path in paths)


class ReviewSlicesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-review-slices-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "--initial-branch=main")
        self.git("config", "user.name", "Slices fixture")
        self.git("config", "user.email", "slices@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        (self.repo / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.repo / "scripts" / SCRIPT.name)
        self.write_ownership(
            {"schema": SCHEMA, "workflowPaths": WORKFLOW_PATHS},
            workflow_text(WORKFLOW_PATHS),
        )
        shutil.copyfile(ROOT / SPEC_DRIFT_PATH, self.repo / SPEC_DRIFT_PATH)

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=self.repo, text=True, stderr=subprocess.STDOUT
        ).strip()

    def write_ownership(self, manifest: object, workflow: str | None) -> None:
        manifest_file = self.repo / MANIFEST_PATH
        manifest_file.parent.mkdir(parents=True, exist_ok=True)
        manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
        workflow_file = self.repo / WORKFLOW_PATH
        workflow_file.parent.mkdir(parents=True, exist_ok=True)
        if workflow is None:
            workflow_file.unlink(missing_ok=True)
        else:
            workflow_file.write_text(workflow, encoding="utf-8")

    def run_check(self, changed: list[str]) -> subprocess.CompletedProcess[str]:
        self.git("add", "-A")
        self.git("commit", "-qm", "base", "--allow-empty")
        self.git("branch", "-f", "base")
        for name in changed:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("changed\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-qm", "change", "--allow-empty")
        return subprocess.run(
            [sys.executable, "-I", "scripts/check-review-slices.py", "--base-ref", "base"],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_green_classified_paths(self) -> None:
        result = self.run_check(["docs/a.md", "scripts/x.py", "third_party/y/Cargo.toml"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review slice check passed (3 files across 3 slices)", result.stdout)
        self.assertIn("- architecture-docs: 1 files", result.stdout)

    def test_green_broad_diff_across_five_slices(self) -> None:
        names = [
            "docs/n{}.md",
            "third_party/n{}.rs",
            "scripts/n{}.py",
            "audits/n{}.md",
            "crates/core/chio-core/n{}.rs",
        ]
        changed = [name.format(index) for name in names for index in range(40)]
        result = self.run_check(changed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review slice check passed (200 files across 5 slices)", result.stdout)

    def test_green_just_below_broad_threshold(self) -> None:
        result = self.run_check([f"docs/n{index}.md" for index in range(199)])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_green_codegen_checked_files_leave_the_broad_count(self) -> None:
        changed = [f"{GENERATED_TREE}/n{index}.py" for index in range(300)]
        result = self.run_check(changed + ["docs/a.md", "scripts/x.py"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review slice check passed (302 files across 3 slices)", result.stdout)
        self.assertIn("outside the broad-diff count: 300", result.stdout)

    def test_red_hand_files_stay_broad_beside_generated_files(self) -> None:
        changed = [f"{GENERATED_TREE}/n{index}.py" for index in range(300)]
        result = self.run_check(changed + [f"docs/n{index}.md" for index in range(200)])
        self.assertEqual(result.returncode, 1)
        self.assertIn("broad diff has 200 files but only 1 review slices", result.stderr)

    def test_red_generated_sibling_path_is_counted(self) -> None:
        result = self.run_check([f"{GENERATED_TREE}_copy/n{index}.py" for index in range(200)])
        self.assertEqual(result.returncode, 1)
        self.assertIn("broad diff has 200 files", result.stderr)

    def test_red_hand_file_beside_a_generated_file_is_counted(self) -> None:
        tree = "crates/core/chio-core-types/src/_generated"
        result = self.run_check([f"{tree}/hand{index}.rs" for index in range(200)])
        self.assertEqual(result.returncode, 1)
        self.assertIn("broad diff has 200 files", result.stderr)

    def test_red_workflow_without_codegen_check(self) -> None:
        workflow = self.repo / SPEC_DRIFT_PATH
        text = workflow.read_text(encoding="utf-8")
        workflow.write_text(text.replace("run: make codegen-check", "run: true"), encoding="utf-8")
        result = self.run_check(["docs/a.md"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("spec-drift workflow does not run make codegen-check", result.stderr)

    def test_red_unclassified_path(self) -> None:
        result = self.run_check(["docs/a.md", "zzz/unknown.txt"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("unclassified changed paths:\n  zzz/unknown.txt", result.stderr)
        self.assertNotIn("docs/a.md", result.stderr)

    def test_red_broad_diff_with_too_few_slices(self) -> None:
        result = self.run_check([f"docs/n{index}.md" for index in range(200)])
        self.assertEqual(result.returncode, 1)
        self.assertIn("broad diff has 200 files but only 1 review slices", result.stderr)

    def test_red_workflow_path_listed_once(self) -> None:
        self.write_ownership(
            {"schema": SCHEMA, "workflowPaths": WORKFLOW_PATHS},
            workflow_text(["docs/**"]) + workflow_text(["scripts/**"], 1),
        )
        result = self.run_check(["docs/a.md"])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr.strip(),
            "review-slice error: hosted workflow must contain 'scripts/**' exactly once for pull and push",
        )

    def test_red_workflow_path_listed_three_times(self) -> None:
        self.write_ownership(
            {"schema": SCHEMA, "workflowPaths": WORKFLOW_PATHS},
            workflow_text(WORKFLOW_PATHS, 3),
        )
        result = self.run_check(["docs/a.md"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("hosted workflow must contain 'docs/**' exactly once", result.stderr)
        self.assertIn("hosted workflow must contain 'scripts/**' exactly once", result.stderr)

    def test_red_unsupported_manifest_schema(self) -> None:
        self.write_ownership(
            {"schema": "chio.cognition-market.components.v2", "workflowPaths": WORKFLOW_PATHS},
            workflow_text(WORKFLOW_PATHS),
        )
        result = self.run_check(["docs/a.md"])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr.strip(),
            "review-slice error: cognition-market component ownership has an unsupported schema",
        )

    def test_red_malformed_workflow_paths(self) -> None:
        cases = {
            "unsorted": ["scripts/**", "docs/**"],
            "duplicate": ["docs/**", "docs/**"],
            "empty list": [],
            "empty entry": ["", "docs/**"],
            "non-string entry": [1, 2],
            "not a list": "docs/**",
        }
        for label, paths in cases.items():
            with self.subTest(label):
                self.write_ownership(
                    {"schema": SCHEMA, "workflowPaths": paths},
                    workflow_text(WORKFLOW_PATHS),
                )
                result = self.run_check(["docs/a.md"])
                self.assertEqual(result.returncode, 1)
                self.assertEqual(
                    result.stderr.strip(),
                    "review-slice error: cognition-market workflow paths must be nonempty, unique, and sorted",
                )

    def test_red_missing_hosted_workflow(self) -> None:
        self.write_ownership({"schema": SCHEMA, "workflowPaths": WORKFLOW_PATHS}, None)
        result = self.run_check(["docs/a.md"])
        self.assertEqual(result.returncode, 1)
        self.assertIn(UNREADABLE, result.stderr)

    def test_red_malformed_manifest(self) -> None:
        self.write_ownership({}, workflow_text(WORKFLOW_PATHS))
        (self.repo / MANIFEST_PATH).write_text("{not json", encoding="utf-8")
        result = self.run_check(["docs/a.md"])
        self.assertEqual(result.returncode, 1)
        self.assertIn(UNREADABLE, result.stderr)


if __name__ == "__main__":
    unittest.main()
