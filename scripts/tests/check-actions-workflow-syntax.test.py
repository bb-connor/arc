#!/usr/bin/env python3
"""Keep recognized queue compatibility separate from every other syntax error."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACTIONLINT = os.environ.get("ACTIONLINT_BIN", "actionlint")
WORKFLOW = """name: Queue syntax fixture
on:
  workflow_dispatch:
jobs:
  authorize-security-check-publication:
    runs-on: ubuntu-latest
    outputs:
      merge_commit_sha: ${{ steps.merge.outputs.sha }}
    steps:
      - id: merge
        run: echo 'sha=fixture' >> "$GITHUB_OUTPUT"
  publish-security-contract:
    needs: authorize-security-check-publication
    concurrency:
      group: security-check-authority-${{ needs.authorize-security-check-publication.outputs.merge_commit_sha }}
      cancel-in-progress: false
      queue: max
    runs-on: ubuntu-latest
    steps:
      - run: echo fixture
"""


class QueueSyntaxCompatibilityTests(unittest.TestCase):
    def run_validator(self, text: str, name: str = "enterprise-evidence-finalizer.yml"):
        with tempfile.TemporaryDirectory(prefix="chio-queue-syntax-") as raw:
            root = Path(raw)
            path = root / ".github/workflows" / name
            path.parent.mkdir(parents=True)
            path.write_text(text)
            return subprocess.run(
                [sys.executable, "-B", str(ROOT / "scripts/check-actions-workflow-syntax.py"),
                 "--root", str(root), "--actionlint", ACTIONLINT, str(path)],
                text=True, capture_output=True, check=False, timeout=30,
            )

    def test_exact_authority_queue_is_validated_before_remaining_syntax(self) -> None:
        result = self.run_validator(WORKFLOW)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("queue contracts verified: 1", result.stdout)
        self.assertIn("hosted workflow acceptance remains unverified", result.stdout)

    def test_unrecognized_or_weakened_queue_is_never_removed(self) -> None:
        for label, text, name in (
            ("wrong-group", WORKFLOW.replace("security-check-authority-", "other-"), "enterprise-evidence-finalizer.yml"),
            ("cancellation", WORKFLOW.replace("cancel-in-progress: false", "cancel-in-progress: true"), "enterprise-evidence-finalizer.yml"),
            ("queue-value", WORKFLOW.replace("queue: max", "queue: single"), "enterprise-evidence-finalizer.yml"),
            ("foreign-workflow", WORKFLOW, "foreign.yml"),
            ("duplicate-key", WORKFLOW.replace("queue: max", "queue: max\n      queue: max"), "enterprise-evidence-finalizer.yml"),
        ):
            with self.subTest(mutation=label):
                result = self.run_validator(text, name)
                self.assertNotEqual(result.returncode, 0)

    def test_every_generic_syntax_error_keeps_its_failure(self) -> None:
        result = self.run_validator(WORKFLOW.replace("runs-on: ubuntu-latest", "unknown-job-key: ubuntu-latest", 1))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown-job-key", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
