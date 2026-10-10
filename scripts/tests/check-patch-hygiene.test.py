#!/usr/bin/env python3
"""Execute the CI hygiene step against committed changes in real Git repositories."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PatchHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-patch-hygiene-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "--initial-branch=main")
        self.git("config", "user.name", "Hygiene fixture")
        self.git("config", "user.email", "hygiene@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        self.base = self.commit("base.txt", "clean base\n")
        script = ROOT / "scripts/check-patch-hygiene.py"
        if script.exists():
            (self.repo / "scripts").mkdir()
            shutil.copyfile(script, self.repo / "scripts" / script.name)
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        self.step = next(
            step["run"]
            for step in workflow["jobs"]["check"]["steps"]
            if step.get("name") == "Patch hygiene"
        )

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=self.repo, text=True, stderr=subprocess.STDOUT
        ).strip()

    def commit(self, name: str, contents: str) -> str:
        (self.repo / name).write_text(contents)
        self.git("add", "--", name)
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def check(
        self, event: dict, kind: str = "pull_request"
    ) -> subprocess.CompletedProcess:
        path = Path(self.temp.name) / "event.json"
        path.write_text(json.dumps(event))
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", self.step],
            cwd=self.repo,
            env={
                **os.environ,
                "GITHUB_EVENT_NAME": kind,
                "GITHUB_EVENT_PATH": str(path),
                "GITHUB_SHA": self.git("rev-parse", "HEAD"),
            },
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def pr(self, head: str, base: str | None = None) -> dict:
        return {
            "pull_request": {"base": {"sha": base or self.base}, "head": {"sha": head}}
        }

    def test_committed_whitespace_is_rejected_in_clean_checkout(self) -> None:
        head = self.commit("bad.txt", "committed trailing whitespace \n")
        self.assertEqual(self.git("diff", "--check"), "")
        result = self.check(self.pr(head))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("bad.txt", result.stdout + result.stderr)

    def test_committed_conflict_marker_is_rejected(self) -> None:
        head = self.commit(
            "conflict.txt", "<<<<<<< HEAD\nleft\n=======\nright\n>>>>>>> topic\n"
        )
        result = self.check(self.pr(head))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("conflict.txt", result.stdout + result.stderr)

    def test_clean_pr_passes(self) -> None:
        result = self.check(self.pr(self.commit("good.txt", "clean change\n")))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_synthetic_merge_checkout_checks_the_pr_head(self) -> None:
        self.git("checkout", "-qb", "topic")
        head = self.commit("good.txt", "clean PR change\n")
        self.git("checkout", "-q", "main")
        base = self.commit("base-only.txt", "advanced base\n")
        self.git("merge", "--no-ff", "-qm", "synthetic merge", "topic")
        result = self.check(self.pr(head, base))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_advanced_base_does_not_charge_existing_base_whitespace_to_pr(self) -> None:
        # The PR leaves an old file alone; meanwhile base fixes its whitespace.
        old = self.commit("old.txt", "historical whitespace \n")
        self.git("checkout", "-qb", "topic")
        head = self.commit("topic.txt", "clean topic change\n")
        self.git("checkout", "-q", "main")
        base = self.commit("old.txt", "fixed on base\n")
        self.git("checkout", "--detach", "-q", head)
        self.assertEqual(self.git("merge-base", base, head), old)
        result = self.check(self.pr(head, base))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_push_checks_all_commits_since_before(self) -> None:
        self.commit("bad.txt", "earlier pushed whitespace \n")
        head = self.commit("last.txt", "clean last commit\n")
        result = self.check({"before": self.base, "after": head}, "push")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("bad.txt", result.stdout + result.stderr)

    def test_first_push_checks_the_entire_tree(self) -> None:
        head = self.commit("bad.txt", "first push whitespace \n")
        result = self.check({"before": "0" * 40, "after": head}, "push")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("bad.txt", result.stdout + result.stderr)

    def test_clean_first_push_passes(self) -> None:
        result = self.check({"before": "0" * 40, "after": self.base}, "push")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_push_cannot_substitute_an_older_clean_head(self) -> None:
        self.commit("bad.txt", "unreported push change \n")
        result = self.check({"before": "0" * 40, "after": self.base}, "push")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_clean_push_passes(self) -> None:
        head = self.commit("good.txt", "ordinary push\n")
        result = self.check({"before": self.base, "after": head}, "push")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_malformed_or_unavailable_identity_fails_closed(self) -> None:
        for event in (
            {},
            self.pr("HEAD"),
            self.pr("--help"),
            self.pr("f" * 40),
            self.pr("0" * 40),
        ):
            with self.subTest(event=event):
                result = self.check(event)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unsupported_event_fails_closed(self) -> None:
        result = self.check({}, "workflow_dispatch")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unrelated_checkout_is_rejected(self) -> None:
        head = self.commit("bad.txt", "head not checked out \n")
        self.git("checkout", "--detach", "-q", self.base)
        result = self.check(self.pr(head))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
