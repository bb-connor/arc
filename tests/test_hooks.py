import os
import subprocess
import unittest
from pathlib import Path

from support import SwarmCase, commit_all, git

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "pre-push"
ZERO = "0" * 40


class PrePushHookTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "hookrepo"
        git(self.tmp, "init", "--quiet", "--initial-branch=main", str(self.repo))
        (self.repo / "f").write_text("a\n")
        self.a = commit_all(self.repo, "a")
        (self.repo / "f").write_text("b\n")
        self.b = commit_all(self.repo, "b")  # child of a
        git(self.repo, "checkout", "--quiet", "-b", "side", self.a)
        (self.repo / "f").write_text("c\n")
        self.c = commit_all(self.repo, "c")  # sibling of b
        git(self.repo, "config", "swarm.item", "F1")

    def push(self, remote_ref, local, remote, role="worker"):
        env = {**os.environ, "SWARM_ROLE": role, "SWARM_HOOK_SKIP_LFS": "1"}
        line = f"refs/heads/x {local} {remote_ref} {remote}\n"
        return subprocess.run([str(HOOK), "origin", "https://example.invalid/arc.git"], cwd=self.repo,
                              input=line, text=True, capture_output=True, env=env)

    def test_fast_forward_lane_push_allowed(self):
        self.assertEqual(self.push("refs/heads/lane/F1-fix", self.b, self.a).returncode, 0)

    def test_new_branch_allowed(self):
        self.assertEqual(self.push("refs/heads/lane/F1-fix", self.b, ZERO).returncode, 0)

    def test_force_push_only_to_own_lane(self):
        self.assertEqual(self.push("refs/heads/lane/F1-fix", self.c, self.b).returncode, 0)
        denied = self.push("refs/heads/lane/F2-other", self.c, self.b)
        self.assertEqual(denied.returncode, 1)
        self.assertIn("only this worktree's own lane/F1-*", denied.stderr)

    def test_protected_refs(self):
        self.assertEqual(self.push("refs/heads/main", self.b, self.a).returncode, 1)
        self.assertEqual(self.push("refs/heads/swarm", self.b, self.a).returncode, 1)
        self.assertEqual(self.push("refs/heads/integration/beta-next", self.b, self.a).returncode, 1)
        self.assertEqual(self.push("refs/heads/integration/beta-next", self.b, self.a, role="integrator").returncode, 0)
        self.assertEqual(self.push("refs/heads/integration/beta-next", self.c, self.b, role="integrator").returncode, 1)
        self.assertEqual(self.push("refs/heads/integration/process-security-m4", self.b, self.a).returncode, 1)

    def test_deletion_denied(self):
        self.assertEqual(self.push("refs/heads/lane/F1-fix", ZERO, self.a).returncode, 1)

    def test_unknown_remote_sha_treated_as_rewrite(self):
        unknown = "1234567890abcdef1234567890abcdef12345678"
        self.assertEqual(self.push("refs/heads/feature/x", self.b, unknown).returncode, 1)


if __name__ == "__main__":
    unittest.main()
