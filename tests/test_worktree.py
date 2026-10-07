import unittest

from support import SwarmCase, commit_all, git

from swarmlib import agents, claims, items, worktree
from swarmlib.store import SwarmError


class WorktreeTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.arc, self.repo = self.make_arc()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        agents.register(self.worker, agent_id=self.worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="m", effort="", tiers=["mid"])
        self.lanes = self.tmp / "lanes"

    def test_creates_lane_from_base_with_hooks_and_identity(self):
        self.add_item(self.conductor, "F1", title="Fix the Thing!")
        claims.claim(self.worker, "F1", [])
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next")
        self.assertEqual(git(lane, "rev-parse", "--abbrev-ref", "HEAD"), "lane/F1-fix-the-thing")
        self.assertEqual(git(lane, "config", "--worktree", "core.hooksPath"), str(self.worker.path("hooks")))
        self.assertEqual(git(lane, "config", "--get", "swarm.item"), "F1")
        self.assertEqual(git(lane, "config", "--get", "user.name"), "codex-ws2-worker1")
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").meta["branch"], "lane/F1-fix-the-thing")
        self.assertEqual(worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes,
                                         base_branch="integration/beta-next"), lane)

    def test_refuses_items_owned_by_someone_else(self):
        self.add_item(self.conductor, "F1")
        with self.assertRaises(SwarmError):
            worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next")

    # Review focus: resuming on another machine starts from the pushed lane, not the base.
    def test_resumes_from_remote_lane_branch(self):
        self.add_item(self.conductor, "F1", title="Resume me")
        claims.claim(self.worker, "F1", [])
        other = self.tmp / "other"
        git(self.tmp, "clone", "--quiet", "--branch", "integration/beta-next", str(self.arc), str(other))
        git(other, "checkout", "--quiet", "-b", "lane/F1-resume-me")
        (other / "progress.txt").write_text("half done\n")
        pushed = commit_all(other, "wip (F1)")
        git(other, "push", "--quiet", "origin", "lane/F1-resume-me")
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next")
        self.assertEqual(git(lane, "rev-parse", "HEAD"), pushed)

    def test_review_worktree_is_detached_at_lane_tip(self):
        self.add_item(self.conductor, "F1", title="Review me")
        claims.claim(self.worker, "F1", [])
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next")
        (lane / "x.txt").write_text("x\n")
        tip = commit_all(lane, "x (F1)")
        git(lane, "push", "--quiet", str(self.arc), "HEAD:refs/heads/lane/F1-review-me")
        reviewer = self.clone("claude-ws2-reviewer1", role="reviewer", vendor="claude")
        view = worktree.create(reviewer, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next", review=True)
        self.assertEqual(git(view, "rev-parse", "HEAD"), tip)
        self.assertEqual(git(view, "rev-parse", "--abbrev-ref", "HEAD"), "HEAD")


if __name__ == "__main__":
    unittest.main()
