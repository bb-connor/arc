import os
import sys
import unittest
from pathlib import Path

from support import SwarmCase, commit_all, git

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ops"))

import worktree_inventory as inv  # noqa: E402


def wt(**kw):
    base = dict(path="/w", branch="b", head="h", age_days=30, dirty=0, pushed=True, target_gb=5)
    base.update(kw)
    return inv.Worktree(**base)


class ClassifyTest(unittest.TestCase):
    def test_rules(self):
        self.assertEqual(inv.classify(wt(), [], "/main")[0], "remove")
        self.assertEqual(inv.classify(wt(age_days=2), [], "/main")[0], "keep")
        self.assertEqual(inv.classify(wt(dirty=3), [], "/main"), ("drop-target", "3 uncommitted files; only build output removed"))
        self.assertEqual(inv.classify(wt(dirty=3, age_days=10), [], "/main")[0], "keep")
        self.assertEqual(inv.classify(wt(pushed=False, target_gb=0.2), [], "/main")[0], "keep")
        self.assertEqual(inv.classify(wt(path="/main"), [], "/main")[0], "keep")
        self.assertEqual(inv.classify(wt(path="/lanes/integration"), ["/lanes/integ*"], "/main"), ("keep", "protected"))


class CollectTest(SwarmCase):
    def test_collect_and_apply_only_remove_clean_pushed(self):
        arc, repo = self.make_arc()
        old = {"GIT_COMMITTER_DATE": "2026-09-01T00:00:00Z", "GIT_AUTHOR_DATE": "2026-09-01T00:00:00Z"}
        clean, dirty = self.tmp / "clean", self.tmp / "dirty"
        git(repo, "worktree", "add", "-q", "-b", "old-clean", str(clean))
        git(repo, "worktree", "add", "-q", "-b", "old-dirty", str(dirty))
        for path in (clean, dirty):
            (path / "f.txt").write_text("x\n")
            os.environ.update(old)
            commit_all(path, "old work")
            for key in old:
                del os.environ[key]
            git(path, "push", "-q", str(arc), "HEAD")
        (dirty / "untracked.txt").write_text("y\n")
        rows = {Path(w.path).name: inv.classify(w, [], os.path.realpath(repo))[0] for w in inv.collect(repo, str(arc))}
        self.assertEqual(rows, {"repo": "keep", "clean": "remove", "dirty": "keep"})
        plan = self.tmp / "plan.tsv"
        plan.write_text(f"remove\tr\t0\t35\t{clean}\told-clean\nremove\tr\t0\t35\t{dirty}\told-dirty\n")
        self.assertEqual(inv.apply(repo, plan, str(arc)), 0)
        self.assertFalse(clean.exists())
        self.assertTrue(dirty.exists())


if __name__ == "__main__":
    unittest.main()
