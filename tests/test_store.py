import shutil
import unittest

from support import SwarmCase, git

from swarmlib import gitio
from swarmlib.store import Halted, SwarmError, halt, record, resume, set_config


class StoreTest(SwarmCase):
    def test_transact_pushes_and_other_clones_see_it(self):
        a, b = self.clone("codex-ws2-worker1"), self.clone("claude-air-worker2")

        def write() -> bool:
            a.path("items", "note.md").write_text("hello\n")
            return True

        self.assertTrue(a.transact("note", write))
        b.sync()
        self.assertEqual(b.path("items", "note.md").read_text(), "hello\n")
        self.assertIn("[swarm] codex-ws2-worker1: note", git(self.origin, "log", "-1", "--format=%s", "swarm"))

    def test_rejected_push_reapplies_mutation_on_fresh_head(self):
        a, b = self.clone("codex-ws2-worker1"), self.clone("claude-air-worker2")
        calls = []

        def b_write() -> bool:
            calls.append(1)
            if len(calls) == 1:  # someone else lands a commit mid-transaction
                a.transact("a", lambda: bool(a.path("items", "a.md").write_text("a\n")))
            b.path("items", "b.md").write_text("b\n")
            return True

        self.assertTrue(b.transact("b", b_write))
        self.assertEqual(len(calls), 2)
        a.sync()
        self.assertTrue(a.path("items", "a.md").exists() and a.path("items", "b.md").exists())

    def test_noop_mutation_does_not_commit(self):
        a = self.clone("codex-ws2-worker1")
        before = git(self.origin, "rev-parse", "swarm")
        self.assertFalse(a.transact("noop", lambda: False))
        self.assertEqual(git(self.origin, "rev-parse", "swarm"), before)

    def test_secret_guard_blocks_push(self):
        a = self.clone("codex-ws2-worker1")
        before = git(self.origin, "rev-parse", "swarm")
        planted = "key " + "sk-" + "ant-" + "z" * 40

        with self.assertRaises(SwarmError):
            a.transact("leak", lambda: bool(a.path("msgs", "leak.md").write_text(planted)))
        self.assertEqual(git(self.origin, "rev-parse", "swarm"), before)

    def test_halt_blocks_writes_until_resumed(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        worker = self.clone("codex-ws2-worker1")
        halt(conductor, "role:worker", "pilot paused")
        with self.assertRaises(Halted):
            worker.transact("x", lambda: bool(worker.path("items", "x.md").write_text("x\n")))
        resume(conductor, None)
        self.assertTrue(worker.transact("x", lambda: bool(worker.path("items", "x.md").write_text("x\n"))))

    def test_only_conductor_halts_and_sets_config(self):
        worker = self.clone("codex-ws2-worker1")
        with self.assertRaises(SwarmError):
            halt(worker, "all", "nope")
        with self.assertRaises(SwarmError):
            set_config(worker, "active_waves", "[1, 2]")

    def test_config_defaults_and_override(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.assertEqual(conductor.config()["base_branch"], "integration/beta-next")
        set_config(conductor, "active_waves", "[1, 2]")
        conductor.sync()
        self.assertEqual(conductor.config()["active_waves"], [1, 2])

    # Review focus: an agent killed between commit and push leaves nothing behind.
    def test_interrupted_push_is_discarded_by_next_sync(self):
        a = self.clone("codex-ws2-worker1")
        before = git(self.origin, "rev-parse", "swarm")
        a.path("items", "half.md").write_text("half\n")
        git(a.root, "add", "-A")
        git(a.root, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "--quiet", "-m", "unpushed")
        a.sync()
        self.assertFalse(a.path("items", "half.md").exists())
        self.assertEqual(git(self.origin, "rev-parse", "swarm"), before)

    # Review focus: GitHub unreachable fails closed with a clear error.
    def test_unreachable_origin_raises_git_error(self):
        a = self.clone("codex-ws2-worker1")
        shutil.rmtree(self.origin)
        with self.assertRaises(gitio.GitError):
            a.transact("x", lambda: bool(a.path("items", "x.md").write_text("x\n")))

    def test_record_numbers_decisions_and_names_digests(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.assertEqual(record(conductor, "decision", "first", "one"), "decisions/0001-first.md")
        self.assertEqual(record(conductor, "decision", "second", "two"), "decisions/0002-second.md")
        self.assertEqual(record(conductor, "digest", "2026-10-07-am", "landed: F1"), "digests/2026-10-07-am.md")
        with self.assertRaises(SwarmError):
            record(conductor, "digest", "2026-10-07-am", "again")
        conductor.sync()
        self.assertEqual(conductor.path("decisions", "0002-second.md").read_text(), "two\n")

    def test_record_requires_conductor_and_safe_names(self):
        worker = self.clone("codex-ws2-worker1")
        with self.assertRaises(SwarmError):
            record(worker, "decision", "x", "y")
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        with self.assertRaises(SwarmError):
            record(conductor, "digest", "../escape", "y")

    def test_missing_agent_identity_refused(self):
        a = self.clone("codex-ws2-worker1")
        a.agent = ""
        with self.assertRaises(SwarmError):
            a.transact("x", lambda: True)


if __name__ == "__main__":
    unittest.main()
