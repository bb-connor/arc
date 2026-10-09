import unittest

from support import SwarmCase, commit_all, git

from swarmlib import agents, claims, items, lifecycle, msgs, worktree
from swarmlib.store import SwarmError, set_config


class LifecycleTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        self.reviewer = self.clone("claude-ws2-reviewer1", role="reviewer", vendor="claude")
        self.same_vendor_reviewer = self.clone("codex-ws2-reviewer2", role="reviewer", vendor="codex")
        self.integrator = self.clone("codex-ws2-integrator", role="integrator", vendor="codex")
        for store in (self.worker, self.reviewer, self.same_vendor_reviewer, self.integrator):
            agents.register(store, agent_id=store.agent, machine="ws2", vendor=store.vendor, role=store.role,
                            model="m", effort="", tiers=["mid", "premium"])

    def _to_review(self, item_id: str) -> None:
        claims.claim(self.worker, item_id, [])
        lifecycle.status(self.worker, item_id, "in-progress")
        lifecycle.status(self.worker, item_id, "review", "submitted")
        self.conductor.sync()

        def stamp_vendor() -> bool:
            item = items.load(self.conductor, item_id)
            item.meta["author_vendor"] = "codex"
            items.save(self.conductor, item)
            return True

        self.conductor.transact("vendor", stamp_vendor)

    def test_transition_table_enforced(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        with self.assertRaisesRegex(SwarmError, "not a permitted move"):
            lifecycle.status(self.worker, "F1", "ready")
        with self.assertRaisesRegex(SwarmError, "may not move"):
            lifecycle.status(self.integrator, "F1", "in-progress")
        lifecycle.status(self.worker, "F1", "in-progress")
        lifecycle.status(self.conductor, "F1", "deferred", "conductor may do anything")
        self.worker.sync()
        self.assertIsNone(claims.read(self.worker, "F1"))

    def test_submitted_items_move_only_by_the_integrator(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        lifecycle.status(self.worker, "F1", "submitted")
        with self.assertRaisesRegex(SwarmError, "may not move"):
            lifecycle.status(self.worker, "F1", "ready")
        lifecycle.status(self.integrator, "F1", "in-progress", "check train T1: E0425 in crates/f1/src/lib.rs")
        lifecycle.status(self.worker, "F1", "submitted")
        lifecycle.status(self.integrator, "F1", "integrated", "landed in train T2")
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").status, "integrated")

    def test_review_accept_cross_vendor_only(self):
        self.add_item(self.conductor, "F1")
        self._to_review("F1")
        self.assertEqual(lifecycle.next_review(self.same_vendor_reviewer), None)
        self.assertEqual(lifecycle.next_review(self.reviewer), "F1")
        lifecycle.verdict(self.reviewer, "F1", "accept", "")
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").status, "ready")
        self.assertEqual([m["kind"] for m in msgs.inbox(self.worker)], ["verdict"])

    def test_changes_return_item_then_block_after_round_limit(self):
        self.add_item(self.conductor, "F1")
        self._to_review("F1")
        for expected in ("in-progress", "in-progress", "blocked"):
            lifecycle.next_review(self.reviewer)
            lifecycle.verdict(self.reviewer, "F1", "changes", "fix the edge case")
            self.worker.sync()
            item = items.load(self.worker, "F1")
            self.assertEqual(item.status, expected)
            if expected == "in-progress":
                lifecycle.status(self.worker, "F1", "review", "resubmitted")
        self.assertIn("## Review round 3", item.body)
        self.conductor.sync()
        self.assertTrue(any("review rounds" in m["subject"] for m in msgs.inbox(self.conductor)))

    def test_changes_need_findings(self):
        self.add_item(self.conductor, "F1")
        self._to_review("F1")
        lifecycle.next_review(self.reviewer)
        with self.assertRaises(SwarmError):
            lifecycle.verdict(self.reviewer, "F1", "changes", "  ")

    def test_next_item_prefers_resume_assignee_then_severity(self):
        self.add_item(self.conductor, "A", severity="P2")
        self.add_item(self.conductor, "B", severity="P0")
        self.add_item(self.conductor, "C", severity="P3", assignee="codex-ws2-worker1")
        self.add_item(self.conductor, "D", severity="P0", tier="cheap")
        self.add_item(self.conductor, "E", severity="P0", wave=2)
        self.assertEqual(lifecycle.next_item(self.worker, ["mid"]), "C")
        self.assertEqual(lifecycle.next_item(self.worker, ["mid"]), "C")  # resumes, does not take more
        lifecycle.status(self.conductor, "C", "done")
        self.assertEqual(lifecycle.next_item(self.worker, ["mid"]), "B")
        set_config(self.conductor, "active_waves", "[1, 2]")
        lifecycle.status(self.conductor, "B", "done")
        self.assertEqual(lifecycle.next_item(self.worker, ["mid"]), "E")

    def test_integrator_bounce_messages_owner(self):
        self.add_item(self.conductor, "F1")
        self._to_review("F1")
        lifecycle.next_review(self.reviewer)
        lifecycle.verdict(self.reviewer, "F1", "accept", "")
        lifecycle.status(self.integrator, "F1", "integrated")
        lifecycle.status(self.integrator, "F1", "in-progress", "broke CI run 123")
        self.worker.sync()
        self.assertIn("returned by the integrator", [m["subject"] for m in msgs.inbox(self.worker)][-1])

    def test_ci_failure_budget_blocks(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        for _ in range(3):
            lifecycle.record_evidence(self.worker, "F1", {"kind": "lane-test", "conclusion": "failure", "url": "u"}, ci_failed=True)
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").status, "blocked")

    def test_sweep_blocks_items_over_twice_estimate(self):
        self.add_item(self.conductor, "F1", estimate_hours=1)
        claims.claim(self.worker, "F1", [])
        janitor = self.clone("hermes-ws2-janitor1", role="janitor", vendor="hermes")
        self.at("2026-10-06T13:59:00Z")
        self.assertEqual(lifecycle.sweep(janitor), [])
        self.at("2026-10-06T14:01:00Z")
        self.assertEqual(lifecycle.sweep(janitor), ["F1"])

    def test_wait_returns_on_message_and_on_timeout(self):
        def deliver(_seconds):
            msgs.send(self.conductor, "codex-ws2-worker1", "request", "", "hello", "body")

        events = lifecycle.wait(self.worker, timeout=60, interval=30, sleep=deliver)
        self.assertEqual(len(events), 1)
        self.assertIn("hello", events[0])
        msgs.inbox(self.worker)  # mark read
        self.assertEqual(lifecycle.wait(self.worker, timeout=60, interval=30, sleep=lambda _s: None), [])

    def test_digest_holds_routine_events_until_the_interval(self):
        sleeps = []

        def deliver(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 1:
                msgs.send(self.conductor, "codex-ws2-worker1", "fyi", "", "routine note", "body")

        events = lifecycle.wait(self.worker, timeout=600, interval=30, digest_every=90, sleep=deliver)
        self.assertEqual(len(sleeps), 3)  # held until 90 s had passed
        self.assertTrue(any("routine note" in e for e in events))

    def test_blockers_and_urgent_subjects_wake_immediately(self):
        for kind, subject in (("blocker", "disk full"), ("fyi", "URGENT: stop pushing")):
            sleeps = []

            def deliver(seconds, kind=kind, subject=subject):
                sleeps.append(seconds)
                if len(sleeps) == 1:
                    msgs.send(self.conductor, "codex-ws2-worker1", kind, "", subject, "body")

            events = lifecycle.wait(self.worker, timeout=600, interval=30, digest_every=1200, sleep=deliver)
            self.assertEqual(len(sleeps), 1, subject)
            self.assertTrue(any(subject in e for e in events))
            msgs.inbox(self.worker)  # mark read before the next case

    # Review focus: a hand-edited, malformed item must not take down every command.
    def test_malformed_item_is_reported_not_fatal(self):
        self.add_item(self.conductor, "F1")
        self.conductor.transact("break", lambda: bool(self.conductor.path("items", "BAD.md").write_text("no front matter\n")))
        self.worker.sync()
        good, bad = items.all_items(self.worker)
        self.assertEqual([i.id for i in good], ["F1"])
        self.assertEqual(bad, ["BAD.md"])
        with self.assertRaisesRegex(SwarmError, "malformed"):
            items.load(self.worker, "BAD")

    def test_brief_excludes_log(self):
        self.add_item(self.conductor, "F1")
        text = lifecycle.brief(self.worker, "F1")
        self.assertIn("## Acceptance", text)
        self.assertNotIn("## Log", text)
        self.assertIn("Decision 0001", text)


class SubmitTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.arc, self.repo = self.make_arc()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        agents.register(self.worker, agent_id=self.worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="m", effort="", tiers=["mid"])
        self.integrator = self.clone("codex-builder-integrator", role="integrator", vendor="codex")

    def test_submit_pushes_lane_and_requests_review(self):
        self.add_item(self.conductor, "F1", title="Stop the bleed")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.tmp / "lanes", base_branch="integration/beta-next")
        (lane / "fix.txt").write_text("fixed\n")
        commit_all(lane, "fix: stop the bleed (F1)")
        commits = lifecycle.submit(self.worker, "F1", lane, repo_url=str(self.arc), base_branch="integration/beta-next")
        self.assertEqual(len(commits), 1)
        self.assertEqual(git(self.arc, "rev-parse", "lane/F1-stop-the-bleed"), commits[0])
        self.worker.sync()
        item = items.load(self.worker, "F1")
        self.assertEqual((item.status, item.meta["author_vendor"]), ("submitted", "codex"))
        self.assertFalse(list(self.worker.path("msgs", "reviewer").glob("*.md")))  # check trains, not item reviews

    def _submitted_lane(self):
        self.add_item(self.conductor, "F1", title="Stop the bleed")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.tmp / "lanes", base_branch="integration/beta-next")
        (lane / "fix.txt").write_text("fixed\n")
        commit_all(lane, "fix: stop the bleed (F1)")
        lifecycle.submit(self.worker, "F1", lane, repo_url=str(self.arc), base_branch="integration/beta-next")
        return lane, git(lane, "rev-parse", "--abbrev-ref", "HEAD")

    # Final review: the integrator's fix-in-place commit was erased by the owner's next force-pushed submit.
    def test_submit_never_overwrites_commits_pushed_by_someone_else(self):
        lane, branch = self._submitted_lane()
        lifecycle.status(self.integrator, "F1", "in-progress", "check train T1: E0308")
        fixer = self.tmp / "fixer"
        git(self.tmp, "clone", "--quiet", "--branch", branch, str(self.arc), str(fixer))
        (fixer / "fix.txt").write_text("fixed by the integrator\n")
        fix = commit_all(fixer, "fix: integrator repairs F1 in place")
        git(fixer, "push", "--quiet", "origin", branch)
        (lane / "more.txt").write_text("owner keeps going\n")
        commit_all(lane, "fix: owner follow-up (F1)")
        with self.assertRaisesRegex(SwarmError, "commits you do not have"):
            lifecycle.submit(self.worker, "F1", lane, repo_url=str(self.arc), base_branch="integration/beta-next")
        self.assertEqual(git(self.arc, "rev-parse", branch), fix)
        git(lane, "pull", "--quiet", "--rebase", str(self.arc), branch)
        lifecycle.submit(self.worker, "F1", lane, repo_url=str(self.arc), base_branch="integration/beta-next")
        git(self.arc, "merge-base", "--is-ancestor", fix, branch)  # raises if the fix was lost

    def test_submit_may_rewrite_the_owners_own_branch(self):
        lane, branch = self._submitted_lane()
        lifecycle.status(self.integrator, "F1", "in-progress", "check train T1: E0308")
        (lane / "fix.txt").write_text("fixed properly\n")
        git(lane, "commit", "--quiet", "--amend", "-a", "--no-edit")
        lifecycle.submit(self.worker, "F1", lane, repo_url=str(self.arc), base_branch="integration/beta-next")
        self.assertEqual(git(self.arc, "rev-parse", branch), git(lane, "rev-parse", "HEAD"))

    def test_owner_hears_when_the_integrator_fixes_a_lane_in_place(self):
        self._submitted_lane()
        lifecycle.status(self.integrator, "F1", "in-progress", "check train T1: E0308")
        msgs.inbox(self.worker)  # the bounce
        lifecycle.status(self.integrator, "F1", "submitted", "fixed the E0308 in place")
        subjects = [m["subject"] for m in msgs.inbox(self.worker)]
        self.assertEqual(subjects, ["F1 fixed in place by the integrator"])

    def test_submit_without_commits_refused(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.tmp / "lanes", base_branch="integration/beta-next")
        with self.assertRaisesRegex(SwarmError, "no commits"):
            lifecycle.submit(self.worker, "F1", lane, repo_url=str(self.arc), base_branch="integration/beta-next")


if __name__ == "__main__":
    unittest.main()
