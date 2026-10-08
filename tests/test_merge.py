import json
import subprocess
import unittest

from support import SwarmCase

from swarmlib import agents, items, lifecycle, merge, msgs
from swarmlib.store import SwarmError

HEAD = "f3f70ed5ac9af5b22bcbc2ff73cb091b7cfb5137"
PR = 1200


class FakeGitHub:
    """Answers the gh calls the merge gate makes; records every call."""

    def __init__(self, *, checks=None, codex_rows=None, findings=None, draft=False, state="open", base="main"):
        self.calls = []
        self.pr = {"state": state, "draft": draft, "base": {"ref": base},
                   "head": {"sha": HEAD, "ref": "integration/beta-next"}}
        self.checks = checks if checks is not None else [
            {"name": name, "status": "completed", "conclusion": "success", "started_at": "2026-10-08T10:00:00Z"}
            for name in merge.REQUIRED_CHECKS
        ]
        rows = codex_rows if codex_rows is not None else [f"| Code Review | Completed | `{HEAD[:7]}` | New commits |"]
        self.issue_comments = [{"user": merge.CODEX_BOT, "body": "## Codex Review Summary\n\n" + "\n".join(rows)}]
        self.findings = findings or []

    def __call__(self, args):
        self.calls.append(args)
        joined = " ".join(args)
        if args[:2] == ["gh", "api"]:
            if joined.endswith(f"/pulls/{PR}"):
                return self._ok(json.dumps(self.pr))
            if "/check-runs" in joined:
                return self._ok("\n".join(json.dumps(c) for c in self.checks))
            if f"/issues/{PR}/comments" in joined:
                return self._ok("\n".join(json.dumps(c) for c in self.issue_comments))
            if f"/pulls/{PR}/comments" in joined:
                return self._ok("\n".join(json.dumps(c) for c in self.findings))
        if args[:3] in (["gh", "pr", "merge"], ["gh", "pr", "ready"]):
            return self._ok("")
        raise AssertionError(f"unexpected gh call {args}")

    @staticmethod
    def _ok(stdout):
        return subprocess.CompletedProcess([], 0, stdout, "")


def finding(comment_id, severity="P1"):
    return {"id": comment_id, "user": "chatgpt-codex-connector[bot]", "path": "a.rs", "line": 3,
            "in_reply_to_id": None, "html_url": f"https://example.invalid/{comment_id}",
            "body": f"**![{severity} Badge](x)  Fix the thing**"}


class MergeGateTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.integrator = self.clone("codex-ws2-integrator", role="integrator", vendor="codex")
        self.reviewer = self.clone("claude-ws2-reviewer1", role="reviewer", vendor="claude")
        self.codex_reviewer = self.clone("codex-ws2-reviewer2", role="reviewer", vendor="codex")
        for store in (self.integrator, self.reviewer, self.codex_reviewer):
            agents.register(store, agent_id=store.agent, machine="ws2", vendor=store.vendor, role=store.role,
                            model="m", effort="", tiers=["premium"])

    def accept_pr_review(self, head=HEAD, reviewer=None):
        reviewer = reviewer or self.reviewer
        lifecycle.request_pr_review(self.integrator, PR, head=head, branch="integration/beta-next", author_vendor="codex")
        self.assertEqual(lifecycle.next_review(reviewer), f"PR{PR}")
        lifecycle.verdict(reviewer, f"PR{PR}", "accept", "")

    def test_green_reviewed_pr_merges_without_admin_on_the_exact_head(self):
        self.accept_pr_review()
        gh = FakeGitHub(draft=True)
        self.assertEqual(merge.merge(self.integrator, gh, PR), HEAD)
        merge_call = next(c for c in gh.calls if c[:3] == ["gh", "pr", "merge"])
        self.assertNotIn("--admin", merge_call)
        self.assertEqual(merge_call[merge_call.index("--match-head-commit") + 1], HEAD)
        self.assertTrue(any(c[:3] == ["gh", "pr", "ready"] for c in gh.calls))
        self.conductor.sync()
        notes = [p.read_text() for p in self.conductor.path("msgs", "human").glob("*.md")]
        self.assertTrue(any(f"merged PR #{PR}" in n and HEAD in n for n in notes))

    def test_failing_or_pending_required_check_blocks(self):
        self.accept_pr_review()
        checks = [{"name": n, "status": "completed", "conclusion": "success", "started_at": "2026-10-08T10:00:00Z"}
                  for n in merge.REQUIRED_CHECKS[1:]]
        checks.append({"name": merge.REQUIRED_CHECKS[0], "status": "completed", "conclusion": "failure",
                       "started_at": "2026-10-08T09:00:00Z"})
        _, reasons = merge.gate(self.integrator, FakeGitHub(checks=checks), PR)
        self.assertTrue(any("concluded failure" in r for r in reasons))
        checks.append({"name": merge.REQUIRED_CHECKS[0], "status": "in_progress", "conclusion": None,
                       "started_at": "2026-10-08T11:00:00Z"})
        _, reasons = merge.gate(self.integrator, FakeGitHub(checks=checks), PR)
        self.assertTrue(any("still in_progress" in r for r in reasons))

    def test_codex_review_must_cover_the_head_commit(self):
        self.accept_pr_review()
        stale = FakeGitHub(codex_rows=["| Code Review | Completed | `0123abc` | New commits |"])
        _, reasons = merge.gate(self.integrator, stale, PR)
        self.assertIn(f"Codex review has not completed on {HEAD[:7]}", reasons)

    def test_open_blocking_finding_blocks_until_integrated_or_reasoned_wontfix(self):
        self.accept_pr_review()
        gh = FakeGitHub(findings=[finding(11, "P1"), finding(12, "P3")])
        _, reasons = merge.gate(self.integrator, gh, PR)
        self.assertTrue(any(f"R{PR}-11" in r and "not imported" in r for r in reasons))
        self.assertFalse(any(f"R{PR}-12" in r for r in reasons))  # P3 does not block
        janitor = self.clone("hermes-ws2-janitor1", role="janitor", vendor="hermes")
        from swarmlib import reviews
        reviews.import_reviews(janitor, gh, PR)
        _, reasons = merge.gate(self.integrator, gh, PR)
        self.assertTrue(any(f"R{PR}-11 is open" in r for r in reasons))
        lifecycle.status(self.conductor, f"R{PR}-11", "wontfix")
        _, reasons = merge.gate(self.integrator, gh, PR)
        self.assertTrue(any("without a recorded reason" in r for r in reasons))
        lifecycle.status(self.conductor, f"R{PR}-11", "open")
        lifecycle.status(self.conductor, f"R{PR}-11", "wontfix", "bot misread the lock order; see decision 0003")
        _, reasons = merge.gate(self.integrator, gh, PR)
        self.assertEqual(reasons, [])

    def test_whole_pr_review_must_match_head_and_be_cross_vendor(self):
        _, reasons = merge.gate(self.integrator, FakeGitHub(), PR)
        self.assertTrue(any("no whole-PR review item" in r for r in reasons))
        self.accept_pr_review(head="0" * 40)
        _, reasons = merge.gate(self.integrator, FakeGitHub(), PR)
        self.assertTrue(any("not head" in r for r in reasons))

    def test_same_vendor_review_cannot_satisfy_the_gate(self):
        lifecycle.request_pr_review(self.integrator, PR, head=HEAD, branch="integration/beta-next", author_vendor="codex")
        self.assertIsNone(lifecycle.next_review(self.codex_reviewer))
        lifecycle.verdict(self.conductor, f"PR{PR}", "accept", "")  # conductor override, reviewer recorded as nobody
        _, reasons = merge.gate(self.integrator, FakeGitHub(), PR)
        self.assertTrue(any("cross-vendor" in r for r in reasons))

    def test_closed_or_wrong_base_pr_refused(self):
        self.accept_pr_review()
        _, reasons = merge.gate(self.integrator, FakeGitHub(state="closed", base="release"), PR)
        self.assertIn(f"PR #{PR} is closed", reasons)
        self.assertIn(f"PR #{PR} targets release, not main", reasons)

    def test_only_integrator_or_conductor_may_merge_and_refusal_does_not_call_merge(self):
        worker = self.clone("codex-ws2-worker1")
        with self.assertRaises(SwarmError):
            merge.merge(worker, FakeGitHub(), PR)
        gh = FakeGitHub()
        with self.assertRaisesRegex(SwarmError, "not mergeable"):
            merge.merge(self.integrator, gh, PR)
        self.assertFalse(any(c[:3] == ["gh", "pr", "merge"] for c in gh.calls))

    def test_new_head_resets_the_review(self):
        self.accept_pr_review()
        lifecycle.request_pr_review(self.integrator, PR, head="1" * 40, branch="integration/beta-next", author_vendor="codex")
        self.integrator.sync()
        item = items.load(self.integrator, f"PR{PR}")
        self.assertEqual((item.status, item.meta["review"]["verdict"], item.meta["commits"]), ("review", "", ["1" * 12]))


if __name__ == "__main__":
    unittest.main()
