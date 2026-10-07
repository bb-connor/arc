import json
import os
import subprocess
import unittest
from unittest import mock

from support import SwarmCase

from swarmlib import build, ci, items, reviews


class BuildTest(SwarmCase):
    def test_slot_exhaustion_waits_then_times_out(self):
        fd, slot, waited = build.acquire(1, poll=0.01)
        self.assertEqual(slot, 0)
        with self.assertRaises(TimeoutError):
            build.acquire(1, poll=0.01, timeout=0.05)
        build.release(fd)
        fd2, _, _ = build.acquire(1, poll=0.01, timeout=1)
        build.release(fd2)

    def test_second_slot_used_when_first_busy(self):
        fd, _, _ = build.acquire(2, poll=0.01)
        fd2, slot, _ = build.acquire(2, poll=0.01, timeout=1)
        self.assertEqual(slot, 1)
        build.release(fd)
        build.release(fd2)

    def test_scope_prefix_respects_switch_and_availability(self):
        with mock.patch.dict(os.environ, {"SWARM_BUILD_CGROUP": "0"}):
            self.assertEqual(build.scope_prefix(), [])
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/systemd-run"):
            prefix = build.scope_prefix()
        self.assertEqual(prefix[:3], ["systemd-run", "--user", "--scope"])
        self.assertIn("CPUWeight=20", prefix)
        self.assertIn("MemoryMax=14G", prefix)

    def test_build_env_disables_incremental_and_uses_sccache(self):
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/sccache"):
            env = build.build_env({"PATH": "/bin"})
        self.assertEqual((env["RUSTC_WRAPPER"], env["CARGO_INCREMENTAL"]), ("sccache", "0"))

    def test_run_records_wait(self):
        with mock.patch.dict(os.environ, {"SWARM_BUILD_CGROUP": "0"}):
            self.assertEqual(build.run(["true"], item="F1"), 0)
        record = json.loads((build.slot_dir() / "waits.log").read_text().splitlines()[-1])
        self.assertEqual((record["item"], record["slot"]), ("F1", 0))


class FakeGh:
    """Records gh invocations and answers from a script of (prefix, stdout, returncode)."""

    def __init__(self, script):
        self.script, self.calls = script, []

    def __call__(self, args):
        self.calls.append(args)
        for prefix, stdout, code in self.script:
            if args[: len(prefix)] == prefix:
                return subprocess.CompletedProcess(args, code, stdout, "")
        raise AssertionError(f"unexpected gh call {args}")


class CITest(unittest.TestCase):
    def test_dispatch_always_targets_main_and_carries_nonce(self):
        gh = FakeGh([(["gh", "workflow", "run"], "", 0)])
        nonce = ci.dispatch(gh, item="F1", target_ref="lane/F1-x", packages=["chio-kernel", "chio-core"],
                            test_filter="recovery", features="")
        call = gh.calls[0]
        self.assertEqual(call[call.index("--ref") + 1], "main")
        self.assertIn("target_ref=lane/F1-x", call)
        self.assertIn("packages=chio-kernel chio-core", call)
        self.assertIn(f"nonce={nonce}", call)

    def test_find_run_matches_nonce(self):
        runs = [{"databaseId": 1, "displayTitle": "lane-test F0 aaa", "url": "u1"},
                {"databaseId": 2, "displayTitle": "lane-test F1 abc123", "url": "u2"}]
        gh = FakeGh([(["gh", "run", "list"], json.dumps(runs), 0)])
        self.assertEqual(ci.find_run(gh, "abc123", sleep=lambda _s: None), (2, "u2"))

    def test_capacity_counts_active_runs(self):
        runs = [{"status": "queued"}, {"status": "in_progress"}, {"status": "completed"}]
        gh = FakeGh([(["gh", "run", "list"], json.dumps(runs), 0)])
        self.assertEqual(ci.in_flight(gh), 2)

    def test_green_rate_ignores_cancelled(self):
        runs = [{"status": "completed", "conclusion": c} for c in ("success", "failure", "cancelled", "success")]
        gh = FakeGh([(["gh", "run", "list"], json.dumps(runs), 0)])
        self.assertAlmostEqual(ci.green_rate(gh, "integration/beta-next"), 2 / 3)

    def test_gh_failure_raises(self):
        gh = FakeGh([(["gh"], "", 1)])
        with self.assertRaises(ci.CIError):
            ci.in_flight(gh)


class ReviewsTest(SwarmCase):
    COMMENTS = [
        {"id": 11, "user": "chatgpt-codex-connector[bot]", "path": "crates/a/src/lib.rs", "line": 7, "in_reply_to_id": None,
         "html_url": "https://example.invalid/r11",
         "body": "**<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub>  Guard the retry**\n\nDetails."},
        {"id": 12, "user": "greptile-apps[bot]", "path": "crates/b/src/x.rs", "line": 3, "in_reply_to_id": None,
         "html_url": "https://example.invalid/r12", "body": "<img alt=\"P2\" src=\"x.svg\"> **Resync passes amplify lag**"},
        {"id": 13, "user": "bb-connor", "path": "a", "line": 1, "in_reply_to_id": None, "html_url": "u", "body": "human"},
        {"id": 14, "user": "greptile-apps[bot]", "path": "a", "line": 1, "in_reply_to_id": 12, "html_url": "u", "body": "reply"},
    ]

    def test_import_creates_items_once(self):
        janitor = self.clone("hermes-ws2-janitor1", role="janitor", vendor="hermes")
        raw = "\n".join(json.dumps(c) for c in self.COMMENTS)
        gh = FakeGh([(["gh", "api"], raw, 0)])
        self.assertEqual(reviews.import_reviews(janitor, gh, 1180), ["R1180-11", "R1180-12"])
        self.assertEqual(reviews.import_reviews(janitor, gh, 1180), [])
        janitor.sync()
        first = items.load(janitor, "R1180-11")
        self.assertEqual((first.meta["severity"], first.meta["tier"]), ("P1", "premium"))
        self.assertEqual(first.meta["title"], "Guard the retry")
        self.assertEqual(items.load(janitor, "R1180-12").meta["title"], "Resync passes amplify lag")

    def test_workers_cannot_import(self):
        worker = self.clone("codex-ws2-worker1")
        with self.assertRaises(reviews.SwarmError):
            reviews.import_reviews(worker, FakeGh([]), 1)


if __name__ == "__main__":
    unittest.main()
