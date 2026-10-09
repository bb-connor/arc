import json
import os
import subprocess
import time
import unittest
from unittest import mock

from support import SwarmCase, git

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

    # Final review ruling: build scripts and proc macros run with the build's environment; keep credentials out.
    def test_build_env_drops_credentials(self):
        env = build.build_env({"PATH": "/bin", "GH_TOKEN": "gho_x", "GITHUB_TOKEN": "ghs_y",
                               "OPENROUTER_API_KEY": "sk-or-z", "AWS_SECRET_ACCESS_KEY": "s"})
        self.assertEqual(env["PATH"], "/bin")
        self.assertFalse({"GH_TOKEN", "GITHUB_TOKEN", "OPENROUTER_API_KEY", "AWS_SECRET_ACCESS_KEY"} & set(env))

    def test_build_env_disables_incremental_and_uses_sccache(self):
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/sccache"):
            env = build.build_env({"PATH": "/bin"})
        self.assertEqual((env["RUSTC_WRAPPER"], env["CARGO_INCREMENTAL"]), ("sccache", "0"))

    def test_run_records_wait(self):
        with mock.patch.dict(os.environ, {"SWARM_BUILD_CGROUP": "0", "SWARM_BUILD_DISK_FLOOR_GB": "0"}):
            self.assertEqual(build.run(["true"], item="F1"), 0)
        record = json.loads((build.slot_dir() / "waits.log").read_text().splitlines()[-1])
        self.assertEqual((record["item"], record["slot"], record["class"]), ("F1", 1, "coder"))  # slot 0 is the integrator's


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


class ResolveShaTest(SwarmCase):
    def test_resolves_branch_and_passes_full_sha_through(self):
        arc, _ = self.make_arc()
        head = git(arc, "rev-parse", "integration/beta-next")
        self.assertEqual(ci.resolve_sha("integration/beta-next", str(arc)), head)
        self.assertEqual(ci.resolve_sha(head, str(arc)), head)

    def test_unknown_branch_raises(self):
        arc, _ = self.make_arc()
        with self.assertRaises(ci.CIError):
            ci.resolve_sha("lane/missing", str(arc))


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


class SchedulerTest(SwarmCase):
    def test_coders_never_take_the_integrator_slot(self):
        self.assertEqual(build.slots_for("integrator", 3), [0, 1, 2])
        self.assertEqual(build.slots_for("coder", 3), [1, 2])
        self.assertEqual(build.slots_for("coder", 1), [0])

    def test_coder_waits_while_integrator_slot_is_free(self):
        held = os.open(build.slot_dir() / "slot-1.lock", os.O_RDWR | os.O_CREAT, 0o644)
        build.fcntl.flock(held, build.fcntl.LOCK_EX)
        try:
            with self.assertRaises(TimeoutError):
                build.acquire(build.slots_for("coder", 2), poll=0.01, timeout=0.05)
            fd, slot, _ = build.acquire(build.slots_for("integrator", 2), poll=0.01, timeout=1)
            self.assertEqual(slot, 0)
            build.release(fd)
        finally:
            build.release(held)

    def test_jobs_are_capped_per_slot(self):
        with mock.patch.dict(os.environ, {"SWARM_BUILD_JOBS": "5"}):
            self.assertEqual(build.build_env({})["CARGO_BUILD_JOBS"], "5")
            self.assertEqual(build.build_env({"CARGO_BUILD_JOBS": "3"})["CARGO_BUILD_JOBS"], "3")
            self.assertEqual(build.build_env({"CARGO_BUILD_JOBS": "8"})["CARGO_BUILD_JOBS"], "5")

    def test_cpu_weight_follows_class(self):
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/systemd-run"):
            self.assertIn("CPUWeight=20", build.scope_prefix("coder"))
            self.assertIn("CPUWeight=100", build.scope_prefix("integrator"))

    def test_disk_floor_refuses_before_taking_a_slot(self):
        usage = build.shutil._ntuple_diskusage(100 * 2**30, 90 * 2**30, 10 * 2**30)
        with mock.patch.object(build.shutil, "disk_usage", return_value=usage), \
                mock.patch.dict(os.environ, {"SWARM_BUILD_CGROUP": "0", "SWARM_BUILD_DISK_FLOOR_GB": "25"}):
            with self.assertRaisesRegex(build.BuildRefused, "10.0 GB free, floor 25 GB"):
                build.run(["true"], item="F1")
        self.assertFalse((build.slot_dir() / "waits.log").exists())

    def test_default_class_comes_from_role(self):
        self.assertEqual(build.class_for_role("integrator"), "integrator")
        self.assertEqual(build.class_for_role("security"), "integrator")
        self.assertEqual(build.class_for_role("conductor"), "integrator")
        self.assertEqual(build.class_for_role("worker"), "coder")
        self.assertEqual(build.class_for_role(""), "coder")


class PruneTest(SwarmCase):
    def make_target(self):
        target = self.tmp / "target"
        deps = target / "debug" / "deps"
        deps.mkdir(parents=True)
        (target / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n")
        (target / "debug" / ".cargo-lock").write_text("")
        old, new = deps / "libold.rlib", deps / "libnew.rlib"
        old.write_bytes(b"x" * 1000)
        new.write_bytes(b"y" * 10)
        stale = time.time() - 72 * 3600
        os.utime(old, (stale, stale))
        return target, old, new

    def test_prunes_only_files_not_accessed_within_the_window(self):
        target, old, new = self.make_target()
        self.assertEqual(build.prune_target(target, older_than_hours=48, dry_run=True), (1, 1000, []))
        self.assertTrue(old.exists())
        self.assertEqual(build.prune_target(target, older_than_hours=48), (1, 1000, []))
        self.assertFalse(old.exists())
        self.assertTrue(new.exists())

    def test_skips_a_profile_whose_cargo_lock_is_held(self):
        target, old, _ = self.make_target()
        held = os.open(target / "debug" / ".cargo-lock", os.O_RDWR)
        build.fcntl.flock(held, build.fcntl.LOCK_EX)
        try:
            self.assertEqual(build.prune_target(target, older_than_hours=48), (0, 0, ["debug"]))
            self.assertTrue(old.exists())
        finally:
            build.release(held)

    def test_refuses_directories_that_are_not_cargo_targets(self):
        plain = self.tmp / "notatarget"
        plain.mkdir()
        with self.assertRaises(build.BuildRefused):
            build.prune_target(plain, older_than_hours=48)


class HostMarkerTest(SwarmCase):
    def test_accepts_a_target_marked_only_by_rustc_info(self):
        target = self.tmp / "target"
        (target / "debug" / "deps").mkdir(parents=True)
        (target / ".rustc_info.json").write_text("{}")
        self.assertEqual(build.prune_target(target, older_than_hours=48), (0, 0, []))

    def test_sccache_can_be_switched_off(self):
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/sccache"), \
                mock.patch.dict(os.environ, {"SWARM_SCCACHE": "0"}):
            self.assertNotIn("RUSTC_WRAPPER", build.build_env({}))


class HostSettingsTest(SwarmCase):
    def test_host_file_supplies_defaults_and_env_overrides_it(self):
        host = self.tmp / "build.env"
        host.write_text("# host build settings\nSWARM_SCCACHE=0\nSWARM_BUILD_JOBS=3\n")
        with mock.patch.dict(os.environ, {"SWARM_BUILD_ENV": str(host)}), \
                mock.patch.object(build.shutil, "which", return_value="/usr/bin/sccache"):
            env = build.build_env({})
            self.assertNotIn("RUSTC_WRAPPER", env)
            self.assertEqual(env["CARGO_BUILD_JOBS"], "3")
            with mock.patch.dict(os.environ, {"SWARM_BUILD_JOBS": "4"}):
                self.assertEqual(build.build_env({})["CARGO_BUILD_JOBS"], "4")


class RunCaptureTest(SwarmCase):
    def test_run_in_a_directory_capturing_output_to_a_log(self):
        log = self.tmp / "logs" / "check.log"
        with mock.patch.dict(os.environ, {"SWARM_BUILD_CGROUP": "0", "SWARM_BUILD_DISK_FLOOR_GB": "0"}):
            code = build.run(["sh", "-c", "pwd; echo built; exit 3"], item="T1", build_class="integrator",
                             cwd=self.tmp, log_path=log)
        self.assertEqual(code, 3)
        self.assertEqual(log.read_text().split(), [str(self.tmp.resolve()), "built"])
