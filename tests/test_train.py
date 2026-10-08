import json
import unittest
from pathlib import Path

from support import SwarmCase, commit_all, git

from swarmlib import agents, claims, items, msgs, train
from swarmlib.store import SwarmError

WORKSPACE = {
    "Cargo.toml": '[workspace]\nmembers = ["crates/a", "crates/b"]\n',
    "crates/a/Cargo.toml": '[package]\nname = "crate-a"\nversion = "0.1.0"\n',
    "crates/a/src/lib.rs": "pub fn a() -> u32 {\n    1\n}\n",
    "crates/b/Cargo.toml": '[package]\nname = "crate-b"\nversion = "0.1.0"\n',
    "crates/b/src/lib.rs": "pub fn b() -> u32 {\n    2\n}\n",
}


def write_tree(root: Path, files: dict) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def compiler_error(file_name, message="cannot find value `x`"):
    return json.dumps({"reason": "compiler-message", "message": {
        "level": "error", "message": message, "rendered": f"error: {message}\n --> {file_name}:2:5\n",
        "spans": [{"file_name": file_name, "is_primary": True}]}})


class WorkspaceCase(SwarmCase):
    """An arc remote whose integration branch holds a two-crate workspace, plus lane-branch helpers."""

    def setUp(self):
        super().setUp()
        self.arc, self.repo = self.make_arc()
        self.author = self.tmp / "author"
        git(self.tmp, "clone", "--quiet", "--branch", "integration/beta-next", str(self.arc), str(self.author))
        write_tree(self.author, WORKSPACE)
        commit_all(self.author, "workspace")
        git(self.author, "push", "--quiet", "origin", "integration/beta-next")

    def push_lane(self, branch: str, files: dict) -> str:
        git(self.author, "checkout", "--quiet", "-B", branch, "origin/integration/beta-next")
        write_tree(self.author, files)
        head = commit_all(self.author, f"work on {branch}")
        git(self.author, "push", "--quiet", "--force", "origin", branch)
        return head


class CrateMapTest(unittest.TestCase):
    def test_package_name_and_crate_lookup(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        write_tree(root, WORKSPACE)
        self.assertEqual(train.crate_of(root, "crates/a/src/lib.rs"), "crate-a")
        self.assertEqual(train.crate_of(root, "crates/b/Cargo.toml"), "crate-b")
        self.assertIsNone(train.crate_of(root, "Cargo.toml"))  # workspace manifest, no [package]
        self.assertIsNone(train.crate_of(root, "docs/notes.md"))


class DiagnosticsTest(unittest.TestCase):
    def test_errors_only_with_primary_span_files(self):
        warning = json.dumps({"reason": "compiler-message", "message": {
            "level": "warning", "message": "unused", "rendered": "warning: unused",
            "spans": [{"file_name": "crates/a/src/lib.rs", "is_primary": True}]}})
        output = "\n".join([
            "   Compiling crate-a v0.1.0",
            compiler_error("crates/b/src/lib.rs"),
            warning,
            compiler_error("/work/train/crates/a/src/lib.rs", "mismatched types"),
            json.dumps({"reason": "build-finished", "success": False}),
        ])
        found = train.diagnostics(output, Path("/work/train"))
        self.assertEqual([f for f, _ in found], ["crates/b/src/lib.rs", "crates/a/src/lib.rs"])
        self.assertIn("mismatched types", found[1][1])


class AttributionTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.root = Path(tempfile.mkdtemp())
        write_tree(self.root, WORKSPACE)
        self.a = train.Lane("A", "lane/A-x", "w1", changed=["crates/a/src/lib.rs"], merged=True)
        self.b = train.Lane("B", "lane/B-x", "w2", changed=["crates/b/src/lib.rs"], merged=True)
        self.c = train.Lane("C", "lane/C-x", "w3", changed=["crates/a/src/lib.rs"], conflict=["crates/a/src/lib.rs"])

    def test_file_then_crate_then_unattributed(self):
        per_lane, loose = train.attribute(
            [self.a, self.b, self.c], self.root,
            [("crates/b/src/lib.rs", "E1"), ("crates/a/src/other.rs", "E2"), ("tools/x.rs", "E3")],
            {"crate-a": "test a::t failed"},
        )
        self.assertEqual(per_lane, {"B": ["E1"], "A": ["E2", "test a::t failed"]})
        self.assertEqual(loose, ["E3"])  # C never merged, so it is never blamed


class RemoteCommandTest(unittest.TestCase):
    def test_reruns_itself_on_the_train_host_with_the_callers_identity(self):
        command = train.remote_command("builder", agent="codex-ws2-integrator", role="integrator", vendor="codex",
                                       args=["--land", "--max-lanes", "6"])
        self.assertEqual(command[:4], ["ssh", "-o", "BatchMode=yes", "builder"])
        script = command[4]
        self.assertIn(". ~/.swarm/env", script)
        self.assertIn("SWARM_AGENT=codex-ws2-integrator", script)
        self.assertIn("SWARM_ROLE=integrator", script)
        self.assertTrue(script.endswith("~/.local/bin/swarm check-train --local --land --max-lanes 6"))

    def test_hostile_arguments_stay_quoted(self):
        script = train.remote_command("builder", agent="a", role="integrator", vendor="codex", args=["$(rm -rf ~)"])[4]
        self.assertIn("'$(rm -rf ~)'", script)


class ComposeTest(WorkspaceCase):
    def test_merges_clean_lanes_and_reports_conflicts(self):
        self.push_lane("lane/A-a", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    10\n}\n"})
        self.push_lane("lane/B-b", {"crates/b/src/lib.rs": "pub fn b() -> u32 {\n    20\n}\n"})
        self.push_lane("lane/C-c", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    11\n}\n"})
        lanes = [train.Lane("A", "lane/A-a", "w1"), train.Lane("B", "lane/B-b", "w2"),
                 train.Lane("C", "lane/C-c", "w3"), train.Lane("D", "lane/D-missing", "w4")]
        workdir = self.tmp / "train-1"
        base = train.compose(self.repo, workdir, "integration/beta-next", lanes,
                             repo_url=str(self.arc), identity="codex-ws2-integrator")
        self.assertEqual(base, git(self.arc, "rev-parse", "integration/beta-next"))
        self.assertEqual([lane.merged for lane in lanes], [True, True, False, False])
        self.assertEqual(lanes[0].changed, ["crates/a/src/lib.rs"])
        self.assertEqual(lanes[2].conflict, ["crates/a/src/lib.rs"])
        self.assertEqual(lanes[3].conflict, ["(branch not on remote)"])
        self.assertIn("10", (workdir / "crates/a/src/lib.rs").read_text())
        self.assertIn("20", (workdir / "crates/b/src/lib.rs").read_text())
        self.assertEqual(git(workdir, "status", "--porcelain"), "")  # aborted merge leaves a clean tree



class FakeCargo:
    """Stands in for build-slot cargo: canned diagnostics per subcommand, failing crates for cargo test."""

    def __init__(self, errors=None, failing_tests=(), silent_check_failure=False):
        self.errors = errors or {}
        self.failing_tests = set(failing_tests)
        self.silent_check_failure = silent_check_failure
        self.commands = []

    def __call__(self, command, cwd, log):
        self.commands.append(command)
        sub = command[1]
        lines, code = [], 0
        if sub == "check" and self.silent_check_failure:
            lines, code = ["error: could not compile (linker failed)"], 101
        for file_name, message in self.errors.get(sub, []):
            lines.append(compiler_error(file_name, message))
            code = 101
        if sub == "test" and command[3] in self.failing_tests:
            lines, code = [f"test {command[3]}::t ... FAILED", "test result: FAILED. 0 passed; 1 failed"], 101
        output = "\n".join(lines)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(output)
        return code, output


class FakeGh:
    def __init__(self, busy):
        self.busy = busy

    def __call__(self, args):
        import subprocess
        status = "in_progress" if self.busy else "completed"
        return subprocess.CompletedProcess(args, 0, json.dumps([{"status": status}]), "")


class RunTrainTest(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.integrator = self.clone("codex-builder-integrator", role="integrator", vendor="codex")
        for agent_id in ("codex-ws2-worker1", "codex-ws2-worker2", "codex-ws2-worker3"):
            worker = self.clone(agent_id)
            agents.register(worker, agent_id=agent_id, machine="ws2", vendor="codex", role="worker",
                            model="m", effort="", tiers=["mid"])

    def submitted(self, item_id, branch, owner, status="submitted"):
        self.add_item(self.conductor, item_id, paths=[])

        def mutate():
            item = items.load(self.conductor, item_id)
            item.meta.update(status=status, branch=branch, owner=owner)
            items.save(self.conductor, item)
            return True

        self.conductor.transact(f"seed {item_id}", mutate)

    def lanes_abc(self):
        self.push_lane("lane/A-a", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    10\n}\n"})
        self.push_lane("lane/B-b", {"crates/b/src/lib.rs": "pub fn b() -> u32 {\n    20\n}\n"})
        self.push_lane("lane/C-c", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    11\n}\n"})
        self.submitted("A", "lane/A-a", "codex-ws2-worker1")
        self.submitted("B", "lane/B-b", "codex-ws2-worker2")
        self.submitted("C", "lane/C-c", "codex-ws2-worker3")

    def run_train(self, cargo, *, land=False, gh=None):
        return train.run_train(self.integrator, repo=self.repo, lanes_dir=self.tmp / "lanes", repo_url=str(self.arc),
                               runner=cargo, land=land, ci_runner=gh)

    def status(self, item_id):
        self.integrator.sync()
        return items.load(self.integrator, item_id).status

    def test_one_build_checks_every_lane_and_returns_only_the_culprits(self):
        self.lanes_abc()
        cargo = FakeCargo(errors={"check": [("crates/b/src/lib.rs", "cannot find value `y`")]})
        result = self.run_train(cargo)
        self.assertEqual((result.green, result.red, result.conflicted, result.landed), (["A"], ["B"], ["C"], ""))
        self.assertEqual(sum(1 for c in cargo.commands if c[1] == "check"), 1)  # one check for the whole train
        self.assertEqual([self.status(i) for i in "ABC"], ["ready", "in-progress", "in-progress"])
        b = items.load(self.integrator, "B")
        self.assertIn(f"## Check train {result.train_id}", b.body)
        self.assertIn("cannot find value `y`", b.body)
        self.assertIn("crates/a/src/lib.rs", items.load(self.integrator, "C").body)
        owner = self.clone("codex-ws2-worker2-reader", role="worker")
        owner.agent = "codex-ws2-worker2"
        self.assertTrue(any("failed check train" in m["subject"] for m in msgs.inbox(owner)))
        self.assertFalse((self.tmp / "lanes" / f"train-{result.train_id}").exists())  # throwaway worktree removed

    def test_a_crate_test_failure_blames_the_lanes_that_touched_it(self):
        self.lanes_abc()
        result = self.run_train(FakeCargo(failing_tests={"crate-a"}))
        self.assertEqual((result.green, result.red), (["B"], ["A"]))

    def test_landing_pushes_an_all_green_train_and_integrates_it(self):
        self.push_lane("lane/A-a", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    10\n}\n"})
        self.push_lane("lane/B-b", {"crates/b/src/lib.rs": "pub fn b() -> u32 {\n    20\n}\n"})
        self.submitted("A", "lane/A-a", "codex-ws2-worker1")
        self.submitted("B", "lane/B-b", "codex-ws2-worker2", status="ready")  # left ready by an earlier train
        claims.reassign(self.conductor, "A", "codex-ws2-worker1")
        result = self.run_train(FakeCargo(), land=True, gh=FakeGh(busy=False))
        self.assertTrue(result.landed)
        self.assertEqual(git(self.arc, "rev-parse", "integration/beta-next"), result.landed)
        self.assertEqual([self.status(i) for i in "AB"], ["integrated", "integrated"])
        self.assertIsNone(claims.read(self.integrator, "A"))

    def test_a_red_lane_blocks_landing_and_keeps_green_lanes_ready(self):
        self.lanes_abc()
        before = git(self.arc, "rev-parse", "integration/beta-next")
        result = self.run_train(FakeCargo(errors={"clippy": [("crates/b/src/lib.rs", "needless return")]}), land=True,
                                gh=FakeGh(busy=False))
        self.assertEqual(result.landed, "")
        self.assertEqual(git(self.arc, "rev-parse", "integration/beta-next"), before)
        self.assertEqual(self.status("A"), "ready")

    def test_busy_ci_defers_landing(self):
        self.push_lane("lane/A-a", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    10\n}\n"})
        self.submitted("A", "lane/A-a", "codex-ws2-worker1")
        result = self.run_train(FakeCargo(), land=True, gh=FakeGh(busy=True))
        self.assertEqual(result.landed, "")
        self.assertIn("CI", result.note)
        self.assertEqual(self.status("A"), "ready")

    # Review focus: a failure no lane can own must not punish or promote anyone.
    def test_unattributable_failure_changes_no_lane_and_alerts_the_conductor(self):
        self.lanes_abc()
        result = self.run_train(FakeCargo(silent_check_failure=True), land=True, gh=FakeGh(busy=False))
        self.assertTrue(result.loose)
        self.assertEqual([self.status(i) for i in "AB"], ["submitted", "submitted"])
        self.assertEqual(self.status("C"), "in-progress")  # a conflict is still the lane's to fix
        self.conductor.sync()
        self.assertTrue(any("could not attribute" in m["subject"] for m in msgs.inbox(self.conductor)))

    def test_only_integrator_or_conductor_runs_trains_and_empty_trains_do_nothing(self):
        worker = self.clone("codex-ws2-worker9")
        with self.assertRaises(SwarmError):
            train.run_train(worker, repo=self.repo, lanes_dir=self.tmp / "lanes", repo_url=str(self.arc),
                            runner=FakeCargo())
        with self.assertRaisesRegex(SwarmError, "only the integrator lands"):
            train.run_train(self.conductor, repo=self.repo, lanes_dir=self.tmp / "lanes", repo_url=str(self.arc),
                            runner=FakeCargo(), land=True)
        result = self.run_train(FakeCargo())
        self.assertEqual((result.green, result.red, result.conflicted), ([], [], []))
        self.assertFalse((self.tmp / "lanes").exists())

    # Review focus: the base can move between composing and pushing; landing must not rewrite it.
    def test_base_moving_mid_train_refuses_the_push_and_keeps_lanes_ready(self):
        self.push_lane("lane/A-a", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    10\n}\n"})
        self.submitted("A", "lane/A-a", "codex-ws2-worker1")
        cargo = FakeCargo()
        original = cargo.__call__

        def racing(command, cwd, log):
            if command[1] == "check":  # someone lands on the base while the train builds
                git(self.author, "checkout", "--quiet", "-B", "hotfix", "origin/integration/beta-next")
                write_tree(self.author, {"crates/b/src/lib.rs": "pub fn b() -> u32 {\n    3\n}\n"})
                commit_all(self.author, "hotfix")
                git(self.author, "push", "--quiet", "origin", "hotfix:integration/beta-next")
            return original(command, cwd, log)

        result = self.run_train(racing, land=True, gh=FakeGh(busy=False))
        self.assertEqual(result.landed, "")
        self.assertIn("push refused", result.note)
        self.assertEqual(self.status("A"), "ready")

    # Review focus: a build the scheduler refuses (disk floor) must leave every lane exactly as it was.
    def test_refused_build_changes_nothing_and_cleans_up(self):
        self.lanes_abc()

        def refuse(command, cwd, log):
            from swarmlib import build
            raise build.BuildRefused("4.0 GB free, floor 25 GB")

        from swarmlib import build
        with self.assertRaises(build.BuildRefused):
            self.run_train(refuse)
        self.assertEqual([self.status(i) for i in "ABC"], ["submitted", "submitted", "submitted"])
        self.assertEqual(list((self.tmp / "lanes").glob("train-*")), [])
    def test_integrator_can_resubmit_a_lane_it_fixed_in_place(self):
        self.push_lane("lane/A-a", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    10\n}\n"})
        self.submitted("A", "lane/A-a", "codex-ws2-worker1")
        self.run_train(FakeCargo(errors={"check": [("crates/a/src/lib.rs", "E0308")]}))
        from swarmlib import lifecycle
        lifecycle.status(self.integrator, "A", "submitted", "integrator fixed the type error in place")
        self.assertEqual(self.status("A"), "submitted")

    def test_max_lanes_caps_the_train_by_severity(self):
        self.lanes_abc()

        def raise_c():
            item = items.load(self.conductor, "C")
            item.meta["severity"] = "P0"
            items.save(self.conductor, item)
            return True

        self.conductor.transact("sev", raise_c)
        result = train.run_train(self.integrator, repo=self.repo, lanes_dir=self.tmp / "lanes", repo_url=str(self.arc),
                                 runner=FakeCargo(), max_lanes=1)
        self.assertEqual(result.green, ["C"])
        self.assertEqual(self.status("A"), "submitted")


if __name__ == "__main__":
    unittest.main()
