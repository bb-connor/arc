"""Owning path-policy controls for the ordinary Cargo evidence producer."""
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).absolute().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OrdinaryExecutionLimitTest(unittest.TestCase):
    def setUp(self):
        self.producer = load("ordinary_limit_producer", ROOT/"scripts/compiled-gate-profiles.py")
        self.recorder = load("ordinary_limit_recorder", ROOT/"scripts/record-rust-compilation.py")

    def exercise(self, timeout, free=10*1024**3, accepted=True):
        evidence = ROOT/"target/explicit-execution-budget"
        runtime, host, environment = {}, {}, {}
        configuration = evidence/"host-execution.json"
        verifier = SimpleNamespace(gate_catalog=lambda: {"contracts": {"command": ["owned-command"]}})
        argv = ["compiled-gate-profiles.py", "--evidence", str(evidence)]
        if timeout is not None:
            argv.extend(["--timeout", str(timeout)])
        with (mock.patch.object(sys, "argv", argv),
              mock.patch.object(self.producer, "load", side_effect=[verifier, self.recorder]),
              mock.patch.object(self.producer.shutil, "disk_usage", return_value=SimpleNamespace(free=free)),
              mock.patch.object(self.producer.resource, "getrlimit", return_value=(16384, 16384)),
              mock.patch.object(self.producer.resource, "setrlimit"),
              mock.patch.object(self.producer, "create_evidence", return_value=evidence) as create,
              mock.patch.object(self.producer, "inventory", return_value=runtime),
              mock.patch.object(self.producer, "write"),
              mock.patch.object(self.producer, "prepare_host", return_value=(host, configuration, environment)),
              mock.patch.object(self.producer, "execute", return_value=({}, runtime)) as execute,
              mock.patch.object(self.producer, "export") as export):
            if not accepted:
                with self.assertRaisesRegex(self.recorder.Refusal, "host_execution_limits"):
                    self.producer.main()
                create.assert_not_called()
                execute.assert_not_called()
                export.assert_not_called()
            else:
                self.producer.main()
                expected = 1800 if timeout is None else timeout
                self.assertEqual(execute.call_args.args[-1], expected)
                self.assertEqual(export.call_args.args[-1], expected)
                create.assert_called_once()
                execute.assert_called_once()
                export.assert_called_once()

    def test_default_and_explicit_finite_budgets_reach_producer_and_inspector(self):
        for timeout in (None, 1, 7200, 7201, 21600):
            with self.subTest(timeout=timeout):
                self.exercise(timeout)

    def test_invalid_budgets_and_disk_floor_refuse_before_evidence_creation(self):
        for timeout in (-1, 0, 21601):
            with self.subTest(timeout=timeout):
                self.exercise(timeout, accepted=False)
        self.exercise(21600, free=10*1024**3-1, accepted=False)


class OrdinaryEvidencePathTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root/"target").mkdir()
        self.producer = load("ordinary_producer", ROOT/"scripts/compiled-gate-profiles.py")
        self.recorder = load("ordinary_recorder", ROOT/"scripts/record-rust-compilation.py")

    def create(self, path):
        operation = getattr(self.producer, "create_evidence", None)
        self.assertIsNotNone(operation, "producer must validate evidence components before mutation")
        return operation(self.root, path, self.recorder)

    def test_export_refuses_instrumentation_error_after_nonzero_compiler_exit(self):
        namespace = self.root / "target/namespace"
        records = namespace / "records"
        records.mkdir(parents=True)
        (records / "failed.json").write_text(json.dumps({"status": "compiler_failed", "compiler_exit": 1,
                                                        "refusal": "unexpected_compiler_output"}))
        with self.assertRaisesRegex(self.recorder.Refusal, "host_compilation_failed"):
            self.producer.export(self.root, self.root/"target", None, {}, {},
                                 {"namespace": str(namespace)}, {}, None, self.recorder, 30)

    def test_parent_traversal_never_creates_outside_evidence(self):
        with self.assertRaisesRegex(self.recorder.Refusal, "parent_traversal"):
            self.create(self.root/"target/../outside")
        self.assertFalse((self.root/"outside").exists())

    def test_symlink_ancestor_never_creates_outside_evidence(self):
        outside = self.root/"outside"
        outside.mkdir()
        (self.root/"target/hop").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(self.recorder.Refusal):
            self.create(self.root/"target/hop/evidence")
        self.assertFalse((outside/"evidence").exists())

    def test_fresh_nested_evidence_preserves_existing_directory(self):
        result = self.create(self.root/"target/parent/evidence")
        self.assertTrue(result.is_dir())
        (result/"original").write_text("preserved")
        with self.assertRaises((self.recorder.Refusal, FileExistsError)):
            self.create(result)
        self.assertEqual((result/"original").read_text(), "preserved")


class OrdinaryToolRetentionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.namespace = Path(self.temporary.name).resolve()
        (self.namespace/"artifacts").mkdir()
        self.verifier = load("ordinary_verifier", ROOT/"scripts/verify-recovery-qualification.py")
        self.body = b"selected ordinary compiler tool"
        self.image = {"sha256": hashlib.sha256(self.body).hexdigest(), "size": len(self.body)}
        self.completed = {(self.image["sha256"], self.image["size"])}
        self.path = self.namespace/"artifacts"/self.image["sha256"]

    def test_tool_bytes_must_be_in_completed_retention_batch(self):
        self.path.write_bytes(self.body)
        with self.assertRaisesRegex(ValueError, "compiled_host_tool_batch"):
            self.verifier.audit_ordinary_host_tool_image(self.namespace, self.image, set())
        self.verifier.audit_ordinary_host_tool_image(self.namespace, self.image, self.completed)

    def test_missing_or_substituted_tool_bytes_are_rejected(self):
        with self.assertRaises((ValueError, OSError)):
            self.verifier.audit_ordinary_host_tool_image(self.namespace, self.image, self.completed)
        self.path.write_bytes(b"x"*len(self.body))
        with self.assertRaisesRegex(ValueError, "compiled_host_tool_image"):
            self.verifier.audit_ordinary_host_tool_image(self.namespace, self.image, self.completed)


class OrdinaryBoundSourcesTest(unittest.TestCase):
    def test_candidate_alias_does_not_authorize_target(self):
        recorder = load("ordinary_bound_recorder", ROOT/"scripts/record-rust-compilation.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root/"source").write_text("actual source")
            (root/"alias").symlink_to(root/"source")
            host = {"repository": str(root), "candidate_sources": {str(root/"source"): "a"*64, str(root/"alias"): "a"*64}}
            self.assertEqual(recorder.ordinary_candidate_files(host), [root/"source"])

    def test_consumer_rejects_conflicting_triples_at_same_tool_path(self):
        verifier = load("ordinary_metadata_verifier", ROOT/"scripts/verify-recovery-qualification.py")
        repository, namespace = Path("/candidate"), Path("/candidate/target/namespace")
        sources = [{"path": "Cargo.toml", "sha256": "c"*64}]
        binding = verifier.binding(sources, None)
        runtime = {"source_inventory_version": verifier.INVENTORY_VERSION, "base_commit": None,
                   "sources": sources, "source_binding": binding}
        blobs = {}
        def retain(value, role, path):
            body = json.dumps(value, sort_keys=True).encode()
            digest = hashlib.sha256(body).hexdigest()
            blobs[digest] = body
            return {"path": path, "sha256": digest, "size": len(body), "role": role}
        runtime_ref = retain(runtime, "host-source-inventory", "/candidate/target/runtime.json")
        host = {"schema": "chio.ordinary-host-execution.v1", "repository": str(repository), "namespace": str(namespace),
                "source_binding": binding, "target_directory": "/candidate/target/fresh", "target": "aarch64-apple-darwin",
                "machine": "arm64", "compiler": "/tool/bin/rustc", "cargo": "/tool/bin/cargo", "linker": "/sdk/bin/clang",
                "sdk": "/sdk", "toolchain": "/tool", "images": [{"path": "/tool/bin/cargo", "sha256": "a"*64, "size": 1, "purpose": "cargo"}],
                "aliases": [], "vendor_roots": ["/vendor"],
                "runtime_inventory": {key: runtime_ref[key] for key in ["path", "sha256", "size"]},
                "runtime_metadata": {"coverage": "ordinary-host-observation-no-retained-os-image-coverage", "system": "Darwin",
                    "release": "observed", "version": "observed", "macos_version": "observed", "shared_cache_file_metadata": []}}
        def audit():
            reference = retain(host, "host-execution-declaration", "/candidate/target/host.json")
            row = {"kind": "probe", "status": "success", "inputs": [reference, runtime_ref], "semantics": {
                "host_execution": {"schema": "chio.ordinary-host-invocation.v1", "declaration": reference,
                                   "loader_paths": {}, "tooling_checks": None}}}
            verifier.audit_ordinary_host_metadata([row], repository, namespace, binding, lambda item: blobs[item["sha256"]], lambda item: None)
        audit()
        host["images"].append({**host["images"][0], "sha256": "b"*64})
        with self.assertRaisesRegex(ValueError, "compiled_host_metadata"):
            audit()


class OrdinarySearchDirectoryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.recorder = load("ordinary_search_recorder", ROOT/"scripts/record-rust-compilation.py")
        self.existing = self.directory/"existing.rlib"
        self.existing.write_bytes(b"original")
        self.emissions = {"dep-info": str(self.directory/"unit.d"), "link": str(self.directory/"libunit.rlib")}
        self.lease = self.recorder.OutputLease(self.directory, self.emissions)
        self.addCleanup(self.lease.close)
        self.before = [str(path) for path in self.recorder.tree_files(self.directory)]
        for path in self.emissions.values():
            Path(path).write_bytes(b"actual filesystem emission")

    def test_own_exact_verified_emissions_extend_same_search_directory(self):
        self.lease.produced()
        self.lease.verify_host_search(self.directory, self.before)

    def test_unrelated_new_file_never_extends_search_authority(self):
        (self.directory/"unrelated.rlib").write_bytes(b"unrelated")
        with self.assertRaisesRegex(self.recorder.Refusal, "unexpected_compiler_output"):
            self.lease.verify_host_search(self.directory, self.before)

    def test_prior_search_image_replacement_still_refuses(self):
        self.existing.write_bytes(b"replaced")
        with self.assertRaisesRegex(self.recorder.Refusal, "preexisting_output_changed"):
            self.lease.verify_host_search(self.directory, self.before)


class OrdinaryProcessCleanupTest(unittest.TestCase):
    def exercise(self, *, write_failure=False, cleanup_timeout=False, exited_leader=False, group_survives_term=False):
        producer = load("ordinary_cleanup_producer", ROOT/"scripts/compiled-gate-profiles.py")
        process = mock.Mock(pid=12345, stdout=io.BytesIO())
        process.poll.return_value = 0 if exited_leader else None
        process.wait.return_value = 0 if exited_leader else -9 if cleanup_timeout or group_survives_term else -15
        error = OSError("deliberate owning pipe failure")
        selector = mock.MagicMock()
        selector.__enter__.return_value = selector
        if write_failure:
            selector.select.return_value = [(SimpleNamespace(fd=99, fileobj=process.stdout), 0)]
        else:
            selector.select.side_effect = error
        with tempfile.TemporaryFile() as original_log:
            log = mock.Mock(wraps=original_log)
            if write_failure:
                log.write.side_effect = error
            with mock.patch.object(producer.subprocess, "Popen", return_value=process), \
                 mock.patch.object(producer.selectors, "DefaultSelector", return_value=selector), \
                 mock.patch.object(producer.shutil, "disk_usage", return_value=SimpleNamespace(free=20*1024**3)), \
                 mock.patch.object(producer.os, "read", return_value=b"observed output"), \
                 mock.patch.object(producer.os, "killpg") as kill, \
                 mock.patch.object(producer, "wait_owned_group_exit", side_effect=[False, True] if cleanup_timeout or group_survives_term else [True]):
                observation, failure = producer.capture_command(Path.cwd(), ["mock-child"], {}, log, 1800)
        self.assertIs(failure, error)
        self.assertTrue(process.stdout.closed)
        self.assertFalse(observation["completed_pipe"])
        self.assertEqual(observation["actual"], process.wait.return_value)
        self.assertIn(mock.call(process.pid, signal.SIGTERM), kill.call_args_list)
        if cleanup_timeout or group_survives_term:
            self.assertIn(mock.call(process.pid, signal.SIGKILL), kill.call_args_list)
        self.assertEqual(process.wait.call_count, 1)

    def completed_command(self, *, descendants):
        producer = load("completed_group_producer", ROOT/"scripts/compiled-gate-profiles.py")
        process = mock.Mock(pid=12345, stdout=io.BytesIO())
        process.poll.return_value = 0
        process.wait.return_value = 0
        selector = mock.MagicMock()
        selector.__enter__.return_value = selector
        selector.select.return_value = [(SimpleNamespace(fd=99, fileobj=process.stdout), 0)]
        with tempfile.TemporaryFile() as log, \
             mock.patch.object(producer.subprocess, "Popen", return_value=process), \
             mock.patch.object(producer.selectors, "DefaultSelector", return_value=selector), \
             mock.patch.object(producer.shutil, "disk_usage", return_value=SimpleNamespace(free=20*1024**3)), \
             mock.patch.object(producer.os, "read", return_value=b""), \
             mock.patch.object(producer.os, "killpg") as kill, \
             mock.patch.object(producer, "wait_owned_group_exit", side_effect=[False, True] if descendants else [True]) as group_exit:
            observation, failure = producer.capture_command(Path.cwd(), ["mock-child"], {}, log, 1800)
        self.assertEqual(observation["actual"], 0)
        self.assertTrue(observation["completed_pipe"])
        self.assertTrue(observation["owned_group_quiescent"])
        self.assertTrue(process.stdout.closed)
        group_exit.assert_any_call(process, grace=0)
        if descendants:
            self.assertIsInstance(failure, RuntimeError)
            self.assertEqual(str(failure), "host command left owned descendants")
            kill.assert_called_once_with(process.pid, signal.SIGTERM)
        else:
            self.assertIsNone(failure)
            kill.assert_not_called()

    def test_successful_leader_with_closed_pipe_still_refuses_live_descendants(self):
        self.completed_command(descendants=True)

    def test_successful_exited_group_preserves_command_success(self):
        self.completed_command(descendants=False)

    def test_uncertain_cleanup_retains_failure_without_final_source_capture(self):
        producer = load("uncertain_cleanup_producer", ROOT/"scripts/compiled-gate-profiles.py")
        failure = subprocess.TimeoutExpired("owned command process group", 10)
        observation = {"actual": 0, "timed_out": False, "disk_floor": False,
            "completed_pipe": True, "cleanup_errors": ["TimeoutExpired"],
            "owned_group_quiescent": False, "ended": 1, "elapsed": 1}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evidence = root/"evidence"
            evidence.mkdir()
            with mock.patch.object(producer, "inventory", return_value={"source_binding":"a"*64}) as inventory, \
                 mock.patch.object(producer, "snapshot", return_value={"content_manifest_sha256":"b"*64}) as snapshot, \
                 mock.patch.object(producer, "capture_command", return_value=(observation, failure)), \
                 mock.patch.object(producer.shutil, "disk_usage", return_value=SimpleNamespace(free=20*1024**3)):
                with self.assertRaises(subprocess.TimeoutExpired) as raised:
                    producer.execute(root, evidence, "producer", ["synthetic-child"], {}, [],
                                     mock.Mock(), mock.Mock(), 30)
            self.assertIs(raised.exception, failure)
            inventory.assert_called_once()
            snapshot.assert_called_once()
            stage = evidence/"producer"
            result = json.loads((stage/"result.json").read_bytes())
            self.assertEqual(result["actual_command_exit"], 0)
            self.assertEqual(result["runner_exit"], 86)
            self.assertFalse(result["inventories_complete"])
            self.assertFalse(result["owned_group_quiescent"])
            self.assertEqual(result["cleanup_errors"], ["TimeoutExpired"])
            for name in ["after.json", "runtime-after.json", "execution.json"]:
                self.assertFalse((stage/name).exists())

    @unittest.skipUnless(os.name == "posix", "owned Unix process groups")
    def test_actual_pipe_detached_descendant_is_stopped_after_leader_success(self):
        producer = load("actual_cleanup_producer", ROOT/"scripts/compiled-gate-profiles.py")
        child_source = '''import os, signal, sys, time
from pathlib import Path
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(60)
'''
        leader_source = '''import os, subprocess, sys, time
from pathlib import Path
Path(sys.argv[1]).write_text(str(os.getpid()))
child = subprocess.Popen([sys.executable, "-I", "-B", "-c", sys.argv[3], sys.argv[2]],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.monotonic()+5
while not Path(sys.argv[2]).exists():
    if child.poll() is not None or time.monotonic() >= deadline:
        child.kill()
        child.wait()
        raise SystemExit(2)
    time.sleep(0.01)
print("leader complete", flush=True)
'''
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as log:
            root = Path(temporary).resolve()
            leader, child = root/"leader.pid", root/"child.pid"
            try:
                # Disk accounting is a separate control; real process launch,
                # group observation, pipe EOF, signals and reaping stay intact.
                with mock.patch.object(producer.shutil, "disk_usage", return_value=SimpleNamespace(free=20*1024**3)):
                    observation, failure = producer.capture_command(root,
                        [sys.executable, "-I", "-B", "-c", leader_source,
                         str(leader), str(child), child_source], {}, log, 15)
                self.assertEqual(observation["actual"], 0)
                self.assertTrue(observation["completed_pipe"])
                self.assertTrue(observation["owned_group_quiescent"])
                self.assertEqual(observation["cleanup_errors"], [])
                self.assertIsInstance(failure, RuntimeError)
                self.assertEqual(str(failure), "host command left owned descendants")
                with self.assertRaises(ProcessLookupError):
                    os.killpg(int(leader.read_text()), 0)
                log.seek(0)
                self.assertEqual(log.read(), b"leader complete\n")
            finally:
                # Even a failed assertion owns cleanup of this exact launch.
                if leader.exists():
                    group = int(leader.read_text())
                    try:
                        os.killpg(group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    deadline = time.monotonic()+5
                    while True:
                        try:
                            os.killpg(group, 0)
                        except ProcessLookupError:
                            break
                        if time.monotonic() >= deadline:
                            raise RuntimeError("test-owned descendant group did not stop")
                        time.sleep(0.05)

    def test_selector_failure_terminates_reaps_and_closes(self):
        self.exercise()

    def test_log_write_failure_terminates_reaps_and_closes(self):
        self.exercise(write_failure=True)

    def test_cleanup_timeout_escalates_only_owned_child_group(self):
        self.exercise(cleanup_timeout=True)

    def test_exited_leader_does_not_exempt_remaining_group(self):
        self.exercise(exited_leader=True)

    def test_group_surviving_term_is_killed_even_after_leader_exits(self):
        self.exercise(exited_leader=True, group_survives_term=True)


class OrdinaryOwnedGroupExitRaceTest(unittest.TestCase):
    """Stop may accept a vanished group only via the bounded wait."""

    def load_with_killpg(self, killpg):
        producer = load("ordinary_exit_race_producer", ROOT/"scripts/compiled-gate-profiles.py")
        patcher = mock.patch.object(producer.os, "killpg", side_effect=killpg)
        patcher.start()
        self.addCleanup(patcher.stop)
        return producer

    def test_permission_error_then_verified_disappearance_permits_cleanup(self):
        def killpg(pid, selected_signal):
            if selected_signal == 0:
                raise ProcessLookupError()
            raise PermissionError()
        producer = self.load_with_killpg(killpg)
        process = SimpleNamespace(pid=12345, poll=mock.Mock(return_value=0))
        # PermissionError on the stop signal defers to the same bounded
        # wait, which here proves the group vanished.
        producer.stop_owned_group(process)

    def test_persistent_permission_error_with_live_group_refuses(self):
        producer = load("ordinary_persistent_permission_producer",
                        ROOT/"scripts/compiled-gate-profiles.py")
        process = SimpleNamespace(pid=12345, poll=mock.Mock(return_value=0))
        with mock.patch.object(producer.os, "killpg", side_effect=PermissionError()), \
             mock.patch.object(producer, "wait_owned_group_exit", side_effect=[False, False]) as group_exit:
            with self.assertRaises(subprocess.TimeoutExpired):
                producer.stop_owned_group(process)
        # Both bounded stop attempts observed a live group before refusing.
        self.assertEqual(group_exit.call_count, 2)

    def test_probe_permission_error_means_group_still_present(self):
        producer = self.load_with_killpg(PermissionError)
        process = SimpleNamespace(pid=12345, poll=mock.Mock(return_value=0))
        self.assertFalse(producer.wait_owned_group_exit(process, grace=0))

    def test_process_lookup_error_still_means_vanished(self):
        producer = self.load_with_killpg(ProcessLookupError)
        producer.stop_owned_group(SimpleNamespace(pid=12345, poll=mock.Mock(return_value=0)))


if __name__ == "__main__":
    unittest.main()
