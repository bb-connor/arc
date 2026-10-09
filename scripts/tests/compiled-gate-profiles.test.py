"""Owning path-policy controls for the ordinary Cargo evidence producer."""
import hashlib
import importlib.util
import io
import json
import signal
import subprocess
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


if __name__ == "__main__":
    unittest.main()
