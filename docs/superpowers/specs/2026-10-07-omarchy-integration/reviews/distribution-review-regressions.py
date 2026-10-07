#!/usr/bin/env python3
"""Extract and check proposed distribution examples; no runtime qualification."""

import argparse
import ast
import contextlib
import copy
import errno
import io
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


PLAN_DIR = Path(__file__).resolve().parents[3] / "plans/2026-10-07-omarchy-integration"
PLAN = PLAN_DIR / "07-distribution-qualification.md"
DOCUMENT = PLAN.read_text()
PYTHON_BLOCKS = re.findall(r"^```python\n(.*?)^```", DOCUMENT, re.M | re.S)


def extract_python(marker):
    matches = [block for block in PYTHON_BLOCKS if marker in block]
    if len(matches) != 1:
        raise AssertionError(f"Expected one {marker!r} example, found {len(matches)}")
    return compile(matches[0], str(PLAN), "exec")


PROCESS = types.ModuleType("distribution_review_process")
exec(extract_python("def run_bounded("), PROCESS.__dict__)
TEST_MODULE = types.ModuleType("distribution_review_document_tests")
with mock.patch.dict(sys.modules, {"integrations.omarchy.qualification.process": PROCESS}):
    exec(extract_python("class ProcessTests("), TEST_MODULE.__dict__)
ProcessTests = TEST_MODULE.ProcessTests
PHASE = types.ModuleType("distribution_review_phase")
exec(extract_python("def add_phase_argument("), PHASE.__dict__)
REVISION = types.ModuleType("distribution_review_revision")
exec(extract_python("def require_public_revision("), REVISION.__dict__)


class LaunchEvidenceTests(unittest.TestCase):
    def test_invalid_executable_format_is_a_retained_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "invalid-format"
            fixture.write_bytes(b"not an executable format\n")
            fixture.chmod(0o700)
            result = PROCESS.run_bounded([str(fixture)], timeout=0.1, limit=64)
        self.assertEqual(result["launch_error"]["errno"], errno.ENOEXEC)
        self.assertEqual(result["launch_error"]["reason"], "invalid_executable")
        self.assertFalse(PROCESS.command_passed(result))

    def test_os_error_metadata_is_bounded_and_excludes_exception_text(self):
        exception_text = "SECRET-FIXTURE-PATH" * 10000
        with mock.patch.object(PROCESS.subprocess, "Popen",
                               side_effect=OSError(errno.EMFILE, exception_text)):
            result = PROCESS.run_bounded(["fixture"], timeout=0.1, limit=64,
                                         prerequisite="AT-LNX-006.native-fixture")
        encoded = json.dumps(result["launch_error"])
        self.assertLess(len(encoded), 256)
        self.assertNotIn("SECRET", encoded)
        self.assertEqual(result["launch_error"]["reason"], "launch_failed")
        self.assertEqual(result["launch_error"]["errno"], errno.EMFILE)
        self.assertFalse(result["launched"])
        self.assertEqual(result["stdout"] + result["stderr"], b"")
        self.assertFalse(PROCESS.command_passed(result))

    def test_execution_policy_denial_is_retained(self):
        with mock.patch.object(PROCESS.subprocess, "Popen",
                               side_effect=PermissionError(errno.EPERM, "denied")):
            result = PROCESS.run_bounded(["fixture"], timeout=0.1, limit=64)
        self.assertEqual(result["launch_error"]["reason"], "not_executable")
        self.assertFalse(PROCESS.command_passed(result))

    def test_launch_refusal_never_cleans_up_a_nonexistent_child(self):
        with mock.patch.object(PROCESS.subprocess, "Popen",
                               side_effect=FileNotFoundError(errno.ENOENT, "missing")):
            with mock.patch.object(PROCESS, "_stop_and_observe_group") as cleanup:
                result = PROCESS.run_bounded(["fixture"], timeout=0.1, limit=64)
        cleanup.assert_not_called()
        self.assertFalse(result["wrapper_reaped"])
        self.assertFalse(result["descendants_absent"])

    def test_prerequisite_identifiers_are_bounded(self):
        for prerequisite in ["", "x" * 129, "with\nnewline", "non-ascii-\u2603", None]:
            with self.subTest(prerequisite=prerequisite):
                with mock.patch.object(PROCESS.subprocess, "Popen") as launch:
                    with self.assertRaises(ValueError):
                        PROCESS.run_bounded(["fixture"], timeout=0.1, limit=64,
                                            prerequisite=prerequisite)
                    launch.assert_not_called()

    def test_success_requires_both_launch_fields(self):
        result = PROCESS.run_bounded([sys.executable, "-c", "pass"],
                                     timeout=2, limit=64)
        self.assertTrue(PROCESS.command_passed(result))
        for field, value in [("launched", False), ("launch_error", {"errno": errno.EIO})]:
            with self.subTest(field=field):
                self.assertFalse(PROCESS.command_passed({**result, field: value}))


class ExistingBoundTests(unittest.TestCase):
    def test_combined_stdout_stderr_flood_stays_within_limit(self):
        result = PROCESS.run_bounded(
            [sys.executable, "-c",
             "import os; os.write(1, b'x' * 1048576); os.write(2, b'y' * 1048576)"],
            timeout=2, limit=65536)
        self.assertTrue(result["overflow"])
        self.assertLessEqual(len(result["stdout"]) + len(result["stderr"]), 65536)
        self.assertTrue(result["wrapper_reaped"])
        self.assertTrue(result["descendants_absent"])
        self.assertFalse(PROCESS.command_passed(result))

    def test_nonzero_exit_keeps_output(self):
        result = PROCESS.run_bounded(
            [sys.executable, "-c", "import sys; print('failure'); sys.exit(7)"],
            timeout=2, limit=64)
        self.assertEqual(result["returncode"], 7)
        self.assertEqual(result["stdout"], b"failure\n")
        self.assertFalse(PROCESS.command_passed(result))

    def test_invalid_argv_is_rejected_before_spawn(self):
        for argv in [[], "fixture", ["fixture", None], ["fixture\0"]]:
            with self.subTest(argv=argv):
                with mock.patch.object(PROCESS.subprocess, "Popen") as launch:
                    with self.assertRaises(ValueError):
                        PROCESS.run_bounded(argv, timeout=0.1, limit=64)
                    launch.assert_not_called()

    def test_unverifiable_group_never_passes(self):
        with mock.patch.object(PROCESS, "_group_exists", return_value=None):
            result = PROCESS.run_bounded([sys.executable, "-c", "pass"],
                                         timeout=2, limit=64)
        self.assertFalse(result["descendants_absent"])
        self.assertFalse(PROCESS.command_passed(result))

    def test_descendant_with_open_pipe_is_stopped(self):
        script = (
            "import os,time\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    time.sleep(20)\n"
            "    os._exit(0)\n"
            "print(os.getpid(), child, flush=True)\n")
        result = PROCESS.run_bounded([sys.executable, "-c", script],
                                     timeout=0.2, limit=64)
        pgid, _ = map(int, result["stdout"].split())
        try:
            with self.assertRaises(ProcessLookupError):
                os.killpg(pgid, 0)
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["wrapper_reaped"])
            self.assertTrue(result["descendants_absent"])
            self.assertFalse(PROCESS.command_passed(result))
        finally:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass


class DescendantCustodyTests(unittest.TestCase):
    def test_missing_initialization_refuses_without_changing_caller_or_launching(self):
        with mock.patch.object(PROCESS.sys, "platform", "linux"):
            with mock.patch.object(PROCESS, "_fixture_worker_pid", None):
                with mock.patch.object(PROCESS.ctypes, "CDLL") as custody:
                    with mock.patch.object(PROCESS.subprocess, "Popen") as launch:
                        result = PROCESS.run_bounded(["fixture"], timeout=0.1, limit=64)
        self.assertEqual(result["launch_error"], {
            "prerequisite": "harness-child-subreaper", "errno": None,
            "reason": "not_initialized"})
        self.assertFalse(PROCESS.command_passed(result))
        custody.assert_not_called()
        launch.assert_not_called()

    def test_subreaper_denial_is_a_named_bounded_refusal(self):
        libc = mock.Mock()
        libc.prctl.return_value = -1
        with mock.patch.object(PROCESS.sys, "platform", "linux"):
            with mock.patch.object(PROCESS, "_fixture_worker_pid", None):
                with mock.patch.object(PROCESS.ctypes, "CDLL", return_value=libc):
                    with mock.patch.object(PROCESS.ctypes, "get_errno", return_value=errno.EPERM):
                        refusal = PROCESS.initialize_fixture_worker()
                self.assertIsNone(PROCESS._fixture_worker_pid)
        self.assertEqual(refusal, {"prerequisite": "harness-child-subreaper",
                                   "errno": errno.EPERM, "reason": "subreaper_unavailable"})

    def test_drain_is_bounded_and_only_reaps_the_fixture_group(self):
        process = mock.Mock(pid=12345)
        process.poll.return_value = 0
        result = {"cleanup_errors": []}
        with mock.patch.object(PROCESS.os, "waitpid", return_value=(12346, 0)) as wait:
            PROCESS._reap_owned_descendants(process, result)
        self.assertEqual(wait.call_count, 64)
        self.assertTrue(all(call == mock.call(-12345, os.WNOHANG) for call in wait.call_args_list))

    def test_wrapper_status_remains_owned_by_popen(self):
        process = mock.Mock(pid=12345)
        process.poll.return_value = None
        with mock.patch.object(PROCESS.os, "waitpid") as wait:
            PROCESS._reap_owned_descendants(process, {"cleanup_errors": []})
        wait.assert_not_called()

    def test_nested_descendants_are_reaped_and_unrelated_child_keeps_status(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(23)"],
                                     start_new_session=True)
        script = (
            "import os,time\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    os.fork()\n"
            "    os.close(1); os.close(2)\n"
            "    time.sleep(20)\n"
            "    os._exit(0)\n"
            "print(os.getpid(), child, flush=True)\n")
        pgid = None
        try:
            result = PROCESS.run_bounded([sys.executable, "-c", script],
                                         timeout=2, limit=64)
            pgid, _ = map(int, result["stdout"].split())
            with self.assertRaises(ProcessLookupError):
                os.killpg(pgid, 0)
            self.assertTrue(result["descendants_absent"])
            self.assertTrue(result["unexpected_descendants"])
            self.assertFalse(PROCESS.command_passed(result))
            # A blanket waitpid(-1, ...) would consume this original status.
            self.assertEqual(unrelated.wait(timeout=2), 23)
        finally:
            if unrelated.poll() is None:
                unrelated.kill()
            unrelated.wait(timeout=2)
            if pgid is not None:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


class ReleaseLockExampleTests(unittest.TestCase):
    # Synthetic shape only; these values are never public release provenance.
    SYNTHETIC_LOCK = {
        "version": "0.0.0-component-fixture", "architecture": "x86_64",
        "source_url": "https://example.invalid/component-fixture.tar.gz",
        "source_sha256": "1" * 64, "public_revision": "2" * 40,
        "runtime_inventory_sha256": "3" * 64, "compatibility_sha256": "4" * 64,
        "plugin_release_sha256": "6" * 64,
        "profiles": ["observe-v1"], "state_read_abis": [1], "state_write_abi": 1,
        "signer_identity": "synthetic-component-signer",
        "native_prerequisites": {"synthetic-component-prerequisite": "5" * 64},
    }

    def run_example(self, check_revision):
        blocks = [block for block in PYTHON_BLOCKS if "class ReleaseLockTests(" in block]
        self.assertEqual(len(blocks), 1)
        source = ast.parse(blocks[0])
        node = next(node for node in source.body if isinstance(node, ast.ClassDef))

        def validate_release_lock(lock):
            # A bounded test double isolates the proposed test's discrimination.
            # All other fields must still match the complete synthetic fixture.
            if set(lock) != set(self.SYNTHETIC_LOCK):
                raise ValueError("missing required release-lock fields")
            for key, value in self.SYNTHETIC_LOCK.items():
                if key != "public_revision" and lock[key] != value:
                    raise ValueError("synthetic positive-control field changed")
            if check_revision:
                REVISION.require_public_revision(lock["public_revision"])
            return lock

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "fixtures").mkdir()
            (path / "fixtures/reviewed-release-lock.json").write_text(json.dumps(self.SYNTHETIC_LOCK))
            namespace = {"unittest": unittest, "copy": copy, "json": json, "Path": Path,
                         "__file__": str(path / "test_release_lock.py"),
                         "module": types.SimpleNamespace(validate_release_lock=validate_release_lock)}
            exec(compile(ast.Module(body=[node], type_ignores=[]), str(PLAN), "exec"), namespace)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(namespace["ReleaseLockTests"])
            result = unittest.TestResult()
            suite.run(result)
        return result

    def test_complete_fixture_and_exact_revision_refusal_pass(self):
        result = self.run_example(check_revision=True)
        self.assertEqual(result.testsRun, 3)
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)

    def test_missing_field_only_validator_mutant_is_killed(self):
        result = self.run_example(check_revision=False)
        self.assertEqual(result.testsRun, 3)
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.failures), 1)
        self.assertIn("test_floating_revision_is_rejected", result.failures[0][0].id())

    def test_revision_check_rejects_mutable_malformed_and_wrong_type_values(self):
        REVISION.require_public_revision(self.SYNTHETIC_LOCK["public_revision"])
        for revision in ["main", "refs/heads/main", "v1.0.0", "2" * 39, "2" * 41, None]:
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError,
                                            "^public_revision must be an immutable 40-hex commit$"):
                    REVISION.require_public_revision(revision)


class PhaseContractTests(unittest.TestCase):
    def parser(self):
        parser = argparse.ArgumentParser()
        PHASE.add_phase_argument(parser)
        return parser

    def test_all_eight_phases_are_accepted_without_substitution(self):
        for index in range(8):
            phase = f"P{index}"
            with self.subTest(phase=phase):
                self.assertEqual(self.parser().parse_args(["--phase", phase]).phase, phase)

    def test_invalid_and_missing_phase_are_rejected(self):
        for argv in [[], ["--phase", "P8"], ["--phase", "P-1"], ["--phase", "p1"]]:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    self.parser().parse_args(argv)
                self.assertEqual(caught.exception.code, 2)

    def test_every_documented_phase_command_is_parseable(self):
        phases = set()
        for plan in PLAN_DIR.glob("*.md"):
            phases.update(re.findall(r"--phase (P[0-9]+)\b", plan.read_text()))
        self.assertEqual(phases, {f"P{index}" for index in range(8)})
        for phase in phases:
            self.assertEqual(self.parser().parse_args(["--phase", phase]).phase, phase)


class PackageInventoryTests(unittest.TestCase):
    REQUIRED = {
        "/usr/bin/chio-desktop-controller":
            ("755", "target/release/chio-desktop-controller"),
        "/usr/bin/chio-desktop-client":
            ("755", "target/release/chio-desktop-client"),
        "/usr/bin/chio-desktop-open":
            ("755", "target/release/chio-desktop-open"),
        "/usr/lib/systemd/user/chio-desktop.service":
            ("644", "packaging/omarchy/units/chio-desktop.service"),
        "/usr/lib/systemd/user/chio-tasks.slice":
            ("644", "packaging/omarchy/units/chio-tasks.slice"),
        "/usr/share/applications/computer.chio.desktop.desktop":
            ("644", "integrations/omarchy/fixtures/desktop/computer.chio.desktop.desktop"),
        "/usr/share/chio/omarchy/menu-fragment.json":
            ("644", "integrations/omarchy/fixtures/desktop/menu-fragment.json"),
    }

    def package_example(self):
        blocks = re.findall(r"^```bash\n(.*?)^```", DOCUMENT, re.M | re.S)
        matches = [block for block in blocks if "package() {" in block]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_package_commands_install_every_required_path_and_mode(self):
        inventory = {}
        for line in self.package_example().splitlines():
            tokens = shlex.split(line)
            if tokens and tokens[0] == "install":
                self.assertEqual(len(tokens), 4)
                self.assertTrue(tokens[3].startswith("$pkgdir/"))
                destination = tokens[3].removeprefix("$pkgdir")
                self.assertNotIn(destination, inventory)
                self.assertRegex(tokens[1], r"^-Dm(?:755|644)$")
                inventory[destination] = (tokens[1][3:], tokens[2])
        self.assertEqual(inventory, self.REQUIRED)

    def test_required_inventory_table_matches_the_package_paths(self):
        rows = re.findall(r"^\| `(/usr/[^`]+)` \| `0(755|644)` \|", DOCUMENT, re.M)
        self.assertEqual(dict(rows), {path: mode for path, (mode, _) in self.REQUIRED.items()})
        self.assertEqual(len(rows), len(self.REQUIRED))

    def test_registration_sources_and_opener_match_the_controller_plan(self):
        controller = (PLAN_DIR / "01-controller-and-plugin.md").read_text()
        for path in ["/usr/share/applications/computer.chio.desktop.desktop",
                     "/usr/share/chio/omarchy/menu-fragment.json"]:
            self.assertIn(self.REQUIRED[path][1], controller)
        self.assertIn("src/bin/chio-desktop-open.rs", controller)
        self.assertIn("Exec=chio-desktop-open", controller)
        self.assertIn("Exec=chio-desktop-open", DOCUMENT)

    def test_package_shell_example_parses(self):
        result = subprocess.run(["/bin/bash", "-n"], input=self.package_example(),
                                text=True, capture_output=True, timeout=2, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    print("Component/specification regression only; no Omarchy runtime qualification.", flush=True)
    refusal = PROCESS.initialize_fixture_worker()
    if refusal is not None:
        print(json.dumps({"outcome": "unknown", "blocker": refusal}), flush=True)
        raise SystemExit(2)
    unittest.main(verbosity=2)
