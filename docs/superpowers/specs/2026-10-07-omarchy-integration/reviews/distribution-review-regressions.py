#!/usr/bin/env python3
"""Extract and check proposed distribution examples; no runtime qualification."""

import argparse
import contextlib
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
    unittest.main(verbosity=2)
