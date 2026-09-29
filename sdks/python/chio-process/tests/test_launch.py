import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from chio_process.launch import provision_native_demo


class NativeLaunchTests(unittest.TestCase):
    def test_missing_enforcement_inputs_refuse_before_running_a_process(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("chio_process.launch.subprocess.run") as launch:
                with self.assertRaisesRegex(ValueError, "CHIO_CAGE_INIT"):
                    provision_native_demo(sys.executable, "test", [sys.executable], "/out", "/")
                launch.assert_not_called()

    def test_explicit_enforcement_inputs_are_passed_without_a_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            grants = root / "grants"
            grants.write_text("/usr/lib\n/path with spaces\n", encoding="utf-8")
            environment = {
                "CHIO_CAGE_INIT": "/helper",
                "CHIO_RECEIPT_ANCHOR_ROOT": "/anchor",
                "CHIO_CAGE_READ_PATHS_FILE": str(grants),
            }
            calls = []

            def provision(arguments, **kwargs):
                calls.append((arguments, kwargs))
                output = Path(arguments[arguments.index("--output-dir") + 1])
                output.mkdir()
                (output / "cage-policy-signer").write_text("11" * 32)
                return subprocess.CompletedProcess(arguments, 0)

            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch("chio_process.launch.subprocess.run", provision):
                    result = provision_native_demo(
                        sys.executable, "test", [sys.executable, "-V"], root / "out", root,
                        environment={"PATH": "/usr/bin"},
                    )
            arguments, kwargs = calls[0]
            self.assertEqual(
                arguments[1:5],
                ["security", "provision-reference-runtime", "--stage", "enforced"],
            )
            self.assertEqual(arguments[arguments.index("--cage-init") + 1], "/helper")
            self.assertEqual(
                arguments[arguments.index("--receipt-rollback-anchor-root") + 1], "/anchor"
            )
            reads = [
                arguments[i + 1] for i, value in enumerate(arguments) if value == "--read-path"
            ]
            self.assertEqual(reads, ["/usr/lib", "/path with spaces"])
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin"})
            self.assertEqual(result["launch_policy_signer"], "11" * 32)

    def test_relative_read_grants_refuse_before_running_a_process(self):
        with tempfile.TemporaryDirectory() as root:
            grants = Path(root) / "grants"
            grants.write_text("relative/path\n", encoding="utf-8")
            environment = {
                "CHIO_CAGE_INIT": "/helper",
                "CHIO_RECEIPT_ANCHOR_ROOT": "/anchor",
                "CHIO_CAGE_READ_PATHS_FILE": str(grants),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch("chio_process.launch.subprocess.run") as launch:
                    with self.assertRaisesRegex(ValueError, "read grants must be absolute"):
                        provision_native_demo(sys.executable, "test", [sys.executable], "/out", "/")
                    launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
