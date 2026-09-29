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
                        sys.executable,
                        "test",
                        [sys.executable, "-V"],
                        root / "out",
                        root,
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


class NativeAuthorityBoundaryTests(unittest.TestCase):
    def test_common_grants_cannot_read_authority_or_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, anchor = root / "authority", root / "anchor"
            anchor.mkdir()
            grants = root / "grants"
            env = {
                "CHIO_CAGE_INIT": "/helper",
                "CHIO_RECEIPT_ANCHOR_ROOT": str(anchor),
                "CHIO_CAGE_READ_PATHS_FILE": str(grants),
            }
            for grant in [root, output, output / "secret", anchor, anchor / "secret", Path("/")]:
                grants.write_text(str(grant) + "\n")
                with (
                    mock.patch.dict(os.environ, env, clear=True),
                    mock.patch("chio_process.launch.subprocess.run") as launch,
                ):
                    with self.assertRaisesRegex(ValueError, "authority|anchors"):
                        provision_native_demo(
                            sys.executable, "test", [sys.executable], output, root
                        )
                    launch.assert_not_called()

    def test_identity_and_tool_data_grants_match_the_operator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tool-data"
            tools.mkdir()
            grants = root / "grants"
            grants.write_text("/usr\n")
            env = {
                "CHIO_CAGE_INIT": "/helper",
                "CHIO_RECEIPT_ANCHOR_ROOT": str(root / "anchor"),
                "CHIO_CAGE_READ_PATHS_FILE": str(grants),
            }

            def provision(arguments, **kwargs):
                output = Path(arguments[arguments.index("--output-dir") + 1])
                output.mkdir()
                (output / "cage-policy-signer").write_text("11" * 32)
                return subprocess.CompletedProcess(arguments, 0)

            with (
                mock.patch.dict(os.environ, env, clear=True),
                mock.patch("chio_process.launch.subprocess.run", side_effect=provision) as launch,
                mock.patch("chio_process.launch.os.getuid", return_value=1001),
                mock.patch("chio_process.launch.os.getgid", return_value=1002),
                mock.patch(
                    "chio_process.launch.os.getgroups", return_value=[1004, 1002, 1003, 1004]
                ),
            ):
                provision_native_demo(
                    sys.executable,
                    "test",
                    [sys.executable],
                    root / "authority",
                    root,
                    read_paths=[tools],
                    write_paths=[tools],
                )
            arguments = launch.call_args.args[0]
            for flag, value in [
                ("--execution-uid", "1001"),
                ("--execution-gid", "1002"),
                ("--write-path", str(tools)),
            ]:
                self.assertEqual(arguments[arguments.index(flag) + 1], value)
            self.assertEqual(
                [
                    arguments[i + 1]
                    for i, item in enumerate(arguments)
                    if item == "--execution-supplementary-gid"
                ],
                ["1003", "1004"],
            )

    def test_oversized_grant_file_fails_before_provisioning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            grants = root / "grants"
            grants.write_text("/" + "a" * 65_536)
            env = {
                "CHIO_CAGE_INIT": "/helper",
                "CHIO_RECEIPT_ANCHOR_ROOT": "/anchor",
                "CHIO_CAGE_READ_PATHS_FILE": str(grants),
            }
            with (
                mock.patch.dict(os.environ, env, clear=True),
                mock.patch("chio_process.launch.subprocess.run") as launch,
            ):
                with self.assertRaisesRegex(ValueError, "64 KiB"):
                    provision_native_demo(
                        sys.executable, "test", [sys.executable], root / "authority", root
                    )
                launch.assert_not_called()
