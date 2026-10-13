import json
import os
import stat
import subprocess
import sys
import tempfile
import traceback
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

    def test_dynamic_runtime_declarations_are_explicit_and_cannot_read_authority(self):
        from chio_process.launch import _native_cage_arguments

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            grants, runtime = root / "reads", root / "runtime"
            grants.write_text("/usr/lib/example.so\n")
            runtime.write_text("/usr/lib/example.so\n")
            env = {
                "CHIO_CAGE_INIT": "/helper",
                "CHIO_RECEIPT_ANCHOR_ROOT": str(root / "anchor"),
                "CHIO_CAGE_READ_PATHS_FILE": str(grants),
                "CHIO_CAGE_RUNTIME_FILES_FILE": str(runtime),
            }
            with mock.patch.dict(os.environ, env, clear=True):
                arguments = _native_cage_arguments(root / "authority")
                self.assertEqual(arguments[-2:], ["--runtime-file", "/usr/lib/example.so"])
                for path in (root / "anchor", root / "authority", root, Path("/")):
                    runtime.write_text(str(path) + "\n")
                    with self.assertRaisesRegex(ValueError, "authority|anchors"):
                        _native_cage_arguments(root / "authority")
                runtime.write_text("a" * 65537)
                with self.assertRaisesRegex(ValueError, "64 KiB"):
                    _native_cage_arguments(root / "authority")


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


class NativeDemoDiagnostics(unittest.TestCase):
    def test_reviewed_fixture_replaces_discovery_for_the_exact_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = directory / "tools.json"
            fixture.write_text('{"tools":[{"name":"task","inputSchema":{"type":"object"}}]}')
            chio = directory / "chio"
            chio.write_text(
                f"#!{sys.executable}\n"
                "import json,sys\n"
                "from pathlib import Path\n"
                "args=sys.argv[1:]\n"
                "if '--discover-tools' in args: sys.exit(14)\n"
                "reviewed=json.loads(Path(args[args.index('--tools-fixture')+1]).read_text())\n"
                "if reviewed['tools'][0]['name']!='task': sys.exit(15)\n"
                "output=Path(args[args.index('--output-dir')+1]); output.mkdir()\n"
                "(output/'cage-policy-signer').write_text('public-signer\\n')\n"
                "(output.parent/'received-arguments.json').write_text(json.dumps(args))\n"
            )
            chio.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            result = provision_native_demo(
                chio,
                "jobs",
                [sys.executable, "worker", "tenant"],
                directory / "launch",
                directory,
                tools_fixture=fixture,
            )
            self.assertEqual(
                result["command"], [str(Path(sys.executable).resolve()), "worker", "tenant"]
            )
            arguments = json.loads((directory / "received-arguments.json").read_text())
            self.assertEqual(
                arguments[arguments.index("--tools-fixture") + 1], str(fixture.resolve())
            )
            self.assertEqual(arguments.count("--tools-fixture"), 1)
            self.assertNotIn("--discover-tools", arguments)

    def test_default_provisioning_still_discovers_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            chio = directory / "chio"
            chio.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "from pathlib import Path\n"
                "args=sys.argv[1:]\n"
                "if '--discover-tools' not in args or '--tools-fixture' in args: sys.exit(14)\n"
                "output=Path(args[args.index('--output-dir')+1]); output.mkdir()\n"
                "(output/'cage-policy-signer').write_text('public-signer\\n')\n"
            )
            chio.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            result = provision_native_demo(
                chio, "jobs", [sys.executable], directory / "launch", directory
            )
            self.assertEqual(result["launch_policy_signer"], "public-signer")

    def test_failed_provisioning_retains_sanitized_error_and_exit_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            chio = directory / "chio"
            chio.write_text(
                f"#!{sys.executable}\n"
                "import os,sys\n"
                "sys.stderr.write('discovery failed: '+os.environ['DATABASE_URL']+'\\n')\n"
                "sys.stderr.write('password='+os.environ['API_TOKEN']+'\\n')\n"
                "sys.exit(7)\n"
            )
            chio.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            environment = {
                **os.environ,
                "DATABASE_URL": "postgres://worker:db-private-password@localhost/jobs",
                "API_TOKEN": "api-private-token",
            }
            try:
                provision_native_demo(
                    chio,
                    "jobs",
                    [sys.executable, "-c", "pass"],
                    directory / "launch",
                    directory,
                    environment=environment,
                )
            except Exception as error:
                rendered = "".join(traceback.format_exception(error))
            else:
                self.fail("failed native discovery returned a server configuration")
            self.assertIn("discovery failed", rendered)
            self.assertIn("exit status 7", rendered)
            self.assertNotIn("db-private-password", rendered)
            self.assertNotIn("api-private-token", rendered)
            self.assertNotIn(environment["DATABASE_URL"], rendered)

    def test_large_stderr_is_bounded_after_redaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            chio = directory / "chio"
            chio.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "sys.stderr.write('discovery failed: '+ 'x' * 100_000)\n"
                "sys.exit(9)\n"
            )
            chio.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            with self.assertRaises(Exception) as failed:
                provision_native_demo(
                    chio, "jobs", [sys.executable], directory / "launch", directory
                )
            message = str(failed.exception)
            self.assertIn("discovery failed", message)
            self.assertIn("truncated", message)
            self.assertLess(len(message), 5000)

    def test_unrecognized_target_stderr_never_enters_public_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            chio = directory / "chio"
            chio.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "sys.stderr.write('unexpected private data: retained-private-password')\n"
                "sys.stdout.write('private signing material: retained-private-seed')\n"
                "sys.exit(11)\n"
            )
            chio.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            with self.assertRaises(Exception) as failed:
                provision_native_demo(
                    chio, "jobs", [sys.executable], directory / "launch", directory
                )
            message = str(failed.exception)
            self.assertIn("exit status 11", message)
            self.assertIn("stderr withheld", message)
            self.assertNotIn("retained-private-password", message)
            self.assertNotIn("retained-private-seed", message)


if __name__ == "__main__":
    unittest.main()
