"""Native demo failures expose bounded diagnostics without supplied credentials."""

import json
import os
import stat
import sys
import tempfile
import traceback
import unittest
from pathlib import Path

from chio_process.launch import provision_native_demo


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
