import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from chio_process.broker_launch import provision_brokered_demo


class BrokerLaunchTests(unittest.TestCase):
    def test_broker_inputs_exclude_discovery_grants_and_provider_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools, binding = root / "tools.json", root / "binding.json"
            tools.touch()
            binding.touch()

            def provision(arguments, **kwargs):
                output = Path(arguments[arguments.index("--output-dir") + 1])
                output.mkdir()
                (output / "cage-policy-signer").write_text("11" * 32)

            environment = {
                "CHIO_CAGE_INIT": "/helper",
                "CHIO_RECEIPT_ANCHOR_ROOT": "/independent/anchor",
                "CHIO_CAGE_READ_PATHS_FILE": "/must-not-be-read",
                "PROVIDER_KEY": "private_marker",
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch(
                    "chio_process.broker_launch.subprocess.run", side_effect=provision
                ) as run,
                mock.patch("chio_process.broker_launch.os.getuid", return_value=1001),
                mock.patch("chio_process.broker_launch.os.getgid", return_value=1001),
                mock.patch("chio_process.broker_launch.os.getgroups", return_value=[1001]),
            ):
                configured = provision_brokered_demo(
                    sys.executable,
                    "broker",
                    [sys.executable, "--tool-name", "execute"],
                    root / "launch",
                    root,
                    tools_fixture=tools,
                    broker_binding=binding,
                )
            args = run.call_args.args[0]
            self.assertEqual(args[args.index("--broker-binding") + 1], str(binding))
            self.assertEqual(args[args.index("--tools-fixture") + 1], str(tools))
            for flag in ["--discover-tools", "--read-path", "--write-path", "--runtime-files"]:
                self.assertNotIn(flag, args)
            self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin"})
            self.assertEqual(configured["launch_policy_signer"], "11" * 32)
