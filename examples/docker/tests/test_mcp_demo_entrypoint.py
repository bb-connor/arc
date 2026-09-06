"""The demo entrypoint launches only with three explicit, distinct credentials."""

import importlib.util
import os
import pathlib
import unittest
from unittest import mock

ENTRYPOINT = pathlib.Path(__file__).resolve().parents[1] / "mcp_demo_entrypoint.py"


def load_entrypoint():
    spec = importlib.util.spec_from_file_location("mcp_demo_entrypoint", ENTRYPOINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DISTINCT = {
    "CHIO_AUTH_TOKEN": "edge-token",
    "CHIO_ADMIN_TOKEN": "admin-token",
    "CHIO_CONTROL_TOKEN": "control-token",
}


class EntrypointTests(unittest.TestCase):
    def launch(self, environment):
        module = load_entrypoint()
        calls = []
        with mock.patch.dict(os.environ, environment, clear=True):
            with mock.patch.object(module.os, "execve", lambda *args: calls.append(args)):
                module.main()
        return calls

    def test_distinct_credentials_reach_the_edge_only_through_its_environment(self):
        calls = self.launch(DISTINCT)
        self.assertEqual(len(calls), 1)
        executable, arguments, environment = calls[0]
        self.assertEqual(executable, "/sbin/tini")
        self.assertIn("serve-http", arguments)
        self.assertNotIn("--auth-token", arguments)
        self.assertNotIn("--admin-token", arguments)
        self.assertNotIn("--control-token", arguments)
        self.assertEqual(environment["CHIO_AUTH_TOKEN"], "edge-token")
        self.assertEqual(environment["CHIO_ADMIN_TOKEN"], "admin-token")
        self.assertEqual(environment["CHIO_CONTROL_TOKEN"], "control-token")

    def test_a_missing_credential_refuses_to_launch(self):
        for missing in DISTINCT:
            environment = {name: value for name, value in DISTINCT.items() if name != missing}
            with self.assertRaises(SystemExit) as refused:
                self.launch(environment)
            self.assertIn(missing, str(refused.exception))

    def test_a_reused_credential_refuses_to_launch(self):
        for reused in ("CHIO_AUTH_TOKEN", "CHIO_CONTROL_TOKEN"):
            environment = dict(DISTINCT)
            environment[reused] = DISTINCT["CHIO_ADMIN_TOKEN"]
            with self.assertRaises(SystemExit) as refused:
                self.launch(environment)
            self.assertIn("must be distinct", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
