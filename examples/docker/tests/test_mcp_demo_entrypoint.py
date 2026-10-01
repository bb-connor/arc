"""The demo entrypoint provisions its launch and starts only with explicit, distinct credentials."""

import importlib.util
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

ENTRYPOINT = pathlib.Path(__file__).resolve().parents[1] / "mcp_demo_entrypoint.py"
MANIFEST_KEY = "11" * 32
POLICY_KEY = "22" * 32
AUTHORITY_KEY = "33" * 32


def load_entrypoint():
    spec = importlib.util.spec_from_file_location("mcp_demo_entrypoint", ENTRYPOINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DISTINCT = {
    "CHIO_AUTH_TOKEN": "edge-token",
    "CHIO_ADMIN_TOKEN": "admin-token",
    "CHIO_CONTROL_TOKEN": "control-token",
    "CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN": "workload-token",
}


class FakeProvisioner:
    """Stands in for the provisioner: records its invocation and writes the public artifacts."""

    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def __call__(self, command, check, stdout, env):
        self.calls.append((command, env))
        if self.fail:
            raise subprocess.CalledProcessError(3, command)
        output_dir = command[command.index("--output-dir") + 1]
        os.makedirs(output_dir, mode=0o700)
        for name, content in (
            ("signed-manifest.json", "{}"),
            ("manifest-public-key", MANIFEST_KEY),
            ("cage-launch-policy.json", "{}"),
            ("cage-policy-signer", POLICY_KEY),
        ):
            with open(os.path.join(output_dir, name), "w", encoding="utf-8") as handle:
                handle.write(content)
        return subprocess.CompletedProcess(command, 0)


class FakeTrustService:
    """Answers the authority lookup the way the trust service does."""

    def __init__(self, public_key=AUTHORITY_KEY):
        self.public_key = public_key
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        body = json.dumps({"configured": True, "publicKey": self.public_key}).encode()
        return io.BytesIO(body)


class EntrypointTests(unittest.TestCase):
    def launch(self, environment, provisioner=None, trust_service=None):
        module = load_entrypoint()
        provisioner = provisioner or FakeProvisioner()
        trust_service = trust_service or FakeTrustService()
        calls = []
        with tempfile.TemporaryDirectory() as provision_dir:
            environment = dict(environment, CHIO_PROVISION_DIR=provision_dir)
            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch.object(module.subprocess, "run", provisioner):
                    with mock.patch.object(module.urllib.request, "urlopen", trust_service):
                        with mock.patch.object(module.os, "getuid", lambda: 10001):
                            with mock.patch.object(module.os, "getgid", lambda: 10001):
                                with mock.patch.object(module.os, "execve", lambda *args: calls.append(args)):
                                    module.main()
            self.keyrings = {}
            self.keyring_modes = {}
            keyring = os.path.join(provision_dir, "resume-hmac-keyring.json")
            if os.path.isfile(keyring):
                with open(keyring, encoding="utf-8") as handle:
                    self.keyrings[keyring] = json.load(handle)
                self.keyring_modes[keyring] = os.stat(keyring).st_mode & 0o777
        return calls, provisioner.calls, trust_service.requests

    def test_distinct_credentials_reach_the_edge_only_through_its_environment(self):
        calls, _, _ = self.launch(DISTINCT)
        self.assertEqual(len(calls), 1)
        executable, arguments, environment = calls[0]
        self.assertEqual(executable, "/sbin/tini")
        self.assertIn("serve-http", arguments)
        self.assertNotIn("--auth-token", arguments)
        self.assertNotIn("--admin-token", arguments)
        self.assertNotIn("--control-token", arguments)
        self.assertNotIn("--remote-authority-workload-token", arguments)
        self.assertEqual(environment["CHIO_AUTH_TOKEN"], "edge-token")
        self.assertEqual(environment["CHIO_ADMIN_TOKEN"], "admin-token")
        self.assertEqual(environment["CHIO_CONTROL_TOKEN"], "control-token")
        self.assertEqual(environment["CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN"], "workload-token")

    def test_the_launch_binds_the_provisioned_command_and_keys(self):
        module = load_entrypoint()
        calls, provisioning, authority_requests = self.launch(DISTINCT)
        _, arguments, _ = calls[0]
        target = os.path.realpath("/usr/bin/python3")
        self.assertEqual(arguments[-3:], ["--", target, module.MOCK_SERVER])
        self.assertEqual(arguments[arguments.index("--manifest-public-key") + 1], MANIFEST_KEY)
        self.assertEqual(arguments[arguments.index("--cage-policy-signer") + 1], POLICY_KEY)
        self.assertEqual(arguments[arguments.index("--control-authority-public-key") + 1], AUTHORITY_KEY)
        self.assertLess(arguments.index("--control-authority-public-key"), arguments.index("mcp"))
        self.assertTrue(arguments[arguments.index("--signed-manifest") + 1].endswith("/security/signed-manifest.json"))
        self.assertTrue(arguments[arguments.index("--cage-policy") + 1].endswith("/security/cage-launch-policy.json"))
        self.assertTrue(arguments[arguments.index("--session-db") + 1].endswith("/mcp-sessions.sqlite3"))
        keyring_path = arguments[arguments.index("--resume-hmac-keyring") + 1]
        self.assertTrue(keyring_path.endswith("/resume-hmac-keyring.json"))
        self.assertEqual(self.keyrings[keyring_path]["schema"], "chio.remote-mcp.resume-hmac-keyring.v1")
        self.assertEqual(len(self.keyrings[keyring_path]["current"]["keyBase64"]), 43)
        self.assertEqual(self.keyring_modes[keyring_path], 0o600)

        self.assertEqual(len(provisioning), 1)
        command, environment = provisioning[0]
        self.assertEqual(command[:3], [module.EXECUTABLE, "security", "provision-native-mcp-demo"])
        self.assertIn("--discover-tools", command)
        self.assertEqual(command[command.index("--target") + 1], target)
        self.assertEqual(command[command.index("--target-arg") + 1], module.MOCK_SERVER)
        self.assertEqual(command[command.index("--execution-uid") + 1], "10001")
        self.assertEqual(command[command.index("--server-id") + 1], "wrapped-http-mock")
        for credential in DISTINCT:
            self.assertNotIn(credential, environment)

        self.assertEqual(len(authority_requests), 1)
        request = authority_requests[0]
        self.assertEqual(request.full_url, "http://chio-trust-demo:8940/v1/authority")
        self.assertEqual(request.get_header("Authorization"), "Bearer control-token")

    def test_a_failed_provision_refuses_to_launch(self):
        with self.assertRaises(SystemExit) as refused:
            self.launch(DISTINCT, provisioner=FakeProvisioner(fail=True))
        self.assertIn("provisioning the demo launch failed", str(refused.exception))

    def test_an_unusable_authority_key_refuses_to_launch(self):
        with self.assertRaises(SystemExit) as refused:
            self.launch(DISTINCT, trust_service=FakeTrustService(public_key="not-a-key"))
        self.assertIn("authority key", str(refused.exception))

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
        environment = dict(DISTINCT)
        environment["CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN"] = DISTINCT["CHIO_CONTROL_TOKEN"]
        with self.assertRaises(SystemExit) as refused:
            self.launch(environment)
        self.assertIn("workload token must differ", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
