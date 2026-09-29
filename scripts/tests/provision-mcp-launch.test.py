"""The shared example helper requires enforcement and preserves existing authority."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / "lib" / "provision-mcp-launch.sh"


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.chio = self.root / "fake-chio"
        self.chio.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
Path(os.environ['TEST_LAUNCH_CAPTURE']).write_text(json.dumps(args))
out=Path(args[args.index('--output-dir')+1]);out.mkdir(exist_ok=True)
for name in ['manifest-public-key','cage-policy-signer','provision-report.json']:
    (out/name).write_text('test-artifact')
''')
        self.chio.chmod(0o700)
        self.grants = self.root / "grants"
        self.grants.write_text("/usr/lib\n/reviewed path\n")
        self.capture = self.root / "arguments.json"
        self.environment = dict(
            os.environ,
            CHIO_CAGE_INIT=str(self.chio),
            CHIO_RECEIPT_ANCHOR_ROOT=str(self.root),
            CHIO_CAGE_READ_PATHS_FILE=str(self.grants),
            TEST_LAUNCH_CAPTURE=str(self.capture),
        )

    def provision(self):
        # A fixed identity exercises the argument builder independently of the
        # test runner's UID; the fake provisioner never launches a native tool.
        return subprocess.run(
            ["bash", "-c", 'set -euo pipefail; id() { printf "10001\\n"; }; source "$1"; chio_provision_mcp_launch "$2" "$3/security" test Test 1 "$3" "$2"', "test", str(HELPER), str(self.chio), str(self.root)],
            env=self.environment, capture_output=True, text=True, timeout=10,
        )

    def test_enforced_arguments_and_repeated_provision_preserve_authority(self):
        first = self.provision()
        self.assertEqual(first.returncode, 0, first.stderr)
        args = json.loads(self.capture.read_text())
        self.assertEqual(args[:4], ["security", "provision-reference-runtime", "--stage", "enforced"])
        self.assertEqual(args[args.index("--cage-init") + 1], str(self.chio))
        self.assertEqual(args[args.index("--receipt-rollback-anchor-root") + 1], str(self.root))
        self.assertEqual([args[i + 1] for i, value in enumerate(args) if value == "--read-path"], ["/usr/lib", "/reviewed path"])
        marker = self.root / "security" / "retained-authority"
        marker.write_bytes(b"retained")
        second = self.provision()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(marker.read_bytes(), b"retained")

    def test_missing_enforcement_input_refuses_before_provisioning(self):
        self.environment.pop("CHIO_CAGE_INIT")
        result = self.provision()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configure absolute CHIO_CAGE_INIT", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_relative_grant_refuses_before_provisioning(self):
        self.grants.write_text("relative/path\n")
        result = self.provision()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("read grants must be absolute paths", result.stderr)
        self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
