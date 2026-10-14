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
        self.script = self.root / "server.py"
        self.script.write_bytes(b"x" * 4096)
        self.script.chmod(0o664)
        self.grants = self.root / "grants"
        self.grants.write_text(f"/usr/lib\n/reviewed path\n{self.script}\n")
        self.library = self.root / "libc.so.6"
        self.library.write_bytes(b"x" * 8192)
        self.runtime = self.root / "runtime-files"
        self.runtime.write_text(f"{self.library}\n")
        self.capture = self.root / "arguments.json"
        self.environment = dict(
            os.environ,
            CHIO_CAGE_INIT=str(self.chio),
            CHIO_RECEIPT_ANCHOR_ROOT=str(self.root),
            CHIO_CAGE_READ_PATHS_FILE=str(self.grants),
            CHIO_CAGE_RUNTIME_FILES_FILE=str(self.runtime),
            CHIO_CAGE_SYSCALL_PROFILE="native-standard-v1",
            TEST_LAUNCH_CAPTURE=str(self.capture),
        )

    def provision(self, groups="10001 10002"):
        # A fixed identity exercises the argument builder independently of the
        # test runner's UID; the fake provisioner never launches a native tool.
        identity = f'id() {{ case "${{1:-}}" in -G) printf "%s\\n" "{groups}";; *) printf "10001\\n";; esac; }}'
        return subprocess.run(
            ["bash", "-c", f'set -euo pipefail; {identity}; source "$1"; chio_provision_mcp_launch "$2" "$3/security" test Test 1 "$3" "$2" "$3/./server.py" --flag', "test", str(HELPER), str(self.chio), str(self.root)],
            env=self.environment, capture_output=True, text=True, timeout=10,
        )

    def values(self, args, flag):
        return [args[i + 1] for i, value in enumerate(args) if value == flag]

    def test_enforced_arguments_and_repeated_provision_preserve_authority(self):
        first = self.provision()
        self.assertEqual(first.returncode, 0, first.stderr)
        args = json.loads(self.capture.read_text())
        self.assertEqual(args[:2], ["security", "provision-reference-runtime"])
        self.assertNotIn("--stage", args)
        self.assertEqual(args[args.index("--cage-init") + 1], str(self.chio))
        self.assertEqual(args[args.index("--receipt-rollback-anchor-root") + 1], str(self.root))
        self.assertEqual(self.values(args, "--read-path"), ["/usr/lib", "/reviewed path", str(self.script)])
        self.assertEqual(self.values(args, "--runtime-file"), [str(self.library), str(self.script)])
        self.assertEqual(self.values(args, "--target-arg"), [str(self.script), "--flag"])
        self.assertEqual(self.values(args, "--syscall-profile"), ["native-standard-v1"])
        self.assertEqual(self.values(args, "--execution-supplementary-gid"), ["10002"])
        retained = [self.chio, self.chio, self.library, self.script]
        self.assertEqual(self.values(args, "--max-artifact-bytes"), [str(max(path.stat().st_size for path in retained))])
        self.assertEqual(self.script.stat().st_mode & 0o022, 0)
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

    def test_missing_runtime_files_refuses_before_provisioning(self):
        self.environment.pop("CHIO_CAGE_RUNTIME_FILES_FILE")
        result = self.provision()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CHIO_CAGE_RUNTIME_FILES_FILE (reviewed runtime files", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_unreviewed_syscall_profile_refuses_before_provisioning(self):
        self.environment["CHIO_CAGE_SYSCALL_PROFILE"] = "unconfined"
        result = self.provision()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("set CHIO_CAGE_SYSCALL_PROFILE to native-minimal-v1", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_root_supplementary_group_refuses_before_provisioning(self):
        result = self.provision(groups="10001 0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to bind the root supplementary group", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_relative_grant_refuses_before_provisioning(self):
        self.grants.write_text("relative/path\n")
        result = self.provision()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("read grants must be absolute paths", result.stderr)
        self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
