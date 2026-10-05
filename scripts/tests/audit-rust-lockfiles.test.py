#!/usr/bin/env python3
"""Every retained Rust graph must be scanned and every scanner failure blocks."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
SCRIPT = ROOT / 'scripts/audit-rust-lockfiles.py'
SPEC = importlib.util.spec_from_file_location('audit_lockfiles', SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class LockfileAuditTests(unittest.TestCase):
    def test_later_failure_blocks_and_all_scans_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in CHECK.LOCKFILES:
                lock = root / relative
                lock.parent.mkdir(parents=True, exist_ok=True)
                lock.write_text('version = 4\n')
            stub = root / 'cargo'
            stub.write_text('#!/usr/bin/env python3\n'
                            'import os,sys\n'
                            'assert sys.argv[1] == "audit" and "--json" in sys.argv\n'
                            'print("{}")\n'
                            'sys.exit(int(os.environ["FAIL"]) if "proof-room-workspace" in sys.argv[3] else 0)\n')
            stub.chmod(0o755)
            for status in (0, 1, 2):
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'], FAIL=str(status))
                result = subprocess.run(['python3', str(SCRIPT), '--repo-root', str(root), '--json'],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, int(status != 0), result.stderr)
                self.assertEqual(len(result.stdout.splitlines()), len(CHECK.LOCKFILES))
                self.assertEqual(len(list((root / 'cargo-audit-workspaces').glob('*.json'))), len(CHECK.LOCKFILES) - 1)
                self.assertTrue((root / 'cargo-audit.json').is_file())
            (root / CHECK.LOCKFILES[-1]).unlink()
            with self.assertRaises(ValueError):
                CHECK.audit(root, ['--json'])


if __name__ == '__main__':
    unittest.main()
