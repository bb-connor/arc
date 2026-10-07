#!/usr/bin/env python3
"""Exercise the actual image package instruction with controlled external I/O."""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'security_apk_contract', ROOT / 'scripts/check-security-ci-contract.py'
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit('cannot load security image contract')
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class PackageClosure(unittest.TestCase):
    def execute(self, *, tamper: bool = False, installed_mismatch: bool = False):
        with tempfile.TemporaryDirectory(prefix='chio-apk-instruction-') as directory:
            root = Path(directory)
            inventory = root / 'security-evidence-apk.lock'
            original = (ROOT / 'deploy/docker/security-evidence-apk.lock').read_bytes()
            inventory.write_bytes(original + b'changed-input\n' if tamper else original)
            installed = root / 'installed.lock'
            lines = original.decode().splitlines()
            if installed_mismatch:
                lines[0] = 'unexpected-installed-package-1.0-r0'
            installed.write_text('\n'.join(lines) + '\n')
            archive = root / 'ca-fixture.apk'
            archive.write_bytes(b'controlled external archive fixture\n')
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            # Replace only external download/package I/O. The real instruction's
            # hashing, constraint preparation and final comparison still execute.
            programs = {
                'wget': '''#!/bin/sh
set -eu
test "$#" -eq 4
test "$1" = -q
test "$2" = -O
test "$4" = https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/ca-certificates-20260909-r0.apk
printf '%s\\n' download > "$FIXTURE_DOWNLOAD"
cp "$FIXTURE_CA_ARCHIVE" "$3"
''',
                'apk': '''#!/bin/sh
set -eu
case "$1:$2" in
  add:--no-cache) printf '%s\\n' "$@" > "$FIXTURE_APK_ARGS" ;;
  info:-v) cat "$FIXTURE_INSTALLED" ;;
  *) exit 64 ;;
esac
''',
            }
            for name, text in programs.items():
                path = bin_dir / name
                path.write_text(text)
                path.chmod(0o755)
            document = (ROOT / 'deploy/docker/Dockerfile.security-evidence-runner').read_text()
            instruction = CHECKER.parse_dockerfile(document)[2][1]
            instruction = instruction.replace('/tmp/', str(root) + '/')
            # The known upstream archive is replaced at the external-I/O boundary;
            # authenticate this fixture with a real SHA256 comparison as usual.
            instruction = instruction.replace(
                'a1258993a229d2fdcc6d9665af75c9305184e4f5e5755c50b9ef0564b35138c4',
                hashlib.sha256(archive.read_bytes()).hexdigest(),
            )
            env = dict(os.environ, PATH=str(bin_dir) + ':' + os.environ['PATH'],
                       LC_ALL='C', FIXTURE_DOWNLOAD=str(root / 'downloaded'),
                       FIXTURE_CA_ARCHIVE=str(archive), FIXTURE_APK_ARGS=str(root / 'apk-args'),
                       FIXTURE_INSTALLED=str(installed))
            result = subprocess.run(['/bin/sh', '-ec', instruction], env=env,
                                    capture_output=True, text=True, timeout=10)
            args_path = root / 'apk-args'
            arguments = args_path.read_text().splitlines() if args_path.exists() else []
            return result, arguments, (root / 'downloaded').exists()

    def test_every_package_is_constrained_before_installation(self):
        result, arguments, downloaded = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(downloaded)
        self.assertEqual(arguments[:2], ['add', '--no-cache'])
        self.assertTrue(arguments[2].endswith('/ca-certificates-20260909-r0.apk'))
        constraints = arguments[3:]
        self.assertEqual(len(constraints), 225)
        self.assertEqual(len({value.split('=', 1)[0] for value in constraints}), 225)
        for value in constraints:
            self.assertRegex(value, r'^[a-z0-9][a-z0-9_.+-]*=[0-9][a-zA-Z0-9_.+-]*$')
        self.assertIn('zlib=1.3.2-r1', constraints)
        self.assertIn('zlib-dev=1.3.2-r1', constraints)
        self.assertIn('openssl-dev=3.5.9-r0', constraints)
        self.assertIn('ca-certificates-bundle=20260909-r0', constraints)

    def test_modified_inventory_is_refused_before_download(self):
        result, arguments, downloaded = self.execute(tamper=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(downloaded, 'inventory must authenticate before external I/O')
        self.assertEqual(arguments, [])

    def test_installed_inventory_mismatch_is_refused(self):
        result, arguments, downloaded = self.execute(installed_mismatch=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(downloaded)
        self.assertTrue(arguments)


if __name__ == '__main__':
    unittest.main()
