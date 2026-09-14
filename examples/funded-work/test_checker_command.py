"""Invoke the actual Rust command; unsupported declarations must fail closed."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_protocol import INPUT, OUTPUT

BINARY = Path(os.environ.get('CHIO_W0_BINARY', 'target/debug/chio-federated-work')).resolve()


class CheckerCommandTests(unittest.TestCase):
    def test_rust_produces_hand_checked_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'openapi.json'
            source.write_bytes(INPUT)
            result = subprocess.run([str(BINARY), 'check-openapi', str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), OUTPUT['operations'])

    def test_rust_denies_duplicates_unsupported_and_oversized_input(self):
        for encoded in (b'{"openapi":"3.1.0","openapi":"3.1.0","paths":{}}',
                        b'{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}', b' ' * 65537):
            with self.subTest(size=len(encoded)), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'openapi.json'
                source.write_bytes(encoded)
                result = subprocess.run([str(BINARY), 'check-openapi', str(source)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
