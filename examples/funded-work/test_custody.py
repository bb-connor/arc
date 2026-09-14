"""Exercise actual SQLite persistence; losing or substituting bytes must deny."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

import artifacts as p
from custody import Custody
from test_protocol import agreement, keys, INPUT, OUTPUT


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "custody.sqlite"
        self.a, self.pins = agreement()

    def test_retained_bytes_and_receipt_survive_reopen(self):
        encoded = p.canonical(OUTPUT)
        with Custody(self.path, self.pins["custodian"]) as store:
            receipt = store.retain(self.a["body"], INPUT, encoded, keys()[3])
        with Custody(self.path, self.pins["custodian"]) as store:
            self.assertEqual(store.get(p.sha256(INPUT)), INPUT)
            self.assertEqual(store.get(p.sha256(encoded)), encoded)
            self.assertEqual(store.retain(self.a["body"], INPUT, encoded, keys()[3]), receipt)
        self.assertEqual(p.envelope(receipt, self.pins["custodian"])["retainUntil"], 2592130)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_missing_or_tampered_bytes_fail(self):
        with Custody(self.path, self.pins["custodian"]) as store:
            store.retain(self.a["body"], INPUT, p.canonical(OUTPUT), keys()[3])
            with self.assertRaises(p.ProtocolError):
                store.get("ab" * 32)
        with sqlite3.connect(self.path) as connection:
            connection.execute("UPDATE objects SET data=? WHERE digest=?", (b'wrong', p.sha256(INPUT)))
        with Custody(self.path, self.pins["custodian"]) as store:
            with self.assertRaises(p.ProtocolError):
                store.get(p.sha256(INPUT))

    def test_unsafe_paths_modes_and_changed_identity_fail(self):
        with Custody(self.path, self.pins["custodian"]):
            pass
        self.path.chmod(0o644)
        with self.assertRaises(p.ProtocolError):
            Custody(self.path, self.pins["custodian"])
        self.path.chmod(0o600)
        link = self.path.with_name("link.sqlite")
        link.symlink_to(self.path)
        with self.assertRaises(p.ProtocolError):
            Custody(link, self.pins["custodian"])
        with self.assertRaises(p.ProtocolError):
            Custody(self.path, self.pins["verifier"])
        self.path.parent.chmod(0o755)
        with self.assertRaises(p.ProtocolError):
            Custody(self.path, self.pins["custodian"])
        self.path.parent.chmod(0o700)

    def test_failed_custody_does_not_issue_a_receipt(self):
        with Custody(self.path, self.pins["custodian"]) as store:
            for source, output, key in ((INPUT+b' ', p.canonical(OUTPUT), keys()[3]),
                                       (INPUT, b'x'*65537, keys()[3]),
                                       (INPUT, p.canonical(OUTPUT), keys()[2])):
                with self.subTest(source=len(source), output=len(output)), self.assertRaises(p.ProtocolError):
                    store.retain(self.a["body"], source, output, key)

    def test_byte_capacity_denies_without_evicting_prior_custody(self):
        with Custody(self.path, self.pins['custodian']) as store:
            receipt = store.retain(self.a['body'], INPUT, p.canonical(OUTPUT), keys()[3])
            exhausted = False
            for n in range(257):
                data = str(n).encode().ljust(65536, b' ')
                try:
                    store.retain(self.a['body'], INPUT, data, keys()[3])
                except p.ProtocolError as error:
                    self.assertIn('capacity exhausted', str(error))
                    exhausted = True
                    break
            self.assertTrue(exhausted, 'unbounded output custody accepted')
            self.assertEqual(store.get(p.digest(receipt)), p.canonical(receipt))
            self.assertEqual(store.get(p.sha256(p.canonical(OUTPUT))), p.canonical(OUTPUT))


if __name__ == '__main__':
    unittest.main()
