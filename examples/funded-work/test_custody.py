"""Exercise actual SQLite persistence; losing or substituting bytes must deny."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

import artifacts as p
from custody import Custody
from test_protocol import agreement, keys, INPUT, OUTPUT


def legacy_store(path, pin):
    connection = sqlite3.connect(path)
    path.chmod(0o600)
    for sql in ('CREATE TABLE identity (pin TEXT PRIMARY KEY)',
                'CREATE TABLE objects (digest TEXT PRIMARY KEY, data BLOB NOT NULL)',
                'CREATE TABLE claims (allocation TEXT PRIMARY KEY, submission TEXT NOT NULL)',
                'CREATE TABLE decisions (allocation TEXT PRIMARY KEY REFERENCES claims(allocation), digest TEXT NOT NULL)'):
        connection.execute(sql)
    connection.execute('INSERT INTO identity VALUES (?)', (pin,))
    connection.execute('PRAGMA user_version=1')
    connection.commit()
    return connection


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "custody.sqlite"
        self.a, self.pins = agreement()

    def test_known_populated_v1_migrates_with_pending_decision_reserve(self):
        with legacy_store(self.path, self.pins['custodian']) as db:
            data = b'{"retained":"original"}'
            db.execute('INSERT INTO objects VALUES (?,?)', (p.sha256(data), data))
            db.execute('INSERT INTO claims VALUES (?,?)', ('0x'+'70'*32, p.sha256(data)))
        with Custody(self.path, self.pins['custodian']) as store:
            self.assertEqual(store.get(p.sha256(data)), data)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT decision_reserved FROM claims').fetchone()[0], 4096)

    def test_unknown_v1_layout_is_denied_without_reinterpreting_rows(self):
        with legacy_store(self.path, self.pins['custodian']) as db:
            db.execute('ALTER TABLE claims ADD COLUMN unknown TEXT')
        with self.assertRaises(p.ProtocolError):
            Custody(self.path, self.pins['custodian'])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(len(db.execute('PRAGMA table_info(claims)').fetchall()), 3)

    def test_full_v1_migration_denies_without_erasing_or_rewriting_evidence(self):
        with legacy_store(self.path, self.pins['custodian']) as db:
            for n in range(64):
                data = str(n).encode().ljust(262144, b'x')
                db.execute('INSERT INTO objects VALUES (?,?)', (p.sha256(data), data))
            db.execute('INSERT INTO claims VALUES (?,?)', ('0x'+'70'*32, p.sha256(data)))
        before = p.sha256(self.path.read_bytes())
        with self.assertRaises(p.ProtocolError):
            Custody(self.path, self.pins['custodian'])
        self.assertEqual(p.sha256(self.path.read_bytes()), before)

    def test_oversized_decision_does_not_consume_reserved_capacity(self):
        allocation = '0x'+'70'*32
        submission = {'retained':'submission'}
        with Custody(self.path, self.pins['custodian']) as store:
            store.bind_submission(allocation, submission)
            with self.assertRaises(p.ProtocolError):
                store.record_decision(allocation, submission, {'unbounded':'x'*4096})
            self.assertIsNone(store.decision(allocation))
            self.assertEqual(store.db.execute('SELECT decision_reserved FROM claims').fetchone()[0],4096)

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
