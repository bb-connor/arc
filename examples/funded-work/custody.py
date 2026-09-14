"""Owner-local durable custody, with immutable bytes and no deletion API.

The host and SQLite file remain trusted. This is not remote custody or rollback
protection. Keep this state after the demo if its unpaid claims matter.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
from owned_sqlite import open_owned, sync_parent

import artifacts as p

CAPACITY_BYTES = 16 * 1024 * 1024
MAX_CLAIMS = 64
DECISION_BYTES = 4096
SCHEMA_V1 = {
    'identity': 'CREATE TABLE identity (pin TEXT PRIMARY KEY)',
    'objects': 'CREATE TABLE objects (digest TEXT PRIMARY KEY, data BLOB NOT NULL)',
    'claims': 'CREATE TABLE claims (allocation TEXT PRIMARY KEY, submission TEXT NOT NULL)',
    'decisions': 'CREATE TABLE decisions (allocation TEXT PRIMARY KEY REFERENCES claims(allocation), digest TEXT NOT NULL)',
}
SCHEMA_V2 = {**SCHEMA_V1, 'claims': 'CREATE TABLE claims (allocation TEXT PRIMARY KEY, submission TEXT NOT NULL, decision_reserved INTEGER NOT NULL DEFAULT 0)'}


class Custody:
    def __init__(self, path, pin):
        p.hash256(pin)
        self.pin = pin
        self.path = Path(os.path.abspath(path))
        self.db, created = open_owned(self.path)
        try:
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('BEGIN IMMEDIATE')
            if created:
                for sql in SCHEMA_V2.values():
                    self.db.execute(sql)
                self.db.execute('INSERT INTO identity VALUES (?)', (pin,))
                self.db.execute('PRAGMA user_version=2')
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            p.require(version in (1, 2), 'unsupported custody schema')
            layout = dict(self.db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
            p.require(layout == (SCHEMA_V1 if version == 1 else SCHEMA_V2), 'unknown custody schema lineage')
            p.require(self.db.execute('SELECT pin FROM identity').fetchall() == [(pin,)], "custody identity changed")
            p.require(not self.db.execute('PRAGMA foreign_key_check').fetchall(), 'orphan custody decision')
            if version == 1:
                self.db.execute('ALTER TABLE claims ADD COLUMN decision_reserved INTEGER NOT NULL DEFAULT 0')
                self.db.execute('UPDATE claims SET decision_reserved=? WHERE allocation NOT IN (SELECT allocation FROM decisions)', (DECISION_BYTES,))
                self.db.execute('PRAGMA user_version=2')
            invalid = self.db.execute('SELECT 1 FROM claims c LEFT JOIN decisions d ON c.allocation=d.allocation WHERE c.decision_reserved != CASE WHEN d.allocation IS NULL THEN ? ELSE 0 END', (DECISION_BYTES,)).fetchone()
            p.require(invalid is None, 'custody decision reservation changed')
            self._budget(0)
            self.db.commit()
            if created:
                sync_parent(self.path)
        except Exception:
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    def get(self, digest):
        p.hash256(digest)
        row = self.db.execute('SELECT length(data) FROM objects WHERE digest=?', (digest,)).fetchone()
        p.require(row is not None and 0 <= row[0] <= p.MAX_JSON, "custody missing or oversized")
        data = self.db.execute('SELECT data FROM objects WHERE digest=?', (digest,)).fetchone()[0]
        p.require(type(data) is bytes and p.sha256(data) == digest, "custody content hash mismatch")
        return data

    def _put(self, data):
        p.require(type(data) is bytes and len(data) <= p.MAX_JSON, "custody object exceeds limit")
        digest = p.sha256(data)
        if self.db.execute('SELECT 1 FROM objects WHERE digest=?', (digest,)).fetchone():
            p.require(self.get(digest) == data, "custody object changed")
        else:
            self._budget(len(data))
            self.db.execute('INSERT INTO objects VALUES (?,?)', (digest, data))
        return digest

    def _budget(self, additional):
        size = self.db.execute('SELECT COALESCE(SUM(length(data)),0) FROM objects').fetchone()[0]
        reserved = self.db.execute('SELECT COALESCE(SUM(decision_reserved),0) FROM claims').fetchone()[0]
        p.require(size + reserved + additional <= CAPACITY_BYTES, 'custody capacity exhausted')

    def retain(self, agreement, source, output, key):
        p.require(key.public_key().public_bytes_raw().hex() == self.pin == agreement['custodianKey'], "wrong custodian")
        p.require(type(source) is bytes and type(output) is bytes
                  and len(source) <= p.MAX_OBJECT and len(output) <= p.MAX_OBJECT, "work bytes exceed custody profile")
        p.require(p.sha256(source) == agreement['inputSha256'], "input differs from agreement")
        receipt = p.sign(p.receipt_body(agreement, p.sha256(output)), key)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            for data in (source, output, p.canonical(agreement), p.canonical(receipt)):
                self._put(data)
        # Retrieve after the FULL-synchronous commit before releasing a receipt.
        for data in (source, output, p.canonical(receipt)):
            p.require(self.get(p.sha256(data)) == data, "custody readback failed")
        return receipt

    def bind_submission(self, allocation, submission):
        p.hash256(allocation, '0x')
        encoded = p.canonical(submission)
        digest = p.sha256(encoded)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT submission FROM claims WHERE allocation=?', (allocation,)).fetchone()
            if row is not None:
                p.require(row[0] == digest, "allocation already binds a different submission")
                p.require(self.get(digest) == encoded, "retained submission unavailable")
                return
            count = self.db.execute('SELECT COUNT(*) FROM claims').fetchone()[0]
            p.require(count < MAX_CLAIMS, "custody claim capacity exhausted")
            self.db.execute('INSERT INTO claims VALUES (?,?,?)', (allocation, digest, DECISION_BYTES))
            self._budget(0)
            self._put(encoded)

    def decision(self, allocation):
        row = self.db.execute('SELECT digest FROM decisions WHERE allocation=?', (allocation,)).fetchone()
        return None if row is None else p.load(self.get(row[0]))

    def record_decision(self, allocation, submission, decision):
        encoded = p.canonical(decision)
        p.require(len(encoded) <= DECISION_BYTES, 'decision exceeds reserved profile bound')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT submission FROM claims WHERE allocation=?', (allocation,)).fetchone()
            p.require(row == (p.digest(submission),), "decision lacks original retained claim")
            original = self.decision(allocation)
            if original is not None:
                p.require(p.canonical(original) == p.canonical(decision), "conflicting financial decision")
            else:
                self.db.execute('UPDATE claims SET decision_reserved=0 WHERE allocation=?', (allocation,))
                digest = self._put(encoded)
                self.db.execute('INSERT INTO decisions VALUES (?,?)', (allocation, digest))
        p.require(self.decision(allocation) == decision, "decision readback failed")
        return decision
