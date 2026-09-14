"""Owner-local durable custody, with immutable bytes and no deletion API.

The host and SQLite file remain trusted. This is not remote custody or rollback
protection. Keep this state after the demo if its unpaid claims matter.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat

import artifacts as p

CAPACITY_BYTES = 16 * 1024 * 1024
MAX_CLAIMS = 64


class Custody:
    def __init__(self, path, pin):
        p.hash256(pin)
        self.pin = pin
        self.path = Path(os.path.abspath(path))
        parent = self.path.parent.stat(follow_symlinks=False)
        p.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
                  and stat.S_IMODE(parent.st_mode) == 0o700, "custody parent must be owned mode 0700")
        created = False
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            created = True
        except FileExistsError:
            try:
                fd = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError as error:
                raise p.ProtocolError("unsafe custody file") from error
        try:
            info = os.fstat(fd)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                      and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "unsafe custody ownership or mode")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(self.path, timeout=5)
        try:
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('BEGIN IMMEDIATE')
            if created:
                self.db.execute('CREATE TABLE identity (pin TEXT PRIMARY KEY)')
                self.db.execute('INSERT INTO identity VALUES (?)', (pin,))
                self.db.execute('CREATE TABLE objects (digest TEXT PRIMARY KEY, data BLOB NOT NULL)')
                self.db.execute('CREATE TABLE claims (allocation TEXT PRIMARY KEY, submission TEXT NOT NULL)')
                self.db.execute('CREATE TABLE decisions (allocation TEXT PRIMARY KEY REFERENCES claims(allocation), digest TEXT NOT NULL)')
                self.db.execute('PRAGMA user_version=1')
            p.require(self.db.execute('PRAGMA user_version').fetchone()[0] == 1, "unsupported custody schema")
            p.require(self.db.execute('SELECT pin FROM identity').fetchall() == [(pin,)], "custody identity changed")
            self.db.commit()
            if created:
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
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
            size = self.db.execute('SELECT COALESCE(SUM(length(data)),0) FROM objects').fetchone()[0]
            p.require(size + len(data) <= CAPACITY_BYTES, "custody capacity exhausted")
            self.db.execute('INSERT INTO objects VALUES (?,?)', (digest, data))
        return digest

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
            self._put(encoded)
            self.db.execute('INSERT INTO claims VALUES (?,?)', (allocation, digest))

    def decision(self, allocation):
        row = self.db.execute('SELECT digest FROM decisions WHERE allocation=?', (allocation,)).fetchone()
        return None if row is None else p.load(self.get(row[0]))

    def record_decision(self, allocation, submission, decision):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT submission FROM claims WHERE allocation=?', (allocation,)).fetchone()
            p.require(row == (p.digest(submission),), "decision lacks original retained claim")
            original = self.decision(allocation)
            if original is not None:
                p.require(p.canonical(original) == p.canonical(decision), "conflicting financial decision")
            else:
                digest = self._put(p.canonical(decision))
                self.db.execute('INSERT INTO decisions VALUES (?,?)', (allocation, digest))
        p.require(self.decision(allocation) == decision, "decision readback failed")
        return decision
