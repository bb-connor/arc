"""Retained native incident vectors and buyer accounting boundaries."""
import copy
from pathlib import Path
import tempfile
import unittest

import client
import incident
import protocol as p
import review


class IncidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = client.read(Path(__file__).resolve().parents[1] / "fixtures/incident-vectors.json")
        cls.public = cls.vectors["valid"]
        cls.work = cls.public["request"]
        cls.peers = cls.vectors["peers"]

    def test_native_incident_verifies_with_local_pins(self):
        self.assertEqual(incident.verify(self.work, self.public["incident"], self.peers), self.public["operationId"])
        for role in ("buyer", "provider"):
            with self.subTest(role=role), self.assertRaises(p.ProtocolError):
                incident.verify(self.work, self.public["incident"], {**self.peers, role: "a" * 64})

    def test_valid_signatures_do_not_authorize_malformed_incidents(self):
        for vector in self.vectors["cases"]:
            value = vector["public"]
            # Every negative vector really carries a valid native signature under
            # the fixture provider key, including the wrong embedded signer case.
            body = value["incident"]["projection"]["body"]
            signature = value["incident"]["projection"]["signature"]
            p.Ed25519PublicKey.from_public_bytes(p.hex_bytes(self.peers["provider"])).verify(
                p.hex_bytes(signature, 64), incident.NATIVE.encode() + b"\0" + p.canonical(body))
            with self.subTest(case=vector["case"]), self.assertRaises(p.ProtocolError):
                incident.verify(value["request"], value["incident"], self.peers)

    def test_unknown_cannot_substitute_for_checked_work(self):
        with self.assertRaises(p.ProtocolError):
            review.terminal(self.work, self.public["incident"], self.peers)
        invented = copy.deepcopy(self.public["incident"])
        invented["settled"] = True
        with self.assertRaises(p.ProtocolError):
            incident.verify(self.work, invented, self.peers)

    def test_retention_requires_local_attempt_and_preserves_reserved_credits(self):
        with tempfile.TemporaryDirectory() as state:
            db = client.connect(state)
            try:
                job = self.work["acceptance"]["quote"]["agreement"]["jobId"]
                artifact = self.public["incident"]
                with self.assertRaises(p.ProtocolError):
                    client.commit_incident(db, job, self.work, artifact, self.peers)
                with client.transaction(db):
                    db.execute("INSERT INTO jobs(job,quote,acceptance,state,request,attempted) VALUES(?,?,?,'accepted',?,0)",
                               (job, p.canonical(self.work["acceptance"]["quote"]), p.canonical(self.work["acceptance"]), p.canonical(self.work)))
                    db.execute("INSERT INTO reservations VALUES(?,100)", (job,))
                    db.execute("UPDATE account SET available=900 WHERE id=1")
                with self.assertRaises(p.ProtocolError):
                    client.commit_incident(db, job, self.work, artifact, self.peers)
                db.execute("UPDATE jobs SET attempted=1 WHERE job=?", (job,))
                for _ in range(2):
                    client.commit_incident(db, job, self.work, artifact, self.peers)
                for vector in self.vectors["cases"]:
                    with self.subTest(case=vector["case"]), self.assertRaises(p.ProtocolError):
                        value = vector["public"]
                        client.commit_incident(db, job, value["request"], value["incident"], self.peers)
                self.assertEqual(client.account(db), {"available": 900, "reserved": 100, "spent": 0})
                self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM terminals").fetchone()[0], 0)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
