"""Release receipts require exact retained consent and atomic local accounting."""
from pathlib import Path
import tempfile
import unittest

import client
import protocol as p
import resolution


class ResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = client.read(Path(__file__).resolve().parents[1] / "fixtures/release-vectors.json")
        cls.public = cls.vectors["valid"]
        cls.peers = cls.vectors["peers"]

    def test_completed_release_verifies_under_local_pins(self):
        self.assertEqual(resolution.verify(self.public, self.peers), self.public["consent"]["proposal"]["body"]["operationId"])
        for role in ("provider", "buyer"):
            with self.subTest(role=role), self.assertRaises(p.ProtocolError):
                resolution.verify(self.public, {**self.peers, role: "a" * 64})

    def test_valid_outer_signatures_cannot_invent_settlement_authority(self):
        for vector in self.vectors["cases"]:
            p.envelope(vector["public"]["receipt"], self.peers["provider"])
            with self.subTest(case=vector["case"]), self.assertRaises(p.ProtocolError):
                resolution.verify(vector["public"], self.peers)

    def test_only_exact_retained_consent_restores_credit_once(self):
        public, peers = self.public, self.peers
        work, artifact, intent = (public[k] for k in ("request", "incident", "consent"))
        job = work["acceptance"]["quote"]["agreement"]["jobId"]
        with tempfile.TemporaryDirectory() as state:
            db = client.connect(state)
            try:
                with self.assertRaises(p.ProtocolError):
                    client.commit_release(db, job, public, peers)
                with client.transaction(db):
                    db.execute("INSERT INTO jobs(job,quote,acceptance,state,request,attempted) VALUES(?,?,?,'accepted',?,1)",
                               (job, p.canonical(work["acceptance"]["quote"]), p.canonical(work["acceptance"]), p.canonical(work)))
                    db.execute("INSERT INTO reservations VALUES(?,100)", (job,))
                    db.execute("UPDATE account SET available=900 WHERE id=1")
                client.commit_incident(db, job, work, artifact, peers)
                with self.assertRaises(p.ProtocolError):
                    client.commit_release(db, job, public, peers)
                client.retain_release_intent(db, job, work, artifact, intent, peers, public["receipt"]["body"]["record"]["acceptedAtUnixMs"])
                self.assertEqual(client.account(db), {"available": 900, "reserved": 100, "spent": 0})
                for vector in self.vectors["cases"]:
                    with self.subTest(case=vector["case"]), self.assertRaises(p.ProtocolError):
                        client.commit_release(db, job, vector["public"], peers)
                    self.assertEqual(client.account(db), {"available": 900, "reserved": 100, "spent": 0})
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM resolved_reservations").fetchone()[0], 0)
                with self.assertRaises(p.ProtocolError):
                    client.commit_release(db, "different-job", public, peers)
                for _ in range(4):
                    client.commit_release(db, job, public, peers)
                self.assertEqual(client.account(db), {"available": 1000, "reserved": 0, "spent": 0})
                self.assertEqual(db.execute("SELECT COUNT(*) FROM resolved_reservations").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM terminals").fetchone()[0], 0)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
