"""Disclosure, independent authority, procurement and nested evidence checks."""
import copy
import hashlib
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import client
import protocol as p
import review
import subcontract as s


class SubcontractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = client.read(Path(__file__).resolve().parents[1] / "fixtures/subcontract-vectors.json")
        cls.parent = cls.vectors["request"]["acceptance"]["quote"]["agreement"]

    def test_project_reconstructs_only_approved_authentication(self):
        source = p.load_json(self.vectors["request"]["input"])
        source["info"] = {"private": "secret"}
        source["paths"]["/accounts"]["get"]["description"] = "secret"
        source["components"]["securitySchemes"]["serviceToken"]["description"] = "secret"
        projected = s.project(p.canonical(source).decode(), ["/accounts", "/refunds"])
        self.assertEqual(p.load_json(projected), {"openapi": "3.1.0", "paths": {
            "/accounts": {"get": {"security": [{"serviceToken": []}]}},
            "/refunds": {"post": {"security": []}}},
            "components": {"securitySchemes": {"serviceToken": {"type": "http", "scheme": "bearer"}}}})
        self.assertNotIn("secret", projected)
        self.assertEqual(hashlib.sha256(projected.encode()).hexdigest(), self.parent["subcontract"]["inputSha256"])

    def test_four_roles_cannot_collapse_to_shared_keys(self):
        for field in ("delegate", "specialist"):
            for other in (self.parent["buyer"], self.parent["provider"], self.parent["subcontract"]["specialist" if field == "delegate" else "delegate"]):
                a = copy.deepcopy(self.parent)
                a["subcontract"][field] = other
                with self.subTest(field=field, other=other), self.assertRaises(p.ProtocolError):
                    s.child_agreement(a)

    def test_disclosure_permission_is_exact_and_bounded(self):
        for changed in ({"paths": []}, {"paths": ["/refunds", "/accounts"]}, {"paths": ["/accounts", "/accounts"]},
                        {"paths": ["relative"]}, {"priceCeiling": 200}, {"priceCeiling": True}, {"inputSha256": "A" * 64}):
            a = copy.deepcopy(self.parent)
            a["subcontract"].update(changed)
            with self.subTest(changed=changed), self.assertRaises(p.ProtocolError):
                s.child_agreement(a)
        work = copy.deepcopy(self.vectors["request"])
        work["acceptance"]["quote"]["agreement"]["subcontract"]["paths"] = ["/health"]
        with self.assertRaises(p.ProtocolError):
            s.disclosure(work)

    def test_parent_hash_separates_otherwise_identical_procurements(self):
        another = {**self.parent, "jobId": "another-parent"}
        self.assertNotEqual(s.child_agreement(another)["jobId"], s.child_agreement(self.parent)["jobId"])

    def test_even_valid_promisor_signatures_cannot_widen_a_permit(self):
        child = s.child_agreement(self.parent)
        body = s.permit_terms(self.vectors["request"])
        signer = Ed25519PrivateKey.generate()
        pin = signer.public_key().public_bytes_raw().hex()
        s.verify_permit(p.sign(body, signer), child, pin)
        changes = ({"parentAgreementSha256": "b" * 64}, {"childAgreementSha256": "b" * 64},
                   {"delegate": pin}, {"specialist": pin}, {"priceCeiling": 200},
                   {"currency": "USD"}, {"expiresAt": body["expiresAt"] + 1}, {"unknown": True})
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(p.ProtocolError):
                s.verify_permit(p.sign({**body, **changed}, signer), child, pin)

    def test_parent_signature_cannot_replace_child_evidence(self):
        review.verify_report(self.vectors["request"], self.vectors["valid"])
        for case in self.vectors["cases"]:
            p.envelope(case["report"], self.parent["provider"])
            with self.subTest(case=case["case"]), self.assertRaises(p.ProtocolError):
                review.verify_report(self.vectors["request"], case["report"])


if __name__ == "__main__":
    unittest.main()
