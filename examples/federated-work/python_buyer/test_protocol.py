"""Adversarial wire and accounting tests using retained native public artifacts."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import client
import protocol as p
import review

EVIDENCE = Path(__file__).resolve().parents[3] / "docs/papers/review-2026-09/evidence/30-recoverable-checked-output-rejections"


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public = client.read(EVIDENCE / "paid-normal-public.json")
        cls.denial = client.read(EVIDENCE / "paid-corrupt-report-public.json")
        cls.work = cls.public["request"]
        a = cls.work["acceptance"]["quote"]["agreement"]
        cls.peers = {k: a[k] for k in ("buyer", "provider")}

    def test_native_success_and_rejection(self):
        for source, expected in ((self.public, False), (self.denial, True)):
            a = source["request"]["acceptance"]["quote"]["agreement"]
            peers = {k: a[k] for k in ("buyer", "provider")}
            self.assertEqual(review.terminal(source["request"], source["delivery"], peers)[0], expected)

    def test_canonical_json_utf16_order_and_numbers(self):
        # UTF-16 ordering puts the supplementary-plane key before U+E000.
        self.assertEqual(p.canonical({"\ue000": 1e30, "\U0001f600": -0.0, "a": 1.0}),
                         '{"a":1,"😀":0,"\ue000":1e+30}'.encode())
        self.assertFalse(p.same(True, 1))
        for encoded in ('{"a":1,"a":2}', '{"a":{"x":1,"x":2}}', 'NaN', 'Infinity', '9007199254740992', '"\\ud800"'):
            with self.subTest(encoded=encoded), self.assertRaises(p.ProtocolError):
                p.load_json(encoded)
        with self.assertRaises(p.ProtocolError):
            p.load_json('{"a":1}'.encode("utf-16"))

    def test_untrusted_pins_do_not_come_from_artifacts(self):
        for role in ("buyer", "provider"):
            peers = {**self.peers, role: "a" * 64}
            with self.subTest(role=role), self.assertRaises(p.ProtocolError):
                review.terminal(self.work, self.public["delivery"], peers)

    def test_each_public_binding_rejects_substitution(self):
        mutations = [
            lambda v: v["request"].update(input=v["request"]["input"] + " "),
            lambda v: v["request"]["acceptance"]["quote"]["agreement"].update(jobId="different"),
            lambda v: v["delivery"]["report"]["body"]["operations"][0].update(authenticationRequired=False),
            lambda v: v["delivery"]["finding"].update(payload_sha256="a" * 64),
            lambda v: v["delivery"]["finding"].update(assurance="collateralized"),
            lambda v: v["delivery"]["receipt"]["metadata"]["financial"].update(cost_charged=0),
            lambda v: v["delivery"]["receipt"].update(capability_id="other"),
            lambda v: v["delivery"]["checkpoint"]["body"].update(tree_size=1),
            lambda v: v["delivery"]["inclusion"].update(receipt_seq=999),
            lambda v: v["delivery"]["inclusion"]["proof"].update(audit_path=[]),
        ]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(self.public)
            mutate(changed)
            with self.subTest(index=index), self.assertRaises(p.ProtocolError):
                review.terminal(changed["request"], changed["delivery"], self.peers)

    def test_valid_provider_signatures_cannot_widen_offer(self):
        buyer, provider = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        peers = {"buyer": buyer.public_key().public_bytes_raw().hex(), "provider": provider.public_key().public_bytes_raw().hex()}
        a = {**self.work["acceptance"]["quote"]["agreement"], **peers, "deadline": 1000}
        quote = {"agreement": a, "bid": p.sign(p.bid_body(a, 100), buyer)}
        body = copy.deepcopy(self.work["acceptance"]["ask"]["body"])
        body.update(agentId=peers["buyer"], bidDigest=p.digest(quote["bid"]["body"]), issuedAt=100, expiresAt=1000)
        body["tokenOffer"].update(issuer=peers["provider"], subject=peers["buyer"], issued_at=100, expires_at=1000)

        def signed(body):
            token = body["tokenOffer"]
            token["signature"] = provider.sign(p.canonical({k: v for k, v in token.items() if k != "signature"})).hex()
            return p.sign(body, provider)

        p.verify_ask(quote, signed(copy.deepcopy(body)), peers)
        mutations = [
            lambda b: b["tokenOffer"]["scope"]["grants"][0].update(max_invocations=2),
            lambda b: b["tokenOffer"]["scope"]["grants"][0].update(max_invocations=True),
            lambda b: b["tokenOffer"]["scope"]["grants"][0].update(max_invocations=1.0),
            lambda b: b["tokenOffer"]["scope"]["grants"][0].update(dpop_required=False),
            lambda b: b["tokenOffer"]["scope"]["grants"][0].update(tool_name="*"),
            lambda b: b["tokenOffer"]["scope"]["grants"][0].update(max_total_cost={"currency": "TST", "units": 101}),
            lambda b: b["tokenOffer"].update(expires_at=1001),
            lambda b: b.update(bidDigest="a" * 64),
            lambda b: b.update(expiresAt=1001),
            lambda b: b.update(quotedPrice={"currency": "USD", "units": 100}),
        ]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(body)
            mutate(changed)
            with self.subTest(index=index), self.assertRaises(p.ProtocolError):
                p.verify_ask(quote, signed(changed), peers)

    def test_receipt_signature_preimage_and_semantics(self):
        identity = Ed25519PrivateKey.generate()
        pin = identity.public_key().public_bytes_raw().hex()
        body = {k: v for k, v in self.public["delivery"]["receipt"].items() if k not in ("id", "signature")}
        body["kernel_key"] = pin

        def receipt(body):
            rid = p.digest(body)
            return {**body, "id": rid, "signature": identity.sign(p.canonical({"id": rid, "body": body})).hex()}

        p.receipt(receipt(body), pin, "review", self.work)
        for change in ({"receipt_kind": "observation"}, {"boundary_class": "observe"}, {"trust_level": "unmediated"},
                       {"tool_origin": "agent"}, {"action": {"parameter_hash": "a" * 64, "parameters": self.work}}):
            with self.subTest(change=list(change)), self.assertRaises(p.ProtocolError):
                p.receipt(receipt({**body, **change}), pin, "review", self.work)
        value = receipt(body)
        value["signature"] = identity.sign(p.canonical({k: v for k, v in value.items() if k != "signature"})).hex()
        with self.assertRaises(p.ProtocolError):
            p.receipt(value, pin, "review", self.work)

    def test_merkle_inclusion_all_positions_and_irregular_trees(self):
        identity = Ed25519PrivateKey.generate()
        pin = identity.public_key().public_bytes_raw().hex()
        leaf = lambda value: hashlib.sha256(b"\x00" + p.canonical(value)).digest()
        node = lambda left, right: hashlib.sha256(b"\x01" + left + right).digest()

        def tree(leaves):
            if len(leaves) == 1:
                return leaves[0]
            split = 1 << ((len(leaves) - 1).bit_length() - 1)
            return node(tree(leaves[:split]), tree(leaves[split:]))

        def path(leaves, index):
            if len(leaves) == 1:
                return []
            split = 1 << ((len(leaves) - 1).bit_length() - 1)
            if index < split:
                return path(leaves[:split], index) + [tree(leaves[split:])]
            return path(leaves[split:], index - split) + [tree(leaves[:split])]

        for size in (1, 2, 3, 5, 8, 17):
            values = [{"position": i} for i in range(size)]
            leaves = list(map(leaf, values))
            root = "0x" + tree(leaves).hex()
            body = {"schema": "chio.checkpoint_statement.v2", "checkpoint_seq": 1, "batch_start_seq": 1,
                    "batch_end_seq": size, "tree_size": size, "merkle_root": root, "chain_root": root,
                    "issued_at": 100, "kernel_key": pin}
            checkpoint = p.sign(body, identity, envelope=False)
            for index, value in enumerate(values):
                proof = {"checkpoint_seq": 1, "receipt_seq": index + 1, "leaf_index": index, "merkle_root": root,
                         "proof": {"leaf_index": index, "tree_size": size,
                                   "audit_path": ["0x" + h.hex() for h in path(leaves, index)]}}
                p.inclusion(value, checkpoint, proof, pin)
                with self.assertRaises(p.ProtocolError):
                    p.inclusion(value, checkpoint, {**proof, "checkpoint_seq": True}, pin)
                changed = copy.deepcopy(proof)
                changed["proof"]["audit_path"].append("0x" + "a" * 64)
                with self.assertRaises(p.ProtocolError):
                    p.inclusion(value, checkpoint, changed, pin)

    def test_checker_inheritance_anonymous_override_and_fail_closed(self):
        doc = {"openapi": "3.1.0", "security": [{"bearer": []}],
               "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
               "paths": {"/inherited": {"get": {}}, "/anonymous": {"post": {"security": [{"bearer": []}, {}]}},
                         "/disabled": {"get": {"security": []}}}}
        rows = review.observations(json.dumps(doc))
        self.assertEqual([r["authenticationRequired"] for r in rows], [False, False, True])
        for modify in (lambda d: d.update(webhooks={}), lambda d: d["paths"].update({"/ref": {"$ref": "x"}}),
                       lambda d: d.update(security=[{"unknown": []}]), lambda d: d.update(openapi="3.0.0"),
                       lambda d: d["paths"]["/inherited"]["get"].update(callbacks={})):
            changed = copy.deepcopy(doc)
            modify(changed)
            with self.assertRaises(p.ProtocolError):
                review.observations(json.dumps(changed))

    def test_accounting_requires_exact_attempt_and_rolls_back_conflicts(self):
        for source in (self.public, self.denial):
            work, delivery = source["request"], source["delivery"]
            a = work["acceptance"]["quote"]["agreement"]
            peers = {k: a[k] for k in ("buyer", "provider")}
            rejected = "schema" in delivery
            with tempfile.TemporaryDirectory() as directory:
                db = client.connect(directory)
                try:
                    with client.transaction(db):
                        db.execute("INSERT INTO jobs(job,quote,state,request,attempted) VALUES(?,?,'accepted',?,1)",
                                   (a["jobId"], p.canonical(work["acceptance"]["quote"]), p.canonical(work)))
                        db.execute("INSERT INTO reservations VALUES(?,100)", (a["jobId"],))
                        db.execute("UPDATE account SET available=900")
                    # Untrusted input changes cannot credit or spend a reservation.
                    bad = {**work, "input": work["input"] + " "}
                    with self.assertRaises(p.ProtocolError):
                        client.commit_terminal(db, a["jobId"], bad, delivery, peers)
                    self.assertEqual(client.account(db), {"available": 900, "reserved": 100, "spent": 0})
                    client.commit_terminal(db, a["jobId"], work, delivery, peers)
                    client.commit_terminal(db, a["jobId"], work, delivery, peers)
                    self.assertEqual(client.account(db), {"available": 1000 if rejected else 900,
                                                         "reserved": 0, "spent": 0 if rejected else 100})
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM terminals").fetchone()[0], 1)
                    # Simulate storage corruption of the retained terminal. Even a
                    # valid incoming terminal must not silently replace that choice.
                    db.execute("UPDATE jobs SET delivery=?", (p.canonical({"conflicting": True}),))
                    with self.assertRaises(p.ProtocolError):
                        client.commit_terminal(db, a["jobId"], work, delivery, peers)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM terminals").fetchone()[0], 1)
                finally:
                    db.close()

    def test_transport_rejects_credential_forwarding_targets(self):
        for url in ("https://127.0.0.1:1234", "http://localhost:1234", "http://127.0.0.1:1234/path",
                    "http://127.0.0.1:1234@evil.invalid", "http://127.0.0.1:0", "http://127.0.0.1:65536"):
            with self.subTest(url=url), self.assertRaises(p.ProtocolError):
                client.Transport(url)


if __name__ == "__main__":
    unittest.main()
