"""Boundary regressions: removing a binding or parser guard must fail these."""
import copy
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import artifacts as p


def keys():
    return [Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in range(1, 5)]


def agreement():
    buyer, provider, verifier, custodian = keys()
    public = [k.public_key().public_bytes_raw().hex() for k in keys()]
    body = {"schema": "chio.experimental.funded-w0-agreement.v1", "workId": "test-work",
            "buyerKey": public[0], "providerKey": public[1], "verifierKey": public[2],
            "custodianKey": public[3], "inputSha256": hashlib.sha256(INPUT).hexdigest(),
            "checkerSha256": p.CHECKER_SHA256, "assurance": "artifact-only-v1",
            "parentAgreementSha256": None,
            "rail": {"chainId": "31337", "escrow": "0x" + "10" * 20,
                     "runtimeKeccak256": "0x" + "20" * 32, "token": "0x" + "30" * 20,
                     "payer": "0x" + "40" * 20, "beneficiary": "0x" + "50" * 20,
                     "verifier": "0x" + "60" * 20, "amount": "100"},
            "deadlines": {"submitBy": 100, "challengeUntil": 110, "resolveBy": 120, "refundAfter": 130},
            "custody": {"policy": "local-retain-indefinitely-v1", "retainUntil": 2592130}}
    value = {"body": body, "buyerSignature": buyer.sign(p.canonical(body)).hex(),
             "providerSignature": provider.sign(p.canonical(body)).hex()}
    return value, {"buyer": public[0], "provider": public[1], "verifier": public[2], "custodian": public[3]}


INPUT = b'{"openapi":"3.1.0","paths":{"/public":{"get":{}},"/private":{"get":{"security":[{"bearer":[]}]}}},"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}}}'
OUTPUT = {"schema": "chio.experimental.funded-w0-output.v1", "operations": [
    {"path": "/private", "method": "get", "authenticationRequired": True},
    {"path": "/public", "method": "get", "authenticationRequired": False}]}


def resign(value):
    value["buyerSignature"] = keys()[0].sign(p.canonical(value["body"])).hex()
    value["providerSignature"] = keys()[1].sign(p.canonical(value["body"])).hex()
    return value


class ProtocolTests(unittest.TestCase):
    def test_shadow_protocol_module_is_not_used_as_the_pinned_library(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'protocol.py').write_text('raise RuntimeError("shadow parser executed")\n')
            script='import sys;sys.path[:0]=[sys.argv[1],sys.argv[2]];import artifacts;print("loaded")'
            result=subprocess.run([sys.executable,'-B','-c',script,str(Path(__file__).parent),directory],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,'loaded\n')

    def test_retained_canonical_and_malformed_vectors(self):
        vectors = json.loads((Path(__file__).parent / 'parser-vectors.json').read_text())
        positive = vectors['positive']
        self.assertEqual(p.canonical(positive['agreement']), base64.b64decode(positive['canonicalBase64'], validate=True))
        self.assertEqual(p.digest(p.verify_agreement(positive['agreement'], positive['pins'])), positive['agreementBodySha256'])
        for vector in vectors['malformed']:
            with self.subTest(vector=vector['name']), self.assertRaises(p.ProtocolError):
                p.load(bytes.fromhex(vector['wireHex']))

    def test_joint_agreement_roundtrip_and_locally_configured_pins(self):
        value, pins = agreement()
        self.assertEqual(p.verify_agreement(p.load(p.canonical(value)), pins)["rail"]["amount"], "100")
        for name in pins:
            changed = dict(pins, **{name: "ab" * 32})
            with self.subTest(pin=name), self.assertRaises(p.ProtocolError):
                p.verify_agreement(value, changed)

    def test_each_joint_term_is_signed_and_rejects_substitution(self):
        value, pins = agreement()
        changes = [((), "workId", "other"), ((), "inputSha256", "ab" * 32),
                   ((), "checkerSha256", "ab" * 32), ((), "parentAgreementSha256", "ab" * 32)]
        changes += [(("rail",), key, "101" if key == "amount" else "1" if key == "chainId"
                     else "0x" + "ab" * (32 if key == "runtimeKeccak256" else 20)) for key in value["body"]["rail"]]
        changes += [(("deadlines",), key, val + 1) for key, val in value["body"]["deadlines"].items()]
        changes += [(("custody",), "retainUntil", 9999999)]
        for parents, key, replacement in changes:
            changed = copy.deepcopy(value)
            target = changed["body"]
            for parent in parents:
                target = target[parent]
            target[key] = replacement
            with self.subTest(field=key), self.assertRaises(p.ProtocolError):
                p.verify_agreement(changed, pins)
        for field in ("buyerSignature", "providerSignature"):
            changed = copy.deepcopy(value)
            changed[field] = "00" * 64
            with self.subTest(signature=field), self.assertRaises(p.ProtocolError):
                p.verify_agreement(changed, pins)

    def test_signed_unsupported_terms_do_not_become_valid(self):
        value, pins = agreement()
        changes = [("assurance", "native-v1"), ("schema", "future.v2"),
                   ("checkerSha256", "ab" * 32), ("extra", True),
                   ("providerKey", pins["buyer"])]
        for field, replacement in changes:
            changed = copy.deepcopy(value)
            changed["body"][field] = replacement
            with self.subTest(field=field), self.assertRaises(p.ProtocolError):
                p.verify_agreement(resign(changed), pins)

    def test_exact_money_and_ordered_deadlines(self):
        value, pins = agreement()
        for amount in (0, True, "0", "01", "+1", "-1", "1e2", "1.0", " 1", str(2**53), str(2**64-1)):
            changed = copy.deepcopy(value)
            changed["body"]["rail"]["amount"] = amount
            with self.subTest(amount=amount), self.assertRaises(p.ProtocolError):
                p.verify_agreement(resign(changed), pins)
        value["body"]["rail"]["amount"] = str(2**53 - 1)
        self.assertEqual(p.verify_agreement(resign(value), pins)["rail"]["amount"], "9007199254740991")
        for field in value["body"]["deadlines"]:
            changed = copy.deepcopy(value)
            changed["body"]["deadlines"][field] = 110
            if changed == value:
                continue
            with self.subTest(deadline=field), self.assertRaises(p.ProtocolError):
                p.verify_agreement(resign(changed), pins)
        value["body"]["custody"]["retainUntil"] -= 1
        with self.assertRaises(p.ProtocolError):
            p.verify_agreement(resign(value), pins)

    def test_wire_limits_duplicates_nonfinite_and_invalid_utf8(self):
        invalid = [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}',
                   b'"\xff"', b'"\\ud800"', b'0 ' + b' ' * 262143,
                   b'[' * 17 + b'0' + b']' * 17]
        for encoded in invalid:
            with self.subTest(encoded=encoded[:40]), self.assertRaises(p.ProtocolError):
                p.load(encoded)
        self.assertEqual(p.load(b'[' * 16 + b'0' + b']' * 16), [[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]])
        # RFC 8785 orders UTF-16 code units, not Python's Unicode code points.
        self.assertEqual(p.canonical({"\ue000": 1, "\U00010000": 2}), '{"\U00010000":2,"\ue000":1}'.encode())


if __name__ == "__main__":
    unittest.main()
