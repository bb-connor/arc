"""Receiver-owned enrollment and TLS policy checks."""
import contextlib
import copy
import io
import os
from pathlib import Path
import ssl
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import client
import protocol as p
import tls_fixture


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        self.buyer = client.init(self.state)["publicKey"]
        self.issuer = Ed25519PrivateKey.generate()
        self.provider = self.issuer.public_key().public_bytes_raw().hex()
        with contextlib.redirect_stdout(io.StringIO()):
            tls_fixture.create(self.state, "127.0.0.1")
        self.origin = "https://127.0.0.1:8443"
        session = {"schema": "chio.capability.v1", "id": "negotiation-test", "issuer": self.provider,
                   "subject": self.buyer, "issued_at": int(time.time()) - 5, "expires_at": int(time.time()) + 60,
                   "scope": {"grants": [{"server_id": p.SERVER, "tool_name": tool, "operations": ["invoke"],
                                         "constraints": [{"type": "max_args_size", "value": 262144}], "dpop_required": True}
                                        for tool in ("quote", "accept", "status", "delivery")]}}
        self.body = {"schema": "chio.example.https-enrollment.v1", "profile": p.PROFILE, "provider": self.provider,
                     "buyer": self.buyer, "origin": self.origin, "caPem": (self.state / "tls-cert.pem").read_text(),
                     "session": session}

    def signed(self, body=None):
        body = copy.deepcopy(body or self.body)
        token = body["session"]
        token["signature"] = self.issuer.sign(p.canonical({k: v for k, v in token.items() if k != "signature"})).hex()
        return p.sign(body, self.issuer)

    def test_local_activation_persists_pins_without_shared_private_credentials(self):
        enrolled = client.enroll(self.state, self.provider, self.origin, self.signed())
        self.assertEqual(enrolled["buyer"], self.buyer)
        self.assertTrue(enrolled["senderConstrained"])
        self.assertEqual(client.configured_peers(self.state), {"buyer": self.buyer, "provider": self.provider})
        self.assertEqual((self.state / "connection.json").stat().st_mode & 0o077, 0)
        self.assertFalse((self.state / "session.json").exists())
        self.assertFalse((self.state / "peers.json").exists())
        original = (self.state / "connection.json").read_bytes()
        changed = self.signed()
        changed["body"]["caPem"] += "untrusted"
        with self.assertRaises(p.ProtocolError):
            client.enroll(self.state, self.provider, self.origin, changed)
        self.assertEqual((self.state / "connection.json").read_bytes(), original)

    def test_valid_signatures_cannot_widen_enrollment_authority(self):
        modifications = [
            lambda b: b.update(buyer="a" * 64),
            lambda b: b.update(origin="https://unselected.invalid"),
            lambda b: b.update(profile="future-profile"),
            lambda b: b["session"]["scope"]["grants"][0].update(dpop_required=False),
            lambda b: b["session"]["scope"]["grants"][0].update(tool_name="review"),
            lambda b: b["session"]["scope"]["grants"][0].update(operations=["invoke", "admin"]),
            lambda b: b["session"]["scope"]["grants"][0]["constraints"][0].update(value=262145),
            lambda b: b["session"].update(subject="a" * 64),
            lambda b: b["session"].update(id=True),
        ]
        for index, modify in enumerate(modifications):
            body = copy.deepcopy(self.body)
            modify(body)
            with self.subTest(index=index), self.assertRaises(p.ProtocolError):
                client.verify_enrollment(self.signed(body), self.provider, self.buyer, self.origin)

    def test_expired_enrollment_cannot_activate_but_historical_pins_remain_readable(self):
        body = copy.deepcopy(self.body)
        body["session"]["issued_at"] = int(time.time()) - 120
        body["session"]["expires_at"] = int(time.time()) - 60
        signed = self.signed(body)
        with self.assertRaises(p.ProtocolError):
            client.enroll(self.state, self.provider, self.origin, signed)
        self.assertFalse((self.state / "connection.json").exists())
        # Model a credential that expired after a prior local activation. Offline
        # artifact verification still needs its peer pins, never live authority.
        (self.state / "connection.json").write_bytes(p.canonical({"provider": self.provider, "origin": self.origin,
                                                                "enrollment": signed}))
        self.assertEqual(client.configured_connection(self.state)["provider"], self.provider)

    def test_tls_uses_activated_roots_hostname_and_version_without_environment_key_logging(self):
        body = client.verify_enrollment(self.signed(), self.provider, self.buyer, self.origin)
        card = {"supportedInterfaces": [{"url": self.origin + "/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
                "skills": [{"id": "quote"}]}
        with patch.object(client.Transport, "http", return_value=card) as requests:
            with patch.dict(os.environ, {"SSLKEYLOGFILE": str(self.state / "leaked-tls-secrets")}):
                transport = client.Transport(self.origin, body)
        self.assertEqual(transport.tls.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(transport.tls.check_hostname)
        self.assertFalse(transport.tls.hostname_checks_common_name)
        self.assertEqual(transport.tls.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(transport.tls.cert_store_stats()["x509"], 1)
        self.assertIsNone(transport.tls.keylog_filename)
        requests.assert_called_once_with("GET", "/.well-known/agent-card.json")

    def test_discovery_cannot_forward_credentials_or_downgrade_transport(self):
        body = client.verify_enrollment(self.signed(), self.provider, self.buyer, self.origin)
        card = {"supportedInterfaces": [{"url": "https://elsewhere.invalid/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}
        with patch.object(client.Transport, "http", return_value=card) as requests:
            with self.assertRaises(p.ProtocolError):
                client.Transport(self.origin, body)
        requests.assert_called_once_with("GET", "/.well-known/agent-card.json")
        with patch.object(client.Transport, "http") as requests:
            with self.assertRaises(p.ProtocolError):
                client.Transport(self.origin.replace("https:", "http:"), body)
        requests.assert_not_called()

    def test_origin_rejects_credentials_routes_and_ambiguous_spellings(self):
        for value in ("https://@host", "https://host:443", "https://host:", "https://HOST", "https://host/",
                      "https://user:pass@host", "https://host?x=1", "https://host#part", "https://host\x00"):
            with self.subTest(value=value), self.assertRaises(p.ProtocolError):
                client.https_origin(value)
        self.assertEqual(client.https_origin("https://company.example"), ("company.example", 443))
        self.assertEqual(client.https_origin("https://[::1]:8443"), ("::1", 8443))


if __name__ == "__main__":
    unittest.main()
