#!/usr/bin/env python3
"""Independently open every pinned FROST vector with Python cryptography.

Requires the development-only `cryptography` package. Fixture private seeds are
public test material: Ed25519 sender i uses byte i+1; recipient i uses byte i+11.
No Chio code or AWS-LC code is called by this verifier.
"""
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "crates/trust/chio-federation-authority/tests/fixtures/frost-round2-sealed-v1.json"


def main():
    envelopes = json.loads(FIXTURE.read_bytes())
    inputs = json.loads(FIXTURE.with_name("frost-round2-inputs-v1.json").read_bytes())
    assert len(inputs["cases"]) == len(envelopes) == 20
    pairs = set()
    for envelope, case in zip(envelopes, inputs["cases"], strict=True):
        metadata = {k: v for k, v in envelope.items() if k not in {"ciphertext", "transportSignature"}}
        aad = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        sender = int(metadata["senderParticipantId"].removeprefix("peer-"))
        recipient = int(metadata["recipientParticipantId"].removeprefix("peer-"))
        assert (sender, recipient) == (case["sender"], case["recipient"])
        assert sender != recipient
        assert metadata["round"] == 2
        assert metadata["schema"] == "chio.frost.dkg-round2-sealed.v1"
        assert metadata["suite"] == "X25519HkdfSha256ChaCha20Poly1305"
        assert (sender, recipient) not in pairs
        pairs.add((sender, recipient))
        ciphertext = bytes(envelope["ciphertext"])
        Ed25519PrivateKey.from_private_bytes(bytes([sender + 1]) * 32).public_key().verify(
            bytes.fromhex(envelope["transportSignature"]), aad + ciphertext
        )
        shared = X25519PrivateKey.from_private_bytes(bytes([recipient + 11]) * 32).exchange(
            X25519PublicKey.from_public_bytes(bytes(metadata["senderEphemeralPublicKey"]))
        )
        material = HKDF(algorithm=hashes.SHA256(), length=44,
                        salt=bytes.fromhex(metadata["participantSetDigest"]), info=aad).derive(shared)
        plaintext = ChaCha20Poly1305(material[:32]).decrypt(material[32:], ciphertext, aad)
        assert plaintext == bytes.fromhex(case["share"])
        ephemeral = X25519PrivateKey.from_private_bytes(bytes.fromhex(case["ephemeralPrivateKey"]))
        assert ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == bytes(metadata["senderEphemeralPublicKey"])
        recipient_public = bytes(inputs["config"]["participants"][recipient]["sealingPublicKey"])
        assert ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public)) == shared
        assert ChaCha20Poly1305(material[:32]).encrypt(material[32:], plaintext, aad) == ciphertext
        assert Ed25519PrivateKey.from_private_bytes(bytes([sender + 1]) * 32).sign(aad + ciphertext).hex() == envelope["transportSignature"]
    assert pairs == {(sender, recipient) for sender in range(5) for recipient in range(5) if sender != recipient}
    print("20 FROST vectors: independent exact sealing, signatures, HKDF and opening passed")


if __name__ == "__main__":
    main()
