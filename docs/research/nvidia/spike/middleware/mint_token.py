"""Mint a Chio capability token (chio.capability.v1 signing body) for the spike.

Uses the issuer/subject/delegatee seeds from tests/bindings/vectors/capability/v1.json
so the token is structurally identical to Chio's binding vectors, with fresh
timestamps. Prints base64url(JSON) for the x-chio-capability-token header.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.environ.get(
    "CHIO_REPO_ROOT", os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "sdks", "python", "chio-py", "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from chio.invariants.capability import capability_signing_body_canonical_json  # noqa: E402
from chio.invariants.json import canonicalize_json  # noqa: E402

VECTORS = os.path.join(REPO_ROOT, "tests", "bindings", "vectors", "capability", "v1.json")


def key(seed_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def pub_hex(private: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def main() -> None:
    links = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    vectors = json.load(open(VECTORS, encoding="utf-8"))
    issuer = key(vectors["issuer_seed_hex"])
    subject = key(vectors["subject_seed_hex"])
    now = int(time.time())
    capability_id = f"cap-openshell-spike-{now}"
    chain = []
    delegator = issuer
    seeds = [vectors["delegatee_seed_hex"]] + [vectors[f"alt_seed_{i}_hex"] for i in range(1, 5)]
    for index in range(links):
        delegatee = key(seeds[index % len(seeds)])
        link = {
            "capability_id": capability_id,
            "delegatee": pub_hex(delegatee),
            "delegator": pub_hex(delegator),
            "timestamp": now - 60 + index,
        }
        link["signature"] = delegator.sign(canonicalize_json(link).encode("utf-8")).hex()
        chain.append(link)
        delegator = delegatee
    capability = {
        "id": capability_id,
        "issuer": pub_hex(issuer),
        "subject": pub_hex(subject),
        "issued_at": now - 60,
        "expires_at": now + 3600,
        "scope": {
            "grants": [
                {
                    "server_id": "srv-files",
                    "tool_name": "file_read",
                    "operations": ["invoke"],
                    "constraints": [{"type": "path_prefix", "value": "/workspace/"}],
                    "max_invocations": 1000,
                }
            ]
        },
        "delegation_chain": chain,
    }
    capability["signature"] = issuer.sign(
        capability_signing_body_canonical_json(capability).encode("utf-8")
    ).hex()
    raw = json.dumps(capability, separators=(",", ":")).encode("utf-8")
    print(base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="))


if __name__ == "__main__":
    main()
