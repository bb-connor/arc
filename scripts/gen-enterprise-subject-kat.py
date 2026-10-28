#!/usr/bin/env python3
"""Generate the enterprise subject known-answer vectors.

An independent reference for the Rust `enterprise_subject` module, built only
on the Python standard library (`hmac`, `hashlib`):

- key_id = SHA-256("chio.tenant-index-key-id.v1\\0" || set key)
- K = HKDF-SHA256(IKM = set key, salt = "chio.tenant-index.v1",
  info = "chio.tenant-index.v1/enterprise-subject", L = 32), RFC 5869
- field(x) = be32(len(x)) || x
- subject = HMAC-SHA256(K, "chio.enterprise-subject.v1\\0" || field(scope) || field(principal)),
  carried as esk1.<hex key_id>.<hex value>
- SCIM capability id = "scim-user:" || esk1 string form of
  HMAC-SHA256(K, "chio.scim-capability.v1\\0" || field(provider id) || field(user id))
- SCIM policy hash = hex of
  HMAC-SHA256(K, "chio.scim-policy.v1\\0" || field(provider id) || field(subject string form))

The HKDF implementation is checked against RFC 5869 Appendix A.1 before any
vector is written.

Usage: python3 -I scripts/gen-enterprise-subject-kat.py write|check
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "crates/core/chio-core-types/tests/fixtures/enterprise_subject_kat_v1.json"

KEY_ID_DOMAIN = b"chio.tenant-index-key-id.v1\x00"
HKDF_SALT = b"chio.tenant-index.v1"
LABEL = b"enterprise-subject"
SUBJECT_DOMAIN = b"chio.enterprise-subject.v1\x00"
SCIM_CAPABILITY_DOMAIN = b"chio.scim-capability.v1\x00"
SCIM_POLICY_DOMAIN = b"chio.scim-policy.v1\x00"

SET_KEYS = [
    bytes(range(32)),
    bytes([0x5A] * 32),
    hashlib.sha256(b"enterprise-subject-kat generation 3").digest(),
]

SUBJECTS = [
    ("scope-a", "alice"),
    ("https://idp.example", "oidc:https://idp.example#sub:user-1"),
    ("ab", "c"),
    ("a", "bc"),
    ("", ""),
    ("scim-provider", "üser@例え.jp"),
]

SCIM_USERS = [
    ("scim-provider", "scim-0123456789abcdef0123456789abcdef"),
    ("scim-provider", "user-1"),
    ("scim-provider-2", "user-1"),
]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def check_rfc5869() -> None:
    okm = hkdf_sha256(
        bytes.fromhex("0b" * 22),
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    expected = (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    if okm.hex() != expected:
        raise SystemExit("HKDF reference does not reproduce RFC 5869 A.1")


def field(text: str) -> bytes:
    data = text.encode("utf-8")
    return len(data).to_bytes(4, "big") + data


def keyed(subkey: bytes, domain: bytes, preimage: bytes) -> str:
    return hmac.new(subkey, domain + preimage, hashlib.sha256).hexdigest()


def build() -> dict:
    check_rfc5869()
    generations = []
    for set_key in SET_KEYS:
        key_id = hashlib.sha256(KEY_ID_DOMAIN + set_key).hexdigest()
        subkey = hkdf_sha256(set_key, HKDF_SALT, HKDF_SALT + b"/" + LABEL, 32)
        subjects = []
        for scope, principal in SUBJECTS:
            value = keyed(subkey, SUBJECT_DOMAIN, field(scope) + field(principal))
            subject = f"esk1.{key_id}.{value}"
            subjects.append(
                {
                    "provider_scope": scope,
                    "principal": principal,
                    "subject": subject,
                    "scim_policy_provider_id": "scim-provider",
                    "scim_policy_hash_hex": keyed(
                        subkey, SCIM_POLICY_DOMAIN, field("scim-provider") + field(subject)
                    ),
                }
            )
        capabilities = []
        for provider_id, user_id in SCIM_USERS:
            value = keyed(subkey, SCIM_CAPABILITY_DOMAIN, field(provider_id) + field(user_id))
            capabilities.append(
                {
                    "provider_id": provider_id,
                    "user_id": user_id,
                    "capability_id": f"scim-user:esk1.{key_id}.{value}",
                }
            )
        generations.append(
            {
                "set_key_hex": set_key.hex(),
                "key_id_hex": key_id,
                "subjects": subjects,
                "scim_capabilities": capabilities,
            }
        )
    return {
        "schema": "chio.enterprise-subject-kat.v1",
        "generator": "python3 -I scripts/gen-enterprise-subject-kat.py write",
        "generations": generations,
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("write", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    text = render()
    if argv[1] == "write":
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(text)
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text() != text:
        print(f"{OUTPUT.relative_to(ROOT)} is stale; run with `write`", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
