#!/usr/bin/env python3
"""Generate the tenant index key set known-answer vectors.

An independent reference for the Rust `tenant_index` module, built only on the
Python standard library (`hmac`, `hashlib`):

- key_id = SHA-256("chio.tenant-index-key-id.v1\\0" || set key)
- K[purpose] = HKDF-SHA256(IKM = set key, salt = "chio.tenant-index.v1",
  info = "chio.tenant-index.v1/" || label, L = 32), RFC 5869
- value = HMAC-SHA256(K[purpose], domain || preimage), where domain is a
  NUL-terminated `chio.<area>.v<N>` constant
- string form = <prefix>1.<hex key_id>.<hex value>

The HKDF implementation is checked against RFC 5869 Appendix A.1 before any
vector is written.

Usage: python3 -I scripts/gen-tenant-index-kat.py write|check
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "crates/core/chio-core-types/tests/fixtures/tenant_index_kat_v1.json"

KEY_ID_DOMAIN = b"chio.tenant-index-key-id.v1\x00"
HKDF_SALT = b"chio.tenant-index.v1"
TENANT_BINDING_DOMAIN = b"chio.receipt.tenant-binding.v1\x00"

PURPOSES = [
    ("tenant_binding", "tenant-binding", "tb1"),
    ("tenant_tag", "tenant-tag", "tt1"),
    ("subject_tag", "subject-tag", "st1"),
    ("enterprise_subject", "enterprise-subject", "esk1"),
    ("active_defense_digest", "active-defense-digest", "ad1"),
]

SET_KEYS = [
    bytes(range(32)),
    bytes([0x5A] * 32),
    hashlib.sha256(b"tenant-index-kat generation 3").digest(),
]

VALUE_INPUTS = [
    ("tenant_binding", TENANT_BINDING_DOMAIN, b"tenant-acme"),
    ("tenant_tag", b"chio.tenant-tag.v1\x00", b"https://idp.example\x00acme"),
    ("subject_tag", b"chio.subject-tag.v1\x00", b"https://idp.example\x00user-1"),
    (
        "enterprise_subject",
        b"chio.enterprise-subject.v1\x00",
        len(b"scope-a").to_bytes(4, "big") + b"scope-a" + len(b"alice").to_bytes(4, "big") + b"alice",
    ),
    ("active_defense_digest", b"chio.active-defense.keyed-digest.v1\x00", bytes(32)),
    ("tenant_tag", b"chio.tenant-tag.v1\x00", b""),
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


def subkey(set_key: bytes, label: str) -> bytes:
    return hkdf_sha256(set_key, HKDF_SALT, HKDF_SALT + b"/" + label.encode(), 32)


def build() -> dict:
    check_rfc5869()
    labels = {name: (label, prefix) for name, label, prefix in PURPOSES}
    generations = []
    for set_key in SET_KEYS:
        generations.append(
            {
                "set_key_hex": set_key.hex(),
                "key_id_hex": hashlib.sha256(KEY_ID_DOMAIN + set_key).hexdigest(),
                "subkeys_hex": {name: subkey(set_key, label).hex() for name, label, _ in PURPOSES},
            }
        )
    values = []
    for generation_index, set_key in enumerate(SET_KEYS):
        key_id = hashlib.sha256(KEY_ID_DOMAIN + set_key).hexdigest()
        for purpose, domain, preimage in VALUE_INPUTS:
            label, prefix = labels[purpose]
            value = hmac.new(subkey(set_key, label), domain + preimage, hashlib.sha256).hexdigest()
            values.append(
                {
                    "generation": generation_index,
                    "purpose": purpose,
                    "domain_hex": domain.hex(),
                    "preimage_hex": preimage.hex(),
                    "value_hex": value,
                    "string_form": f"{prefix}.{key_id}.{value}",
                }
            )
    return {
        "schema": "chio.tenant-index-kat.v1",
        "generator": "python3 -I scripts/gen-tenant-index-kat.py write",
        "key_id_domain_hex": KEY_ID_DOMAIN.hex(),
        "hkdf_salt_hex": HKDF_SALT.hex(),
        "generations": generations,
        "values": values,
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True) + "\n"


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
