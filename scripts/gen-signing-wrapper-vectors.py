#!/usr/bin/env python3
"""Reference generator and checker for the signing-wrapper and committed-receipt vectors.

Usage:
    gen-signing-wrapper-vectors.py write   rewrite both vector files
    gen-signing-wrapper-vectors.py check   regenerate in memory, byte-compare with the
                                           committed files and run the self-checks

Contract: the Rust signing-wrapper and committed-receipt implementation consumes
these exact vectors in a test, so two independent implementations agree on every
byte. This script exists only as that independent cross-check; if it stops being
one, delete it.

Run exactly as recorded in each vector file's `generator` member:
    uv run --with-requirements scripts/gen-signing-wrapper-vectors.requirements.txt \
        python3 -I scripts/gen-signing-wrapper-vectors.py check
The Python standard library has no Ed25519 or ECDSA signer, so `cryptography` is
required and pinned exactly in the requirements file; the script refuses to run
under any other `cryptography` version. Output is byte-identical under the Python
versions listed in `GENERATOR["python_verified"]`.

Output is a pure function of this file, `spec/schemas/registry.json` and
`tests/bindings/vectors/canonical/v1.json`. Every key, salt, body and timestamp
below is a synthetic test value (keys are repeated single bytes) and must never be
used outside test vectors. ECDSA signatures are RFC 6979 deterministic.

Signing wrapper (PROTOCOL section 4.5), 88 bytes:
    "chio.signing-wrapper.v1" || 0x00 || SHA-256(utf8(schema_id)) || SHA-256(canonical_body)
Ed25519 signs the wrapper bytes, P-256 is ECDSA with SHA-256 over the wrapper, P-384 is
ECDSA with SHA-384 over the wrapper. ML-DSA-65 and hybrid vectors are out of scope for
this library version.

Receipt commitments (PROTOCOL "Committed Receipts And Disclosure"):
    value = SHA-256(domain || salt || preimage), salt 32 bytes, domain chosen by the
    commitment's position in the receipt. Content preimages: canonical JSON for a
    value, the zero-length byte string for an empty output, and the concatenated
    lowercase hex SHA-256 of each canonical chunk for a stream (no chunks is empty).
    A verifier derives the preimage from its own copy of the output; each case's
    `preimages` member is that copy. An opening document that repeats a salt across
    salt_refs is rejected as a whole.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys

import cryptography
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATED_BY = "scripts/gen-signing-wrapper-vectors.py"
REQUIRED_CRYPTOGRAPHY = "44.0.3"
GENERATOR = {
    "command": "uv run --with-requirements scripts/gen-signing-wrapper-vectors.requirements.txt python3 -I scripts/gen-signing-wrapper-vectors.py write",
    "dependencies": ["cryptography==" + REQUIRED_CRYPTOGRAPHY],
    "python_verified": ["3.11", "3.12"],
    "script": GENERATED_BY,
}
REGISTRY_PATH = REPO_ROOT / "spec/schemas/registry.json"
CANONICAL_VECTORS_PATH = REPO_ROOT / "tests/bindings/vectors/canonical/v1.json"
RECEIPT_V1_VECTORS_PATH = REPO_ROOT / "tests/bindings/vectors/receipt/v1.json"
WRAPPER_VECTORS_PATH = REPO_ROOT / "tests/bindings/vectors/signing/wrapper/v1.json"
COMMITTED_VECTORS_PATH = REPO_ROOT / "tests/bindings/vectors/receipt/committed/v1.json"

WRAPPER_PREFIX = b"chio.signing-wrapper.v1\x00"
WRAPPER_LEN = 88
MAX_SAFE_INTEGER = 2**53 - 1


SIGNATURE_SCHEMA_IDS = (
    "chio.receipt.v1",
    "chio.capability.v1",
    "chio.delegation-link.v1",
    "chio.root-policy.v1",
    "chio.idp-key-snapshot.v1",
    "chio.revocation-request.v1",
    "chio.settlement-closure.v1",
)
UNREGISTERED_FIXTURE_ID = "chio.unregistered-fixture.v1"

# Synthetic fixture keys: each is one byte repeated, never real key material.
ED25519_SEED = bytes([0x01]) * 32
P256_SCALAR = bytes([0x02]) * 32
P384_SCALAR = bytes([0x03]) * 48

# Synthetic fixture salts, one per salt_ref.
FIXTURE_SALTS = {
    "params": bytes([0x10]) * 32,
    "content": bytes([0x11]) * 32,
    "anchor.sub": bytes([0x12]) * 32,
    "anchor.tenant": bytes([0x13]) * 32,
}

INPUT_SEEDS = {
    "ecdsa_nonces": "RFC 6979 deterministic, derived from the key and message",
    "ed25519_seed_hex": ED25519_SEED.hex(),
    "p256_scalar_hex": P256_SCALAR.hex(),
    "p384_scalar_hex": P384_SCALAR.hex(),
    "receipt_salts_hex": {ref: salt.hex() for ref, salt in FIXTURE_SALTS.items()},
}

PARAMETERS_DOMAIN = b"chio.receipt.parameters.v1\x00"
CONTENT_DOMAIN = b"chio.receipt.content.v1\x00"
SUBJECT_DOMAIN = b"chio.delegation-context.subject.v1\x00"
TENANT_DOMAIN = b"chio.delegation-context.tenant.v1\x00"
CONTEXT_DIGEST_DOMAIN = b"chio.delegation-context.v1\x00"
ROOT_POLICY_DIGEST_DOMAIN = b"chio.root-policy.v1\x00"
CHAIN_DIGEST_DOMAIN = b"chio.receipt.chain-digest.v1\x00"
PROVIDER_IDENTITY_DIGEST_DOMAIN = b"chio.enterprise-provider-identity.v1\x00"

COMMITMENT_DOMAINS = {
    "params": PARAMETERS_DOMAIN,
    "content": CONTENT_DOMAIN,
    "anchor.sub": SUBJECT_DOMAIN,
    "anchor.tenant": TENANT_DOMAIN,
}

SALT_PATTERN = re.compile(r"\Ab64u:[A-Za-z0-9_-]{43}\Z")
FIXTURE_TIMESTAMP = 1792234800

# Cases of tests/bindings/vectors/canonical/v1.json inside the restricted subset.
CANONICAL_IN_SUBSET = (
    "object_key_sorting",
    "nested_structures",
    "string_escaping",
    "u007f_escape",
    "u001f_escape",
    "u009f_escape",
    "empty_object",
    "empty_array",
    "empty_string_value",
    "bare_null_literal",
    "boolean_and_null_array",
    "deeply_nested_object",
    "long_integer_array",
)


class _Float:
    """Marker for a JSON number with a fraction or exponent."""


def _refuse_float(_: str) -> _Float:
    return _Float()


def _refuse_constant(name: str) -> None:
    raise ValueError(f"non-finite number {name} is outside the canonical subset")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def parse_json(text: str) -> object:
    return json.loads(
        text,
        parse_float=_refuse_float,
        parse_constant=_refuse_constant,
        object_pairs_hook=_reject_duplicates,
    )


def _check_subset(value: object) -> None:
    if value is None or isinstance(value, bool) or isinstance(value, str):
        if isinstance(value, str):
            value.encode("utf-8")
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"integer {value} is outside the canonical subset")
        return
    if isinstance(value, list):
        for item in value:
            _check_subset(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f"object key {key!r} is outside the canonical subset")
            _check_subset(item)
        return
    raise ValueError(f"{type(value).__name__} is outside the canonical subset")


def canonical_json(value: object) -> bytes:
    """RFC 8785 for ASCII object keys, strings, booleans, null, arrays and safe integers.

    ASCII keys make UTF-16 and code-point ordering agree, and safe integers make the
    ECMAScript number form equal the decimal form. Anything else raises ValueError.
    """
    try:
        _check_subset(value)
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"string is not valid UTF-8: {error}") from error


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def digest_str(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def wrapper(schema_id: str, canonical_body: bytes) -> bytes:
    out = WRAPPER_PREFIX + sha256(schema_id.encode("utf-8")) + sha256(canonical_body)
    if len(out) != WRAPPER_LEN:
        raise ValueError("wrapper length invariant violated")
    return out


def b64u(data: bytes) -> str:
    return "b64u:" + base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_salt(encoded: object) -> bytes | None:
    if not isinstance(encoded, str) or SALT_PATTERN.fullmatch(encoded) is None:
        return None
    raw = base64.urlsafe_b64decode(encoded[len("b64u:"):] + "=")
    if len(raw) != 32 or b64u(raw) != encoded:
        return None
    return raw


class Keys:
    def __init__(self) -> None:
        self.ed25519 = ed25519.Ed25519PrivateKey.from_private_bytes(ED25519_SEED)
        self.p256 = ec.derive_private_key(int.from_bytes(P256_SCALAR, "big"), ec.SECP256R1())
        self.p384 = ec.derive_private_key(int.from_bytes(P384_SCALAR, "big"), ec.SECP384R1())

    def public_hex(self, algorithm: str) -> str:
        if algorithm == "ed25519":
            raw = self.ed25519.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return raw.hex()
        key = self.p256 if algorithm == "p256" else self.p384
        point = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return f"{algorithm}:{point.hex()}"

    def sign(self, algorithm: str, message: bytes, ecdsa_hash: hashes.HashAlgorithm | None = None) -> str:
        if algorithm == "ed25519":
            return self.ed25519.sign(message).hex()
        if algorithm == "p256":
            key, default_hash = self.p256, hashes.SHA256()
        elif algorithm == "p384":
            key, default_hash = self.p384, hashes.SHA384()
        else:
            raise ValueError(f"unknown algorithm {algorithm}")
        chosen = ecdsa_hash if ecdsa_hash is not None else default_hash
        der = key.sign(message, ec.ECDSA(chosen, deterministic_signing=True))
        return f"{algorithm}:{der.hex()}"


def key_algorithm(public_key: str) -> str | None:
    if public_key.startswith("p256:") and len(public_key) == 5 + 130:
        return "p256"
    if public_key.startswith("p384:") and len(public_key) == 5 + 194:
        return "p384"
    if re.fullmatch(r"[0-9a-f]{64}", public_key):
        return "ed25519"
    return None


def signature_algorithm(signature: str) -> str | None:
    if signature.startswith("p256:"):
        return "p256"
    if signature.startswith("p384:"):
        return "p384"
    if re.fullmatch(r"[0-9a-f]{128}", signature):
        return "ed25519"
    return None


def load_public_key(public_key: str):
    algorithm = key_algorithm(public_key)
    if algorithm == "ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
    curve = ec.SECP256R1() if algorithm == "p256" else ec.SECP384R1()
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, bytes.fromhex(public_key[5:]))


def verify_message(public_key: str, signature: str, message: bytes) -> bool:
    """Algorithm-bound verification over exact message bytes."""
    algorithm = key_algorithm(public_key)
    if algorithm is None or signature_algorithm(signature) != algorithm:
        return False
    key = load_public_key(public_key)
    try:
        if algorithm == "ed25519":
            key.verify(bytes.fromhex(signature), message)
        else:
            chosen = hashes.SHA256() if algorithm == "p256" else hashes.SHA384()
            key.verify(bytes.fromhex(signature[5:]), message, ec.ECDSA(chosen))
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_wrapped(
    known_ids: frozenset[str], schema_id: str, canonical_body: bytes, public_key: str, signature: str
) -> bool:
    """Wrapper verification; `schema_id` comes from the verification context."""
    if schema_id not in known_ids:
        return False
    return verify_message(public_key, signature, wrapper(schema_id, canonical_body))


def known_wrapper_ids() -> list[str]:
    registry = json.loads(REGISTRY_PATH.read_bytes())
    return sorted({row["schema"] for row in registry["artifacts"]})


def dump(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def flip_low_bit(data: bytes, index: int = 0) -> bytes:
    mutable = bytearray(data)
    mutable[index] ^= 0x01
    return bytes(mutable)


# Signing-wrapper vectors.

SIGNATURE_BODY = canonical_json({"fixture": "signing-wrapper", "n": 1})
ALGORITHM_MEMBER_BODY = canonical_json({"algorithm": "ed25519", "fixture": "signing-wrapper", "n": 1})
SIGNATURE_BODY_ONE_BIT = canonical_json({"fixture": "signing-wrapper", "n": 0})
WRAPPER_CASE_BODY = canonical_json({"a": 1})


def build_wrapper_document(keys: Keys, ids: list[str]) -> dict:
    known = frozenset(ids)
    wrapper_cases = [
        {
            "canonical_body": WRAPPER_CASE_BODY.decode("utf-8"),
            "id": schema_id,
            "schema_id": schema_id,
            "wrapper_hex": wrapper(schema_id, WRAPPER_CASE_BODY).hex(),
        }
        for schema_id in ids
    ]

    cases: list[dict] = []

    def add(case_id, description, algorithm, signed_id, verify_id, body, public_key, signature, intended):
        cases.append(
            {
                "algorithm": algorithm,
                "canonical_body": body.decode("utf-8"),
                "description": description,
                "expected_verify": intended,
                "id": case_id,
                "public_key": public_key,
                "signature": signature,
                "signed_schema_id": signed_id,
                "verify_schema_id": verify_id,
            }
        )

    algorithms = ("ed25519", "p256", "p384")
    for algorithm in algorithms:
        public_key = keys.public_hex(algorithm)
        for schema_id in SIGNATURE_SCHEMA_IDS:
            add(
                f"{algorithm}/{schema_id}/valid",
                f"{algorithm} signature over the {schema_id} wrapper verifies under the same schema id.",
                algorithm,
                schema_id,
                schema_id,
                SIGNATURE_BODY,
                public_key,
                keys.sign(algorithm, wrapper(schema_id, SIGNATURE_BODY)),
                True,
            )

    for algorithm in algorithms:
        public_key = keys.public_hex(algorithm)
        add(
            f"{algorithm}/schema-id-substitution",
            "Signed as chio.capability.v1 and verified as chio.receipt.v1; the verifier takes the schema id from its context.",
            algorithm,
            "chio.capability.v1",
            "chio.receipt.v1",
            SIGNATURE_BODY,
            public_key,
            keys.sign(algorithm, wrapper("chio.capability.v1", SIGNATURE_BODY)),
            False,
        )
        add(
            f"{algorithm}/raw-body-signature",
            "Signature over the canonical body bytes instead of the wrapper.",
            algorithm,
            "chio.receipt.v1",
            "chio.receipt.v1",
            SIGNATURE_BODY,
            public_key,
            keys.sign(algorithm, SIGNATURE_BODY),
            False,
        )
        add(
            f"{algorithm}/one-bit-body-change",
            "Body changed in one bit after signing.",
            algorithm,
            "chio.receipt.v1",
            "chio.receipt.v1",
            SIGNATURE_BODY_ONE_BIT,
            public_key,
            keys.sign(algorithm, wrapper("chio.receipt.v1", SIGNATURE_BODY)),
            False,
        )
        add(
            f"{algorithm}/truncated-wrapper",
            "Signature over the first 87 bytes of the wrapper.",
            algorithm,
            "chio.receipt.v1",
            "chio.receipt.v1",
            SIGNATURE_BODY,
            public_key,
            keys.sign(algorithm, wrapper("chio.receipt.v1", SIGNATURE_BODY)[: WRAPPER_LEN - 1]),
            False,
        )

    mismatches = (("ed25519", "p256"), ("p256", "p384"), ("p384", "ed25519"))
    for key_alg, sig_alg in mismatches:
        add(
            f"{key_alg}-key/{sig_alg}-signature/algorithm-mismatch",
            f"A pinned {key_alg} key admits only {key_alg} signatures; a valid {sig_alg} signature over the same wrapper rejects before any cryptographic check.",
            sig_alg,
            "chio.receipt.v1",
            "chio.receipt.v1",
            SIGNATURE_BODY,
            keys.public_hex(key_alg),
            keys.sign(sig_alg, wrapper("chio.receipt.v1", SIGNATURE_BODY)),
            False,
        )

    add(
        "p256-key/ed25519-signature/algorithm-member",
        "A body carrying an algorithm member that names ed25519, with an Ed25519 signature, under a pinned P-256 key; the key alone selects the verifier and the signature rejects on its encoding prefix.",
        "ed25519",
        "chio.receipt.v1",
        "chio.receipt.v1",
        ALGORITHM_MEMBER_BODY,
        keys.public_hex("p256"),
        keys.sign("ed25519", wrapper("chio.receipt.v1", ALGORITHM_MEMBER_BODY)),
        False,
    )

    receipt_wrapper = wrapper("chio.receipt.v1", SIGNATURE_BODY)
    add(
        "p256/double-hash",
        "ECDSA-SHA256 over SHA-256(wrapper): the wrapper digest hashed a second time.",
        "p256",
        "chio.receipt.v1",
        "chio.receipt.v1",
        SIGNATURE_BODY,
        keys.public_hex("p256"),
        keys.sign("p256", hashlib.sha256(receipt_wrapper).digest()),
        False,
    )
    add(
        "p384/double-hash",
        "ECDSA-SHA384 over SHA-384(wrapper): the wrapper digest hashed a second time.",
        "p384",
        "chio.receipt.v1",
        "chio.receipt.v1",
        SIGNATURE_BODY,
        keys.public_hex("p384"),
        keys.sign("p384", hashlib.sha384(receipt_wrapper).digest()),
        False,
    )
    add(
        "p384/sha256-digest",
        "P-384 ECDSA computed with SHA-256 over the wrapper; P-384 requires SHA-384.",
        "p384",
        "chio.receipt.v1",
        "chio.receipt.v1",
        SIGNATURE_BODY,
        keys.public_hex("p384"),
        keys.sign("p384", receipt_wrapper, hashes.SHA256()),
        False,
    )
    add(
        "ed25519/unregistered-schema-id",
        "A well-formed signature over the wrapper of an id outside the registry; verification refuses unregistered ids.",
        "ed25519",
        UNREGISTERED_FIXTURE_ID,
        UNREGISTERED_FIXTURE_ID,
        SIGNATURE_BODY,
        keys.public_hex("ed25519"),
        keys.sign("ed25519", wrapper(UNREGISTERED_FIXTURE_ID, SIGNATURE_BODY)),
        False,
    )

    for case in cases:
        actual = verify_wrapped(
            known,
            case["verify_schema_id"],
            case["canonical_body"].encode("utf-8"),
            case["public_key"],
            case["signature"],
        )
        if actual != case["expected_verify"]:
            raise AssertionError(f"signature case {case['id']}: verify returned {actual}")

    return {
        "algorithms": {
            "ed25519": "Ed25519 over the 88 wrapper bytes",
            "p256": "ECDSA P-256 with SHA-256 over the 88 wrapper bytes, DER signature",
            "p384": "ECDSA P-384 with SHA-384 over the 88 wrapper bytes, DER signature",
        },
        "fixture_material": "Every key and body in this file is a fixed test fixture. Never use these keys outside test vectors.",
        "generated_by": GENERATED_BY,
        "generator": GENERATOR,
        "input_seeds": INPUT_SEEDS,
        "keys": {
            "ed25519": {"public_key": keys.public_hex("ed25519"), "seed_hex": ED25519_SEED.hex()},
            "p256": {"public_key": keys.public_hex("p256"), "scalar_hex": P256_SCALAR.hex()},
            "p384": {"public_key": keys.public_hex("p384"), "scalar_hex": P384_SCALAR.hex()},
        },
        "prefix_hex": WRAPPER_PREFIX.hex(),
        "signature_cases": cases,
        "version": 1,
        "wrapper_cases": wrapper_cases,
    }


# Committed-receipt vectors.

def commitment(domain: bytes, salt: bytes, preimage: bytes) -> str:
    return digest_str(domain + salt + preimage)


def stream_preimage(chunks: list[object]) -> bytes:
    return b"".join(hashlib.sha256(canonical_json(chunk)).hexdigest().encode("ascii") for chunk in chunks)


def receipt_id_input(receipt: dict) -> dict:
    return {
        key: value
        for key, value in receipt.items()
        if key not in ("id", "signature", "bbs_signature", "algorithm") and value is not None
    }


def receipt_id(receipt: dict) -> str:
    return hashlib.sha256(canonical_json(receipt_id_input(receipt))).hexdigest()


def signing_body(receipt: dict) -> dict:
    body = {"body": receipt_id_input(receipt), "id": receipt["id"]}
    if "bbs_signature" in receipt:
        body["bbs_signature"] = receipt["bbs_signature"]
    return body


def finalize_receipt(keys: Keys, body: dict, wrap: bool = True) -> dict:
    """Bind the signing nonce, compute the id and sign, as PROTOCOL section 6 orders it."""
    receipt = dict(body)
    pre_nonce_id = receipt_id(receipt)
    metadata = dict(receipt.get("metadata") or {})
    metadata["chio_receipt_signing_nonce"] = pre_nonce_id
    receipt["metadata"] = metadata
    receipt["id"] = receipt_id(receipt)
    message = canonical_json(signing_body(receipt))
    receipt["signature"] = keys.sign("ed25519", wrapper("chio.receipt.v1", message) if wrap else message)
    return receipt


def delegation_context(subject: str, tenant: str, exchange_key: str) -> dict:
    return {
        "anchor": {
            "alg": "RS256",
            "artifact_digest": digest_str(b"fixture:id-jag-compact-jws"),
            "artifact_retained": False,
            "claims": {"client_id": "mcp-client-fixture", "scope": ["files.read"]},
            "issuer": "https://idp.fixture.example",
            "key_snapshot_digest": digest_str(b"fixture:idp-key-snapshot"),
            "kid": "k-fixture-1",
            "kind": "oauth_id_jag",
            "provider_identity_digest": digest_str(
                PROVIDER_IDENTITY_DIGEST_DOMAIN + canonical_json(FIXTURE_PROVIDER_IDENTITY)
            ),
            "provider_record_id": FIXTURE_PROVIDER_IDENTITY["provider_id"],
            "replay_key_digest": digest_str(b"fixture:replay-key"),
            "subject": {
                "commit": commitment(SUBJECT_DOMAIN, FIXTURE_SALTS["anchor.sub"], subject.encode("utf-8")),
                "salt_ref": "anchor.sub",
            },
            "tenant": {
                "commit": commitment(TENANT_DOMAIN, FIXTURE_SALTS["anchor.tenant"], tenant.encode("utf-8")),
                "salt_ref": "anchor.tenant",
            },
            "token_exp": 1792235090,
            "token_iat": 1792234790,
        },
        "effective_root_scope_hash": digest_str(b"fixture:effective-root-scope"),
        "exchange": {
            "exchange_key": exchange_key,
            "exchanged_at": 1792234795,
            "holder": "edge_session",
            "request_digest": digest_str(b"fixture:exchange-request"),
        },
        "root_policy_rule_id": "fixture-rule",
        "schema": "chio.delegation-context.v1",
    }


PARAMETERS = {"mode": "read", "path": "/workspace/docs/roadmap.md"}
DENIED_PARAMETERS = {"mode": "read", "path": "/etc/shadow"}
VALUE_OUTPUT = {"lines": 42, "text": "Roadmap"}
STREAM_CHUNKS = [{"delta": "Road"}, {"delta": "map"}]
SUBJECT_VALUE = "00u1fixturesubject"
TENANT_VALUE = "tenant-fixture"
FIXTURE_ROOT_POLICY_BODY = {"policy_id": "fixture-policy", "schema": "chio.root-policy.v1"}
# Synthetic enterprise provider record identity projection; the delegation
# context pins its digest the way a root policy rule does.
FIXTURE_PROVIDER_IDENTITY = {
    "audiences": [],
    "issuer": "https://idp.fixture.example",
    "jwks_url": "https://idp.fixture.example/oauth2/v1/keys",
    "kind": "oidc_jwks",
    "provider_id": "fixture-provider",
    "schema": "chio.enterprise-provider-identity.v1",
    "subject_mapping": {"principal_source": "sub", "tenant_id_field": "iss"},
    "trust_material_ref": "fixture-trust-material",
}
FIXTURE_ROOT_TOKEN = {"fixture": "root-capability-placeholder", "id": "cap-fixture-root"}


def base_body(keys: Keys, parameters: dict, content_preimage: bytes, decision: dict, *, content_domain: bytes = CONTENT_DOMAIN, content_salt: bytes | None = None) -> dict:
    salt_params = FIXTURE_SALTS["params"]
    salt_content = FIXTURE_SALTS["content"] if content_salt is None else content_salt
    return {
        "action": {
            "parameter_commitment": {
                "alg": "sha256-salted",
                "salt_ref": "params",
                "value": commitment(PARAMETERS_DOMAIN, salt_params, canonical_json(parameters)),
            }
        },
        "boundary_class": "prevent",
        "capability_id": "cap-fixture-001",
        "content_commitment": {
            "alg": "sha256-salted",
            "salt_ref": "content",
            "value": commitment(content_domain, salt_content, content_preimage),
        },
        "decision": decision,
        "disclosure": {"parameter_inline_fields": [], "result_inline_fields": []},
        "evidence": [{"details": "path checked", "guard_name": "ForbiddenPathGuard", "verdict": True}],
        "kernel_key": keys.public_hex("ed25519"),
        "metadata": {"surface": "committed-receipt-vectors"},
        "policy_hash": "policy-fixture-v1",
        "receipt_kind": "mediated_decision",
        "timestamp": FIXTURE_TIMESTAMP,
        "tool_name": "file_read",
        "tool_origin": "caller_executed",
        "tool_server": "srv-files",
        "trust_level": "mediated",
    }


def opening(salt_ref: str, salt: str, payload: object) -> dict:
    return {"payload": payload, "salt": salt, "salt_ref": salt_ref}


def disclosure_doc(rid: str, openings: list[dict]) -> dict:
    return {"openings": openings, "receipt_id": rid, "schema": "chio.receipt-disclosure.v1"}


FORBIDDEN_RECEIPT_MEMBERS = ("redaction_mode", "content_hash")
FORBIDDEN_ACTION_MEMBERS = ("parameters", "parameter_hash")


def verify_committed_case(case: dict, known: frozenset[str]) -> dict:
    """Reference verifier for one committed-receipt case."""
    receipt = case["receipt"]
    disclosure = case["disclosure"]
    preimages = case["preimages"]
    context = case.get("delegation_context")

    id_ok = receipt_id(receipt) == receipt["id"]
    signature_valid = id_ok and verify_wrapped(
        known,
        "chio.receipt.v1",
        canonical_json(signing_body(receipt)),
        receipt["kernel_key"],
        receipt["signature"],
    )

    structure_ok = all(member not in receipt for member in FORBIDDEN_RECEIPT_MEMBERS)
    structure_ok = structure_ok and all(member not in receipt["action"] for member in FORBIDDEN_ACTION_MEMBERS)
    if "authority" in receipt:
        if "tenant_id" in receipt:
            structure_ok = False
        if context is None or digest_str(CONTEXT_DIGEST_DOMAIN + canonical_json(context)) != receipt["authority"]["root_anchor"]["context_digest"]:
            structure_ok = False
    receipt_valid = signature_valid and structure_ok

    openings = disclosure.get("openings", [])
    salts: list[bytes] = []
    refs: list[str] = []
    disclosure_valid = disclosure.get("schema") == "chio.receipt-disclosure.v1" and disclosure.get("receipt_id") == receipt["id"]
    by_ref: dict[str, tuple[bytes, object]] = {}
    for entry in openings:
        salt = decode_salt(entry.get("salt"))
        ref = entry.get("salt_ref")
        if salt is None or ref not in COMMITMENT_DOMAINS:
            disclosure_valid = False
            continue
        salts.append(salt)
        refs.append(ref)
        by_ref[ref] = (salt, entry.get("payload"))
    if len(set(salts)) != len(salts) or len(set(refs)) != len(refs):
        disclosure_valid = False

    def field(ref: str, committed: str, preimage: bytes | None) -> str:
        if ref not in by_ref and not any(entry.get("salt_ref") == ref for entry in openings):
            return "unverifiable"
        if not disclosure_valid or ref not in by_ref or preimage is None:
            return "rejected"
        salt = by_ref[ref][0]
        return "verified" if commitment(COMMITMENT_DOMAINS[ref], salt, preimage) == committed else "rejected"

    result = {
        "content": field(
            "content",
            receipt["content_commitment"]["value"],
            bytes.fromhex(preimages["content_preimage_hex"]),
        ),
        "disclosure_valid": disclosure_valid,
        "parameters": field(
            "params",
            receipt["action"]["parameter_commitment"]["value"],
            preimages["parameters_canonical"].encode("utf-8"),
        ),
        "receipt_valid": receipt_valid,
        "signature_valid": signature_valid,
    }
    if context is not None:
        for ref, member, key in (("anchor.sub", "subject", "anchor_subject"), ("anchor.tenant", "tenant", "anchor_tenant")):
            payload = by_ref.get(ref, (None, None))[1]
            preimage = payload.encode("utf-8") if isinstance(payload, str) else None
            result[key] = field(ref, context["anchor"][member]["commit"], preimage)
    return result


def build_committed_document(keys: Keys, known: frozenset[str]) -> dict:
    s = {ref: b64u(salt) for ref, salt in FIXTURE_SALTS.items()}
    allow = {"verdict": "allow"}
    deny = {"guard": "ForbiddenPathGuard", "reason": "path is forbidden", "verdict": "deny"}
    params_canonical = canonical_json(PARAMETERS)
    value_preimage = canonical_json(VALUE_OUTPUT)
    empty_preimage = b""
    cases: list[dict] = []

    def add(case_id, description, receipt, openings, parameters_canonical, content_preimage, intended, context=None):
        case = {
            "description": description,
            "disclosure": disclosure_doc(receipt["id"], openings),
            "expected": intended,
            "id": case_id,
            "preimages": {
                "content_preimage_hex": content_preimage.hex(),
                "parameters_canonical": parameters_canonical.decode("utf-8"),
            },
            "receipt": receipt,
        }
        if context is not None:
            case["delegation_context"] = context
        cases.append(case)

    def ok(**overrides):
        expected = {
            "content": "verified",
            "disclosure_valid": True,
            "parameters": "verified",
            "receipt_valid": True,
            "signature_valid": True,
        }
        expected.update(overrides)
        return expected

    value_receipt = finalize_receipt(keys, base_body(keys, PARAMETERS, value_preimage, allow))
    value_openings = [opening("params", s["params"], PARAMETERS), opening("content", s["content"], VALUE_OUTPUT)]

    add(
        "value_output",
        "Allow receipt over a value output; both commitments open with the fixture salts.",
        value_receipt,
        value_openings,
        params_canonical,
        value_preimage,
        ok(),
    )

    empty_receipt = finalize_receipt(keys, base_body(keys, PARAMETERS, empty_preimage, allow))
    add(
        "empty_output",
        "Empty output: the content preimage is the zero-length byte string. The opening carries the salt only; the verifier derives the preimage from its own copy of the output.",
        empty_receipt,
        [opening("params", s["params"], PARAMETERS), opening("content", s["content"], None)],
        params_canonical,
        empty_preimage,
        ok(),
    )

    stream_bytes = stream_preimage(STREAM_CHUNKS)
    stream_receipt = finalize_receipt(keys, base_body(keys, PARAMETERS, stream_bytes, allow))
    add(
        "stream_output",
        "Stream output: the content preimage is the concatenation of the lowercase hex SHA-256 of each canonical chunk. No per-chunk digest appears in the receipt.",
        stream_receipt,
        [opening("params", s["params"], PARAMETERS), opening("content", s["content"], None)],
        params_canonical,
        stream_bytes,
        ok(),
    )

    if stream_preimage([]) != empty_preimage:
        raise AssertionError("a stream with no chunks must have the empty preimage")
    empty_stream_receipt = finalize_receipt(keys, base_body(keys, PARAMETERS, stream_preimage([]), allow))
    add(
        "stream_output_no_chunks",
        "Stream output with no chunks: the content preimage is the zero-length byte string, the same as an empty output.",
        empty_stream_receipt,
        [opening("params", s["params"], PARAMETERS), opening("content", s["content"], None)],
        params_canonical,
        stream_preimage([]),
        ok(),
    )

    deny_canonical = canonical_json(DENIED_PARAMETERS)
    deny_receipt = finalize_receipt(keys, base_body(keys, DENIED_PARAMETERS, empty_preimage, deny))
    add(
        "deny_receipt",
        "Deny receipt: parameters are committed, the content commitment covers the empty output (zero-length preimage).",
        deny_receipt,
        [opening("params", s["params"], DENIED_PARAMETERS), opening("content", s["content"], None)],
        deny_canonical,
        empty_preimage,
        ok(),
    )

    context = delegation_context(SUBJECT_VALUE, TENANT_VALUE, keys.public_hex("ed25519"))
    authority = {
        "chain_depth": 0,
        "chain_digest": digest_str(CHAIN_DIGEST_DOMAIN + canonical_json([FIXTURE_ROOT_TOKEN])),
        "holder": "edge_session",
        "root_anchor": {
            "anchored_at": 1792234795,
            "assertion_exp": 1792235090,
            "context_digest": digest_str(CONTEXT_DIGEST_DOMAIN + canonical_json(context)),
            "kind": "oauth_id_jag",
            "root_policy_digest": digest_str(ROOT_POLICY_DIGEST_DOMAIN + canonical_json(FIXTURE_ROOT_POLICY_BODY)),
        },
    }
    authority_body = base_body(keys, PARAMETERS, value_preimage, allow)
    authority_body["authority"] = authority
    authority_body["capability_id"] = "cap-fixture-root"
    authority_receipt = finalize_receipt(keys, authority_body)
    authority_openings = value_openings + [
        opening("anchor.sub", s["anchor.sub"], SUBJECT_VALUE),
        opening("anchor.tenant", s["anchor.tenant"], TENANT_VALUE),
    ]
    add(
        "authority_chain_depth_0",
        "Receipt with an authority block at chain_depth 0 and no tenant_id; the delegation context recomputes context_digest and its subject and tenant commitments open. chain_digest and root_policy_digest are computed over fixture placeholders and are not checked here.",
        authority_receipt,
        authority_openings,
        params_canonical,
        value_preimage,
        ok(anchor_subject="verified", anchor_tenant="verified"),
        context,
    )

    tenant_body = dict(authority_body)
    tenant_body["tenant_id"] = TENANT_VALUE
    tenant_receipt = finalize_receipt(keys, tenant_body)
    add(
        "tenant_id_with_authority",
        "Receipt carrying both tenant_id and an authority block. Signing must refuse it; this fixture is signed anyway so a verifier shows the rule independently of the signature.",
        tenant_receipt,
        authority_openings,
        params_canonical,
        value_preimage,
        ok(receipt_valid=False, anchor_subject="verified", anchor_tenant="verified"),
        context,
    )

    add(
        "salt_one_bit_change",
        "The parameters opening carries the fixture salt with one bit flipped.",
        value_receipt,
        [opening("params", b64u(flip_low_bit(FIXTURE_SALTS["params"])), PARAMETERS), opening("content", s["content"], VALUE_OUTPUT)],
        params_canonical,
        value_preimage,
        ok(parameters="rejected"),
    )

    tampered_output = {"lines": 43, "text": "Roadmap"}
    tampered_preimage = canonical_json(tampered_output)
    if bin(int.from_bytes(tampered_preimage, "big") ^ int.from_bytes(value_preimage, "big")).count("1") != 1:
        raise AssertionError("payload tamper must differ in exactly one bit")
    add(
        "payload_one_bit_change",
        "The content opening's payload differs from the committed output in one bit.",
        value_receipt,
        [opening("params", s["params"], PARAMETERS), opening("content", s["content"], tampered_output)],
        params_canonical,
        tampered_preimage,
        ok(content="rejected"),
    )

    add(
        "parameters_opening_for_content",
        "The parameters opening (salt and payload) is presented under salt_ref content and checked against the content commitment.",
        value_receipt,
        [opening("content", s["params"], PARAMETERS)],
        params_canonical,
        params_canonical,
        ok(content="rejected", parameters="unverifiable"),
    )

    swapped_receipt = finalize_receipt(keys, base_body(keys, PARAMETERS, value_preimage, allow, content_domain=PARAMETERS_DOMAIN))
    add(
        "content_commitment_under_parameters_domain",
        "The content commitment was computed with the parameters domain. The opening is correct, and the verifier rejects it because the domain comes from the commitment position, never from the opening.",
        swapped_receipt,
        [opening("params", s["params"], PARAMETERS), opening("content", s["content"], VALUE_OUTPUT)],
        params_canonical,
        value_preimage,
        ok(content="rejected"),
    )

    add(
        "salt_31_bytes",
        "The parameters opening carries a 31-byte salt; salts are exactly 32 bytes.",
        value_receipt,
        [opening("params", b64u(FIXTURE_SALTS["params"][:31]), PARAMETERS), opening("content", s["content"], VALUE_OUTPUT)],
        params_canonical,
        value_preimage,
        ok(content="rejected", disclosure_valid=False, parameters="rejected"),
    )

    add(
        "salt_padded_b64u",
        "The parameters opening carries the right salt with base64url padding; the encoding is unpadded.",
        value_receipt,
        [opening("params", s["params"] + "=", PARAMETERS), opening("content", s["content"], VALUE_OUTPUT)],
        params_canonical,
        value_preimage,
        ok(content="rejected", disclosure_valid=False, parameters="rejected"),
    )

    reused_receipt = finalize_receipt(keys, base_body(keys, PARAMETERS, value_preimage, allow, content_salt=FIXTURE_SALTS["params"]))
    add(
        "salt_reused_across_fields",
        "The producer used one salt for both the parameters and the content commitment. A verifier rejects an opening document that repeats a salt across salt_refs, so every opened field is rejected and the receipt is marked as tampered disclosure.",
        reused_receipt,
        [opening("params", s["params"], PARAMETERS), opening("content", s["params"], VALUE_OUTPUT)],
        params_canonical,
        value_preimage,
        ok(content="rejected", disclosure_valid=False, parameters="rejected"),
    )

    add(
        "subject_opening_as_tenant",
        "The subject opening (salt and value) is presented as the tenant opening; the tenant commitment uses its own domain and salt.",
        authority_receipt,
        value_openings + [opening("anchor.tenant", s["anchor.sub"], SUBJECT_VALUE)],
        params_canonical,
        value_preimage,
        ok(anchor_subject="unverifiable", anchor_tenant="rejected"),
        context,
    )

    add(
        "subject_value_as_tenant",
        "The tenant opening carries the tenant salt with the subject value.",
        authority_receipt,
        value_openings
        + [
            opening("anchor.sub", s["anchor.sub"], SUBJECT_VALUE),
            opening("anchor.tenant", s["anchor.tenant"], SUBJECT_VALUE),
        ],
        params_canonical,
        value_preimage,
        ok(anchor_subject="verified", anchor_tenant="rejected"),
        context,
    )

    add(
        "content_opening_absent",
        "Only the parameters opening is disclosed; the content commitment stays hiding.",
        value_receipt,
        [opening("params", s["params"], PARAMETERS)],
        params_canonical,
        value_preimage,
        ok(content="unverifiable"),
    )

    unwrapped_receipt = finalize_receipt(keys, base_body(keys, PARAMETERS, value_preimage, allow), wrap=False)
    add(
        "body_signature_without_wrapper",
        "The kernel signed the canonical ChioReceiptSigningBody directly instead of its wrapper.",
        unwrapped_receipt,
        value_openings,
        params_canonical,
        value_preimage,
        ok(receipt_valid=False, signature_valid=False),
    )

    for case in cases:
        actual = verify_committed_case(case, known)
        if actual != case["expected"]:
            raise AssertionError(f"committed case {case['id']}: expected {case['expected']}, verifier returned {actual}")

    return {
        "cases": cases,
        "commitment_domains": {ref: domain.decode("ascii").replace("\x00", "\\0") for ref, domain in COMMITMENT_DOMAINS.items()},
        "fixture_material": "Every key, salt and body in this file is a fixed test fixture. Production salts are 32 fresh bytes per receipt per field.",
        "fixture_provider_identity": FIXTURE_PROVIDER_IDENTITY,
        "fixture_salts": {ref: salt.hex() for ref, salt in FIXTURE_SALTS.items()},
        "generated_by": GENERATED_BY,
        "generator": GENERATOR,
        "input_seeds": INPUT_SEEDS,
        "kernel_key": keys.public_hex("ed25519"),
        "kernel_key_seed_hex": ED25519_SEED.hex(),
        "version": 1,
    }


# Self-checks.

def self_check_canonical() -> None:
    corpus = json.loads(CANONICAL_VECTORS_PATH.read_bytes())
    in_subset = set(CANONICAL_IN_SUBSET)
    seen: set[str] = set()
    for case in corpus["cases"]:
        try:
            produced = canonical_json(parse_json(case["input_json"]))
        except ValueError:
            if case["id"] in in_subset:
                raise AssertionError(f"canonical case {case['id']} refused but listed as in subset") from None
            continue
        if case["id"] not in in_subset:
            raise AssertionError(f"canonical case {case['id']} accepted but not listed as in subset")
        if produced != case["canonical_json"].encode("utf-8"):
            raise AssertionError(f"canonical case {case['id']} diverges from the corpus")
        seen.add(case["id"])
    if seen != in_subset:
        raise AssertionError(f"canonical subset cases missing from corpus: {sorted(in_subset - seen)}")
    for refused in ({"\u00e9": 1}, 1.5, 2**53, -(2**53), _Float()):
        try:
            canonical_json(refused)
        except ValueError:
            continue
        raise AssertionError(f"canonical_json accepted {refused!r}")


def _ecdsa_holds(key, der: bytes, data: bytes, algorithm: ec.ECDSA) -> bool:
    try:
        key.verify(der, data, algorithm)
    except InvalidSignature:
        return False
    return True


def self_check_wrapper(document: dict) -> None:
    sample = wrapper("chio.receipt.v1", b"{}")
    if len(sample) != WRAPPER_LEN or sample[23] != 0 or sample[:24] != WRAPPER_PREFIX:
        raise AssertionError("wrapper layout invariant violated")
    for case in document["wrapper_cases"]:
        raw = bytes.fromhex(case["wrapper_hex"])
        if len(raw) != WRAPPER_LEN or raw[23] != 0:
            raise AssertionError(f"wrapper case {case['id']} has a bad layout")
    for case in document["signature_cases"]:
        message = wrapper(case["verify_schema_id"], case["canonical_body"].encode("utf-8"))
        public_key = case["public_key"]
        if key_algorithm(public_key) not in ("p256", "p384") or signature_algorithm(case["signature"]) != key_algorithm(public_key):
            continue
        chosen = hashes.SHA256() if key_algorithm(public_key) == "p256" else hashes.SHA384()
        digest = hashlib.new(chosen.name, message).digest()
        key = load_public_key(public_key)
        der = bytes.fromhex(case["signature"][5:])

        direct = _ecdsa_holds(key, der, message, ec.ECDSA(chosen))
        prehashed = _ecdsa_holds(key, der, digest, ec.ECDSA(utils.Prehashed(chosen)))
        if direct != prehashed:
            raise AssertionError(f"signature case {case['id']}: message and digest verification disagree")
        if direct != case["expected_verify"]:
            raise AssertionError(f"signature case {case['id']}: ECDSA result {direct} differs from expected")
        if case["id"].endswith("double-hash") and (direct or prehashed):
            raise AssertionError(f"signature case {case['id']}: double hash verified")


def self_check_receipt_ids() -> None:
    corpus = json.loads(RECEIPT_V1_VECTORS_PATH.read_bytes())
    for case in corpus["cases"]:
        matches = receipt_id(case["receipt"]) == case["receipt"]["id"]
        if matches != case["expected"]["receipt_id_valid"]:
            raise AssertionError(f"receipt id function disagrees with receipt/v1.json case {case['id']}")


def self_check_committed(document: dict) -> None:
    for case in document["cases"]:
        receipt = case["receipt"]
        for member in FORBIDDEN_RECEIPT_MEMBERS:
            if member in receipt:
                raise AssertionError(f"committed case {case['id']} carries {member}")
        for entry in case["disclosure"]["openings"]:
            if entry["salt_ref"] == "params" and entry["payload"] is not None and case["expected"]["parameters"] == "verified":
                if canonical_json(entry["payload"]).decode("utf-8") != case["preimages"]["parameters_canonical"]:
                    raise AssertionError(f"committed case {case['id']}: parameters payload differs from its preimage")
            if entry["salt_ref"] == "content" and entry["payload"] is not None and case["expected"]["content"] == "verified":
                if canonical_json(entry["payload"]).hex() != case["preimages"]["content_preimage_hex"]:
                    raise AssertionError(f"committed case {case['id']}: content payload differs from its preimage")
        if "authority" in receipt and "tenant_id" in receipt and case["expected"]["receipt_valid"]:
            raise AssertionError(f"committed case {case['id']}: tenant_id with authority marked valid")


def build_all() -> dict[Path, bytes]:
    keys = Keys()
    ids = known_wrapper_ids()
    known = frozenset(ids)
    wrapper_document = build_wrapper_document(keys, ids)
    committed_document = build_committed_document(keys, known)
    self_check_canonical()
    self_check_wrapper(wrapper_document)
    self_check_receipt_ids()
    self_check_committed(committed_document)
    return {
        WRAPPER_VECTORS_PATH: dump(wrapper_document),
        COMMITTED_VECTORS_PATH: dump(committed_document),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("write", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    if cryptography.__version__ != REQUIRED_CRYPTOGRAPHY:
        print(
            f"requires cryptography=={REQUIRED_CRYPTOGRAPHY}; found cryptography=={cryptography.__version__}",
            file=sys.stderr,
        )
        return 2
    outputs = build_all()
    if argv[1] == "write":
        for path, data in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            print(f"wrote {path.relative_to(REPO_ROOT)}")
        return 0
    stale = []
    for path, data in outputs.items():
        if not path.is_file() or path.read_bytes() != data:
            stale.append(str(path.relative_to(REPO_ROOT)))
    if stale:
        print("stale vector files; rerun with `write`: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("signing-wrapper and committed-receipt vectors match the reference generator")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
