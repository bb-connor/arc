#!/usr/bin/env python3

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "spec/schemas/chio-wire/v1"
VECTOR_ROOT = ROOT / "tests/bindings/vectors/security/protocol-primitives"
WIRE_SCHEMA_BASE = "https://chio.world/schemas/chio-wire/v1/"
EXPECTED_POSITIVES = 26
EXPECTED_MUTATIONS = 43
EXPECTED_NEGATIVES = 44
EXPECTED_STRUCTURAL_REJECTIONS = 16
EXPECTED_SEMANTIC_REJECTIONS = 28
JCS_MAX_DEPTH = 64
JCS_MAX_NODES = 200_000
JCS_MAX_BYTES = 16 * 1024 * 1024
JCS_SAFE_INTEGER = 9_007_199_254_740_991


class ContractError(RuntimeError):
    pass


class JsonParseError(ContractError):
    pass


def _reject_json_float(value: str) -> None:
    raise JsonParseError(f"floating-point JSON value is outside the bounded JCS profile: {value}")


def _reject_json_constant(value: str) -> None:
    raise JsonParseError(f"non-finite JSON value is invalid: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise JsonParseError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def parse_json_bytes(source: bytes, label: str) -> Any:
    try:
        text = source.decode("utf-8")
        return json.loads(
            text,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except JsonParseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise JsonParseError(f"{label}: invalid JSON: {error}") from error


def load_json(path: Path) -> Any:
    try:
        return parse_json_bytes(path.read_bytes(), str(path))
    except OSError as error:
        raise ContractError(f"{path}: cannot read JSON: {error}") from error


def _validate_jcs_string(value: str) -> None:
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise ContractError("bounded JCS rejects lone Unicode surrogates")


def _jcs_string_bytes(value: str) -> bytes:
    _validate_jcs_string(value)
    escaped = bytearray(b'"')
    short_escapes = {
        0x08: b"\\b",
        0x09: b"\\t",
        0x0A: b"\\n",
        0x0C: b"\\f",
        0x0D: b"\\r",
        0x22: b'\\"',
        0x5C: b"\\\\",
    }
    for character in value:
        codepoint = ord(character)
        if codepoint in short_escapes:
            escaped.extend(short_escapes[codepoint])
        elif codepoint <= 0x1F:
            escaped.extend(f"\\u{codepoint:04x}".encode("ascii"))
        else:
            escaped.extend(character.encode("utf-8"))
    escaped.append(0x22)
    return bytes(escaped)


def _utf16_sort_key(value: str) -> bytes:
    _validate_jcs_string(value)
    return value.encode("utf-16-be")


def _canonical_json_bytes(
    value: Any,
    *,
    depth: int,
    budget: list[int],
) -> bytes:
    if depth > JCS_MAX_DEPTH:
        raise ContractError(f"bounded JCS exceeds maximum depth {JCS_MAX_DEPTH}")
    budget[0] += 1
    if budget[0] > JCS_MAX_NODES:
        raise ContractError(f"bounded JCS exceeds maximum node count {JCS_MAX_NODES}")
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        if not -JCS_SAFE_INTEGER <= value <= JCS_SAFE_INTEGER:
            raise ContractError("bounded JCS rejects integers outside the interoperable safe range")
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise ContractError("bounded JCS rejects floating-point values")
    if isinstance(value, str):
        return _jcs_string_bytes(value)
    if isinstance(value, list):
        return b"[" + b",".join(
            _canonical_json_bytes(item, depth=depth + 1, budget=budget)
            for item in value
        ) + b"]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ContractError("bounded JCS requires string object keys")
        members = []
        for key in sorted(value, key=_utf16_sort_key):
            members.append(
                _jcs_string_bytes(key)
                + b":"
                + _canonical_json_bytes(value[key], depth=depth + 1, budget=budget)
            )
        return b"{" + b",".join(members) + b"}"
    raise ContractError(f"bounded JCS rejects value of type {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    encoded = _canonical_json_bytes(value, depth=0, budget=[0])
    if len(encoded) > JCS_MAX_BYTES:
        raise ContractError(f"bounded JCS exceeds maximum output size {JCS_MAX_BYTES}")
    return encoded


def verify_jcs_profile() -> None:
    non_bmp = canonical_json_bytes({"\ue000": 1, "\U00010000": 2})
    expected = '{"\U00010000":2,"\ue000":1}'.encode("utf-8")
    if non_bmp != expected:
        raise ContractError("bounded JCS does not use RFC 8785 UTF-16 key ordering")
    minimal = canonical_json_bytes({"s": "\b\t\n\f\r\"\\\u0000"})
    if minimal != b'{"s":"\\b\\t\\n\\f\\r\\"\\\\\\u0000"}':
        raise ContractError("bounded JCS string escaping is not minimal")
    rejected = (1.0, JCS_SAFE_INTEGER + 1, "\ud800")
    for value in rejected:
        try:
            canonical_json_bytes(value)
        except ContractError:
            continue
        raise ContractError("bounded JCS accepted an excluded value")


ED25519_FIELD = 2**255 - 19
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, ED25519_FIELD - 2, ED25519_FIELD)) % ED25519_FIELD
ED25519_I = pow(2, (ED25519_FIELD - 1) // 4, ED25519_FIELD)
ED25519_IDENTITY = (0, 1)


def ed25519_recover_x(y: int, sign: int) -> int | None:
    if y >= ED25519_FIELD:
        return None
    y_squared = y * y % ED25519_FIELD
    x_squared = (y_squared - 1) * pow(
        ED25519_D * y_squared + 1, ED25519_FIELD - 2, ED25519_FIELD
    ) % ED25519_FIELD
    x = pow(x_squared, (ED25519_FIELD + 3) // 8, ED25519_FIELD)
    if (x * x - x_squared) % ED25519_FIELD != 0:
        x = x * ED25519_I % ED25519_FIELD
    if (x * x - x_squared) % ED25519_FIELD != 0:
        return None
    if x == 0 and sign != 0:
        return None
    if x & 1 != sign:
        x = ED25519_FIELD - x
    return x


def ed25519_decode_point(encoded: bytes) -> tuple[int, int] | None:
    if len(encoded) != 32:
        return None
    raw = int.from_bytes(encoded, "little")
    sign = raw >> 255
    y = raw & ((1 << 255) - 1)
    x = ed25519_recover_x(y, sign)
    return None if x is None else (x, y)


def ed25519_add(
    left: tuple[int, int], right: tuple[int, int]
) -> tuple[int, int]:
    left_x, left_y = left
    right_x, right_y = right
    product = ED25519_D * left_x * right_x * left_y * right_y % ED25519_FIELD
    x = (left_x * right_y + left_y * right_x) * pow(
        1 + product, ED25519_FIELD - 2, ED25519_FIELD
    ) % ED25519_FIELD
    y = (left_y * right_y + left_x * right_x) * pow(
        1 - product, ED25519_FIELD - 2, ED25519_FIELD
    ) % ED25519_FIELD
    return x, y


def ed25519_multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = ED25519_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = ed25519_add(result, addend)
        addend = ed25519_add(addend, addend)
        scalar >>= 1
    return result


ED25519_BASE_Y = 4 * pow(5, ED25519_FIELD - 2, ED25519_FIELD) % ED25519_FIELD
ED25519_BASE_X = ed25519_recover_x(ED25519_BASE_Y, 0)
if ED25519_BASE_X is None:
    raise RuntimeError("invalid embedded Ed25519 base point")
ED25519_BASE = (ED25519_BASE_X, ED25519_BASE_Y)


def ed25519_verify(public_key_hex: Any, signature_hex: Any, message: bytes) -> bool:
    if (
        not isinstance(public_key_hex, str)
        or len(public_key_hex) != 64
        or not isinstance(signature_hex, str)
        or len(signature_hex) != 128
    ):
        return False
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    public_point = ed25519_decode_point(public_key)
    encoded_r = signature[:32]
    r_point = ed25519_decode_point(encoded_r)
    scalar_s = int.from_bytes(signature[32:], "little")
    if public_point is None or r_point is None or scalar_s >= ED25519_ORDER:
        return False
    if (
        ed25519_multiply(public_point, 8) == ED25519_IDENTITY
        or ed25519_multiply(r_point, 8) == ED25519_IDENTITY
    ):
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % ED25519_ORDER
    left = ed25519_multiply(ED25519_BASE, scalar_s)
    right = ed25519_add(r_point, ed25519_multiply(public_point, challenge))
    return left == right


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ContractError(reason)


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_governed_security_relationships(positives: dict[str, Any]) -> None:
    active = positives.get("governed_active_response_intent")
    request = positives.get("tool_call_request_full_security")
    require(isinstance(active, dict), "governed active-response positive is missing")
    require(isinstance(request, dict), "full-security request positive is missing")

    security_fields = {
        "supplemental_authorization",
        "governed_intent",
        "approval_tokens",
        "threshold_approval_proposal",
        "declassification_grant",
    }
    require(
        security_fields <= set(request),
        "full-security request does not carry every compatible security field",
    )
    require("approval_token" not in request, "full-security request uses both approval forms")

    capability = request.get("capability_token")
    require(isinstance(capability, dict), "full-security capability is missing")
    reference_list = load_json(
        VECTOR_ROOT / "positive/capability-list-delegation-family-v1.json"
    )
    require(
        isinstance(reference_list, dict)
        and isinstance(reference_list.get("capabilities"), list)
        and len(reference_list["capabilities"]) == 1,
        "reference aggregate capability list is malformed",
    )
    require(
        capability == reference_list["capabilities"][0],
        "full-security request does not reuse the governed aggregate capability exactly",
    )
    require(
        "aggregate_invocation_budget" in capability,
        "full-security capability has no aggregate invocation budget",
    )
    require("algorithm" not in capability, "default capability algorithm must be omitted")
    capability_body = {
        key: value for key, value in capability.items() if key != "signature"
    }
    require(
        ed25519_verify(
            capability.get("issuer"),
            capability.get("signature"),
            canonical_json_bytes(capability_body),
        ),
        "full-security capability signature is invalid",
    )
    aggregate = capability["aggregate_invocation_budget"]
    root_binding = aggregate.get("root_binding") if isinstance(aggregate, dict) else None
    require(isinstance(root_binding, dict), "aggregate root binding is missing")
    root_body = root_binding.get("body")
    require(isinstance(root_body, dict), "aggregate root binding body is missing")
    require(
        ed25519_verify(
            root_body.get("root_issuer"),
            root_binding.get("signature"),
            b"chio.aggregate-budget-root.v1\0" + canonical_json_bytes(root_body),
        ),
        "aggregate root binding signature is invalid",
    )
    capability_hash = sha256_hex(canonical_json_bytes(capability))
    require(
        capability_hash
        == "aa99ecc73fb1e222bdfa0039d28a45a442515cb9a5091810f36adbbf1296886b",
        "full-security capability envelope hash drifted",
    )

    active_body = active.get("body")
    require(
        active.get("schema") == "chio.governed-transaction-intent.v2"
        and active.get("kind") == "active_response_plan"
        and isinstance(active_body, dict),
        "governed active-response positive is not the v2 active-response variant",
    )
    require(
        active_body.get("operatorCapabilityId") == capability.get("id")
        and active_body.get("operatorCapabilityHash") == capability_hash
        and active_body.get("operatorCapabilityExpiresAt") == capability.get("expires_at")
        and active_body.get("executorSubject") == capability.get("subject"),
        "active-response intent is not bound to the complete operator capability",
    )
    plan_body = active_body.get("canonicalPlanBody")
    require(isinstance(plan_body, dict), "active-response canonical plan body is missing")
    require(
        active_body.get("planBodyHash")
        == sha256_hex(b"chio:response-plan:v1\0" + canonical_json_bytes(plan_body)),
        "active-response canonical plan-body hash is invalid",
    )
    require(
        isinstance(active_body.get("expiresAt"), int)
        and active_body["expiresAt"] <= capability["expires_at"],
        "active-response intent outlives its operator capability",
    )

    intent = request.get("governed_intent")
    require(
        isinstance(intent, dict)
        and intent.get("schema") == "chio.governed-transaction-intent.v2"
        and intent.get("kind") == "tool_invocation",
        "full-security governed intent is not a v2 tool invocation",
    )
    intent_body = intent.get("body")
    require(
        isinstance(intent_body, dict)
        and intent_body.get("id") == "governed-tool-invocation-vector-1"
        and intent_body.get("server_id") == request.get("server_id")
        and intent_body.get("tool_name") == request.get("tool")
        and intent_body.get("purpose") == "security-review",
        "full-security governed intent does not bind the request target and purpose",
    )
    intent_hash = sha256_hex(canonical_json_bytes(intent))
    require(
        intent_hash
        == "4038b08d10b13d45684f64e5a784c646ceaf1ceea85f350be5b90b458b8ed26d",
        "full-security governed-intent hash drifted",
    )

    proposal = request.get("threshold_approval_proposal")
    require(isinstance(proposal, dict), "full-security threshold proposal is missing")
    require("algorithm" not in proposal, "default proposal algorithm must be omitted")
    proposal_body = proposal.get("body")
    require(isinstance(proposal_body, dict), "threshold proposal body is missing")
    require(
        proposal_body.get("requestId") == request.get("id")
        and proposal_body.get("governedIntentHash") == intent_hash
        and proposal_body.get("subject") == capability.get("subject")
        and proposal_body.get("authorizationCapabilityHash") == capability_hash
        and proposal_body.get("policyHash")
        == "b3c841fed81ab385f4fb653edd9ede90ad75ade788401dd86eebeb03e53861f8"
        and proposal_body.get("required") == 2,
        "threshold proposal bindings drifted",
    )
    proposal_message = (
        b"chio.threshold-approval-proposal.v1\0"
        + canonical_json_bytes(proposal_body)
    )
    proposal_hash = sha256_hex(proposal_message)
    require(
        proposal_hash
        == "e7d3f8bdba18f04a0a5e18b018828a1612bd53b94facf1a14ac225a1eb702cd6",
        "threshold proposal hash drifted",
    )
    require(
        ed25519_verify(
            proposal.get("policyAuthority"), proposal.get("signature"), proposal_message
        ),
        "threshold proposal signature is invalid",
    )

    approvals = request.get("approval_tokens")
    require(
        isinstance(approvals, list) and len(approvals) == 2,
        "full-security request must carry exactly two approval tokens",
    )
    expected_approvers = [
        (
            "alice",
            "db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d",
        ),
        (
            "bob",
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        ),
    ]
    eligible_entries = [
        {"approverId": identifier, "publicKey": public_key}
        for identifier, public_key in expected_approvers
    ]
    eligible_digest = sha256_hex(
        b"chio.approver-set.v1\0" + canonical_json_bytes(eligible_entries)
    )
    require(
        eligible_digest == proposal_body.get("eligibleSetDigest"),
        "threshold proposal eligible-set digest is invalid",
    )
    require(
        [token.get("approver") for token in approvals]
        == [public_key for _, public_key in expected_approvers],
        "approval tokens do not match the governed eligible set",
    )
    token_ids: set[str] = set()
    for token in approvals:
        require(isinstance(token, dict), "approval token is not an object")
        require("algorithm" not in token, "default approval algorithm must be omitted")
        token_id = token.get("id")
        require(isinstance(token_id, str) and token_id not in token_ids, "approval token IDs repeat")
        token_ids.add(token_id)
        require(
            token.get("subject") == capability.get("subject")
            and token.get("request_id") == request.get("id")
            and token.get("governed_intent_hash") == intent_hash
            and token.get("threshold_proposal_hash") == proposal_hash
            and token.get("decision") == "approved"
            and proposal_body["proposalCreatedAt"] <= token.get("issued_at", -1)
            and token.get("issued_at", -1) < token.get("expires_at", -1)
            and token.get("expires_at") <= proposal_body["proposalDeadline"],
            "approval token does not bind the proposal, request, subject, and validity window",
        )
        token_body = {
            key: value
            for key, value in token.items()
            if key not in {"algorithm", "signature"}
        }
        require(
            ed25519_verify(
                token.get("approver"), token.get("signature"), canonical_json_bytes(token_body)
            ),
            f"approval token signature is invalid: {token_id}",
        )

    supplemental = request.get("supplemental_authorization")
    require(isinstance(supplemental, dict), "supplemental authorization is missing")
    require(
        supplemental.get("reference")
        == "supplemental://protocol-primitives/full-security-v1"
        and supplemental.get("artifact")
        == list(b"opaque-supplemental-vector-v1"),
        "supplemental authorization bytes or reference drifted",
    )

    grant = request.get("declassification_grant")
    require(isinstance(grant, dict), "declassification grant is missing")
    grant_body = grant.get("body")
    require(
        grant.get("algorithm") == "ed25519" and isinstance(grant_body, dict),
        "declassification grant algorithm or body is invalid",
    )
    expected_request_hash = list(
        hashlib.sha256(canonical_json_bytes(request.get("params"))).digest()
    )
    source_label = {
        "kind": "known",
        "owners": {"owner-a": ["owner-a"]},
        "compartments": ["restricted"],
    }
    expected_source_label_hash = list(
        hashlib.sha256(canonical_json_bytes(source_label)).digest()
    )
    require(
        grant_body.get("capability_id") == capability.get("id")
        and grant_body.get("subject_id") == capability.get("subject")
        and grant_body.get("agent_id") == capability.get("subject")
        and grant_body.get("destination_id") == request.get("server_id")
        and grant_body.get("tool_name") == request.get("tool")
        and grant_body.get("purpose") == intent_body.get("purpose")
        and grant_body.get("request_hash") == expected_request_hash
        and grant_body.get("source_label_hash") == expected_source_label_hash
        and grant_body.get("target_label")
        == {"kind": "known", "owners": {"owner-a": ["owner-a"]}, "compartments": []}
        and proposal_body["proposalCreatedAt"]
        <= grant_body.get("issued_at_unix_seconds", -1)
        < grant_body.get("expires_at_unix_seconds", -1)
        <= proposal_body["proposalDeadline"],
        "declassification grant is not bound to the request, capability, labels, and window",
    )
    require(
        ed25519_verify(
            grant.get("authority_key"),
            grant.get("signature"),
            b"chio:declassification-grant:v1\0" + canonical_json_bytes(grant_body),
        ),
        "declassification grant signature is invalid",
    )


def partition_digest(domain: bytes, value: Any) -> str:
    return sha256_hex(domain + canonical_json_bytes(value))


def validate_partition_quota(quota: Any) -> tuple[str, str]:
    require(isinstance(quota, dict), "partition_escrow_quota_invalid")
    profile = quota.get("profile")
    owner_id = quota.get("ownerId")
    grant_index = quota.get("grantIndex")
    maximum = quota.get("maxInvocations")
    require(
        isinstance(owner_id, str)
        and owner_id
        and isinstance(maximum, int)
        and 0 <= maximum <= 4_294_967_295,
        "partition_escrow_quota_invalid",
    )
    if profile == "chio.grant-invocation.v1":
        require(isinstance(grant_index, int), "partition_escrow_quota_invalid")
    else:
        require(grant_index is None, "partition_escrow_quota_invalid")
    key = {"profile": profile, "ownerId": owner_id}
    if grant_index is not None:
        key["grantIndex"] = grant_index
    return (
        partition_digest(b"chio.partition-escrow-quota-key.v1\0", key),
        partition_digest(b"chio.partition-escrow-quota-descriptor.v1\0", quota),
    )


def validate_partition_commitment(commitment: Any) -> tuple[dict[str, Any], str]:
    require(isinstance(commitment, dict), "partition_escrow_quota_commitment_invalid")
    body = commitment.get("body")
    require(
        isinstance(body, dict)
        and body.get("schema") == "chio.partition-escrow-quota-commitment.v1"
        and commitment.get("algorithm") == "ed25519",
        "partition_escrow_quota_commitment_invalid",
    )
    quota_key_digest, _ = validate_partition_quota(body.get("quota"))
    require(
        body.get("quotaKeyDigest") == quota_key_digest,
        "partition_escrow_quota_key_mismatch",
    )
    source_not_before = body.get("sourceNotBefore")
    source_expires_at = body.get("sourceExpiresAt")
    require(
        isinstance(source_not_before, int)
        and isinstance(source_expires_at, int)
        and 0 <= source_not_before < source_expires_at <= JCS_SAFE_INTEGER,
        "partition_escrow_source_window_invalid",
    )
    require(
        ed25519_verify(
            commitment.get("signerKey"),
            commitment.get("signature"),
            b"chio:partition-escrow-quota-commitment:v1\0"
            + canonical_json_bytes(body),
        ),
        "partition_escrow_quota_commitment_signature_invalid",
    )
    return (
        body,
        partition_digest(
            b"chio.partition-escrow-quota-commitment-digest.v1\0", commitment
        ),
    )


def validate_partition_allocation_set(
    allocation_set: Any,
) -> tuple[dict[str, Any], str, int]:
    require(isinstance(allocation_set, dict), "partition_escrow_allocation_set_invalid")
    body = allocation_set.get("body")
    require(
        isinstance(body, dict)
        and body.get("schema") == "chio.partition-escrow-allocation-set.v1"
        and allocation_set.get("algorithm") == "ed25519",
        "partition_escrow_allocation_set_invalid",
    )
    quota = body.get("quota")
    validate_partition_quota(quota)
    allocations = body.get("allocations")
    require(
        isinstance(allocations, list) and 1 <= len(allocations) <= 64,
        "partition_escrow_allocation_set_invalid",
    )
    partition_ids: set[str] = set()
    authority_ids: set[str] = set()
    total = 0
    for allocation in allocations:
        require(isinstance(allocation, dict), "partition_escrow_allocation_set_invalid")
        partition_id = allocation.get("partitionId")
        authority_id = allocation.get("authorityId")
        amount = allocation.get("allocatedInvocations")
        require(
            isinstance(partition_id, str)
            and partition_id
            and partition_id not in partition_ids
            and isinstance(authority_id, str)
            and authority_id
            and authority_id not in authority_ids
            and isinstance(amount, int)
            and 0 <= amount <= 4_294_967_295,
            "partition_escrow_allocation_set_invalid",
        )
        partition_ids.add(partition_id)
        authority_ids.add(authority_id)
        total += amount
    require(
        total <= quota.get("maxInvocations", -1),
        "partition_escrow_allocation_exceeds_maximum",
    )
    not_before = body.get("notBefore")
    expires_at = body.get("expiresAt")
    commitment_expires_at = body.get("quotaCommitmentExpiresAt")
    require(
        isinstance(not_before, int)
        and isinstance(expires_at, int)
        and isinstance(commitment_expires_at, int)
        and 0 <= not_before < expires_at <= commitment_expires_at <= JCS_SAFE_INTEGER,
        "partition_escrow_allocation_window_invalid",
    )
    plan = {
        "authorityDomain": body.get("authorityDomain"),
        "allocationRootId": body.get("allocationRootId"),
        "allocationEpoch": body.get("allocationEpoch"),
        "quota": quota,
        "sourceExpiresAt": commitment_expires_at,
        "notBefore": not_before,
        "expiresAt": expires_at,
        "allocations": allocations,
    }
    require(
        body.get("allocationPlanDigest")
        == partition_digest(b"chio.partition-escrow-allocation-plan.v1\0", plan),
        "partition_escrow_allocation_plan_mismatch",
    )
    require(
        ed25519_verify(
            allocation_set.get("allocatorKey"),
            allocation_set.get("signature"),
            b"chio:partition-escrow-allocation-set:v1\0"
            + canonical_json_bytes(body),
        ),
        "partition_escrow_allocation_signature_invalid",
    )
    return (
        body,
        partition_digest(
            b"chio.partition-escrow-allocation-set-digest.v1\0", allocation_set
        ),
        total,
    )


def validate_partition_source_trust(
    quota: dict[str, Any], source_trust: Any
) -> None:
    require(isinstance(source_trust, dict), "partition_escrow_source_trust_invalid")
    kind = source_trust.get("kind")
    profile = quota.get("profile")
    owner_id = quota.get("ownerId")
    if kind == "grantCapability":
        require(
            profile == "chio.grant-invocation.v1"
            and source_trust.get("capability_id") == owner_id
            and source_trust.get("grant_index") == quota.get("grantIndex"),
            "partition_escrow_source_trust_invalid",
        )
    elif kind == "aggregateCapability":
        require(
            profile == "chio.aggregate-capability-invocation.v1"
            and source_trust.get("capability_id") == owner_id,
            "partition_escrow_source_trust_invalid",
        )
    elif kind == "aggregateFamily":
        require(
            profile == "chio.aggregate-family-invocation.v1"
            and source_trust.get("family_owner") == owner_id,
            "partition_escrow_source_trust_invalid",
        )
    elif kind == "brokerCapability":
        require(
            profile == "chio.broker-capability-execution.v1"
            and source_trust.get("quota_owner_id") == owner_id,
            "partition_escrow_source_trust_invalid",
        )
    else:
        raise ContractError("partition_escrow_source_trust_invalid")


def validate_partition_admission(evidence: Any) -> str:
    require(
        isinstance(evidence, dict)
        and evidence.get("schema") == "chio.partition-escrow-admission-evidence.v1",
        "partition_escrow_admission_evidence_invalid",
    )
    resolver = evidence.get("resolver")
    durable = evidence.get("durableStore")
    quotas = evidence.get("quotas")
    require(
        isinstance(resolver, dict)
        and isinstance(durable, dict)
        and isinstance(quotas, list)
        and 1 <= len(quotas) <= 8,
        "partition_escrow_admission_evidence_invalid",
    )
    partition_id = evidence.get("partitionId")
    authority_id = evidence.get("authorityId")
    require(
        durable.get("storeIdentityDigest") == authority_id,
        "partition_escrow_store_identity_mismatch",
    )
    expected_namespace = partition_digest(
        b"chio.partition-escrow-counter-namespace.v1\0",
        {"partitionId": partition_id, "authorityId": authority_id},
    )
    require(
        durable.get("counterNamespaceDigest") == expected_namespace,
        "partition_escrow_counter_namespace_mismatch",
    )
    verified_at = evidence.get("verifiedAt")
    fencing_token = durable.get("fencingToken")
    require(
        isinstance(verified_at, int)
        and 0 <= verified_at <= JCS_SAFE_INTEGER
        and isinstance(fencing_token, int)
        and 1 <= fencing_token <= JCS_SAFE_INTEGER,
        "partition_escrow_admission_evidence_invalid",
    )
    pins = []
    seen_quota_keys: set[str] = set()
    for quota_evidence in quotas:
        require(
            isinstance(quota_evidence, dict),
            "partition_escrow_admission_evidence_invalid",
        )
        quota = quota_evidence.get("globalQuota")
        quota_key_digest, quota_descriptor_digest = validate_partition_quota(quota)
        require(
            quota_evidence.get("quotaKeyDigest") == quota_key_digest
            and quota_key_digest not in seen_quota_keys,
            "partition_escrow_quota_key_mismatch",
        )
        seen_quota_keys.add(quota_key_digest)
        require(
            quota_evidence.get("quotaDescriptorDigest") == quota_descriptor_digest,
            "partition_escrow_quota_descriptor_mismatch",
        )
        commitment = quota_evidence.get("quotaCommitment")
        commitment_body, commitment_digest = validate_partition_commitment(commitment)
        allocation_set = quota_evidence.get("allocationSet")
        allocation_body, allocation_digest, total = validate_partition_allocation_set(
            allocation_set
        )
        source_not_before = quota_evidence.get("sourceNotBefore")
        source_expires_at = quota_evidence.get("sourceExpiresAt")
        require(
            isinstance(source_not_before, int)
            and isinstance(source_expires_at, int)
            and source_not_before <= verified_at < source_expires_at,
            "partition_escrow_source_expired",
        )
        require(
            allocation_body.get("notBefore") <= verified_at < allocation_body.get("expiresAt"),
            "partition_escrow_allocation_expired",
        )
        source_trust = quota_evidence.get("sourceTrust")
        validate_partition_source_trust(quota, source_trust)
        source_binding = {
            "schema": "chio.partition-escrow-source-trust-binding.v1",
            "profile": quota.get("profile"),
            "quotaKeyDigest": quota_key_digest,
            "quotaDescriptorDigest": quota_descriptor_digest,
            "underlyingSourceArtifactDigest": quota_evidence.get(
                "underlyingSourceArtifactDigest"
            ),
            "sourceSigner": quota_evidence.get("sourceSigner"),
            "sourceNotBefore": source_not_before,
            "sourceExpiresAt": source_expires_at,
            "profileTrust": source_trust,
        }
        source_trust_digest = partition_digest(
            b"chio.partition-escrow-source-trust-binding.v1\0", source_binding
        )
        require(
            quota_evidence.get("sourceTrustBindingDigest") == source_trust_digest
            and commitment_body.get("sourceTrustBindingDigest") == source_trust_digest,
            "partition_escrow_source_trust_binding_mismatch",
        )
        require(
            commitment_body.get("quota") == quota
            and allocation_body.get("quota") == quota
            and commitment_body.get("quotaKeyDigest") == quota_key_digest,
            "partition_escrow_quota_binding_mismatch",
        )
        require(
            quota_evidence.get("quotaCommitmentDigest") == commitment_digest
            and allocation_body.get("quotaCommitmentDigest") == commitment_digest,
            "partition_escrow_quota_commitment_digest_mismatch",
        )
        require(
            commitment_body.get("underlyingSourceArtifactDigest")
            == quota_evidence.get("underlyingSourceArtifactDigest")
            and commitment_body.get("sourceNotBefore") == source_not_before
            and commitment_body.get("sourceExpiresAt") == source_expires_at
            and commitment.get("signerKey") == quota_evidence.get("sourceSigner"),
            "partition_escrow_source_binding_mismatch",
        )
        root_id = quota_evidence.get("allocationRootId")
        require(
            commitment_body.get("allocationRootId") == root_id
            and allocation_body.get("allocationRootId") == root_id,
            "partition_escrow_allocation_root_mismatch",
        )
        epoch = quota_evidence.get("allocationEpoch")
        require(
            epoch == fencing_token
            and commitment_body.get("allocationEpoch") == epoch
            and allocation_body.get("allocationEpoch") == epoch,
            "partition_escrow_allocation_epoch_mismatch",
        )
        plan_digest = quota_evidence.get("allocationPlanDigest")
        require(
            commitment_body.get("allocationPlanDigest") == plan_digest
            and allocation_body.get("allocationPlanDigest") == plan_digest,
            "partition_escrow_allocation_plan_mismatch",
        )
        require(
            quota_evidence.get("allocationSetDigest") == allocation_digest,
            "partition_escrow_allocation_set_digest_mismatch",
        )
        require(
            quota_evidence.get("totalAllocatedInvocations") == total,
            "partition_escrow_total_allocation_mismatch",
        )
        local = [
            allocation
            for allocation in allocation_body.get("allocations", [])
            if allocation.get("partitionId") == partition_id
            and allocation.get("authorityId") == authority_id
        ]
        require(
            len(local) == 1
            and quota_evidence.get("localAllocatedInvocations")
            == local[0].get("allocatedInvocations"),
            "partition_escrow_local_allocation_mismatch",
        )
        certificate_binding = {
            "authorityDomain": evidence.get("authorityDomain"),
            "allocationRootId": root_id,
            "allocationEpoch": epoch,
            "quota": quota,
            "commitmentDigest": commitment_digest,
            "underlyingSourceArtifactDigest": quota_evidence.get(
                "underlyingSourceArtifactDigest"
            ),
            "sourceTrustBindingDigest": source_trust_digest,
            "sourceNotBefore": source_not_before,
            "sourceExpiresAt": source_expires_at,
            "certificateSigner": quota_evidence.get("sourceSigner"),
            "allocationPlanDigest": plan_digest,
        }
        certificate_digest = partition_digest(
            b"chio.partition-escrow-quota-authority-binding.v1\0",
            certificate_binding,
        )
        require(
            quota_evidence.get("quotaCertificateBindingDigest") == certificate_digest,
            "partition_escrow_quota_certificate_binding_mismatch",
        )
        pins.append(
            (
                quota_key_digest,
                {
                    "quota": quota,
                    "quotaKeyDigest": quota_key_digest,
                    "quotaDescriptorDigest": quota_descriptor_digest,
                    "quotaCertificateBindingDigest": certificate_digest,
                    "quotaCommitmentDigest": commitment_digest,
                    "underlyingSourceArtifactDigest": quota_evidence.get(
                        "underlyingSourceArtifactDigest"
                    ),
                    "sourceTrustBindingDigest": source_trust_digest,
                    "sourceNotBefore": source_not_before,
                    "sourceExpiresAt": source_expires_at,
                    "sourceSigner": quota_evidence.get("sourceSigner"),
                    "allocationPlanDigest": plan_digest,
                    "allocationRootId": root_id,
                    "allocationEpoch": epoch,
                    "allocationSetDigest": allocation_digest,
                },
            )
        )
    registry_configuration = {
        "schema": "chio.partition-escrow-registry.v1",
        "authorityDomain": evidence.get("authorityDomain"),
        "partitionId": partition_id,
        "authorityId": authority_id,
        "resolverId": resolver.get("resolverId"),
        "resolverImplementationId": resolver.get("implementationId"),
        "resolverImplementationVersion": resolver.get("implementationVersion"),
        "durableStore": durable,
        "allocationPins": [pin for _, pin in sorted(pins)],
    }
    require(
        resolver.get("configurationDigest")
        == partition_digest(
            b"chio.partition-escrow-registry.v1\0", registry_configuration
        ),
        "partition_escrow_registry_configuration_mismatch",
    )
    return partition_digest(
        b"chio.partition-escrow-admission-evidence.v1\0", evidence
    )


def validate_partition_wrapper(wrapper: Any) -> tuple[dict[str, Any], str]:
    require(isinstance(wrapper, dict), "partition_escrow_wrapper_invalid")
    canonical_text = wrapper.get("canonicalJson")
    require(isinstance(canonical_text, str), "partition_escrow_wrapper_invalid")
    canonical = canonical_text.encode("utf-8")
    require(
        0 < len(canonical) <= 1024 * 1024,
        "partition_escrow_evidence_size_invalid",
    )
    try:
        evidence = parse_json_bytes(canonical, "partition escrow canonicalJson")
    except JsonParseError as error:
        raise ContractError("partition_escrow_noncanonical_evidence") from error
    require(
        canonical_json_bytes(evidence) == canonical,
        "partition_escrow_noncanonical_evidence",
    )
    evidence_digest = validate_partition_admission(evidence)
    require(
        wrapper.get("digest") == evidence_digest,
        "partition_escrow_evidence_digest_mismatch",
    )
    return evidence, evidence_digest


def validate_partition_budget(value: Any) -> tuple[dict[str, Any], str]:
    require(isinstance(value, dict), "partition_escrow_budget_evidence_invalid")
    evidence, evidence_digest = validate_partition_wrapper(
        value.get("partitionEscrowEvidence")
    )
    invocation_quotas = value.get("invocationQuotas")
    escrow_quotas = evidence.get("quotas")
    require(
        isinstance(invocation_quotas, list)
        and isinstance(escrow_quotas, list)
        and len(invocation_quotas) == len(escrow_quotas),
        "partition_escrow_local_maximum_mismatch",
    )
    for local, escrow in zip(invocation_quotas, escrow_quotas):
        global_quota = escrow.get("globalQuota")
        require(
            local.get("key")
            == {
                key: global_quota[key]
                for key in ("profile", "ownerId", "grantIndex")
                if key in global_quota
            }
            and local.get("maxInvocations")
            == escrow.get("localAllocatedInvocations"),
            "partition_escrow_local_maximum_mismatch",
        )
    revocation_set = value.get("revocationSet")
    require(isinstance(revocation_set, dict), "partition_escrow_revocation_mismatch")
    for escrow in escrow_quotas:
        source_trust = escrow.get("sourceTrust")
        require(
            source_trust.get("revocation_set_digest") == revocation_set.get("digest"),
            "partition_escrow_revocation_mismatch",
        )
    return evidence, evidence_digest


def validate_partition_capture(value: Any) -> tuple[dict[str, Any], str]:
    require(isinstance(value, dict), "partition_escrow_capture_invalid")
    evidence, evidence_digest = validate_partition_wrapper(
        value.get("partitionEscrowEvidence")
    )
    require(
        value.get("guaranteeLevel") == "partition_escrowed"
        and "leaderEpoch" not in value,
        "partition_escrow_capture_guarantee_mismatch",
    )
    require(
        value.get("authorizationArtifactDigests", []).count(evidence_digest) == 1,
        "partition_escrow_capture_artifact_digest_mismatch",
    )
    durable = evidence.get("durableStore")
    authority = value.get("authority")
    require(
        isinstance(authority, dict)
        and authority.get("authorityId") == evidence.get("authorityId")
        and authority.get("leaseEpoch") == durable.get("fencingToken"),
        "partition_escrow_capture_authority_mismatch",
    )
    transitions = value.get("invocationQuotas")
    escrow_quotas = evidence.get("quotas")
    require(
        isinstance(transitions, list)
        and len(transitions) == len(escrow_quotas),
        "partition_escrow_local_maximum_mismatch",
    )
    for transition, escrow in zip(transitions, escrow_quotas):
        require(
            transition.get("maxInvocations")
            == escrow.get("localAllocatedInvocations"),
            "partition_escrow_local_maximum_mismatch",
        )
    return evidence, evidence_digest


def validate_partition_receipt(value: Any) -> tuple[dict[str, Any], str]:
    require(isinstance(value, dict), "partition_escrow_receipt_invalid")
    canonical_text = value.get("canonical_json")
    require(isinstance(canonical_text, str), "partition_escrow_receipt_invalid")
    canonical = canonical_text.encode("utf-8")
    evidence = parse_json_bytes(canonical, "partition escrow receipt canonical_json")
    require(
        canonical_json_bytes(evidence) == canonical,
        "partition_escrow_noncanonical_evidence",
    )
    evidence_digest = validate_partition_admission(evidence)
    require(
        value.get("evidence_digest") == evidence_digest,
        "partition_escrow_evidence_digest_mismatch",
    )
    resolver = evidence.get("resolver")
    durable = evidence.get("durableStore")
    expected_summary = {
        "resolver_id": resolver.get("resolverId"),
        "resolver_implementation_id": resolver.get("implementationId"),
        "resolver_implementation_version": resolver.get("implementationVersion"),
        "resolver_configuration_digest": resolver.get("configurationDigest"),
        "store_identity_digest": durable.get("storeIdentityDigest"),
        "counter_namespace_digest": durable.get("counterNamespaceDigest"),
        "fencing_token": durable.get("fencingToken"),
        "partition_id": evidence.get("partitionId"),
        "authority_id": evidence.get("authorityId"),
    }
    require(
        value.get("summary") == expected_summary,
        "partition_escrow_receipt_summary_mismatch",
    )
    return evidence, evidence_digest


def validate_partition_escrow_relationships(positives: dict[str, Any]) -> None:
    commitment = positives.get("partition_escrow_quota_commitment")
    allocation_set = positives.get("partition_escrow_allocation_set")
    evidence = positives.get("partition_escrow_admission_evidence")
    receipt = positives.get("partition_escrow_receipt_metadata")
    budget = positives.get("budget_admission_evidence_partition_escrow")
    capture = positives.get("admission_capture_metadata_partition_escrow")
    validate_partition_commitment(commitment)
    validate_partition_allocation_set(allocation_set)
    evidence_digest = validate_partition_admission(evidence)
    receipt_evidence, receipt_digest = validate_partition_receipt(receipt)
    budget_evidence, budget_digest = validate_partition_budget(budget)
    capture_evidence, capture_digest = validate_partition_capture(capture)
    require(
        evidence == receipt_evidence == budget_evidence == capture_evidence
        and evidence_digest == receipt_digest == budget_digest == capture_digest,
        "partition_escrow_positive_evidence_drift",
    )
    require(
        evidence.get("quotas")[0].get("quotaCommitment") == commitment
        and evidence.get("quotas")[0].get("allocationSet") == allocation_set,
        "partition_escrow_positive_artifact_drift",
    )
    require(
        budget.get("partitionEscrowEvidence") == capture.get("partitionEscrowEvidence"),
        "partition_escrow_wrapper_drift",
    )


def validate_partition_semantic_case(base: str, instance: Any) -> None:
    if base.endswith("partition-escrow-quota-commitment-v1.json"):
        validate_partition_commitment(instance)
    elif base.endswith("partition-escrow-allocation-set-v1.json"):
        validate_partition_allocation_set(instance)
    elif base.endswith("partition-escrow-admission-evidence-v1.json"):
        validate_partition_admission(instance)
    elif base.endswith("partition-escrow-receipt-metadata-v1.json"):
        validate_partition_receipt(instance)
    elif base.endswith("budget-invocation-admission-evidence-partition-escrow-v1.json"):
        validate_partition_budget(instance)
    elif base.endswith("admission-capture-metadata-partition-escrow-v1.json"):
        validate_partition_capture(instance)
    else:
        raise ContractError("partition_escrow_semantic_case_has_unknown_base")


def schema_registry() -> tuple[Registry, dict[str, tuple[Path, Any]]]:
    resources: list[tuple[str, Resource]] = []
    schemas: dict[str, tuple[Path, Any]] = {}
    for path in sorted(SCHEMA_ROOT.rglob("*.json")):
        schema = load_json(path)
        if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
            continue
        schema_id = schema["$id"]
        if schema_id in schemas:
            raise ContractError(f"duplicate schema ID {schema_id}")
        schemas[schema_id] = (path, schema)
        resources.append((schema_id, Resource.from_contents(schema)))
    return Registry().with_resources(resources), schemas


def schema_accepts(
    schema_id: str,
    instance: Any,
    registry: Registry,
    schemas: dict[str, tuple[Path, Any]],
) -> bool:
    if schema_id not in schemas:
        raise ContractError(f"unregistered schema ID {schema_id}")
    _, schema = schemas[schema_id]
    return not any(Draft202012Validator(schema, registry=registry).iter_errors(instance))


def pointer_segments(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ContractError(f"mutation pointer is not absolute: {pointer}")
    return [segment.replace("~1", "/").replace("~0", "~") for segment in pointer[1:].split("/")]


def apply_mutation(value: Any, mutation: dict[str, Any]) -> Any:
    operation = mutation.get("op")
    if operation == "append_bytes":
        raise ContractError("append_bytes must be applied to the source byte sequence")
    path = mutation.get("path")
    if not isinstance(path, str):
        raise ContractError("JSON mutation has no string path")
    segments = pointer_segments(path)
    parent = value
    for segment in segments[:-1]:
        parent = parent[int(segment)] if isinstance(parent, list) else parent[segment]
    target = segments[-1]
    if operation in {"add", "replace"}:
        if "value" not in mutation:
            raise ContractError(f"{operation} mutation has no value")
        if isinstance(parent, list):
            parent[int(target)] = mutation["value"]
        else:
            parent[target] = mutation["value"]
    elif operation == "remove":
        if isinstance(parent, list):
            del parent[int(target)]
        else:
            del parent[target]
    else:
        raise ContractError(f"unsupported mutation operation {operation}")
    return value


def mutated_bytes(base: bytes, mutation: dict[str, Any]) -> bytes:
    if mutation.get("op") == "append_bytes":
        suffix = mutation.get("hex")
        if not isinstance(suffix, str):
            raise ContractError("append_bytes mutation has no hex payload")
        try:
            return base + bytes.fromhex(suffix)
        except ValueError as error:
            raise ContractError(f"append_bytes payload is invalid hex: {suffix}") from error
    return canonical_json_bytes(
        apply_mutation(parse_json_bytes(base, "mutation base"), mutation)
    )


def validate() -> dict[str, Any]:
    verify_jcs_profile()
    registry, schemas = schema_registry()
    index = load_json(VECTOR_ROOT / "index.json")
    positives = index.get("positive") if isinstance(index, dict) else None
    negatives = index.get("negative") if isinstance(index, dict) else None
    if not isinstance(positives, list) or len(positives) != EXPECTED_POSITIVES:
        raise ContractError(f"positive inventory must contain exactly {EXPECTED_POSITIVES} entries")
    if not isinstance(negatives, list) or len(negatives) != 2:
        raise ContractError("negative inventory must contain the direct vector and mutation corpus")

    positive_ids: set[str] = set()
    positive_files: set[str] = set()
    schema_by_file: dict[str, str] = {}
    positive_instances: dict[str, Any] = {}
    for entry in positives:
        if not isinstance(entry, dict):
            raise ContractError("positive inventory entry is not an object")
        identifier = entry.get("id")
        relative = entry.get("file")
        schema_id = entry.get("schema_id")
        if not all(isinstance(item, str) for item in (identifier, relative, schema_id)):
            raise ContractError("positive inventory entry has non-string fields")
        if identifier in positive_ids or relative in positive_files:
            raise ContractError(f"duplicate positive inventory entry {identifier}")
        positive_ids.add(identifier)
        positive_files.add(relative)
        schema_by_file[relative] = schema_id
        path = VECTOR_ROOT / relative
        source = path.read_bytes()
        instance = parse_json_bytes(source, str(path))
        if canonical_json_bytes(instance) != source.removesuffix(b"\n"):
            raise ContractError(f"{path}: positive vector is not canonical JSON")
        if not schema_accepts(schema_id, instance, registry, schemas):
            raise ContractError(f"{path}: positive vector fails {schema_id}")
        positive_instances[identifier] = instance

    validate_governed_security_relationships(positive_instances)
    validate_partition_escrow_relationships(positive_instances)

    direct = negatives[0]
    if not isinstance(direct, dict):
        raise ContractError("direct negative inventory entry is not an object")
    direct_path = VECTOR_ROOT / direct["file"]
    direct_instance = load_json(direct_path)
    direct_schema_valid = schema_accepts(
        direct["schema_id"], direct_instance, registry, schemas
    )
    if direct_schema_valid:
        raise ContractError(f"{direct_path}: direct negative vector passed its schema")

    corpus = load_json(VECTOR_ROOT / negatives[1]["file"])
    cases = corpus.get("cases") if isinstance(corpus, dict) else None
    if not isinstance(cases, list) or len(cases) != EXPECTED_MUTATIONS:
        raise ContractError(f"mutation corpus must contain exactly {EXPECTED_MUTATIONS} cases")
    case_ids: set[str] = set()
    case_results: list[dict[str, Any]] = []
    structural_rejections = 1
    semantic_rejections = 0
    for case in cases:
        if not isinstance(case, dict):
            raise ContractError("mutation case is not an object")
        identifier = case.get("id")
        base = case.get("base")
        mutation = case.get("mutation")
        expected = case.get("expected")
        if not isinstance(identifier, str) or identifier in case_ids:
            raise ContractError(f"duplicate or invalid mutation ID {identifier}")
        case_ids.add(identifier)
        if not isinstance(base, str) or base not in schema_by_file:
            raise ContractError(f"{identifier}: mutation base is not a positive vector")
        if not isinstance(mutation, dict) or not isinstance(expected, dict):
            raise ContractError(f"{identifier}: malformed mutation or expectation")
        raw = mutated_bytes((VECTOR_ROOT / base).read_bytes().removesuffix(b"\n"), mutation)
        try:
            instance = parse_json_bytes(raw, identifier)
            parse_valid = True
        except JsonParseError:
            instance = None
            parse_valid = False
        if parse_valid != expected.get("json_parse_valid"):
            raise ContractError(f"{identifier}: JSON parse classification drifted")
        schema_valid = parse_valid and schema_accepts(
            schema_by_file[base], instance, registry, schemas
        )
        if schema_valid != expected.get("json_schema_valid"):
            raise ContractError(f"{identifier}: JSON Schema classification drifted")
        if expected.get("semantic_valid") is not False:
            raise ContractError(f"{identifier}: mutation is not classified semantic-invalid")
        failure = expected.get("failure")
        if schema_valid and isinstance(failure, str) and failure.startswith("partition_escrow_"):
            try:
                validate_partition_semantic_case(base, instance)
            except ContractError as error:
                if str(error) != failure:
                    raise ContractError(
                        f"{identifier}: semantic failure drifted to {error}, expected {failure}"
                    ) from error
            else:
                raise ContractError(
                    f"{identifier}: partition escrow semantic mutation was accepted"
                )
        case_results.append(
            {
                "id": identifier,
                "json_parse_valid": parse_valid,
                "json_schema_valid": schema_valid,
                "semantic_valid": False,
            }
        )
        if schema_valid:
            semantic_rejections += 1
        else:
            structural_rejections += 1

    if structural_rejections != EXPECTED_STRUCTURAL_REJECTIONS:
        raise ContractError(
            f"structural rejection count is {structural_rejections}, expected {EXPECTED_STRUCTURAL_REJECTIONS}"
        )
    if semantic_rejections != EXPECTED_SEMANTIC_REJECTIONS:
        raise ContractError(
            f"semantic rejection count is {semantic_rejections}, expected {EXPECTED_SEMANTIC_REJECTIONS}"
        )
    if structural_rejections + semantic_rejections != EXPECTED_NEGATIVES:
        raise ContractError(f"negative corpus must contain exactly {EXPECTED_NEGATIVES} cases")
    return {
        "direct": {
            "id": direct["id"],
            "json_parse_valid": True,
            "json_schema_valid": direct_schema_valid,
            "semantic_valid": False,
        },
        "cases": case_results,
    }


def main() -> int:
    try:
        report = validate()
    except (ContractError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"protocol primitive vector contract failed: {error}", file=sys.stderr)
        return 1
    if sys.argv[1:] == ["--report-json"]:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    if sys.argv[1:]:
        print(f"unsupported arguments: {' '.join(sys.argv[1:])}", file=sys.stderr)
        return 1
    print(
        "protocol primitive vectors passed "
        f"({EXPECTED_POSITIVES} positive, {EXPECTED_STRUCTURAL_REJECTIONS} structural negative, "
        f"{EXPECTED_SEMANTIC_REJECTIONS} semantic negative)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
