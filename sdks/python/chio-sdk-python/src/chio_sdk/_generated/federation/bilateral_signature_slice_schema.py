# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class CoSign(Enum):
    bilateral_required = "bilateral_required"
    bilateral_if_cross_org = "bilateral_if_cross_org"


class CrossOrgVisibility(Enum):
    private = "private"
    treaty_only = "treaty_only"
    federated = "federated"
    public = "public"


class Digest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class SubjectItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    digest: Digest
    name: Annotated[str, Field(pattern="^chio-receipt:.+")]


class HashRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    alg: Literal["sha256"]
    value: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class KernelIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    alg: Literal["ed25519"]
    kernel_id: Annotated[str, Field(min_length=1)]
    passport_key_fingerprint: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class JointDisposition(Enum):
    allow = "allow"
    deny = "deny"


class Verdict(Enum):
    allow = "allow"
    deny = "deny"


class PolicyVerdict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_id: Annotated[str, Field(min_length=1)]
    policy_version: Annotated[str, Field(min_length=1)]
    rationale_code: Annotated[str | None, Field(min_length=1)] = None
    verdict: Verdict


class CapabilityLeaseRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expires_at_unix_ms: Annotated[int, Field(ge=0)]
    issuer: Annotated[str, Field(min_length=1)]
    lease_id: Annotated[str, Field(min_length=1)]
    scope_digest: HashRecord | None = None


class GovernanceReceiptRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    digest: HashRecord
    kernel_id: Annotated[str, Field(min_length=1)]
    receipt_id: Annotated[str, Field(min_length=1)]


class PolicyEvaluationSummary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    joint_disposition: JointDisposition | None = None
    server_a_verdict: PolicyVerdict
    server_b_verdict: PolicyVerdict


class Predicate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_lease_ref: CapabilityLeaseRef | None = None
    co_sign: CoSign
    consistency_anchor: Annotated[str | None, Field(min_length=1)] = None
    consistency_model: Literal["crdt-commutative"]
    cross_org_visibility: CrossOrgVisibility
    governance_receipt_ref: GovernanceReceiptRef | None = None
    invocation_id: Annotated[str, Field(min_length=1)]
    policy_evaluation_summary: PolicyEvaluationSummary | None = None
    receipt_canonical_json: Annotated[str, Field(min_length=2)]
    schema_: Annotated[
        Literal["chio.bilateral-signature-slice.v1"], Field(alias="schema")
    ]
    timestamp_unix_ms: Annotated[int, Field(ge=0)]
    tool_name: Annotated[str, Field(min_length=1)]
    tool_server_a: KernelIdentity
    tool_server_b: KernelIdentity


class ChioBilateralDsseSignatureSliceStatement(BaseModel):
    """
    Bounded in-toto Statement payload for Chio bilateral DSSE signature slices. This is not the strict treaty-bound bilateral invocation predicate.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    field_type: Annotated[
        Literal["https://in-toto.io/Statement/v1"], Field(alias="_type")
    ]
    predicate: Predicate
    predicateType: Literal["chio.bilateral-signature-slice.v1"]
    subject: Annotated[list[SubjectItem], Field(max_length=1, min_length=1)]
