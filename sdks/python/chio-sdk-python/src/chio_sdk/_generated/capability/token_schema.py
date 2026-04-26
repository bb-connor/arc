# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: addbe60437bb0258103fb68da7ee1ee5c1d4fade2ca6aab98f2d5ddc89f0b7e1
#
# Manual edits will be overwritten by the next regeneration; the
# M01.P3.T5 spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class Algorithm(Enum):
    """
    Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
    """

    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"


class Operation(Enum):
    invoke = "invoke"
    read_result = "read_result"
    read = "read"
    subscribe = "subscribe"
    get = "get"
    delegate = "delegate"


class MonetaryAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(ge=0)
    currency: constr(min_length=1)


class Constraint(BaseModel):
    """
    Tagged enum mirroring `Constraint` in `chio-core-types`. Encoded as `{ type, value }` (or just `{ type }` for unit variants such as `governed_intent_required`). Constraint variants intentionally remain extensible; `additionalProperties` is permissive here so new variants do not require schema rev-locks.
    """

    type: constr(min_length=1)


class Attenuation(BaseModel):
    type: constr(min_length=1)


class DelegationLink(BaseModel):
    """
    A single link in a delegation chain. Mirrors `DelegationLink`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: constr(min_length=1)
    delegator: constr(pattern=r"^[0-9a-f]{64}$")
    delegatee: constr(pattern=r"^[0-9a-f]{64}$")
    attenuations: list[Attenuation] | None = None
    timestamp: conint(ge=0)
    signature: constr(pattern=r"^[0-9a-f]+$", min_length=96)


class ToolGrant(BaseModel):
    """
    Authorization to invoke a single tool. Mirrors `ToolGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    server_id: constr(min_length=1)
    tool_name: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)
    constraints: list[Constraint] | None = None
    max_invocations: conint(ge=0) | None = None
    max_cost_per_invocation: MonetaryAmount | None = None
    max_total_cost: MonetaryAmount | None = None
    dpop_required: bool | None = None


class ResourceGrant(BaseModel):
    """
    Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    uri_pattern: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)


class PromptGrant(BaseModel):
    """
    Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    prompt_name: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)


class ChioScope(BaseModel):
    """
    What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[ToolGrant] | None = None
    resource_grants: list[ResourceGrant] | None = None
    prompt_grants: list[PromptGrant] | None = None


class ChioCapabilitytoken(BaseModel):
    """
    A Chio capability token: an Ed25519-signed (or FIPS-algorithm), scoped, time-bounded authorization to invoke a tool. Mirrors the serde shape of `CapabilityToken` in `crates/chio-core-types/src/capability.rs`. The `signature` field covers the canonical JSON of all other fields except `algorithm`. The `algorithm` envelope field is informational (verification dispatches off the signature hex prefix) and is omitted for legacy Ed25519 tokens.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    id: constr(min_length=1) = Field(
        ..., description="Unique token ID (UUIDv7 recommended), used for revocation."
    )
    issuer: constr(pattern=r"^[0-9a-f]{64}$") = Field(
        ...,
        description="Hex-encoded public key of the Capability Authority (or delegating agent) that issued this token.",
    )
    subject: constr(pattern=r"^[0-9a-f]{64}$") = Field(
        ...,
        description="Hex-encoded public key of the agent this capability is bound to (DPoP sender constraint).",
    )
    scope: ChioScope
    issued_at: conint(ge=0) = Field(
        ..., description="Unix timestamp (seconds) when the token was issued."
    )
    expires_at: conint(ge=0) = Field(
        ..., description="Unix timestamp (seconds) when the token expires."
    )
    delegation_chain: list[DelegationLink] | None = Field(
        None,
        description="Ordered list of delegation links from the root authority to this token. Omitted (or empty) for direct issuances.",
    )
    algorithm: Algorithm | None = Field(
        None,
        description="Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.",
    )
    signature: constr(pattern=r"^[0-9a-f]+$", min_length=96) = Field(
        ...,
        description="Hex-encoded signature over the canonical JSON of the token body. Length depends on the signing algorithm (Ed25519 = 128 hex chars, P-256 = 96+, P-384 = 144+).",
    )
