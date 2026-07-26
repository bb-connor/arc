# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from . import (
    aggregate_family_preservation_evidence_schema,
    aggregate_invocation_budget_schema,
)


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class ScopeAttenuation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: Annotated[str, Field(min_length=1)]


class Kind(Enum):
    restrict_tool = "restrict_tool"
    bind_session = "bind_session"
    restrict_audience = "restrict_audience"
    restrict_geo = "restrict_geo"
    restrict_time_window = "restrict_time_window"


class Caveat(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind
    predicate: Annotated[str, Field(min_length=1)]
    sig: Annotated[
        str | None,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ] = None


class Constraint(BaseModel):
    """
    Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
    """

    type: Annotated[str, Field(min_length=1)]
    value: Any | None = None


class Attenuation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: Annotated[str, Field(min_length=1)]


class DelegationLink(BaseModel):
    """
    A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_family_preservation: (
        aggregate_family_preservation_evidence_schema.ChioAggregateFamilyPreservationEvidence
        | None
    ) = None
    attenuations: list[Attenuation] | None = None
    capability_id: Annotated[str, Field(min_length=1)]
    delegatee: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+)$"
        ),
    ]
    delegator: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+)$"
        ),
    ]
    scope_hash: Annotated[
        str,
        Field(
            description="RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.",
            pattern="^[0-9a-f]{64}$",
        ),
    ]
    signature: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+:[0-9a-f]+)$"
        ),
    ]
    timestamp: Annotated[int, Field(ge=0)]


class GrantKind(Enum):
    tool = "tool"
    resource = "resource"
    prompt = "prompt"


class Subset(Enum):
    boolean_True = True


class GrantSubsetRelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childIndex: Annotated[int, Field(ge=0)]
    grantKind: GrantKind
    parentIndex: Annotated[int, Field(ge=0)]
    subset: Subset


class MonetaryAmount(BaseModel):
    """
    A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    currency: Annotated[str, Field(min_length=1)]
    units: Annotated[int, Field(ge=0)]


class Operation(Enum):
    invoke = "invoke"
    read_result = "read_result"
    read = "read"
    subscribe = "subscribe"
    get = "get"
    delegate = "delegate"


class PromptGrant(BaseModel):
    """
    Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    operations: Annotated[list[Operation], Field(min_length=1)]
    prompt_name: Annotated[str, Field(min_length=1)]


class ResourceGrant(BaseModel):
    """
    Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    operations: Annotated[list[Operation], Field(min_length=1)]
    uri_pattern: Annotated[str, Field(min_length=1)]


class ToolGrant(BaseModel):
    """
    Authorization to invoke a single tool. Mirrors `ToolGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    constraints: list[Constraint] | None = None
    dpop_required: bool | None = None
    max_cost_per_invocation: MonetaryAmount | None = None
    max_invocations: Annotated[int | None, Field(ge=0)] = None
    max_total_cost: MonetaryAmount | None = None
    operations: Annotated[list[Operation], Field(min_length=1)]
    server_id: Annotated[str, Field(min_length=1)]
    tool_name: Annotated[str, Field(min_length=1)]


class AttenuationWitness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    normalizedChildScope: Annotated[str, Field(min_length=2)]
    normalizedParentScope: Annotated[str, Field(min_length=2)]
    restrictedPredicates: list[str] | None = None
    subsetRelations: list[GrantSubsetRelation] | None = None


class ChioScope(BaseModel):
    """
    What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[ToolGrant] | None = None
    prompt_grants: list[PromptGrant] | None = None
    resource_grants: list[ResourceGrant] | None = None


class AttenuationProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateFamilyPreservation: (
        aggregate_family_preservation_evidence_schema.ChioAggregateFamilyPreservationEvidence
        | None
    ) = None
    childScopeHash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    normalizedSubsetProof: AttenuationWitness
    parentScopeHash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class ChioCapabilitytoken(BaseModel):
    """
    A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_invocation_budget: (
        aggregate_invocation_budget_schema.ChioAggregateInvocationBudget | None
    ) = None
    algorithm: Algorithm | None = None
    attenuation_proof: AttenuationProof | None = None
    budget_share_bps: Annotated[
        int | None,
        Field(
            description="Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.",
            ge=0,
            le=10000,
        ),
    ] = None
    caveats: list[Caveat] | None = None
    delegation_chain: list[DelegationLink] | None = None
    expires_at: Annotated[int, Field(ge=0)]
    id: Annotated[str, Field(min_length=1)]
    issued_at: Annotated[int, Field(ge=0)]
    issuer: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
    schema_: Annotated[Literal["chio.capability.v1"], Field(alias="schema")] = (
        "chio.capability.v1"
    )
    scope: ChioScope
    scope_attenuations: list[ScopeAttenuation] | None = None
    signature: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
    subject: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
