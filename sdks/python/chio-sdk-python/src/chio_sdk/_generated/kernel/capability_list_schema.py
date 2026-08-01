# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..capability import aggregate_invocation_budget_schema


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class AttenuationProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    child_scope_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    normalized_subset_proof: list[str]
    parent_scope_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Caveat(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    enforced_at: Annotated[str | None, Field(min_length=1)] = None
    kind: Annotated[str, Field(min_length=1)]
    predicate: Any


class DelegationChainItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attenuations: list[dict[str, Any]] | None = None
    capability_id: Annotated[str, Field(min_length=1)]
    delegatee: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    delegator: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    signature: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
    timestamp: Annotated[int, Field(ge=0)]


class Constraint(BaseModel):
    type: Annotated[str, Field(min_length=1)]
    value: Any | None = None


class MaxCostPerInvocation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: Annotated[str, Field(min_length=1)]
    units: Annotated[int, Field(ge=0)]


class MaxTotalCost(BaseModel):
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


class Grant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    constraints: list[Constraint] | None = None
    dpop_required: bool | None = None
    max_cost_per_invocation: MaxCostPerInvocation | None = None
    max_invocations: Annotated[int | None, Field(ge=0)] = None
    max_total_cost: MaxTotalCost | None = None
    operations: Annotated[list[Operation], Field(min_length=1)]
    server_id: Annotated[str, Field(min_length=1)]
    tool_name: Annotated[str, Field(min_length=1)]


class PromptGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operations: Annotated[list[Operation], Field(min_length=1)]
    prompt_name: Annotated[str, Field(min_length=1)]


class ResourceGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operations: Annotated[list[Operation], Field(min_length=1)]
    uri_pattern: Annotated[str, Field(min_length=1)]


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant] | None = None
    prompt_grants: list[PromptGrant] | None = None
    resource_grants: list[ResourceGrant] | None = None


class ScopeAttenuation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: Annotated[str, Field(min_length=1)]


class Capability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_invocation_budget: (
        aggregate_invocation_budget_schema.ChioAggregateInvocationBudget | None
    ) = None
    algorithm: Algorithm | None = None
    attenuation_proof: AttenuationProof | None = None
    budget_share_bps: Annotated[int | None, Field(ge=0, le=10000)] = None
    caveats: list[Caveat] | None = None
    delegation_chain: list[DelegationChainItem] | None = None
    expires_at: Annotated[int, Field(ge=0)]
    id: Annotated[str, Field(min_length=1)]
    issued_at: Annotated[int, Field(ge=0)]
    issuer: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
    schema_: Annotated[
        Literal["chio.capability.v1"],
        Field(
            alias="schema",
            description="Signed-artifact schema ID for live capability-token serialization.",
        ),
    ] = "chio.capability.v1"
    scope: Scope
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


class ChioKernelmessageCapabilityList(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilities: list[Capability]
    type: Literal["capability_list"]
