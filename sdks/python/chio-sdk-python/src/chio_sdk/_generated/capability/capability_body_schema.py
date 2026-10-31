# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..root_authority import root_anchor_schema


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_capability_hash: str
    root_capability_id: str
    root_expires_at: int
    root_issuer: str
    root_scope_hash: str
    root_subject: str
    schema_: str = Field(..., alias="schema")


class RootBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str


class AggregateInvocationBudget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding: RootBinding
    scope: str


class Binding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_budget_epoch: int
    approval_budget_id: str
    currency: str
    root_binding_digest: str


class CumulativeApproval(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bindings: list[Binding]


class SubsetRelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childIndex: int
    grantKind: str
    parentIndex: int
    subset: bool


class NormalizedSubsetProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cumulativeApproval: CumulativeApproval | None = None
    normalizedChildScope: str
    normalizedParentScope: str
    restrictedPredicates: list[str]
    subsetRelations: list[SubsetRelation]


class AttenuationProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childScopeHash: str
    normalizedSubsetProof: NormalizedSubsetProof
    parentScopeHash: str


class AggregateBudget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding_digest: str


class Constraint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: str
    value: int


class Attenuation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    constraint: Constraint | None = None
    max_invocations: int | None = None
    server_id: str
    tool_name: str
    type: str


class CumulativeApproval1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bindings: list[Binding]


class DelegationChainItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_budget: AggregateBudget | None = None
    attenuations: list[Attenuation] | None = None
    capability_id: str
    cumulative_approval: CumulativeApproval1 | None = None
    delegatee: str
    delegator: str
    scope_hash: str | None = None
    signature: str
    timestamp: int


class Threshold(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body21(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_budget_epoch: int
    approval_budget_id: str
    root_capability_hash: str
    root_capability_id: str
    root_expires_at: int
    root_grant_hash: str
    root_issuer: str
    root_scope_hash: str
    root_subject: str
    schema_: str = Field(..., alias="schema")
    signer_key_epoch: int
    threshold: Threshold


class CumulativeApprovalRootBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body21
    signature: str


class Settlement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    mode: str


class Value(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowed_model_ids: list[str] | None = None
    approval_budget_epoch: int | None = None
    approval_budget_id: str | None = None
    cumulative_approval_root_binding: CumulativeApprovalRootBinding | None = None
    finding_id: str | None = None
    listing_id: str | None = None
    max_recoveries: int | None = None
    min_safety_tier: str | None = None
    original_capability_id: str | None = None
    original_delivery_receipt_id: str | None = None
    purchase_key: str | None = None
    recovery_id: str | None = None
    settlement: Settlement | None = None
    threshold: Threshold | None = None
    threshold_units: int | None = None


class Constraint2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: str
    value: int | str | Value | None = None


class MaxCostPerInvocation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MaxTotalCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Grant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    constraints: list[Constraint2] | None = None
    dpop_required: bool | None = None
    max_cost_per_invocation: MaxCostPerInvocation | None = None
    max_invocations: int | None = None
    max_total_cost: MaxTotalCost | None = None
    operations: list[str]
    server_id: str
    tool_name: str


class PromptGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operations: list[str]
    prompt_name: str


class ResourceGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operations: list[str]
    uri_pattern: str


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant] | None = None
    prompt_grants: list[PromptGrant] | None = None
    resource_grants: list[ResourceGrant] | None = None


class ScopeAttenuation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation: str
    server_id: str
    tool_name: str
    type: str


class ChioCapabilityV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_invocation_budget: AggregateInvocationBudget | None = None
    attenuation_proof: AttenuationProof | None = None
    budget_share_bps: int | None = None
    delegation_chain: list[DelegationChainItem] | None = None
    expires_at: int | None = None
    fixture: str | None = None
    id: str | None = None
    issued_at: int | None = None
    issuer: str | None = None
    n: int | None = None
    root_anchor: root_anchor_schema.ChioRootAnchor | None = None
    schema_: Literal["chio.capability.v1"] = Field("chio.capability.v1", alias="schema")
    scope: Scope | None = None
    scope_attenuations: list[ScopeAttenuation] | None = None
    subject: str | None = None
