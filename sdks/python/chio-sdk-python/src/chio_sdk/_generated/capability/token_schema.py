# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 35f8e30cf30553986a159b074ee485804a85db29547a8102522cd7bfa3080d2e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from enum import Enum
from typing import Any, Literal
from pydantic import StrictBool, BaseModel, ConfigDict, Field, RootModel, conint, constr
from . import aggregate_invocation_budget_schema, cumulative_approval_root_schema

class CapabilityTokenAlgorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class CapabilityTokenScopeAttenuationsItems(BaseModel):
    model_config = ConfigDict(extra='allow')
    type: constr(min_length=1)

class CapabilityTokenDefinitionsOperation(Enum):
    invoke = 'invoke'
    read_result = 'read_result'
    read = 'read'
    subscribe = 'subscribe'
    get = 'get'
    delegate = 'delegate'

class CapabilityTokenDefinitionsMonetaryAmount(BaseModel):
    """
    A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
    """
    model_config = ConfigDict(extra='forbid')
    units: conint(strict=True, ge=0)
    currency: constr(min_length=1)

class CapabilityTokenDefinitionsGenericConstraint(BaseModel):
    """
    Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
    """
    model_config = ConfigDict(extra='forbid')
    type: constr(min_length=1)
    value: Any | None = None

class CapabilityTokenDefinitionsLegacyApprovalConstraintValue(BaseModel):
    model_config = ConfigDict(extra='forbid')
    threshold_units: conint(strict=True, ge=0)

class CapabilityTokenDefinitionsLegacyApprovalConstraint(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['require_approval_above']
    value: CapabilityTokenDefinitionsLegacyApprovalConstraintValue

class CapabilityTokenDefinitionsCumulativeApprovalDirectConstraintValue(BaseModel):
    model_config = ConfigDict(extra='forbid')
    threshold: CapabilityTokenDefinitionsMonetaryAmount
    approval_budget_id: constr(min_length=1)
    approval_budget_epoch: conint(strict=True, ge=0)
    cumulative_approval_root_binding: Any | None = None

class CapabilityTokenDefinitionsCumulativeApprovalDirectConstraint(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['require_cumulative_approval_above']
    value: CapabilityTokenDefinitionsCumulativeApprovalDirectConstraintValue

class CapabilityTokenDefinitionsCaveatKind(Enum):
    restrict_tool = 'restrict_tool'
    bind_session = 'bind_session'
    restrict_audience = 'restrict_audience'
    restrict_geo = 'restrict_geo'
    restrict_time_window = 'restrict_time_window'
    bind_security_context = 'bind_security_context'

class CapabilityTokenDefinitionsCaveat(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: CapabilityTokenDefinitionsCaveatKind
    predicate: constr(min_length=1)
    sig: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$') | None = None

class CapabilityTokenDefinitionsDelegationLinkAttenuationsItems(BaseModel):
    model_config = ConfigDict(extra='allow')
    type: constr(min_length=1)

class CapabilityTokenDefinitionsDelegationLink(BaseModel):
    """
    A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
    """
    model_config = ConfigDict(extra='forbid')
    capability_id: constr(min_length=1)
    delegator: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+)$')
    delegatee: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+)$')
    attenuations: list[CapabilityTokenDefinitionsDelegationLinkAttenuationsItems] | None = None
    timestamp: conint(strict=True, ge=0)
    signature: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+:[0-9a-f]+)$')
    scope_hash: constr(pattern='^[0-9a-f]{64}$') = Field(..., description='RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.')

class CapabilityTokenDefinitionsGrantSubsetRelationGrantKind(Enum):
    tool = 'tool'
    resource = 'resource'
    prompt = 'prompt'

class Subset(Enum):
    boolean_True = True

class CapabilityTokenDefinitionsGrantSubsetRelation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    grantKind: CapabilityTokenDefinitionsGrantSubsetRelationGrantKind
    childIndex: conint(strict=True, ge=0)
    parentIndex: conint(strict=True, ge=0)
    subset: Subset

class CapabilityTokenDefinitionsResourceGrant(BaseModel):
    """
    Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
    """
    model_config = ConfigDict(extra='forbid')
    uri_pattern: constr(min_length=1)
    operations: list[CapabilityTokenDefinitionsOperation] = Field(..., min_length=1)

class CapabilityTokenDefinitionsPromptGrant(BaseModel):
    """
    Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
    """
    model_config = ConfigDict(extra='forbid')
    prompt_name: constr(min_length=1)
    operations: list[CapabilityTokenDefinitionsOperation] = Field(..., min_length=1)

class CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraintValue(BaseModel):
    model_config = ConfigDict(extra='forbid')
    threshold: CapabilityTokenDefinitionsMonetaryAmount
    approval_budget_id: constr(min_length=1)
    approval_budget_epoch: conint(strict=True, ge=0)
    cumulative_approval_root_binding: cumulative_approval_root_schema.ChioCumulativeApprovalRootBinding

class CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraint(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['require_cumulative_approval_above']
    value: CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraintValue

class CapabilityTokenDefinitionsAttenuationWitness(BaseModel):
    model_config = ConfigDict(extra='forbid')
    normalizedParentScope: constr(min_length=2)
    normalizedChildScope: constr(min_length=2)
    subsetRelations: list[CapabilityTokenDefinitionsGrantSubsetRelation] | None = None
    restrictedPredicates: list[str] | None = None

class Constraint(RootModel[CapabilityTokenDefinitionsGenericConstraint | CapabilityTokenDefinitionsLegacyApprovalConstraint | CapabilityTokenDefinitionsCumulativeApprovalDirectConstraint | CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraint]):
    root: CapabilityTokenDefinitionsGenericConstraint | CapabilityTokenDefinitionsLegacyApprovalConstraint | CapabilityTokenDefinitionsCumulativeApprovalDirectConstraint | CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraint

    @property
    def type(self) -> str:
        return self.root.type

    @property
    def value(self) -> Any:
        return self.root.value

class CapabilityTokenDefinitionsAttenuationProof(BaseModel):
    model_config = ConfigDict(extra='forbid')
    parentScopeHash: constr(pattern='^[0-9a-f]{64}$')
    childScopeHash: constr(pattern='^[0-9a-f]{64}$')
    normalizedSubsetProof: CapabilityTokenDefinitionsAttenuationWitness

class CapabilityTokenDefinitionsToolGrant(BaseModel):
    """
    Authorization to invoke a single tool. Mirrors `ToolGrant`.
    """
    model_config = ConfigDict(extra='forbid')
    server_id: constr(min_length=1)
    tool_name: constr(min_length=1)
    operations: list[CapabilityTokenDefinitionsOperation] = Field(..., min_length=1)
    constraints: list[Constraint] | None = None
    max_invocations: conint(strict=True, ge=0) | None = None
    max_cost_per_invocation: CapabilityTokenDefinitionsMonetaryAmount | None = None
    max_total_cost: CapabilityTokenDefinitionsMonetaryAmount | None = None
    dpop_required: StrictBool | None = None

class CapabilityTokenDefinitionsChioScope(BaseModel):
    """
    What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
    """
    model_config = ConfigDict(extra='forbid')
    grants: list[CapabilityTokenDefinitionsToolGrant] | None = None
    resource_grants: list[CapabilityTokenDefinitionsResourceGrant] | None = None
    prompt_grants: list[CapabilityTokenDefinitionsPromptGrant] | None = None

class ChioCapabilityToken(BaseModel):
    """
    A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
    """
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.capability.v1'] = Field('chio.capability.v1', alias='schema')
    id: constr(min_length=1)
    issuer: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')
    subject: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')
    scope: CapabilityTokenDefinitionsChioScope
    issued_at: conint(strict=True, ge=0)
    expires_at: conint(strict=True, ge=0)
    delegation_chain: list[CapabilityTokenDefinitionsDelegationLink] | None = None
    aggregate_invocation_budget: aggregate_invocation_budget_schema.ChioAggregateInvocationBudget | None = None
    algorithm: CapabilityTokenAlgorithm | None = None
    caveats: list[CapabilityTokenDefinitionsCaveat] | None = None
    scope_attenuations: list[CapabilityTokenScopeAttenuationsItems] | None = None
    attenuation_proof: CapabilityTokenDefinitionsAttenuationProof | None = None
    budget_share_bps: conint(strict=True, ge=0, le=10000) | None = Field(None, description='Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.')
    signature: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

# Public compatibility aliases reference the actual current model classes.
Algorithm = CapabilityTokenAlgorithm
Attenuation = CapabilityTokenDefinitionsDelegationLinkAttenuationsItems
AttenuationProof = CapabilityTokenDefinitionsAttenuationProof
AttenuationWitness = CapabilityTokenDefinitionsAttenuationWitness
CapabilityTokenChioCapabilityToken = ChioCapabilityToken
CapabilityTokenConstraint = Constraint
CapabilityTokenSubset = Subset
Caveat = CapabilityTokenDefinitionsCaveat
ChioCapabilitytoken = ChioCapabilityToken
ChioScope = CapabilityTokenDefinitionsChioScope
CumulativeApprovalDelegableConstraint = CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraint
CumulativeApprovalDirectConstraint = CapabilityTokenDefinitionsCumulativeApprovalDirectConstraint
DelegationLink = CapabilityTokenDefinitionsDelegationLink
GenericConstraint = CapabilityTokenDefinitionsGenericConstraint
GrantKind = CapabilityTokenDefinitionsGrantSubsetRelationGrantKind
GrantSubsetRelation = CapabilityTokenDefinitionsGrantSubsetRelation
Kind = CapabilityTokenDefinitionsCaveatKind
LegacyApprovalConstraint = CapabilityTokenDefinitionsLegacyApprovalConstraint
MonetaryAmount = CapabilityTokenDefinitionsMonetaryAmount
Operation = CapabilityTokenDefinitionsOperation
PromptGrant = CapabilityTokenDefinitionsPromptGrant
ResourceGrant = CapabilityTokenDefinitionsResourceGrant
ScopeAttenuation = CapabilityTokenScopeAttenuationsItems
ToolGrant = CapabilityTokenDefinitionsToolGrant
Value = CapabilityTokenDefinitionsLegacyApprovalConstraintValue
Value1 = CapabilityTokenDefinitionsCumulativeApprovalDirectConstraintValue
Value2 = CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraintValue
