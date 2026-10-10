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
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class CapabilityGrantDefinitionsOperation(Enum):
    invoke = 'invoke'
    read_result = 'read_result'
    read = 'read'
    subscribe = 'subscribe'
    get = 'get'
    delegate = 'delegate'

class CapabilityGrantDefinitionsMonetaryAmount(BaseModel):
    """
    A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.
    """
    model_config = ConfigDict(extra='forbid')
    units: conint(ge=0)
    currency: constr(min_length=1)

class CapabilityGrantDefinitionsConstraint(BaseModel):
    """
    Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.
    """
    type: constr(min_length=1)
    value: Any | None = None

class CapabilityGrantDefinitionsToolGrant(BaseModel):
    """
    Authorization to invoke a single tool. Mirrors `ToolGrant`.
    """
    model_config = ConfigDict(extra='forbid')
    server_id: constr(min_length=1) = Field(..., description='Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).')
    tool_name: constr(min_length=1) = Field(..., description='Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).')
    operations: list[CapabilityGrantDefinitionsOperation] = Field(..., min_length=1)
    constraints: list[CapabilityGrantDefinitionsConstraint] | None = None
    max_invocations: conint(ge=0) | None = None
    max_cost_per_invocation: CapabilityGrantDefinitionsMonetaryAmount | None = None
    max_total_cost: CapabilityGrantDefinitionsMonetaryAmount | None = None
    dpop_required: bool | None = Field(None, description='If true, the kernel requires a valid DPoP proof for every invocation under this grant.')

class CapabilityGrantDefinitionsResourceGrant(BaseModel):
    """
    Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
    """
    model_config = ConfigDict(extra='forbid')
    uri_pattern: constr(min_length=1)
    operations: list[CapabilityGrantDefinitionsOperation] = Field(..., min_length=1)

class CapabilityGrantDefinitionsPromptGrant(BaseModel):
    """
    Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
    """
    model_config = ConfigDict(extra='forbid')
    prompt_name: constr(min_length=1)
    operations: list[CapabilityGrantDefinitionsOperation] = Field(..., min_length=1)

class ChioCapabilityGrant(RootModel[CapabilityGrantDefinitionsToolGrant | CapabilityGrantDefinitionsResourceGrant | CapabilityGrantDefinitionsPromptGrant]):
    root: CapabilityGrantDefinitionsToolGrant | CapabilityGrantDefinitionsResourceGrant | CapabilityGrantDefinitionsPromptGrant = Field(..., description="A single grant carried inside a capability token's `scope`. Chio uses three distinct grant kinds (tool, resource, prompt) that share no common discriminator field; this schema accepts any one of them via `oneOf`. Mirrors `ToolGrant`, `ResourceGrant`, and `PromptGrant` in `crates/core/chio-core-types/src/capability/scope.rs`. The wrapper `ChioScope` partitions grants into three named arrays (`grants`, `resource_grants`, `prompt_grants`); validators that consume a token can dispatch to the appropriate `$defs/*` shape directly without relying on `oneOf` matching.", title='Chio Capability Grant')

# Public compatibility aliases reference the actual current model classes.
CapabilityGrantChioCapabilityGrant = ChioCapabilityGrant
Constraint = CapabilityGrantDefinitionsConstraint
MonetaryAmount = CapabilityGrantDefinitionsMonetaryAmount
Operation = CapabilityGrantDefinitionsOperation
PromptGrant = CapabilityGrantDefinitionsPromptGrant
ResourceGrant = CapabilityGrantDefinitionsResourceGrant
ToolGrant = CapabilityGrantDefinitionsToolGrant
