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
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, conint, constr
from . import active_response_governed_intent_schema

class AgentGovernedTransactionIntentMaxAmount(BaseModel):
    model_config = ConfigDict(extra='forbid')
    units: conint(ge=0)
    currency: constr(min_length=1)

class AgentGovernedTransactionIntentBodyToolInvocation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['tool_invocation']

class AgentGovernedTransactionIntentBodyActiveResponsePlan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['active_response_plan']
    value: active_response_governed_intent_schema.ChioGovernedActiveResponseIntentBody

class AgentGovernedTransactionIntentDefinitionsBoundToolInvocationBinding(BaseModel):
    model_config = ConfigDict(extra='forbid')
    capability_id: constr(min_length=1)
    parameters_hash: constr(pattern='^0x[0-9a-f]{64}$') = Field(..., description='SHA-256 of RFC 8785 canonical tool arguments, serialized as the canonical chio-core-types Hash (32 bytes, lowercase hex with 0x prefix).')

class ChioBoundToolInvocation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['bound_tool_invocation']
    value: AgentGovernedTransactionIntentDefinitionsBoundToolInvocationBinding

class ChioGovernedTransactionIntent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: constr(min_length=1)
    server_id: constr(min_length=1)
    tool_name: constr(min_length=1)
    purpose: str
    max_amount: AgentGovernedTransactionIntentMaxAmount | None = None
    commerce: dict[str, Any] | None = None
    metered_billing: dict[str, Any] | None = None
    runtime_attestation: dict[str, Any] | None = None
    call_chain: dict[str, Any] | None = None
    autonomy: dict[str, Any] | None = None
    context: Any | None = None
    body: AgentGovernedTransactionIntentBodyToolInvocation | AgentGovernedTransactionIntentBodyActiveResponsePlan | ChioBoundToolInvocation | None = None

# Public compatibility aliases reference the actual current model classes.
AgentGovernedTransactionIntentChioBoundToolInvocation = ChioBoundToolInvocation
AgentGovernedTransactionIntentChioGovernedTransactionIntent = ChioGovernedTransactionIntent
Body = AgentGovernedTransactionIntentBodyToolInvocation
Body4 = AgentGovernedTransactionIntentBodyActiveResponsePlan
Body5 = ChioBoundToolInvocation
BoundToolInvocationBinding = AgentGovernedTransactionIntentDefinitionsBoundToolInvocationBinding
MaxAmount = AgentGovernedTransactionIntentMaxAmount
