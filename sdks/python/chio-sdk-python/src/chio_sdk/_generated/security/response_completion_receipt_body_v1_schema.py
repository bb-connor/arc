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
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint
from . import effect_transition_receipt_body_v1_schema, response_state_transition_receipt_body_v1_schema
from .response_state_transition_receipt_body_v1_schema import SecurityResponseStateTransitionReceiptBodyV1DefinitionsHeader

class SecurityResponseCompletionReceiptBodyV1FinalState(Enum):
    active = 'active'
    apply_partial = 'apply_partial'
    failed = 'failed'

class SecurityResponseCompletionReceiptBodyV1DefinitionsDispatchApprovalVariant0(BaseModel):
    model_config = ConfigDict(extra='forbid')
    approval_mode: Literal['automatic']

class SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomePlanned(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['planned']

class Header(SecurityResponseStateTransitionReceiptBodyV1DefinitionsHeader):
    prior_receipt_ids: list | None = Field(None, max_length=1)

class SecurityResponseCompletionReceiptBodyV1DefinitionsDispatchApprovalVariant1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    approval_mode: Literal['governed']
    admission_operation_id: response_state_transition_receipt_body_v1_schema.Identifier
    admission_operation_version: conint(ge=1, le=9007199254740991)
    approval_set_hash: response_state_transition_receipt_body_v1_schema.Digest

class DispatchApproval(RootModel[SecurityResponseCompletionReceiptBodyV1DefinitionsDispatchApprovalVariant0 | SecurityResponseCompletionReceiptBodyV1DefinitionsDispatchApprovalVariant1]):
    root: SecurityResponseCompletionReceiptBodyV1DefinitionsDispatchApprovalVariant0 | SecurityResponseCompletionReceiptBodyV1DefinitionsDispatchApprovalVariant1

class SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomeApplied(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['applied']
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest

class SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomeApplyFailed(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['apply_failed']
    error_code: response_state_transition_receipt_body_v1_schema.Identifier

class CompletionOutcome(RootModel[SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomePlanned | SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomeApplied | SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomeApplyFailed]):
    root: SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomePlanned | SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomeApplied | SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomeApplyFailed

class SecurityResponseCompletionReceiptBodyV1EffectsItems(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect: effect_transition_receipt_body_v1_schema.SecurityEffectTransitionReceiptBodyV1DefinitionsEffect
    outcome: CompletionOutcome

class SecurityResponseCompletionReceiptBodyV1DefinitionsExecutionDispatch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal[1]
    tenant_id: response_state_transition_receipt_body_v1_schema.Identifier
    dispatch_id: response_state_transition_receipt_body_v1_schema.Identifier
    action_id: response_state_transition_receipt_body_v1_schema.Identifier
    plan_hash: response_state_transition_receipt_body_v1_schema.Digest
    executor_authority_id: response_state_transition_receipt_body_v1_schema.Identifier
    executor_authority_generation: conint(ge=1, le=9007199254740991)
    authorization_capability_hash: response_state_transition_receipt_body_v1_schema.Digest
    governed_intent_hash: response_state_transition_receipt_body_v1_schema.Digest
    policy_decision_hash: response_state_transition_receipt_body_v1_schema.Digest
    approval: DispatchApproval
    authorized_at_unix_ms: conint(ge=1, le=9007199254740991)

class ChioResponseCompletionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    header: Header
    response: response_state_transition_receipt_body_v1_schema.SecurityResponseStateTransitionReceiptBodyV1DefinitionsResponse
    execution_dispatch: SecurityResponseCompletionReceiptBodyV1DefinitionsExecutionDispatch | None = None
    dispatch_authorization_hash: response_state_transition_receipt_body_v1_schema.Digest | None = None
    response_generation: conint(ge=1, le=9007199254740991)
    response_body_hash: response_state_transition_receipt_body_v1_schema.Digest
    final_state: SecurityResponseCompletionReceiptBodyV1FinalState
    error_code: response_state_transition_receipt_body_v1_schema.Identifier | None = None
    effects: list[SecurityResponseCompletionReceiptBodyV1EffectsItems] = Field(..., max_length=64, min_length=1)

# Public compatibility aliases reference the actual current model classes.
CompletionOutcome1 = SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomePlanned
CompletionOutcome2 = SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomeApplied
CompletionOutcome3 = SecurityResponseCompletionReceiptBodyV1DefinitionsCompletionOutcomeApplyFailed
DispatchApproval1 = SecurityResponseCompletionReceiptBodyV1DefinitionsDispatchApprovalVariant0
DispatchApproval2 = SecurityResponseCompletionReceiptBodyV1DefinitionsDispatchApprovalVariant1
Effect = SecurityResponseCompletionReceiptBodyV1EffectsItems
ExecutionDispatch = SecurityResponseCompletionReceiptBodyV1DefinitionsExecutionDispatch
FinalState = SecurityResponseCompletionReceiptBodyV1FinalState
SecurityResponseCompletionReceiptBodyV1ChioResponseCompletionReceiptBodyV1 = ChioResponseCompletionReceiptBodyV1
SecurityResponseCompletionReceiptBodyV1CompletionOutcome = CompletionOutcome
SecurityResponseCompletionReceiptBodyV1DispatchApproval = DispatchApproval
SecurityResponseCompletionReceiptBodyV1Header = Header
