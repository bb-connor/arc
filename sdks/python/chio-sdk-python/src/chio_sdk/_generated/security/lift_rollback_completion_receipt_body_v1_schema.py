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
from . import effect_transition_receipt_body_v1_schema, response_completion_receipt_body_v1_schema, response_state_transition_receipt_body_v1_schema
from .response_state_transition_receipt_body_v1_schema import SecurityResponseStateTransitionReceiptBodyV1DefinitionsHeader

class SecurityLiftRollbackCompletionReceiptBodyV1FinalState(Enum):
    lifted = 'lifted'
    rollback_partial = 'rollback_partial'

class SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomePlanned(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['planned']

class SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeNoRollbackRequired(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['no_rollback_required']

class Header(SecurityResponseStateTransitionReceiptBodyV1DefinitionsHeader):
    prior_receipt_ids: list | None = Field(None, max_length=1)

class SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeApplyFailed(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['apply_failed']
    error_code: response_state_transition_receipt_body_v1_schema.Identifier

class SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeRestored(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['restored']
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest

class SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeRollbackFailed(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['rollback_failed']
    error_code: response_state_transition_receipt_body_v1_schema.Identifier

class LiftOutcome(RootModel[SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomePlanned | SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeApplyFailed | SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeRestored | SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeRollbackFailed | SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeNoRollbackRequired]):
    root: SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomePlanned | SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeApplyFailed | SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeRestored | SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeRollbackFailed | SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeNoRollbackRequired

class SecurityLiftRollbackCompletionReceiptBodyV1EffectsItems(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect: effect_transition_receipt_body_v1_schema.SecurityEffectTransitionReceiptBodyV1DefinitionsEffect
    outcome: LiftOutcome

class ChioLiftOrRollbackCompletionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    header: Header
    response: response_state_transition_receipt_body_v1_schema.SecurityResponseStateTransitionReceiptBodyV1DefinitionsResponse
    execution_dispatch: response_completion_receipt_body_v1_schema.SecurityResponseCompletionReceiptBodyV1DefinitionsExecutionDispatch | None = None
    dispatch_authorization_hash: response_state_transition_receipt_body_v1_schema.Digest | None = None
    response_generation: conint(ge=1, le=9007199254740991)
    response_body_hash: response_state_transition_receipt_body_v1_schema.Digest
    final_state: SecurityLiftRollbackCompletionReceiptBodyV1FinalState
    effects: list[SecurityLiftRollbackCompletionReceiptBodyV1EffectsItems] = Field(..., max_length=64, min_length=1)

# Public compatibility aliases reference the actual current model classes.
Effect = SecurityLiftRollbackCompletionReceiptBodyV1EffectsItems
FinalState = SecurityLiftRollbackCompletionReceiptBodyV1FinalState
LiftOutcome1 = SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomePlanned
LiftOutcome2 = SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeApplyFailed
LiftOutcome3 = SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeRestored
LiftOutcome4 = SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeRollbackFailed
LiftOutcome5 = SecurityLiftRollbackCompletionReceiptBodyV1DefinitionsLiftOutcomeNoRollbackRequired
SecurityLiftRollbackCompletionReceiptBodyV1ChioLiftOrRollbackCompletionReceiptBodyV1 = ChioLiftOrRollbackCompletionReceiptBodyV1
SecurityLiftRollbackCompletionReceiptBodyV1Header = Header
SecurityLiftRollbackCompletionReceiptBodyV1LiftOutcome = LiftOutcome
