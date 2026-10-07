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
from . import response_state_transition_receipt_body_v1_schema
from .response_state_transition_receipt_body_v1_schema import SecurityResponseStateTransitionReceiptBodyV1DefinitionsHeader

class JsonSafePositiveInteger(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)

class SecurityEffectTransitionReceiptBodyV1DefinitionsKind(Enum):
    escalate_alert = 'escalate_alert'
    throttle_session = 'throttle_session'
    restrict_egress = 'restrict_egress'
    suspend_session = 'suspend_session'
    suspend_capability_set = 'suspend_capability_set'
    freeze_issuance = 'freeze_issuance'

class SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRequested(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['requested']

class SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRollbackRequested(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['rollback_requested']

class Header(SecurityResponseStateTransitionReceiptBodyV1DefinitionsHeader):
    prior_receipt_ids: list | None = Field(None, max_length=1)

class SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant0(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_type: Literal['tenant']
    tenant_id: response_state_transition_receipt_body_v1_schema.Identifier

class SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_type: Literal['session']
    session_id: response_state_transition_receipt_body_v1_schema.Identifier

class SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant2(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_type: Literal['lineage']
    lineage_id: response_state_transition_receipt_body_v1_schema.Identifier

class SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant3(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_type: Literal['capability_set']
    affected_set_hash: response_state_transition_receipt_body_v1_schema.Digest

class Target(RootModel[SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant0 | SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant1 | SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant2 | SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant3]):
    root: SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant0 | SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant1 | SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant2 | SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant3

class SecurityEffectTransitionReceiptBodyV1DefinitionsEffect(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect_id: response_state_transition_receipt_body_v1_schema.Identifier
    ordinal: conint(ge=0, le=65535)
    kind: SecurityEffectTransitionReceiptBodyV1DefinitionsKind
    target: Target
    contribution_hash: response_state_transition_receipt_body_v1_schema.Digest
    observed_base_version_hash: response_state_transition_receipt_body_v1_schema.Digest

class SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeApplied(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['applied']
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest

class SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeApplyFailed(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['apply_failed']
    error_code: response_state_transition_receipt_body_v1_schema.Identifier

class SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRestored(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['restored']
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest

class SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRollbackFailed(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state: Literal['rollback_failed']
    error_code: response_state_transition_receipt_body_v1_schema.Identifier

class Outcome(RootModel[SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRequested | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeApplied | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeApplyFailed | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRollbackRequested | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRestored | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRollbackFailed]):
    root: SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRequested | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeApplied | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeApplyFailed | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRollbackRequested | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRestored | SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRollbackFailed

class ChioEffectTransitionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    header: Header
    response: response_state_transition_receipt_body_v1_schema.SecurityResponseStateTransitionReceiptBodyV1DefinitionsResponse
    effect: SecurityEffectTransitionReceiptBodyV1DefinitionsEffect
    generation: JsonSafePositiveInteger
    scheduler_lease_owner_id: response_state_transition_receipt_body_v1_schema.Identifier | None = None
    scheduler_fencing_token: JsonSafePositiveInteger
    outcome: Outcome

# Public compatibility aliases reference the actual current model classes.
Effect = SecurityEffectTransitionReceiptBodyV1DefinitionsEffect
Kind = SecurityEffectTransitionReceiptBodyV1DefinitionsKind
Outcome1 = SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRequested
Outcome2 = SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeApplied
Outcome3 = SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeApplyFailed
Outcome4 = SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRollbackRequested
Outcome5 = SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRestored
Outcome6 = SecurityEffectTransitionReceiptBodyV1DefinitionsOutcomeRollbackFailed
SecurityEffectTransitionReceiptBodyV1ChioEffectTransitionReceiptBodyV1 = ChioEffectTransitionReceiptBodyV1
SecurityEffectTransitionReceiptBodyV1Header = Header
SecurityEffectTransitionReceiptBodyV1JsonSafePositiveInteger = JsonSafePositiveInteger
SecurityEffectTransitionReceiptBodyV1Outcome = Outcome
SecurityEffectTransitionReceiptBodyV1Target = Target
Target1 = SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant0
Target2 = SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant1
Target3 = SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant2
Target4 = SecurityEffectTransitionReceiptBodyV1DefinitionsTargetVariant3
