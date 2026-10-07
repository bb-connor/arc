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
from pydantic import field_validator
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from pydantic import field_validator as _facet_field_validator

class Template(Enum):
    support_ticket_public_issue = 'support_ticket_public_issue'

class RecoveryCommandCommandReportDecisionDecision(Enum):
    accepted = 'accepted'
    declined = 'declined'
    needs_review = 'needs_review'

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryCommandDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryCommandCommandCreateWorkflow(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['create_workflow']
    creation_key: OpaqueId
    template: Template
    request_seed: constr(min_length=1, max_length=32768)

    @_facet_field_validator('request_seed', mode='after')
    @classmethod
    def _require_request_seed_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 32768)
        return value

class RecoveryCommandCommandInspectWorkflow(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['inspect_workflow']
    workflow_id: OpaqueId

class RecoveryCommandCommandSelectOffer(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['select_offer']
    workflow_id: OpaqueId
    expected_revision: SafeInteger
    offer_id: OpaqueId

class RecoveryCommandCommandSubmitApproval(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['submit_approval']
    workflow_id: OpaqueId
    expected_revision: SafeInteger
    approval: constr(min_length=1, max_length=32768)

    @_facet_field_validator('approval', mode='after')
    @classmethod
    def _require_approval_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 32768)
        return value

class RecoveryCommandCommandResumeWorkflow(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['resume_workflow']
    workflow_id: OpaqueId
    expected_revision: SafeInteger

class RecoveryCommandCommandCancelWorkflow(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['cancel_workflow']
    workflow_id: OpaqueId
    expected_revision: SafeInteger

class RecoveryCommandCommandReportDecision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['report_decision']
    workflow_id: OpaqueId
    expected_revision: SafeInteger
    decision: RecoveryCommandCommandReportDecisionDecision

class RecoveryCommandV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.recovery.command.v1'] = Field(..., alias='schema')
    version: Literal[1]
    command_id: OpaqueId
    command: RecoveryCommandCommandCreateWorkflow | RecoveryCommandCommandInspectWorkflow | RecoveryCommandCommandSelectOffer | RecoveryCommandCommandSubmitApproval | RecoveryCommandCommandResumeWorkflow | RecoveryCommandCommandCancelWorkflow | RecoveryCommandCommandReportDecision

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
Command = RecoveryCommandCommandCreateWorkflow
Command1 = RecoveryCommandCommandInspectWorkflow
Command2 = RecoveryCommandCommandSelectOffer
Command3 = RecoveryCommandCommandSubmitApproval
Command4 = RecoveryCommandCommandResumeWorkflow
Command5 = RecoveryCommandCommandCancelWorkflow
Command6 = RecoveryCommandCommandReportDecision
Decision = RecoveryCommandCommandReportDecisionDecision
RecoveryCommandOpaqueId = OpaqueId
RecoveryCommandRecoveryDigest32 = RecoveryDigest32
RecoveryCommandRecoveryDigestOctet = RecoveryDigestOctet
RecoveryCommandSafeInteger = SafeInteger
RecoveryCommandTemplate = Template
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryCommandDefinitionsScope
