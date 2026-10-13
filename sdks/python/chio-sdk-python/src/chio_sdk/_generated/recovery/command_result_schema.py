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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from ..receipt import record_schema
from . import command_response_schema

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class RecoveryEffectAdmissionUnresolvedV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    admission_intent: OpaqueId
    kind: Literal['admission_unresolved']

class RecoveryEffectNeverAdmittedV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['never_admitted']

class RecoveryCommandResultDefinitionsRefusalCode(Enum):
    invalid_evidence = 'invalid_evidence'
    unsupported_profile = 'unsupported_profile'
    stale_basis = 'stale_basis'
    revoked = 'revoked'
    expired = 'expired'
    budget_unavailable = 'budget_unavailable'
    unknown_effect = 'unknown_effect'
    audience_denied = 'audience_denied'
    resource_exhausted = 'resource_exhausted'

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryCommandResultDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryCommandResultDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    native_admission_digest: RecoveryDigest32
    operation_id: OpaqueId
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryCommandResultDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryCommandResultDefinitionsOperation

class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    closure: OpaqueId
    kind: Literal['closed_before_effect']
    operation: RecoveryCommandResultDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect_count: SafeInteger
    kind: Literal['complete']
    operation: RecoveryCommandResultDefinitionsOperation

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal['failed_after_effect']
    operation: RecoveryCommandResultDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryCommandResultDefinitionsOperation

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal['partial']
    operation: RecoveryCommandResultDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryCommandResultDefinitionsOperation

class RecoveryCommandResultOriginalResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    receipt: record_schema.ChioReceiptRecord
    result: Any

class RecoveryCommandResultV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    original_response: RecoveryCommandResultOriginalResponse | None = None
    status: command_response_schema.RecoveryCommandResponseV1

# Public compatibility aliases reference the actual current model classes.
Operation = RecoveryCommandResultDefinitionsOperation
OriginalResponse = RecoveryCommandResultOriginalResponse
RecoveryCommandResultOpaqueId = OpaqueId
RecoveryCommandResultRecoveryDigest32 = RecoveryDigest32
RecoveryCommandResultRecoveryDigestOctet = RecoveryDigestOctet
RecoveryCommandResultRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryCommandResultRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryCommandResultRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryCommandResultRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryCommandResultRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryCommandResultRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryCommandResultRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryCommandResultRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryCommandResultRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryCommandResultRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryCommandResultSafeInteger = SafeInteger
RecoveryDigest32Item = RecoveryDigestOctet
RefusalCode = RecoveryCommandResultDefinitionsRefusalCode
Scope = RecoveryCommandResultDefinitionsScope
