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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class RecoveryTransportRequestV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    capability: constr(min_length=1, max_length=32768)
    command: constr(min_length=1, max_length=32768)

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryTransportRequestDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryTransportRequestDefinitionsRefusalCode(Enum):
    invalid_evidence = 'invalid_evidence'
    unsupported_profile = 'unsupported_profile'
    stale_basis = 'stale_basis'
    revoked = 'revoked'
    expired = 'expired'
    budget_unavailable = 'budget_unavailable'
    unknown_effect = 'unknown_effect'
    audience_denied = 'audience_denied'
    resource_exhausted = 'resource_exhausted'

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class RecoveryEffectNeverAdmittedV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['never_admitted']

class RecoveryEffectAdmissionUnresolvedV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['admission_unresolved']
    admission_intent: OpaqueId

class RecoveryTransportRequestDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['closed_before_effect']
    operation: RecoveryTransportRequestDefinitionsOperation
    closure: OpaqueId

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryTransportRequestDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryTransportRequestDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryTransportRequestDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryTransportRequestDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['complete']
    operation: RecoveryTransportRequestDefinitionsOperation
    effect_count: SafeInteger

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['partial']
    operation: RecoveryTransportRequestDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['failed_after_effect']
    operation: RecoveryTransportRequestDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

# Public compatibility aliases reference the actual current model classes.
Operation = RecoveryTransportRequestDefinitionsOperation
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryTransportRequestOpaqueId = OpaqueId
RecoveryTransportRequestRecoveryDigest32 = RecoveryDigest32
RecoveryTransportRequestRecoveryDigestOctet = RecoveryDigestOctet
RecoveryTransportRequestRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryTransportRequestRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryTransportRequestRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryTransportRequestRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryTransportRequestRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryTransportRequestRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryTransportRequestRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryTransportRequestRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryTransportRequestRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryTransportRequestRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryTransportRequestSafeInteger = SafeInteger
RefusalCode = RecoveryTransportRequestDefinitionsRefusalCode
Scope = RecoveryTransportRequestDefinitionsScope
