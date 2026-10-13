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

class RecoveryObservationReleaseNotAvailable(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['not_available']

class RecoveryObservationControl(Enum):
    active = 'active'
    cancel_requested = 'cancel_requested'
    cancelled = 'cancelled'
    quarantined = 'quarantined'

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryObservationDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryObservationDefinitionsRefusalCode(Enum):
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

class RecoveryObservationReleasePending(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['pending']
    release_id: OpaqueId

class RecoveryObservationReleaseWithheld(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['withheld']
    evidence: OpaqueId

class RecoveryObservationReleaseReleased(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['released']
    release_id: OpaqueId

class RecoveryObservationReleaseDenied(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['denied']
    reason: RecoveryObservationDefinitionsRefusalCode

class RecoveryObservationDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['closed_before_effect']
    operation: RecoveryObservationDefinitionsOperation
    closure: OpaqueId

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryObservationDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryObservationDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryObservationDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryObservationDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['complete']
    operation: RecoveryObservationDefinitionsOperation
    effect_count: SafeInteger

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['partial']
    operation: RecoveryObservationDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['failed_after_effect']
    operation: RecoveryObservationDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryObservationV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.recovery.observation.v1'] = Field(..., alias='schema')
    version: Literal[1]
    scope: RecoveryObservationDefinitionsScope
    workflow_id: OpaqueId
    step_id: OpaqueId
    continuation_id: OpaqueId
    revision: SafeInteger
    effect: RecoveryEffectNeverAdmittedV1 | RecoveryEffectAdmissionUnresolvedV1 | RecoveryEffectClosedBeforeEffectV1 | RecoveryEffectAwaitingApprovalV1 | RecoveryEffectInFlightV1 | RecoveryEffectAwaitingCallerReportV1 | RecoveryEffectUnknownV1 | RecoveryEffectCompleteV1 | RecoveryEffectPartialV1 | RecoveryEffectFailedAfterEffectV1
    release: RecoveryObservationReleaseNotAvailable | RecoveryObservationReleasePending | RecoveryObservationReleaseWithheld | RecoveryObservationReleaseReleased | RecoveryObservationReleaseDenied
    control: RecoveryObservationControl
    knowledge_digest: RecoveryDigest32

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
Control = RecoveryObservationControl
Operation = RecoveryObservationDefinitionsOperation
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryObservationOpaqueId = OpaqueId
RecoveryObservationRecoveryDigest32 = RecoveryDigest32
RecoveryObservationRecoveryDigestOctet = RecoveryDigestOctet
RecoveryObservationRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryObservationRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryObservationRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryObservationRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryObservationRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryObservationRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryObservationRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryObservationRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryObservationRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryObservationRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryObservationSafeInteger = SafeInteger
RefusalCode = RecoveryObservationDefinitionsRefusalCode
Release = RecoveryObservationReleaseNotAvailable
Release6 = RecoveryObservationReleasePending
Release7 = RecoveryObservationReleaseWithheld
Release8 = RecoveryObservationReleaseReleased
Release9 = RecoveryObservationReleaseDenied
Scope = RecoveryObservationDefinitionsScope
