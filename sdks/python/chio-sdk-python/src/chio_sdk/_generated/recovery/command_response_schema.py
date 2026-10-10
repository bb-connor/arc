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

class RecoveryCommandResponseControl(Enum):
    active = 'active'
    cancel_requested = 'cancel_requested'
    cancelled = 'cancelled'
    quarantined = 'quarantined'

class RecoveryCommandResponseReleaseNotAvailable(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['not_available']

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryCommandResponseDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryCommandResponseDefinitionsRefusalCode(Enum):
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

class RecoveryCommandResponseReleasePending(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['pending']
    release_id: OpaqueId

class RecoveryCommandResponseReleaseWithheld(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['withheld']
    evidence: OpaqueId

class RecoveryCommandResponseReleaseReleased(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['released']
    release_id: OpaqueId

class RecoveryCommandResponseReleaseDenied(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['denied']
    reason: RecoveryCommandResponseDefinitionsRefusalCode

class RecoveryCommandResponseDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['closed_before_effect']
    operation: RecoveryCommandResponseDefinitionsOperation
    closure: OpaqueId

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryCommandResponseDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryCommandResponseDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryCommandResponseDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryCommandResponseDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['complete']
    operation: RecoveryCommandResponseDefinitionsOperation
    effect_count: SafeInteger

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['partial']
    operation: RecoveryCommandResponseDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['failed_after_effect']
    operation: RecoveryCommandResponseDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryCommandResponseV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    command_id: OpaqueId
    workflow_id: OpaqueId
    revision: SafeInteger
    control: RecoveryCommandResponseControl
    effect: RecoveryEffectNeverAdmittedV1 | RecoveryEffectAdmissionUnresolvedV1 | RecoveryEffectClosedBeforeEffectV1 | RecoveryEffectAwaitingApprovalV1 | RecoveryEffectInFlightV1 | RecoveryEffectAwaitingCallerReportV1 | RecoveryEffectUnknownV1 | RecoveryEffectCompleteV1 | RecoveryEffectPartialV1 | RecoveryEffectFailedAfterEffectV1
    release: RecoveryCommandResponseReleaseNotAvailable | RecoveryCommandResponseReleasePending | RecoveryCommandResponseReleaseWithheld | RecoveryCommandResponseReleaseReleased | RecoveryCommandResponseReleaseDenied

# Public compatibility aliases reference the actual current model classes.
Control = RecoveryCommandResponseControl
Operation = RecoveryCommandResponseDefinitionsOperation
RecoveryCommandResponseOpaqueId = OpaqueId
RecoveryCommandResponseRecoveryDigest32 = RecoveryDigest32
RecoveryCommandResponseRecoveryDigestOctet = RecoveryDigestOctet
RecoveryCommandResponseRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryCommandResponseRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryCommandResponseRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryCommandResponseRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryCommandResponseRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryCommandResponseRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryCommandResponseRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryCommandResponseRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryCommandResponseRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryCommandResponseRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryCommandResponseSafeInteger = SafeInteger
RecoveryDigest32Item = RecoveryDigestOctet
RefusalCode = RecoveryCommandResponseDefinitionsRefusalCode
Release = RecoveryCommandResponseReleaseNotAvailable
Release1 = RecoveryCommandResponseReleasePending
Release2 = RecoveryCommandResponseReleaseWithheld
Release3 = RecoveryCommandResponseReleaseReleased
Release4 = RecoveryCommandResponseReleaseDenied
Scope = RecoveryCommandResponseDefinitionsScope
