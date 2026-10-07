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
from pydantic import field_validator as _facet_field_validator

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryExplanationRequestDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class DestinationId(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

    @_facet_field_validator('root', mode='after')
    @classmethod
    def _require_root_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

class RecoveryExplanationRequestDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryExplanationRequestDefinitionsRefusalCode(Enum):
    invalid_evidence = 'invalid_evidence'
    unsupported_profile = 'unsupported_profile'
    stale_basis = 'stale_basis'
    revoked = 'revoked'
    expired = 'expired'
    budget_unavailable = 'budget_unavailable'
    unknown_effect = 'unknown_effect'
    audience_denied = 'audience_denied'
    resource_exhausted = 'resource_exhausted'

class RecoveryEffectNeverAdmittedV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['never_admitted']

class RecoveryEffectAdmissionUnresolvedV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['admission_unresolved']
    admission_intent: OpaqueId

class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['closed_before_effect']
    operation: RecoveryExplanationRequestDefinitionsOperation
    closure: OpaqueId

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryExplanationRequestDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryExplanationRequestDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryExplanationRequestDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryExplanationRequestDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['complete']
    operation: RecoveryExplanationRequestDefinitionsOperation
    effect_count: SafeInteger

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['partial']
    operation: RecoveryExplanationRequestDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['failed_after_effect']
    operation: RecoveryExplanationRequestDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryExplanationRequestV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    capability: constr(min_length=1, max_length=32768)
    workflow_id: OpaqueId

# Public compatibility aliases reference the actual current model classes.
Operation = RecoveryExplanationRequestDefinitionsOperation
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryExplanationRequestDestinationId = DestinationId
RecoveryExplanationRequestOpaqueId = OpaqueId
RecoveryExplanationRequestRecoveryDigest32 = RecoveryDigest32
RecoveryExplanationRequestRecoveryDigestOctet = RecoveryDigestOctet
RecoveryExplanationRequestRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryExplanationRequestRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryExplanationRequestRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryExplanationRequestRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryExplanationRequestRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryExplanationRequestRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryExplanationRequestRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryExplanationRequestRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryExplanationRequestRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryExplanationRequestRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryExplanationRequestSafeInteger = SafeInteger
RefusalCode = RecoveryExplanationRequestDefinitionsRefusalCode
Scope = RecoveryExplanationRequestDefinitionsScope
