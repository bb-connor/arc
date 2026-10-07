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
from . import explanation_view_schema
from pydantic import field_validator as _facet_field_validator

class RecoverySignedExplanationViewAlgorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoverySignedExplanationViewDefinitionsScope(BaseModel):
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

class RecoverySignedExplanationViewDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)

class RecoverySignedExplanationViewDefinitionsRefusalCode(Enum):
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
    operation: RecoverySignedExplanationViewDefinitionsOperation
    closure: OpaqueId

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoverySignedExplanationViewDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoverySignedExplanationViewDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoverySignedExplanationViewDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoverySignedExplanationViewDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['complete']
    operation: RecoverySignedExplanationViewDefinitionsOperation
    effect_count: SafeInteger

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['partial']
    operation: RecoverySignedExplanationViewDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['failed_after_effect']
    operation: RecoverySignedExplanationViewDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoverySignedExplanationViewV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    body: explanation_view_schema.RecoveryExplanationViewV1
    authority_key: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')
    algorithm: RecoverySignedExplanationViewAlgorithm
    signature: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

# Public compatibility aliases reference the actual current model classes.
Algorithm = RecoverySignedExplanationViewAlgorithm
Operation = RecoverySignedExplanationViewDefinitionsOperation
RecoveryDigest32Item = RecoveryDigestOctet
RecoverySignedExplanationViewDestinationId = DestinationId
RecoverySignedExplanationViewOpaqueId = OpaqueId
RecoverySignedExplanationViewRecoveryDigest32 = RecoveryDigest32
RecoverySignedExplanationViewRecoveryDigestOctet = RecoveryDigestOctet
RecoverySignedExplanationViewRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoverySignedExplanationViewRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoverySignedExplanationViewRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoverySignedExplanationViewRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoverySignedExplanationViewRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoverySignedExplanationViewRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoverySignedExplanationViewRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoverySignedExplanationViewRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoverySignedExplanationViewRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoverySignedExplanationViewRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoverySignedExplanationViewSafeInteger = SafeInteger
RefusalCode = RecoverySignedExplanationViewDefinitionsRefusalCode
Scope = RecoverySignedExplanationViewDefinitionsScope
