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

class RecoveryExplanationReportLimits(BaseModel):
    model_config = ConfigDict(extra='forbid')
    offers: conint(ge=1, le=16)
    work: conint(ge=2, le=4096)

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryExplanationReportDefinitionsScope(BaseModel):
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

class RecoveryExplanationReportDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryExplanationReportDefinitionsRefusalCode(Enum):
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
    operation: RecoveryExplanationReportDefinitionsOperation
    closure: OpaqueId

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryExplanationReportDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryExplanationReportDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryExplanationReportDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryExplanationReportDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['complete']
    operation: RecoveryExplanationReportDefinitionsOperation
    effect_count: SafeInteger

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['partial']
    operation: RecoveryExplanationReportDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['failed_after_effect']
    operation: RecoveryExplanationReportDefinitionsOperation
    applied_effects: conint(ge=1, le=9007199254740991)

class RecoveryExplanationReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.recovery.explanation-report.v1'] = Field(..., alias='schema')
    version: Literal[1]
    scope: RecoveryExplanationReportDefinitionsScope
    deployment_digest: RecoveryDigest32
    policy_digest: RecoveryDigest32
    contract_digest: RecoveryDigest32
    planner_version: Literal['chio.recovery.planner.v1']
    trust_domain: OpaqueId
    issuer: OpaqueId
    snapshot_digest: RecoveryDigest32
    registry_digest: RecoveryDigest32
    intent_digest: RecoveryDigest32
    evaluation_digest: RecoveryDigest32
    projection_digest: RecoveryDigest32
    protected_graph_ref: OpaqueId
    recipient: OpaqueId
    limits: RecoveryExplanationReportLimits
    issued_at_unix_ms: SafeInteger
    expires_at_unix_ms: SafeInteger

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
Limits = RecoveryExplanationReportLimits
Operation = RecoveryExplanationReportDefinitionsOperation
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryExplanationReportDestinationId = DestinationId
RecoveryExplanationReportOpaqueId = OpaqueId
RecoveryExplanationReportRecoveryDigest32 = RecoveryDigest32
RecoveryExplanationReportRecoveryDigestOctet = RecoveryDigestOctet
RecoveryExplanationReportRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryExplanationReportRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryExplanationReportRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryExplanationReportRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryExplanationReportRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryExplanationReportRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryExplanationReportRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryExplanationReportRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryExplanationReportRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryExplanationReportRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryExplanationReportSafeInteger = SafeInteger
RefusalCode = RecoveryExplanationReportDefinitionsRefusalCode
Scope = RecoveryExplanationReportDefinitionsScope
