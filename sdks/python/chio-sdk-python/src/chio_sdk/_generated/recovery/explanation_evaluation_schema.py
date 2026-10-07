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
from ..security import information_label_schema
from pydantic import field_validator as _facet_field_validator

class RecoveryExplanationEvaluationAssessment(Enum):
    feasible_under_snapshot = 'feasible_under_snapshot'
    requires_exact_approval = 'requires_exact_approval'
    requires_transformation = 'requires_transformation'
    requires_prerequisite = 'requires_prerequisite'
    needs_fresh_evidence = 'needs_fresh_evidence'
    blocked_by_capability = 'blocked_by_capability'
    unknown_outcome = 'unknown_outcome'
    no_registered_remedy = 'no_registered_remedy'
    search_bound_reached = 'search_bound_reached'

class DestinationId(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

    @_facet_field_validator('root', mode='after')
    @classmethod
    def _require_root_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

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

class RecoveryExplanationEvaluationDefinitionsRefusalCode(Enum):
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

class RecoveryExplanationEvaluationDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryExplanationEvaluationCandidatesItems(BaseModel):
    model_config = ConfigDict(extra='forbid')
    assessment: RecoveryExplanationEvaluationAssessment
    template_id: OpaqueId

class RecoveryExplanationEvaluationDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    native_admission_digest: RecoveryDigest32
    operation_id: OpaqueId
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryExplanationEvaluationDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryExplanationEvaluationDefinitionsOperation

class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    closure: OpaqueId
    kind: Literal['closed_before_effect']
    operation: RecoveryExplanationEvaluationDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect_count: SafeInteger
    kind: Literal['complete']
    operation: RecoveryExplanationEvaluationDefinitionsOperation

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal['failed_after_effect']
    operation: RecoveryExplanationEvaluationDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryExplanationEvaluationDefinitionsOperation

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal['partial']
    operation: RecoveryExplanationEvaluationDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryExplanationEvaluationDefinitionsOperation

class RecoveryExplanationEvaluationV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    assessment: RecoveryExplanationEvaluationAssessment
    candidates: list[RecoveryExplanationEvaluationCandidatesItems] = Field(..., max_length=16)
    classification: information_label_schema.InformationLabel
    complete: bool
    planner_version: Literal['chio.recovery.planner.v1']
    work_used: conint(ge=0, le=4096)

# Public compatibility aliases reference the actual current model classes.
Assessment = RecoveryExplanationEvaluationAssessment
Candidate = RecoveryExplanationEvaluationCandidatesItems
Operation = RecoveryExplanationEvaluationDefinitionsOperation
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryExplanationEvaluationDestinationId = DestinationId
RecoveryExplanationEvaluationOpaqueId = OpaqueId
RecoveryExplanationEvaluationRecoveryDigest32 = RecoveryDigest32
RecoveryExplanationEvaluationRecoveryDigestOctet = RecoveryDigestOctet
RecoveryExplanationEvaluationRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryExplanationEvaluationRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryExplanationEvaluationRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryExplanationEvaluationRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryExplanationEvaluationRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryExplanationEvaluationRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryExplanationEvaluationRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryExplanationEvaluationRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryExplanationEvaluationRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryExplanationEvaluationRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryExplanationEvaluationSafeInteger = SafeInteger
RefusalCode = RecoveryExplanationEvaluationDefinitionsRefusalCode
Scope = RecoveryExplanationEvaluationDefinitionsScope
