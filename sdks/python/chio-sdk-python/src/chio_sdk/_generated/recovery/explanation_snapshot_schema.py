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
from ..security import information_label_schema
from pydantic import field_validator as _facet_field_validator

class RecoveryExplanationSnapshotInfluenceObservedIntegrity(Enum):
    native_owned = 'native_owned'
    operator_verified = 'operator_verified'
    provider_verified = 'provider_verified'
    unverified = 'unverified'

class RecoveryExplanationSnapshotInfluenceUnknown(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']

class RecoveryExplanationSnapshotObservationsItemsFact(Enum):
    capability = 'capability'
    policy = 'policy'
    destination_acl = 'destination_acl'
    authority_coverage = 'authority_coverage'
    transformation = 'transformation'
    prerequisite = 'prerequisite'

class RecoveryExplanationSnapshotObservationsItemsSource(Enum):
    native_authority = 'native_authority'
    process_journal = 'process_journal'
    operator_registry = 'operator_registry'
    provider_acl = 'provider_acl'

class RecoveryExplanationSnapshotObservationsItemsStateGapReason(Enum):
    unavailable = 'unavailable'
    not_consulted = 'not_consulted'
    unsupported = 'unsupported'

class RecoveryExplanationSnapshotObservationsItemsStateGap(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['gap']
    reason: RecoveryExplanationSnapshotObservationsItemsStateGapReason

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

class RecoveryExplanationSnapshotDefinitionsRefusalCode(Enum):
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

class RecoveryExplanationSnapshotDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryExplanationSnapshotInfluenceObserved(BaseModel):
    model_config = ConfigDict(extra='forbid')
    basis: RecoveryDigest32
    integrity: RecoveryExplanationSnapshotInfluenceObservedIntegrity
    kind: Literal['observed']

class RecoveryExplanationSnapshotObservationsItemsStateKnown(BaseModel):
    model_config = ConfigDict(extra='forbid')
    evidence: OpaqueId
    kind: Literal['known']
    satisfied: bool
    version: conint(ge=1, le=9007199254740991)

class RecoveryExplanationSnapshotObservationsItemsStateFreshnessQualified(BaseModel):
    model_config = ConfigDict(extra='forbid')
    evidence: OpaqueId
    kind: Literal['freshness_qualified']
    satisfied: bool

class RecoveryExplanationSnapshotObservationsItemsTargetIntent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    intent: RecoveryDigest32
    kind: Literal['intent']

class RecoveryExplanationSnapshotObservationsItemsTargetDestination(BaseModel):
    model_config = ConfigDict(extra='forbid')
    destination: DestinationId
    kind: Literal['destination']

    @_facet_field_validator('destination', mode='after')
    @classmethod
    def _require_destination_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

class RecoveryExplanationSnapshotObservationsItemsTargetAuthority(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['authority']
    scope: RecoveryDigest32

class RecoveryExplanationSnapshotObservationsItemsTargetTemplate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['template']
    template: OpaqueId

class RecoveryExplanationSnapshotDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    native_admission_digest: RecoveryDigest32
    operation_id: OpaqueId
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryExplanationSnapshotDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryExplanationSnapshotDefinitionsOperation

class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    closure: OpaqueId
    kind: Literal['closed_before_effect']
    operation: RecoveryExplanationSnapshotDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect_count: SafeInteger
    kind: Literal['complete']
    operation: RecoveryExplanationSnapshotDefinitionsOperation

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal['failed_after_effect']
    operation: RecoveryExplanationSnapshotDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryExplanationSnapshotDefinitionsOperation

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal['partial']
    operation: RecoveryExplanationSnapshotDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryExplanationSnapshotDefinitionsOperation

class RecoveryExplanationSnapshotObservationsItems(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expires_at_unix_ms: SafeInteger
    fact: RecoveryExplanationSnapshotObservationsItemsFact
    id: OpaqueId
    integrity: RecoveryExplanationSnapshotInfluenceObservedIntegrity
    label: information_label_schema.InformationLabel
    object: OpaqueId
    observed_at_unix_ms: SafeInteger
    scope: RecoveryExplanationSnapshotDefinitionsScope
    source: RecoveryExplanationSnapshotObservationsItemsSource
    state: RecoveryExplanationSnapshotObservationsItemsStateKnown | RecoveryExplanationSnapshotObservationsItemsStateGap | RecoveryExplanationSnapshotObservationsItemsStateFreshnessQualified
    target: RecoveryExplanationSnapshotObservationsItemsTargetIntent | RecoveryExplanationSnapshotObservationsItemsTargetDestination | RecoveryExplanationSnapshotObservationsItemsTargetAuthority | RecoveryExplanationSnapshotObservationsItemsTargetTemplate

class RecoveryExplanationSnapshotV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context_label: information_label_schema.InformationLabel
    contract_digest: RecoveryDigest32
    deployment_digest: RecoveryDigest32
    effect: RecoveryEffectNeverAdmittedV1 | RecoveryEffectAdmissionUnresolvedV1 | RecoveryEffectClosedBeforeEffectV1 | RecoveryEffectAwaitingApprovalV1 | RecoveryEffectInFlightV1 | RecoveryEffectAwaitingCallerReportV1 | RecoveryEffectUnknownV1 | RecoveryEffectCompleteV1 | RecoveryEffectPartialV1 | RecoveryEffectFailedAfterEffectV1
    expires_at_unix_ms: SafeInteger
    influence: RecoveryExplanationSnapshotInfluenceObserved | RecoveryExplanationSnapshotInfluenceUnknown
    intent_digest: RecoveryDigest32
    observations: list[RecoveryExplanationSnapshotObservationsItems] = Field(..., max_length=32)
    observed_at_unix_ms: SafeInteger
    policy_digest: RecoveryDigest32
    schema_: Literal['chio.recovery.explanation-snapshot.v1'] = Field(..., alias='schema')
    scope: RecoveryExplanationSnapshotDefinitionsScope
    version: Literal[1]

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
Fact = RecoveryExplanationSnapshotObservationsItemsFact
Influence = RecoveryExplanationSnapshotInfluenceObserved
Influence1 = RecoveryExplanationSnapshotInfluenceUnknown
Integrity = RecoveryExplanationSnapshotInfluenceObservedIntegrity
Observation = RecoveryExplanationSnapshotObservationsItems
Operation = RecoveryExplanationSnapshotDefinitionsOperation
Reason = RecoveryExplanationSnapshotObservationsItemsStateGapReason
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryExplanationSnapshotDestinationId = DestinationId
RecoveryExplanationSnapshotOpaqueId = OpaqueId
RecoveryExplanationSnapshotRecoveryDigest32 = RecoveryDigest32
RecoveryExplanationSnapshotRecoveryDigestOctet = RecoveryDigestOctet
RecoveryExplanationSnapshotRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryExplanationSnapshotRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryExplanationSnapshotRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryExplanationSnapshotRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryExplanationSnapshotRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryExplanationSnapshotRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryExplanationSnapshotRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryExplanationSnapshotRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryExplanationSnapshotRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryExplanationSnapshotRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryExplanationSnapshotSafeInteger = SafeInteger
RefusalCode = RecoveryExplanationSnapshotDefinitionsRefusalCode
Scope = RecoveryExplanationSnapshotDefinitionsScope
Source = RecoveryExplanationSnapshotObservationsItemsSource
State = RecoveryExplanationSnapshotObservationsItemsStateGap
State4 = RecoveryExplanationSnapshotObservationsItemsStateKnown
State6 = RecoveryExplanationSnapshotObservationsItemsStateFreshnessQualified
Target = RecoveryExplanationSnapshotObservationsItemsTargetIntent
Target6 = RecoveryExplanationSnapshotObservationsItemsTargetDestination
Target7 = RecoveryExplanationSnapshotObservationsItemsTargetAuthority
Target8 = RecoveryExplanationSnapshotObservationsItemsTargetTemplate
