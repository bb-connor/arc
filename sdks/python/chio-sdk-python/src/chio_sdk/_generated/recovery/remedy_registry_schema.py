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

class RecoveryRemedyRegistryTemplatesItemsCostLatency(Enum):
    local = 'local'
    remote = 'remote'
    unspecified = 'unspecified'

class RecoveryRemedyRegistryTemplatesItemsKind(Enum):
    existing_destination = 'existing_destination'
    exact_approval = 'exact_approval'
    transformation = 'transformation'
    prerequisite = 'prerequisite'

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

class RecoveryRemedyRegistryDefinitionsRefusalCode(Enum):
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

class RecoveryRemedyRegistryDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryRemedyRegistryTemplatesItemsCost(BaseModel):
    model_config = ConfigDict(extra='forbid')
    approvals: conint(ge=0, le=8)
    budget_units: SafeInteger
    evidence: OpaqueId
    irreversible_effects: conint(ge=0, le=8)
    latency: RecoveryRemedyRegistryTemplatesItemsCostLatency

class RecoveryRemedyRegistryTemplatesItems(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_scope: RecoveryDigest32
    classification: information_label_schema.InformationLabel
    cost: RecoveryRemedyRegistryTemplatesItemsCost
    destination: DestinationId
    disclosure_label: information_label_schema.InformationLabel
    family: RecoveryDigest32
    kind: RecoveryRemedyRegistryTemplatesItemsKind
    requirements: list[OpaqueId] = Field(..., max_length=8, min_length=1)
    requires_integrity: bool
    satisfies_task: bool
    template_id: OpaqueId

    @_facet_field_validator('destination', mode='after')
    @classmethod
    def _require_destination_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

class RecoveryRemedyRegistryV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    classification: information_label_schema.InformationLabel
    contract_digest: RecoveryDigest32
    deployment_digest: RecoveryDigest32
    policy_digest: RecoveryDigest32
    schema_: Literal['chio.recovery.remedy-registry.v1'] = Field(..., alias='schema')
    scope: RecoveryRemedyRegistryDefinitionsScope
    templates: list[RecoveryRemedyRegistryTemplatesItems] = Field(..., max_length=16)
    version: Literal[1]

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

class RecoveryRemedyRegistryDefinitionsOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    native_admission_digest: RecoveryDigest32
    operation_id: OpaqueId
    operation_version: conint(ge=1, le=9007199254740991)

class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_approval']
    operation: RecoveryRemedyRegistryDefinitionsOperation

class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['awaiting_caller_report']
    operation: RecoveryRemedyRegistryDefinitionsOperation

class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    closure: OpaqueId
    kind: Literal['closed_before_effect']
    operation: RecoveryRemedyRegistryDefinitionsOperation

class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect_count: SafeInteger
    kind: Literal['complete']
    operation: RecoveryRemedyRegistryDefinitionsOperation

class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal['failed_after_effect']
    operation: RecoveryRemedyRegistryDefinitionsOperation

class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['in_flight']
    operation: RecoveryRemedyRegistryDefinitionsOperation

class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal['partial']
    operation: RecoveryRemedyRegistryDefinitionsOperation

class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']
    operation: RecoveryRemedyRegistryDefinitionsOperation

# Public compatibility aliases reference the actual current model classes.
Cost = RecoveryRemedyRegistryTemplatesItemsCost
Kind = RecoveryRemedyRegistryTemplatesItemsKind
Latency = RecoveryRemedyRegistryTemplatesItemsCostLatency
Operation = RecoveryRemedyRegistryDefinitionsOperation
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryRemedyRegistryDestinationId = DestinationId
RecoveryRemedyRegistryOpaqueId = OpaqueId
RecoveryRemedyRegistryRecoveryDigest32 = RecoveryDigest32
RecoveryRemedyRegistryRecoveryDigestOctet = RecoveryDigestOctet
RecoveryRemedyRegistryRecoveryEffectAdmissionUnresolvedV1 = RecoveryEffectAdmissionUnresolvedV1
RecoveryRemedyRegistryRecoveryEffectAwaitingApprovalV1 = RecoveryEffectAwaitingApprovalV1
RecoveryRemedyRegistryRecoveryEffectAwaitingCallerReportV1 = RecoveryEffectAwaitingCallerReportV1
RecoveryRemedyRegistryRecoveryEffectClosedBeforeEffectV1 = RecoveryEffectClosedBeforeEffectV1
RecoveryRemedyRegistryRecoveryEffectCompleteV1 = RecoveryEffectCompleteV1
RecoveryRemedyRegistryRecoveryEffectFailedAfterEffectV1 = RecoveryEffectFailedAfterEffectV1
RecoveryRemedyRegistryRecoveryEffectInFlightV1 = RecoveryEffectInFlightV1
RecoveryRemedyRegistryRecoveryEffectNeverAdmittedV1 = RecoveryEffectNeverAdmittedV1
RecoveryRemedyRegistryRecoveryEffectPartialV1 = RecoveryEffectPartialV1
RecoveryRemedyRegistryRecoveryEffectUnknownV1 = RecoveryEffectUnknownV1
RecoveryRemedyRegistrySafeInteger = SafeInteger
RefusalCode = RecoveryRemedyRegistryDefinitionsRefusalCode
Scope = RecoveryRemedyRegistryDefinitionsScope
Template = RecoveryRemedyRegistryTemplatesItems
