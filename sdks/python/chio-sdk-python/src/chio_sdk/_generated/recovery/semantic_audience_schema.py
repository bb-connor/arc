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

class RecoverySemanticAudienceCompleteness(Enum):
    complete = 'complete'
    partial = 'partial'
    ambiguous = 'ambiguous'
    outage = 'outage'
    rate_limited = 'rate_limited'

class RecoverySemanticAudiencePaginationCursor(Enum):
    complete = 'complete'
    pending = 'pending'

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoverySemanticAudienceDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoverySemanticAudiencePagination(BaseModel):
    model_config = ConfigDict(extra='forbid')
    cursor: RecoverySemanticAudiencePaginationCursor
    pages_expected: SafeInteger
    pages_observed: SafeInteger

class SemanticAudienceV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    account: OpaqueId
    audience: information_label_schema.InformationLabel
    completeness: RecoverySemanticAudienceCompleteness
    domain_version: Literal[1]
    observed_at_unix_ms: SafeInteger
    pagination: RecoverySemanticAudiencePagination
    provider: OpaqueId
    provider_version: constr(min_length=1, max_length=128)
    query: RecoveryDigest32
    resource: OpaqueId
    scope: RecoverySemanticAudienceDefinitionsScope
    subject_mapping: RecoveryDigest32
    valid_until_unix_ms: SafeInteger

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

    @_facet_field_validator('provider_version', mode='after')
    @classmethod
    def _require_provider_version_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

# Public compatibility aliases reference the actual current model classes.
Completeness = RecoverySemanticAudienceCompleteness
Cursor = RecoverySemanticAudiencePaginationCursor
Pagination = RecoverySemanticAudiencePagination
RecoveryDigest32Item = RecoveryDigestOctet
RecoverySemanticAudienceOpaqueId = OpaqueId
RecoverySemanticAudienceRecoveryDigest32 = RecoveryDigest32
RecoverySemanticAudienceRecoveryDigestOctet = RecoveryDigestOctet
RecoverySemanticAudienceSafeInteger = SafeInteger
RecoverySemanticAudienceSemanticAudienceV1 = SemanticAudienceV1
Scope = RecoverySemanticAudienceDefinitionsScope
