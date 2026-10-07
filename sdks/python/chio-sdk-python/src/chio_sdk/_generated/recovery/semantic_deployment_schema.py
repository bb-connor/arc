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
from typing import Literal
from pydantic import field_validator
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from ..security import information_label_schema
from pydantic import field_validator as _facet_field_validator

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoverySemanticDeploymentDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoverySemanticDeploymentDefinitionsSemanticAnnotator(BaseModel):
    model_config = ConfigDict(extra='forbid')
    facts: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    key: RecoveryDigest32
    may_attest_facts: bool

class RecoverySemanticDeploymentDefinitionsSemanticOverride(BaseModel):
    model_config = ConfigDict(extra='forbid')
    fixture_digests: list[RecoveryDigest32] = Field(..., max_length=8, min_length=1)
    reason: constr(min_length=1, max_length=512)
    selector_index: SafeInteger

    @_facet_field_validator('reason', mode='after')
    @classmethod
    def _require_reason_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 512)
        return value

class RecoverySemanticDeploymentDefinitionsSemanticSelectorPresent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    field: OpaqueId
    kind: Literal['present']

class RecoverySemanticDeploymentDefinitionsSemanticSelectorTextBytesAtMost(BaseModel):
    model_config = ConfigDict(extra='forbid')
    bytes: SafeInteger
    field: OpaqueId
    kind: Literal['text_bytes_at_most']

class RecoverySemanticDeploymentDefinitionsSemanticValueText(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['text']
    value: constr(min_length=1, max_length=4096)

    @_facet_field_validator('value', mode='after')
    @classmethod
    def _require_value_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 4096)
        return value

class RecoverySemanticDeploymentDefinitionsSemanticValueInteger(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['integer']
    value: SafeInteger

class RecoverySemanticDeploymentDefinitionsSemanticValueBoolean(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['boolean']
    value: bool

class SemanticValue(RootModel[RecoverySemanticDeploymentDefinitionsSemanticValueText | RecoverySemanticDeploymentDefinitionsSemanticValueInteger | RecoverySemanticDeploymentDefinitionsSemanticValueBoolean]):
    root: RecoverySemanticDeploymentDefinitionsSemanticValueText | RecoverySemanticDeploymentDefinitionsSemanticValueInteger | RecoverySemanticDeploymentDefinitionsSemanticValueBoolean

class RecoverySemanticDeploymentDefinitionsSemanticDestination(BaseModel):
    model_config = ConfigDict(extra='forbid')
    account: OpaqueId
    acl_query: RecoveryDigest32
    audience: information_label_schema.InformationLabel
    destination: OpaqueId
    endpoint: constr(min_length=1, max_length=2048)
    provider: OpaqueId
    purpose: constr(min_length=1, max_length=256)
    require_provider_precondition: bool
    resource: OpaqueId
    subject_mapping: RecoveryDigest32

    @_facet_field_validator('endpoint', mode='after')
    @classmethod
    def _require_endpoint_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 2048)
        return value

    @_facet_field_validator('purpose', mode='after')
    @classmethod
    def _require_purpose_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

class RecoverySemanticDeploymentDefinitionsSemanticSelectorEquals(BaseModel):
    model_config = ConfigDict(extra='forbid')
    field: OpaqueId
    kind: Literal['equals']
    value: SemanticValue

class SemanticSelector(RootModel[RecoverySemanticDeploymentDefinitionsSemanticSelectorPresent | RecoverySemanticDeploymentDefinitionsSemanticSelectorEquals | RecoverySemanticDeploymentDefinitionsSemanticSelectorTextBytesAtMost]):
    root: RecoverySemanticDeploymentDefinitionsSemanticSelectorPresent | RecoverySemanticDeploymentDefinitionsSemanticSelectorEquals | RecoverySemanticDeploymentDefinitionsSemanticSelectorTextBytesAtMost

class RecoverySemanticDeploymentDefinitionsSemanticRoute(BaseModel):
    model_config = ConfigDict(extra='forbid')
    annotators: list[RecoverySemanticDeploymentDefinitionsSemanticAnnotator] = Field(..., max_length=16, min_length=0)
    destinations: list[RecoverySemanticDeploymentDefinitionsSemanticDestination] = Field(..., max_length=16, min_length=1)
    endorsement_key: RecoveryDigest32
    implementation: RecoveryDigest32
    input_schema: RecoveryDigest32
    operation: OpaqueId
    operator_selectors: list[SemanticSelector] = Field(..., max_length=16, min_length=0)
    output_schema: RecoveryDigest32
    package: RecoveryDigest32
    prerequisite_key: RecoveryDigest32
    resolver_key: RecoveryDigest32
    reviewed_overrides: list[RecoverySemanticDeploymentDefinitionsSemanticOverride] = Field(..., max_length=16, min_length=0)
    server: constr(min_length=1, max_length=128)
    tool: constr(min_length=1, max_length=128)
    transformation_key: RecoveryDigest32

    @_facet_field_validator('server', mode='after')
    @classmethod
    def _require_server_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

    @_facet_field_validator('tool', mode='after')
    @classmethod
    def _require_tool_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

class SemanticDeploymentV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context_binding: RecoveryDigest32
    domain_version: Literal[1]
    exposure_binding: RecoveryDigest32
    generation: conint(ge=1, le=9007199254740991)
    native_binding: RecoveryDigest32
    packages: list[RecoveryDigest32] = Field(..., max_length=16, min_length=1)
    routes: list[RecoverySemanticDeploymentDefinitionsSemanticRoute] = Field(..., max_length=16, min_length=1)
    scope: RecoverySemanticDeploymentDefinitionsScope

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
RecoveryDigest32Item = RecoveryDigestOctet
RecoverySemanticDeploymentOpaqueId = OpaqueId
RecoverySemanticDeploymentRecoveryDigest32 = RecoveryDigest32
RecoverySemanticDeploymentRecoveryDigestOctet = RecoveryDigestOctet
RecoverySemanticDeploymentSafeInteger = SafeInteger
RecoverySemanticDeploymentSemanticDeploymentV1 = SemanticDeploymentV1
RecoverySemanticDeploymentSemanticSelector = SemanticSelector
RecoverySemanticDeploymentSemanticValue = SemanticValue
Scope = RecoverySemanticDeploymentDefinitionsScope
SemanticAnnotator = RecoverySemanticDeploymentDefinitionsSemanticAnnotator
SemanticDestination = RecoverySemanticDeploymentDefinitionsSemanticDestination
SemanticOverride = RecoverySemanticDeploymentDefinitionsSemanticOverride
SemanticRoute = RecoverySemanticDeploymentDefinitionsSemanticRoute
SemanticSelector1 = RecoverySemanticDeploymentDefinitionsSemanticSelectorPresent
SemanticSelector2 = RecoverySemanticDeploymentDefinitionsSemanticSelectorEquals
SemanticSelector3 = RecoverySemanticDeploymentDefinitionsSemanticSelectorTextBytesAtMost
SemanticValue1 = RecoverySemanticDeploymentDefinitionsSemanticValueText
SemanticValue2 = RecoverySemanticDeploymentDefinitionsSemanticValueInteger
SemanticValue3 = RecoverySemanticDeploymentDefinitionsSemanticValueBoolean
