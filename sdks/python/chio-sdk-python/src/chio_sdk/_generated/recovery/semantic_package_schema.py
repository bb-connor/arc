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
from typing import Any
from pydantic import field_validator, model_serializer, SerializerFunctionWrapHandler
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

class RecoverySemanticPackageDefinitionsSemanticChannelChannel(Enum):
    input = 'input'
    success = 'success'
    error = 'error'
    no_value = 'no_value'
    nested = 'nested'
    batch = 'batch'
    pagination = 'pagination'
    redirect = 'redirect'
    stream = 'stream'
    file = 'file'
    log = 'log'
    shell = 'shell'
    model = 'model'

class RecoverySemanticPackageDefinitionsSemanticChannel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    channel: RecoverySemanticPackageDefinitionsSemanticChannelChannel
    enabled: bool

class RecoverySemanticPackageDefinitionsSemanticOperationKind(Enum):
    support_read = 'support_read'
    issue_write = 'issue_write'
    field_projection = 'field_projection'

class RecoverySemanticPackageDefinitionsSemanticPrerequisiteRequirementKind(Enum):
    historical_fact = 'historical_fact'
    current_predicate = 'current_predicate'
    held_reservation = 'held_reservation'

class RecoverySemanticPackageDefinitionsSemanticPrerequisiteRequirement(BaseModel):
    model_config = ConfigDict(extra='forbid')
    fact: OpaqueId
    kind: RecoverySemanticPackageDefinitionsSemanticPrerequisiteRequirementKind
    resource: OpaqueId

class RecoverySemanticPackageDefinitionsSemanticSelectorPresent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    field: OpaqueId
    kind: Literal['present']

class RecoverySemanticPackageDefinitionsSemanticSelectorTextBytesAtMost(BaseModel):
    model_config = ConfigDict(extra='forbid')
    bytes: SafeInteger
    field: OpaqueId
    kind: Literal['text_bytes_at_most']

class RecoverySemanticPackageDefinitionsSemanticValueText(BaseModel):
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

class RecoverySemanticPackageDefinitionsSemanticValueInteger(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['integer']
    value: SafeInteger

class RecoverySemanticPackageDefinitionsSemanticValueBoolean(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['boolean']
    value: bool

class SemanticValue(RootModel[RecoverySemanticPackageDefinitionsSemanticValueText | RecoverySemanticPackageDefinitionsSemanticValueInteger | RecoverySemanticPackageDefinitionsSemanticValueBoolean]):
    root: RecoverySemanticPackageDefinitionsSemanticValueText | RecoverySemanticPackageDefinitionsSemanticValueInteger | RecoverySemanticPackageDefinitionsSemanticValueBoolean

class RecoverySemanticPackageDefinitionsSemanticSelectorEquals(BaseModel):
    model_config = ConfigDict(extra='forbid')
    field: OpaqueId
    kind: Literal['equals']
    value: SemanticValue

class SemanticSelector(RootModel[RecoverySemanticPackageDefinitionsSemanticSelectorPresent | RecoverySemanticPackageDefinitionsSemanticSelectorEquals | RecoverySemanticPackageDefinitionsSemanticSelectorTextBytesAtMost]):
    root: RecoverySemanticPackageDefinitionsSemanticSelectorPresent | RecoverySemanticPackageDefinitionsSemanticSelectorEquals | RecoverySemanticPackageDefinitionsSemanticSelectorTextBytesAtMost

class SemanticWithheldStatusV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    audience: information_label_schema.InformationLabel

class RecoverySemanticPackageDefinitionsSemanticOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    channels: list[RecoverySemanticPackageDefinitionsSemanticChannel] = Field(..., max_length=13, min_length=1)
    external_influence: bool
    implementation: RecoveryDigest32
    input_fields: list[OpaqueId] = Field(..., max_length=16, min_length=0)
    input_schema: RecoveryDigest32
    kind: RecoverySemanticPackageDefinitionsSemanticOperationKind
    operation: OpaqueId
    output_schema: RecoveryDigest32
    prerequisites: list[RecoverySemanticPackageDefinitionsSemanticPrerequisiteRequirement] = Field(..., max_length=8, min_length=0)
    projection_fields: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    required_assertions: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    selectors: list[SemanticSelector] = Field(..., max_length=16, min_length=0)
    source_label: information_label_schema.InformationLabel
    withheld_status: SemanticWithheldStatusV1 | None = None

    @field_validator('withheld_status', mode='before')
    @classmethod
    def _withheld_status_must_not_be_null(cls, value: object) -> object:
        if value is None:
            raise ValueError('withheld status must be omitted instead of null')
        return value

    @model_serializer(mode='wrap')
    def _omit_absent_withheld_status(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value = handler(self)
        if self.withheld_status is None:
            value.pop('withheld_status', None)
        return value

class SemanticPackageV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    dependencies: list[RecoveryDigest32] = Field(..., max_length=16, min_length=0)
    domain_version: Literal[1]
    operations: list[RecoverySemanticPackageDefinitionsSemanticOperation] = Field(..., max_length=16, min_length=1)
    package: OpaqueId

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
Channel = RecoverySemanticPackageDefinitionsSemanticChannelChannel
Kind = RecoverySemanticPackageDefinitionsSemanticOperationKind
Kind13 = RecoverySemanticPackageDefinitionsSemanticPrerequisiteRequirementKind
RecoveryDigest32Item = RecoveryDigestOctet
RecoverySemanticPackageOpaqueId = OpaqueId
RecoverySemanticPackageRecoveryDigest32 = RecoveryDigest32
RecoverySemanticPackageRecoveryDigestOctet = RecoveryDigestOctet
RecoverySemanticPackageSafeInteger = SafeInteger
RecoverySemanticPackageSemanticPackageV1 = SemanticPackageV1
RecoverySemanticPackageSemanticSelector = SemanticSelector
RecoverySemanticPackageSemanticValue = SemanticValue
RecoverySemanticPackageSemanticWithheldStatusV1 = SemanticWithheldStatusV1
SemanticChannel = RecoverySemanticPackageDefinitionsSemanticChannel
SemanticOperation = RecoverySemanticPackageDefinitionsSemanticOperation
SemanticPrerequisiteRequirement = RecoverySemanticPackageDefinitionsSemanticPrerequisiteRequirement
SemanticSelector4 = RecoverySemanticPackageDefinitionsSemanticSelectorPresent
SemanticSelector5 = RecoverySemanticPackageDefinitionsSemanticSelectorEquals
SemanticSelector6 = RecoverySemanticPackageDefinitionsSemanticSelectorTextBytesAtMost
SemanticValue4 = RecoverySemanticPackageDefinitionsSemanticValueText
SemanticValue5 = RecoverySemanticPackageDefinitionsSemanticValueInteger
SemanticValue6 = RecoverySemanticPackageDefinitionsSemanticValueBoolean
SemanticWithheldStatus = SemanticWithheldStatusV1
