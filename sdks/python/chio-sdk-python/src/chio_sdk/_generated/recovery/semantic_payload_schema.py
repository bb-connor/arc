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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from pydantic import field_validator as _facet_field_validator

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoverySemanticPayloadDefinitionsSemanticValueText(BaseModel):
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

class RecoverySemanticPayloadDefinitionsSemanticValueInteger(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['integer']
    value: SafeInteger

class RecoverySemanticPayloadDefinitionsSemanticValueBoolean(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['boolean']
    value: bool

class SemanticValue(RootModel[RecoverySemanticPayloadDefinitionsSemanticValueText | RecoverySemanticPayloadDefinitionsSemanticValueInteger | RecoverySemanticPayloadDefinitionsSemanticValueBoolean]):
    root: RecoverySemanticPayloadDefinitionsSemanticValueText | RecoverySemanticPayloadDefinitionsSemanticValueInteger | RecoverySemanticPayloadDefinitionsSemanticValueBoolean

class RecoverySemanticPayloadDefinitionsSemanticField(BaseModel):
    model_config = ConfigDict(extra='forbid')
    field: OpaqueId
    value: SemanticValue

class SemanticPayloadV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    fields: list[RecoverySemanticPayloadDefinitionsSemanticField] = Field(..., max_length=16, min_length=1)

# Public compatibility aliases reference the actual current model classes.
RecoverySemanticPayloadOpaqueId = OpaqueId
RecoverySemanticPayloadSafeInteger = SafeInteger
RecoverySemanticPayloadSemanticPayloadV1 = SemanticPayloadV1
RecoverySemanticPayloadSemanticValue = SemanticValue
SemanticField = RecoverySemanticPayloadDefinitionsSemanticField
SemanticValue7 = RecoverySemanticPayloadDefinitionsSemanticValueText
SemanticValue8 = RecoverySemanticPayloadDefinitionsSemanticValueInteger
SemanticValue9 = RecoverySemanticPayloadDefinitionsSemanticValueBoolean
