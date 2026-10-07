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
from pydantic import BaseModel, ConfigDict, Field, RootModel, constr
from pydantic import field_validator as _facet_field_validator

class SecurityInformationLabelTop(BaseModel):
    """
    Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.
    """
    model_config = ConfigDict(extra='forbid')
    kind: Literal['top']

class FlowIdentifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

    @_facet_field_validator('root', mode='after')
    @classmethod
    def _require_root_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

class SecurityInformationLabelKnown(BaseModel):
    """
    Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.
    """
    model_config = ConfigDict(extra='forbid')
    kind: Literal['known']
    owners: dict[str, list[FlowIdentifier]]
    compartments: list[FlowIdentifier] = Field(..., max_length=64)

    @_facet_field_validator('owners', mode='after')
    @classmethod
    def _require_owners_keys_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            for key in value:
                FlowIdentifier.model_validate(key)
                _require_utf8_bound(key, 256)
        return value

class InformationLabel(RootModel[SecurityInformationLabelKnown | SecurityInformationLabelTop]):
    root: SecurityInformationLabelKnown | SecurityInformationLabelTop = Field(..., description='Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.', title='Information Label')

# Public compatibility aliases reference the actual current model classes.
InformationLabel1 = SecurityInformationLabelKnown
InformationLabel2 = SecurityInformationLabelTop
SecurityInformationLabelFlowIdentifier = FlowIdentifier
SecurityInformationLabelInformationLabel = InformationLabel
