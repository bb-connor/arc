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
from chio_sdk._manifest_wire import SecurityWireModel as BaseModel
from pydantic import StrictBool, ConfigDict, Field, RootModel, constr

class FlowIdentifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

class SecurityToolFlowDeclarationDefinitionsKnownLabel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['known']
    owners: dict[str, list[FlowIdentifier]]
    compartments: list[FlowIdentifier] = Field(..., max_length=64)

class ToolFlowDeclaration(BaseModel):
    """
    Publisher-authenticated information-flow constraints retained across protocol bridges.
    """
    model_config = ConfigDict(extra='forbid')
    output_label: SecurityToolFlowDeclarationDefinitionsKnownLabel | None = None
    input_clearance: SecurityToolFlowDeclarationDefinitionsKnownLabel | None = None
    egress: StrictBool
    declassification_purposes: list[FlowIdentifier] | None = Field(None, min_length=1)

# Public compatibility aliases reference the actual current model classes.
KnownLabel = SecurityToolFlowDeclarationDefinitionsKnownLabel
SecurityToolFlowDeclarationFlowIdentifier = FlowIdentifier
SecurityToolFlowDeclarationToolFlowDeclaration = ToolFlowDeclaration
