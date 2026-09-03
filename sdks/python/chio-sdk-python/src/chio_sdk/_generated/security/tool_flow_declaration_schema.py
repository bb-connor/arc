# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 389bcf1b0204c491a4db719480c568ace486987ea9871d15adefdc3bb3a365cc
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, constr


class FlowIdentifier(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=256,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )


class KnownLabel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["known"]
    owners: dict[str, list[FlowIdentifier]]
    compartments: list[FlowIdentifier] = Field(..., max_length=64)


class ToolFlowDeclaration(BaseModel):
    """
    Publisher-authenticated information-flow constraints retained across protocol bridges.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    output_label: KnownLabel | None = None
    input_clearance: KnownLabel | None = None
    egress: bool
    declassification_purposes: list[FlowIdentifier] | None = Field(None, min_length=1)
