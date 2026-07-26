# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class FlowIdentifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class KnownLabel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compartments: Annotated[list[FlowIdentifier], Field(max_length=64)]
    kind: Literal["known"]
    owners: dict[str, list[FlowIdentifier]]


class ToolFlowDeclaration(BaseModel):
    """
    Publisher-authenticated information-flow constraints retained across protocol bridges.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    declassification_purposes: Annotated[
        list[FlowIdentifier] | None, Field(min_length=1)
    ] = None
    egress: bool
    input_clearance: KnownLabel | None = None
    output_label: KnownLabel | None = None
