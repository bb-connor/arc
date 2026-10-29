# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, constr


class InformationLabel2(BaseModel):
    """
    Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["top"]


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


class InformationLabel1(BaseModel):
    """
    Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["known"]
    owners: dict[str, list[FlowIdentifier]]
    compartments: list[FlowIdentifier] = Field(..., max_length=64)


class InformationLabel(RootModel[InformationLabel1 | InformationLabel2]):
    root: InformationLabel1 | InformationLabel2 = Field(
        ...,
        description="Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.",
        title="Information Label",
    )
