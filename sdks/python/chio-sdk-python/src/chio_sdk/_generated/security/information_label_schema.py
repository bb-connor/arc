# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class InformationLabel2(BaseModel):
    """
    Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["top"]


class FlowIdentifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class InformationLabel1(BaseModel):
    """
    Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    compartments: Annotated[list[FlowIdentifier], Field(max_length=64)]
    kind: Literal["known"]
    owners: dict[str, list[FlowIdentifier]]


class InformationLabel(RootModel[InformationLabel1 | InformationLabel2]):
    root: Annotated[
        InformationLabel1 | InformationLabel2,
        Field(
            description="Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.",
            title="Information Label",
        ),
    ]
