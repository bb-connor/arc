# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f9c25e1eb1ce1c8ea4083ef04968d45682cd9f79d853175aac0d03e295257b73
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class OpaqueId(
    RootModel[
        constr(
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
        )
    ]
):
    root: constr(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
    )


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class SemanticValue7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["text"]
    value: constr(min_length=1, max_length=4096)


class SemanticValue8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["integer"]
    value: SafeInteger


class SemanticValue9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["boolean"]
    value: bool


class SemanticValue(RootModel[SemanticValue7 | SemanticValue8 | SemanticValue9]):
    root: SemanticValue7 | SemanticValue8 | SemanticValue9


class SemanticField(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field: OpaqueId
    value: SemanticValue


class SemanticPayloadV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    fields: list[SemanticField] = Field(..., max_length=16, min_length=1)
