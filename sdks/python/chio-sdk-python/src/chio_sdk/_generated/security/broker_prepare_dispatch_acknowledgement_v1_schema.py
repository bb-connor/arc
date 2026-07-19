# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class ChioBrokerPrepareDispatchAcknowledgementV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attemptId: Identifier
    operationId: Identifier
    preparedAtUnixSeconds: Annotated[int, Field(ge=1)]
    preparedDispatchId: Identifier
    schema_: Annotated[
        Literal["chio.broker-prepare-dispatch-acknowledgement.v1"],
        Field(alias="schema"),
    ]
