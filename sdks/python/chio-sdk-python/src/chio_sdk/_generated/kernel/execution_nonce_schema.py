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

from pydantic import BaseModel, ConfigDict, Field


class BoundTo(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: Annotated[str, Field(min_length=1)]
    parameter_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    request_id: Annotated[str, Field(min_length=1)]
    subject_id: Annotated[str, Field(min_length=1)]
    tool_name: Annotated[str, Field(min_length=1)]
    tool_server: Annotated[str, Field(min_length=1)]


class Nonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bound_to: BoundTo
    expires_at: Annotated[int, Field(ge=0)]
    issued_at: Annotated[int, Field(ge=0)]
    nonce_id: Annotated[str, Field(min_length=1)]
    reserved_hold_id: Annotated[str | None, Field(min_length=1)] = None
    reserving_request_id: Annotated[str | None, Field(min_length=1)] = None
    schema_: Annotated[Literal["chio.execution_nonce.v1"], Field(alias="schema")]


class ChioSignedExecutionNonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nonce: Nonce
    signature: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
