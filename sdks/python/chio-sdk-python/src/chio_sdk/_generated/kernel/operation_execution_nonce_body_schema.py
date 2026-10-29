# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class BoundTo(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: str
    parameter_hash: str
    request_id: str
    subject_id: str
    tool_name: str
    tool_server: str


class Nonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bound_to: BoundTo
    expires_at: int
    issued_at: int
    nonce_id: str
    schema_: str = Field(..., alias="schema")


class ChioOperationExecutionNonceSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nonce: Nonce
    operation_id: str
