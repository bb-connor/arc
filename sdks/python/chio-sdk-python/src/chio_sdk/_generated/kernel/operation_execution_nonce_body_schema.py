# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
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
