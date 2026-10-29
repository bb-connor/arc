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


class ChioExecutionNonceSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bound_to: BoundTo
    expires_at: int
    issued_at: int
    nonce_id: str
    reserved_hold_id: str | None = None
    reserving_request_id: str | None = None
    schema_: Literal["chio.execution_nonce.v1"] = Field(..., alias="schema")
