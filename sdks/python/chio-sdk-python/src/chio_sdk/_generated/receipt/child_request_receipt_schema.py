# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Surface(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lane: str


class Metadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    message: str | None = None
    message_sha256: str | None = None
    message_truncated: bool | None = None
    outcome: str | None = None
    source: str | None = None
    surface: Surface | None = None


class TerminalState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    reason: str | None = None
    state: str


class ChioChildRequestReceiptSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: str
    kernel_key: str
    metadata: Metadata | None = None
    operation_kind: str
    outcome_hash: str
    parent_request_id: str
    policy_hash: str
    request_id: str
    session_id: str
    terminal_state: TerminalState
    timestamp: int
