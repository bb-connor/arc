# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    component_id: str | None = None
    component_type: str


class ChioAgUiReceiptSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agent_id: str
    allowed: bool
    capability_id: str
    classification: str
    denial_reason: str | None = None
    event_id: str
    event_type: str
    id: str
    kernel_key: str
    payload_hash: str
    session_id: str | None = None
    target: Target | None = None
    timestamp: int
    transport: str
