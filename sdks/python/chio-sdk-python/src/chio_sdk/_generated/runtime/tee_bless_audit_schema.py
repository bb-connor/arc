# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Capture(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    frames_after_dedupe: int
    frames_after_redact: int
    frames_in: int
    path: str


class Fixture(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    family: str
    name: str
    path: str
    receipts_root: str


class Operator(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    git_user: str
    id: str


class ChioTeeBlessAuditSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capture: Capture
    control_plane_capability: str
    event: str
    fixture: Fixture
    operator: Operator
    redaction_pass_id: str
    ts: str
