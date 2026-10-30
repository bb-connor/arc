# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Principal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    account_id: str
    assumed_role_session_arn: None
    caller_arn: str
    kind: str


class ReceivedAt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nanos_since_epoch: int
    secs_since_epoch: int


class ChioProvenanceStampSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    api_version: str
    principal: Principal
    provider: str
    received_at: ReceivedAt
    request_id: str
