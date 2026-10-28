# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ChioSignedWatermarkEnvelopeSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    application_id: str
    encoding: str
    expires_at_unix_ms: int
    issued_at_unix_ms: int
    key_id: str
    marker_ref: str
    sequence: int
    session_id: str
    source_receipt_id: str
    tenant_id: str
    tool_id: str
