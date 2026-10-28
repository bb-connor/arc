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


class Invocation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cmd: str | None = None
    q: str | None = None
    to: str | None = None
    tool: str | None = None


class Otel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    span_id: str
    trace_id: str


class Provenance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    otel: Otel


class Upstream(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    api_version: str
    operation: str
    system: str


class ChioTeeCaptureFrameSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    deny_reason: str | None = None
    event_id: str
    invocation: Invocation
    provenance: Provenance
    redaction_pass_id: str
    request_blob_sha256: str
    response_blob_sha256: str
    schema_version: str
    tee_id: str
    ts: str
    upstream: Upstream
    verdict: str
    would_have_blocked: bool
