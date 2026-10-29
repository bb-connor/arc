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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SessionAnchor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sessionAnchorHash: str
    sessionAnchorId: str


class ChioRequestLineageRecordSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilityId: str
    continuationTokenId: str
    evidenceClass: str
    intentHash: str
    issuerKey: str
    lineageMode: str
    operationKind: str
    parentRequestId: str
    requestId: str
    schema_: Literal["chio.request_lineage_record.v1"] = Field(..., alias="schema")
    sessionAnchor: SessionAnchor
    startedAt: int
    subjectKey: str
