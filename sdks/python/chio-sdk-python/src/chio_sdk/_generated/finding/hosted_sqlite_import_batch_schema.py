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


class Payload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    invalid: bool


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateId: str
    artifactSignerKey: str
    authorityEpoch: int
    committedAt: int
    eventId: str
    eventKind: str
    expectedEventSha256: None
    expectedRevision: int
    payload: Payload
    schema_: str = Field(..., alias="schema")
    sequence: int
    sourceAuthority: str
    tenantId: str


class Event(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class Entry(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    entry_kind: str
    event: Event


class ChioFindingHostedSqliteImportBatchSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityEpoch: int
    entries: list[Entry]
    exportedAt: int
    firstSequence: int
    lastSequence: int
    schema_: Literal["chio.finding.hosted-sqlite-import-batch.v1"] = Field(
        ..., alias="schema"
    )
    sourceProjectionSha256: str
    tenantId: str
