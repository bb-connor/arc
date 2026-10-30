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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LowerBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class UpperBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class Window(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    endsAt: int
    startsAt: int


class ChioFincredSourceCheckpointV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpointAuthorityEpoch: int
    checkpointAuthorityKey: str
    checkpointSequence: int
    cutoff: int
    expiresAt: int
    indexRoot: str
    indexSize: int
    issuedAt: int
    lowerBoundary: LowerBoundary
    rangeRoot: str
    schema_: Literal["chio.fincred.source-checkpoint.v1"] = Field(..., alias="schema")
    sourceId: str
    storeGeneration: int
    upperBoundary: UpperBoundary
    window: Window
