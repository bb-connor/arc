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


class Lifecycle(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    at: int | None = None
    issueUntil: int | None = None
    state: str
    verifyUntil: int | None = None


class TrustedKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activatedAt: int
    generation: int
    lifecycle: Lifecycle
    publicKeyHex: str


class Snapshot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generation: int
    publicKeyHex: str
    rotatedAt: int
    trustedKeys: list[TrustedKey]


class ChioAuthoritySnapshotSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchorDigest: str
    chainCommitment: str
    expiresAt: int
    issuedAt: int
    schema_: Literal["chio.authority-snapshot.v1"] = Field(..., alias="schema")
    snapshot: Snapshot
    streamId: str
