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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilityPublicKeyHex: str
    createdAt: int
    operation: str
    overlapExpiresAt: int | None = None
    previousEventSha256: str | None = None
    principalId: str
    role: str
    schema_: str = Field(..., alias="schema")
    tenantId: str


class LifecycleEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class ChioFindingHostedPrincipalReplicationEventSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityEpoch: int
    committedAt: int
    lifecycleEvent: LifecycleEvent
    schema_: Literal["chio.finding.hosted-principal-replication-event.v1"] = Field(
        ..., alias="schema"
    )
    sequence: int
    sourceAuthority: str
    tenantId: str
