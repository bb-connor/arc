# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Participant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    participantId: str
    verificationShare: str


class ChioFrostRosterV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedDomains: list[str]
    authorityScope: str
    ceremonyTranscriptDigest: str
    groupPublicKey: str
    keyEpoch: int
    keyOrigin: str
    participantCount: int
    participants: list[Participant]
    predecessorRosterDigest: str | None = None
    rosterAuthorityKeyId: str
    rosterId: str
    schema_: Literal["chio.frost.roster.v1"] = Field(..., alias="schema")
    scopeId: str
    suiteId: str
    threshold: int
    validFrom: int
    validUntil: int
