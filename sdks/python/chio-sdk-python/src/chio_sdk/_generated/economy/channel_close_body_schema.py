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

from pydantic import BaseModel, ConfigDict, Field


class FinalCumulativeOwed(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    channelId: str
    channelStateVersion: int
    closeKind: str
    closeSubmissionCutoffUnixSecs: int
    disputeDeadlineUnixMs: int
    disputeWindowSecs: int
    escrowReservationVersion: int
    expectedRefundAfterReleaseTokenBaseUnits: str
    expectedReleaseTokenBaseUnits: str
    finalCumulativeOwed: FinalCumulativeOwed
    finalStateDigest: str
    finalStateSequence: int
    lifecycleFence: int
    openDigest: str
    proposedAtUnixMs: int
    schema_: str = Field(..., alias="schema")


class ChioChannelCloseV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    keyEpoch: int
    signerId: str
    signerKey: str
