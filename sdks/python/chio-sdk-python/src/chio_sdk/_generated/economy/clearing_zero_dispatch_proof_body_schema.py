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


class Disposition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class DispatchStatus(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dispatchIdempotencyKey: str
    disposition: Disposition
    intentDigest: str
    intentId: str


class ChioClearingZeroDispatchProofV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admissionCommitDigest: str
    admissionCommitSequence: int
    admissionStoreId: str
    authorityId: str
    authorityKeyEpoch: int
    dispatchStatusCount: int
    dispatchStatusRoot: str
    dispatchStatuses: list[DispatchStatus]
    expiresAtUnixMs: int
    issuedAtUnixMs: int
    outputManifestDigest: str
    roundCoreDigest: str
    roundId: str
    schema_: Literal["chio.clearing.zero-dispatch-proof.v1"] = Field(
        ..., alias="schema"
    )
    settlementIntentCount: int
    settlementIntentRoot: str
    sourceLifecycleFence: int
    sourceLifecycleHeadDigest: str
    sourceLifecycleVersion: int
