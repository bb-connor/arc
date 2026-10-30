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

from pydantic import BaseModel, ConfigDict, Field


class EscrowReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: str
    escrowContract: str
    escrowId: str


class FinalCumulativeOwed(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Frost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionDigest: str
    authorizationId: str
    authorizationSlotId: str
    signedEnvelopeDigest: str


class Authority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    assetBindingDigest: str
    authorizedAtUnixMs: int
    boundTokenBaseUnits: str
    channelExpiryUnixMs: int
    channelId: str
    channelStateVersion: int
    closeBodyDigest: str
    closeDigest: str
    closeSubmissionCutoffUnixMs: int
    disputeDeadlineUnixMs: int
    effectiveCloseDigest: str
    escrowDeadlineUnixMs: int
    escrowReference: EscrowReference
    escrowReservationVersion: int
    expectedRefundTokenBaseUnits: str
    expectedReleaseTokenBaseUnits: str
    finalCumulativeOwed: FinalCumulativeOwed
    finalStateDigest: str
    finalStateSequence: int
    frost: Frost
    frostIssuedAtUnixMs: int
    frostKeyEpoch: int
    frostResourceFence: int
    frostResourceId: str
    frostResourceVersion: int
    frostRosterDigest: str
    frostScopeId: str
    lifecycleFence: int
    openDigest: str
    originalOperator: str
    originalOperatorKeyHash: str
    originalWeb3DispatchDigest: str
    payeeBeneficiaryAddress: str
    publisherFence: int


class ReleaseBroadcast(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    callDigest: str
    effectKind: str
    effectSlotId: str
    idempotencyKey: str
    operationId: str
    resourceHeadDigest: str
    scopeId: str


class RootPublication(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    callDigest: str
    effectKind: str
    effectSlotId: str
    idempotencyKey: str
    operationId: str
    resourceHeadDigest: str
    scopeId: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority: Authority
    publicationRoot: str
    releaseBroadcast: ReleaseBroadcast
    rootPublication: RootPublication
    schema_: str = Field(..., alias="schema")


class ChioChannelReleaseAuthorizationV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    keyEpoch: int
    signerId: str
    signerKey: str
