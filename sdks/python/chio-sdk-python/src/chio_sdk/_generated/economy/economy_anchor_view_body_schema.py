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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AbsentRequestKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    requestId: str
    requestNamespaceDigest: str


class AbsentResourceKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resourceFamily: str
    resourceId: str
    scopeId: str


class Frost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionDigest: str
    authorizationId: str
    authorizationSlotId: str
    signedEnvelopeDigest: str


class ResourceKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resourceFamily: str
    resourceId: str
    scopeId: str


class StoreFence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lease_id: str
    owner_epoch: int
    store_uuid: str


class AdmissionHandoff(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lifecycleFence: int
    operationVersion: int
    state: str
    storeFence: StoreFence


class Key(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundCoverageBodyDigest: str
    evidenceRangeDigest: str
    parametricPolicyBodyDigest: str
    subjectKey: str
    triggerPredicateBodyDigest: str
    windowEnd: int
    windowStart: int


class Identity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimId: str
    key: Key
    triggerInstanceId: str


class PayoutAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class PayoutMode(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    windowSeconds: int


class PayoutRail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destinationAccountDigest: str
    kind: str
    railId: str


class TriggerMagnitude(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    value: int


class Claim(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiaryId: str
    contestDeadline: int
    contestDigest: str | None = None
    coverageAuthorityId: str
    fundingFacilityId: str
    identity: Identity
    lifecycleFence: int
    openedAt: int
    payerId: str
    payoutAmount: PayoutAmount
    payoutMode: PayoutMode
    payoutRail: PayoutRail
    schema_: str = Field(..., alias="schema")
    state: str
    triggerMagnitude: TriggerMagnitude
    version: int


class Disposition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    round_id: str


class EscrowReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: str
    escrowContract: str
    escrowId: str


class IntentProgressItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ambiguityCount: int
    attemptCount: int
    completedEffectSlotId: str
    intentDigest: str
    intentId: str
    noEffectCount: int
    reconciliationChainDigest: str
    reconciliationCount: int


class LastTransition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_digest: str
    kind: str
    round_id: str


class Request(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    requestBindingDigest: str
    requestId: str
    requestNamespaceDigest: str


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    qualificationDigest: str
    targetId: str
    targetKeyEpoch: int


class Value(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cancellation: str


class Proof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    storage: str
    value: Value


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    storage: str
    value: Any


class Terminal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str | None = None
    outcome: str
    proof: Proof | None = None
    proof_digest: str | None = None
    proof_id: str | None = None
    result: Result | None = None
    result_digest: str | None = None
    result_id: str | None = None


class SequenceRange(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    first: int
    last: int


class Window(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    endAt: int
    startAt: int


class Range(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchorEpoch: int
    checkpointAt: int
    checkpointId: str
    checkpointRoot: str
    expectedCount: int
    indexNamespace: str
    queryIndexRoot: str
    rangeProofDigest: str
    selectedMemberRoot: str
    sequenceRange: SequenceRange
    signerKeyEpoch: int
    sourceId: str
    sourceKind: str
    sourcePrefixCutoff: int
    subjectKey: str
    window: Window


class EvidenceManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ranges: list[Range]


class Identity1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimId: str
    key: Key
    triggerInstanceId: str


class Magnitude(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    value: int


class CoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class EvaluatorAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: str
    keyEpoch: int
    keyId: str


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class PayoutSchedule(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    kind: str


class Predicate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    minEvents: int
    thresholdBps: int


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiaryId: str
    boundCoverageBodyDigest: str
    boundCoverageEnvelopeDigest: str
    coverageAmount: CoverageAmount
    coverageAuthorityId: str
    effectiveFrom: int
    effectiveUntil: int
    evaluatorAuthority: EvaluatorAuthority
    fundingFacilityId: str
    issuedAt: int
    maxCheckpointLagSeconds: int
    payerId: str
    payoutMode: PayoutMode
    payoutRail: PayoutRail
    payoutSchedule: PayoutSchedule
    preActionAuthorityDigest: str
    predicate: Predicate
    schema_: str = Field(..., alias="schema")
    subjectKey: str
    windowAnchor: int
    windowSeconds: int


class SignedPolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class Trigger(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidenceManifest: EvidenceManifest
    identity: Identity1
    magnitude: Magnitude
    schema_: str = Field(..., alias="schema")
    signedPolicy: SignedPolicy


class Value2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionDigest: str | None = None
    admissionHandoff: AdmissionHandoff | None = None
    admittedDisputeDigest: str | None = None
    anchorId: str | None = None
    atomDigest: str | None = None
    channelId: str | None = None
    claim: Claim | None = None
    disposition: Disposition | None = None
    effectKind: str | None = None
    escrowReference: EscrowReference | None = None
    fence: int | None = None
    finalizationDigest: str | None = None
    firstDispatchOperationId: str | None = None
    governanceScopeId: str | None = None
    idempotencyKey: str | None = None
    inputManifestDigest: str | None = None
    intentProgress: list[IntentProgressItem] | None = None
    lastTransition: LastTransition | None = None
    lastTransitionDigest: str | None = None
    latestSequence: int | None = None
    latestStateDigest: str | None = None
    lifecycleFence: int | None = None
    namespace: str | None = None
    obligationId: str | None = None
    openDigest: str | None = None
    operationId: str | None = None
    outputManifestDigest: str | None = None
    parametersDigest: str | None = None
    participantAcceptanceCount: int | None = None
    participantAcceptanceRoot: str | None = None
    pendingCloseBodyDigest: str | None = None
    request: Request | None = None
    reservationCount: int | None = None
    reservationRoot: str | None = None
    resourceHeadDigest: str | None = None
    resourceId: str | None = None
    resourceKey: ResourceKey | None = None
    resourceVersion: int | None = None
    roundCoreDigest: str | None = None
    roundId: str | None = None
    rowVersion: int | None = None
    schema_: str | None = Field(None, alias="schema")
    slotId: str | None = None
    state: str | None = None
    stateVersion: int | None = None
    status: str | None = None
    target: Target | None = None
    terminal: Terminal | None = None
    trigger: Trigger | None = None
    trustedOpenedAt: int | None = None
    version: int | None = None


class State(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    storage: str
    value: Value2


class TerminalResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    result: Result
    resultDigest: str
    resultId: str


class Head(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchorId: str
    effectIdempotencyKey: str | None = None
    frost: Frost | None = None
    headVersion: int
    lifecycleFence: int
    lifecycleState: str
    namespace: str
    operationId: str | None = None
    predecessorDigest: str | None = None
    resourceKey: ResourceKey
    resourceVersion: int
    schema_: str = Field(..., alias="schema")
    state: State
    stateDigest: str
    terminalResult: TerminalResult | None = None
    trustedClockHighWater: int


class RequestReplay(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effectSlotIds: list[str]
    operationId: str
    request: Request


class ChioEconomyAnchorViewV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    absentRequestKeys: list[AbsentRequestKey]
    absentResourceKeys: list[AbsentResourceKey]
    anchorId: str
    checkpointDigest: str
    checkpointSequence: int
    heads: list[Head]
    headsRoot: str
    namespace: str
    observedAt: int
    requestReplays: list[RequestReplay]
    requestReplaysRoot: str
    schema_: Literal["chio.economy.anchor-view.v1"] = Field(..., alias="schema")
    signerKeyEpoch: int
    signerKeyId: str
