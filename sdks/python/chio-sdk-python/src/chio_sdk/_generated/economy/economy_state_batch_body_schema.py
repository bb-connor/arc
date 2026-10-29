# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


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


class Request(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    requestBindingDigest: str
    requestId: str
    requestNamespaceDigest: str


class ResourceKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resourceFamily: str
    resourceId: str
    scopeId: str


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    qualificationDigest: str
    targetId: str
    targetKeyEpoch: int


class EffectSlot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionDigest: str
    admissionHandoff: AdmissionHandoff
    anchorId: str
    effectKind: str
    idempotencyKey: str
    namespace: str
    operationId: str
    parametersDigest: str
    request: Request
    resourceHeadDigest: str
    resourceKey: ResourceKey
    schema_: str = Field(..., alias="schema")
    slotId: str
    state: str
    target: Target


class RequestReplay(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effectSlotIds: list[str]
    operationId: str
    request: Request


class Frost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionDigest: str
    authorizationId: str
    authorizationSlotId: str
    signedEnvelopeDigest: str


class AdmissionHandoff2(BaseModel):
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
    satisfaction_digest: str | None = None


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
    activeEffectSlotId: str | None = None
    ambiguityCount: int
    attemptCount: int
    completedEffectSlotId: str | None = None
    intentDigest: str
    intentId: str
    noEffectCount: int
    reconciliationChainDigest: str | None = None
    reconciliationCount: int


class LastTransition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_digest: str
    kind: str
    round_id: str
    satisfaction_digest: str | None = None


class AdmissionHandoff3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lifecycleFence: int
    operationVersion: int
    state: str
    storeFence: StoreFence


class Provider(BaseModel):
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
    actionDigest: str | None = None
    admissionHandoff: AdmissionHandoff3 | None = None
    authenticatedClockUnixMs: int | None = None
    cancellation: str | None = None
    channelId: str | None = None
    idempotencyKey: str | None = None
    issuedAt: int | None = None
    operationId: str | None = None
    parametersDigest: str | None = None
    provider: Provider | None = None
    request: Request | None = None
    reservationDigest: str | None = None
    reservationId: str | None = None
    reservationProposalDigest: str | None = None
    schema_: str | None = Field(None, alias="schema")
    serviceBindingDigest: str | None = None
    sourceChannelHeadDigest: str | None = None
    sourceCheckpointDigest: str | None = None
    sourceCheckpointSequence: int | None = None
    sourceEffectHeadDigest: str | None = None
    sourceEscrowHeadDigest: str | None = None


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


class Identity3(BaseModel):
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
    identity: Identity3
    magnitude: Magnitude
    schema_: str = Field(..., alias="schema")
    signedPolicy: SignedPolicy


class Value4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionDigest: str | None = None
    admissionHandoff: AdmissionHandoff2 | None = None
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
    value: Value4


class TerminalResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    result: Result
    resultDigest: str
    resultId: str


class NextHead(BaseModel):
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


class Authorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    mode: str


class PreparedEffect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionDigest: str
    authorization: Authorization
    effectSlotDigest: str
    effectSlotId: str
    operationId: str


class Transition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expectedHeadDigest: str | None = None
    nextHead: NextHead
    preparedEffect: PreparedEffect | None = None
    resourceKey: ResourceKey
    transitionProofDigest: str


class ChioEconomyStateBatchV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchorId: str
    batchId: str
    checkpointSequence: int
    effectSlots: list[EffectSlot]
    expectedHeadsRoot: str
    issuedAt: int
    namespace: str
    nextHeadsRoot: str
    operationId: str | None = None
    previousCheckpointDigest: str
    requestReplays: list[RequestReplay]
    schema_: Literal["chio.economy.state-batch.v1"] = Field(..., alias="schema")
    signerKeyEpoch: int
    signerKeyId: str
    transitions: list[Transition]
