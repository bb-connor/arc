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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


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


class PayoutRail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destinationAccountDigest: str
    kind: str
    railId: str


class Binding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    beneficiaryId: str
    boundCoverageBodyDigest: str
    capitalInstructionBodyDigest: str
    capitalInstructionEnvelopeDigest: str
    capitalInstructionId: str
    capitalInstructionTemplateDigest: str
    claimId: str
    completionFlowRowId: str
    coverageHeadDigest: str
    coverageReservationId: str
    coverageReservationLifecycleFence: int
    coverageReservationVersion: int
    custodianAuthorityKeyEpoch: int
    effectIdempotencyKey: str
    effectSlot: EffectSlot
    effectSlotId: str
    expectedClaimVersion: int
    expectedLifecycleFence: int
    facilityAuthorityKeyEpoch: int
    fundingFacilityId: str
    governedReceiptId: str
    instructionSignerKeyEpoch: int
    operationId: str
    parametricPolicyBodyDigest: str
    payerId: str
    payoutRail: PayoutRail
    request: Request
    schema_: str = Field(..., alias="schema")
    sourceAccountDigest: str
    triggerInstanceId: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvedAt: int
    expiresAt: int
    principalId: str
    role: str
    schema_: str = Field(..., alias="schema")


class AuthorityProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class AuthorityChainItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvedAt: int
    authorityProof: AuthorityProof
    expiresAt: int
    principalId: str
    role: str


class ExecutionWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    notAfter: int
    notBefore: int


class Query(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    bondLimit: int
    facilityLimit: int
    lossEventLimit: int
    receiptLimit: int


class Rail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    custodyProviderId: str
    destinationAccountRef: str
    jurisdiction: str
    kind: str
    railId: str
    sourceAccountRef: str


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticDispatchSupported: bool
    capitalBookAuthoritative: bool
    custodyNeutralInstructionSupported: bool
    externalExecutionAuthoritative: bool


class Body174(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    amount: Amount
    authorityChain: list[AuthorityChainItem]
    completionFlowRowId: str
    counterpartyId: str
    counterpartyRole: str
    description: str
    executionWindow: ExecutionWindow
    governedReceiptId: str
    instructionId: str
    intendedState: str
    issuedAt: int
    ownerRole: str
    query: Query
    rail: Rail
    reconciledState: str
    schema_: str = Field(..., alias="schema")
    sourceId: str
    sourceKind: str
    subjectKey: str
    supportBoundary: SupportBoundary


class CapitalInstruction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body174
    signature: str
    signerKey: str


class ChioParametricPayoutIntentSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    binding: Binding
    capitalInstruction: CapitalInstruction
    payoutIntentId: str
    schema_: Literal["chio.parametric.payout-intent.v1"] = Field(..., alias="schema")
