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


class ConcentrationCapAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class CurrentOutstandingAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class CurrentReserveAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class EvidenceRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    locator: str
    observedAt: int
    referenceId: str


class ExecutionWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    notAfter: int
    notBefore: int


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class InstructionDraft(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    amount: Amount
    description: str
    sourceId: str
    sourceKind: str


class ProjectedOutstandingAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


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


class RequestedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class RequiredReserveAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticDispatchSupported: bool
    capitalBookAuthoritative: bool
    externalExecutionAuthoritative: bool
    simulationFirstOnly: bool


class UtilizationCeilingAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioCreditCapitalAllocationSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocationId: str
    approvalTokenId: str
    authorityChain: list[AuthorityChainItem]
    bondId: str
    capabilityId: str
    concentrationCapAmount: ConcentrationCapAmount
    currentOutstandingAmount: CurrentOutstandingAmount
    currentReserveAmount: CurrentReserveAmount
    description: str
    evidenceRefs: list[EvidenceRef]
    executionWindow: ExecutionWindow
    facilityId: str
    governedReceiptId: str
    instructionDrafts: list[InstructionDraft]
    intentId: str
    issuedAt: int
    outcome: str
    projectedOutstandingAmount: ProjectedOutstandingAmount
    query: Query
    rail: Rail
    requestedAmount: RequestedAmount
    requiredReserveAmount: RequiredReserveAmount
    reserveSourceId: str
    schema_: Literal["chio.credit.capital-allocation.v1"] = Field(..., alias="schema")
    sourceId: str
    sourceKind: str
    subjectKey: str
    supportBoundary: SupportBoundary
    toolName: str
    toolServer: str
    utilizationCeilingAmount: UtilizationCeilingAmount
