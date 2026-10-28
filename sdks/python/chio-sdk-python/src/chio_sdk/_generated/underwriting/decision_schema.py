# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Budget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    ceilingFactor: float | None = None
    rationale: str


class Certification(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    checkedAt: int
    publishedAt: int
    state: str
    toolServerId: str
    verdict: str


class Filters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    receiptLimit: int


class ReceiptRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    locator: str
    observedAt: int
    referenceId: str


class Receipts(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionableMeteredReceipts: int
    actionableSettlementReceipts: int
    allowCount: int
    approvalReceipts: int
    approvedReceipts: int
    callChainReceipts: int
    cancelledCount: int
    denyCount: int
    failedSettlementReceipts: int
    governedReceipts: int
    incompleteCount: int
    matchingReceipts: int
    meteredReceipts: int
    pendingSettlementReceipts: int
    receiptRefs: list[ReceiptRef] | None = None
    returnedReceipts: int
    runtimeAssuranceReceipts: int
    sharedEvidenceProofRequiredCount: int
    sharedEvidenceReferenceCount: int


class Reputation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedImportedSignalCount: int
    effectiveScore: float
    importedSignalCount: int
    probationary: bool
    resolvedTier: str
    subjectKey: str


class RuntimeAssurance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    governedReceipts: int
    highestTier: str
    latestEvidenceSha256: str
    latestSchema: str
    latestVerifier: str
    latestVerifierFamily: str
    observedVerifierFamilies: list[str]
    runtimeAssuranceReceipts: int


class Taxonomy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    supportedClasses: list[str]
    supportedReasons: list[str]
    version: str


class Input(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification | None = None
    filters: Filters
    generatedAt: int
    receipts: Receipts
    reputation: Reputation | None = None
    runtimeAssurance: RuntimeAssurance | None = None
    schema_: str = Field(..., alias="schema")
    taxonomy: Taxonomy


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    denyReputationScoreBelow: float
    maximumReceiptAgeSeconds: int
    minimumApproveReputationScore: float
    minimumApproveRuntimeAssuranceTier: str
    minimumReceiptHistory: int
    minimumStepUpRuntimeAssuranceTier: str
    reduceCeilingFactor: float
    requireActiveToolCertification: bool
    requireComplianceScoreReference: bool
    schema_: str = Field(..., alias="schema")
    version: str


class Evaluation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generatedAt: int
    input: Input
    outcome: str
    policy: Policy
    riskClass: str
    schema_: str = Field(..., alias="schema")
    suggestedCeilingFactor: float | None = None


class QuotedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Premium(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    basisPoints: int | None = None
    quotedAmount: QuotedAmount | None = None
    rationale: str
    state: str


class ChioUnderwritingDecisionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget: Budget
    decisionId: str
    evaluation: Evaluation
    issuedAt: int
    lifecycleState: str
    premium: Premium
    reviewState: str
    schema_: Literal["chio.underwriting.decision.v1"] = Field(..., alias="schema")
    supersedesDecisionId: str | None = None
