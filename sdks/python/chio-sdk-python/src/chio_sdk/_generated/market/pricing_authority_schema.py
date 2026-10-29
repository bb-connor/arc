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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Query(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    bondLimit: int
    facilityLimit: int
    lossEventLimit: int
    receiptLimit: int


class CommittedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class DisbursedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ImpairedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Source(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalSource: str
    committedAmount: CommittedAmount
    counterpartyId: str
    counterpartyRole: str
    currency: str
    description: str
    disbursedAmount: DisbursedAmount
    facilityId: str
    impairedAmount: ImpairedAmount
    jurisdiction: str
    kind: str
    ownerRole: str
    sourceId: str


class Summary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currencies: list[str]
    fundingSources: int
    ledgerEvents: int
    matchingBonds: int
    matchingFacilities: int
    matchingLossEvents: int
    matchingReceipts: int
    mixedCurrencyBook: bool
    returnedBonds: int
    returnedFacilities: int
    returnedLossEvents: int
    returnedReceipts: int
    truncatedBonds: bool
    truncatedFacilities: bool
    truncatedLossEvents: bool
    truncatedReceipts: bool


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticCapitalExecutionSupported: bool
    custodyExecutionSupported: bool
    mixedCurrencyNettingSupported: bool
    sourceOfFundsAuthoritative: bool


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    events: list[dict[str, Any]]
    generatedAt: int
    query: Query
    schema_: str = Field(..., alias="schema")
    sources: list[Source]
    subjectKey: str
    summary: Summary
    supportBoundary: SupportBoundary


class CapitalBook(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class Envelope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityChainRef: str
    delegateId: str
    kind: str


class Filters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int


class Prerequisites(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificationMet: bool
    certificationRequired: bool
    manualReviewRequired: bool
    minimumRuntimeAssuranceTier: str
    runtimeAssuranceMet: bool


class Scorecard(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anomalyCount: int
    band: str
    confidence: str
    currencies: list[str]
    matchingDecisions: int
    matchingReceipts: int
    mixedCurrencyBook: bool
    overallScore: float
    probationary: bool
    returnedDecisions: int
    returnedReceipts: int


class SupportBoundary96(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class CreditLimit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Terms(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalSource: str
    concentrationCapBps: int
    creditLimit: CreditLimit
    reserveRatioBps: int
    ttlSeconds: int
    utilizationCeilingBps: int


class Report(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    filters: Filters
    generatedAt: int
    prerequisites: Prerequisites
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary96
    terms: Terms


class Body181(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expiresAt: int
    facilityId: str
    issuedAt: int
    lifecycleState: str
    report: Report
    schema_: str = Field(..., alias="schema")


class Facility(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body181
    signature: str
    signerKey: str


class MaxCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MaxPremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ProviderPolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundCoverageSupported: bool
    claimsSupported: bool
    coverageClass: str
    currency: str
    displayName: str
    jurisdiction: str
    maxCoverageAmount: MaxCoverageAmount
    providerId: str
    providerRecordId: str
    quoteTtlSeconds: int
    requiredEvidence: list[str]


class ProviderPolicy14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundCoverageSupported: bool
    claimsSupported: bool
    coverageClass: str
    currency: str
    displayName: str
    jurisdiction: str
    maxCoverageAmount: MaxCoverageAmount
    providerId: str
    providerRecordId: str
    quoteTtlSeconds: int
    requiredEvidence: list[str]


class RequestedCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Certification(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    required: bool


class Position(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activeQuotedPremiumUnits: int
    currency: str
    failedUnits: int
    governedMaxExposureUnits: int
    pendingUnits: int
    provisionalLossUnits: int
    quotedPremiumUnits: int
    recoveredUnits: int
    reservedUnits: int
    settledUnits: int


class Summary61(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionableReceipts: int
    activeDecisions: int
    currencies: list[str]
    failedSettlementReceipts: int
    matchingDecisions: int
    matchingReceipts: int
    mixedCurrencyBook: bool
    pendingSettlementReceipts: int
    returnedDecisions: int
    returnedReceipts: int
    supersededDecisions: int
    truncatedDecisions: bool
    truncatedReceipts: bool


class SupportBoundary97(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body184(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary61
    supportBoundary: SupportBoundary97


class Exposure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body184
    signature: str
    signerKey: str


class SupportBoundary98(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class Terms24(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalSource: str
    concentrationCapBps: int
    creditLimit: CreditLimit
    reserveRatioBps: int
    ttlSeconds: int
    utilizationCeilingBps: int


class FacilityReport(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    filters: Filters
    generatedAt: int
    prerequisites: Prerequisites
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary98
    terms: Terms24


class Filters75(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int
    recentLossLimit: int


class LatestFacility(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    creditLimit: CreditLimit
    disposition: str
    expiresAt: int
    facilityId: str
    issuedAt: int
    lifecycleState: str
    signerKey: str


class Summary62(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    failedSettlementEvents: int
    matchingLossEvents: int
    provisionalLossEvents: int
    recoveredEvents: int
    returnedLossEvents: int


class RecentLossHistory(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    entries: list[dict[str, Any]]
    summary: Summary62


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
    stale: bool


class Filters76(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int


class Probation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    probationary: bool
    receiptCount: int
    spanDays: int
    targetReceiptCount: int
    targetSpanDays: int


class Reputation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedImportedSignalCount: int
    effectiveScore: float
    importedSignalCount: int
    probationary: bool


class Summary63(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anomalyCount: int
    band: str
    confidence: str
    currencies: list[str]
    matchingDecisions: int
    matchingReceipts: int
    mixedCurrencyBook: bool
    overallScore: float
    probationary: bool
    returnedDecisions: int
    returnedReceipts: int


class SupportBoundary99(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body185(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters76
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: str = Field(..., alias="schema")
    summary: Summary63
    supportBoundary: SupportBoundary99


class Scorecard38(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body185
    signature: str
    signerKey: str


class SupportBoundary100(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    autonomousPricingSupported: bool
    complianceScoreReferenceSupported: bool
    externalCapitalReviewSupported: bool
    facilityPolicyAuthoritative: bool
    liabilityMarketSupported: bool
    signedExposureAuthoritative: bool
    signedScorecardAuthoritative: bool


class Body183(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification
    exposure: Exposure
    facilityReport: FacilityReport
    filters: Filters75
    generatedAt: int
    latestFacility: LatestFacility
    recentLossHistory: RecentLossHistory
    runtimeAssurance: RuntimeAssurance
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard38
    subjectKey: str
    supportBoundary: SupportBoundary100


class RiskPackage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body183
    signature: str
    signerKey: str


class Body182(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    notes: str
    providerPolicy: ProviderPolicy14
    quoteRequestId: str
    requestedCoverageAmount: RequestedCoverageAmount
    requestedEffectiveFrom: int
    requestedEffectiveUntil: int
    riskPackage: RiskPackage
    schema_: str = Field(..., alias="schema")


class QuoteRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body182
    signature: str
    signerKey: str


class Budget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    ceilingFactor: int
    rationale: str


class Certification15(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    checkedAt: int
    publishedAt: int
    state: str
    toolServerId: str
    verdict: str


class Filters77(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    receiptLimit: int


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
    returnedReceipts: int
    runtimeAssuranceReceipts: int
    sharedEvidenceProofRequiredCount: int
    sharedEvidenceReferenceCount: int


class Reputation16(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedImportedSignalCount: int
    effectiveScore: float
    importedSignalCount: int
    probationary: bool
    resolvedTier: str
    subjectKey: str


class RuntimeAssurance16(BaseModel):
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
    certification: Certification15
    filters: Filters77
    generatedAt: int
    receipts: Receipts
    reputation: Reputation16
    runtimeAssurance: RuntimeAssurance16
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
    suggestedCeilingFactor: int


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
    basisPoints: int
    quotedAmount: QuotedAmount
    rationale: str
    state: str


class Body186(BaseModel):
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
    schema_: str = Field(..., alias="schema")


class UnderwritingDecision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body186
    signature: str
    signerKey: str


class ChioMarketPricingAuthoritySignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: str
    autoBindEnabled: bool
    capitalBook: CapitalBook
    envelope: Envelope
    expiresAt: int
    facility: Facility
    issuedAt: int
    maxCoverageAmount: MaxCoverageAmount
    maxPremiumAmount: MaxPremiumAmount
    notes: str
    providerPolicy: ProviderPolicy
    quoteRequest: QuoteRequest
    schema_: Literal["chio.market.pricing-authority.v1"] = Field(..., alias="schema")
    underwritingDecision: UnderwritingDecision
