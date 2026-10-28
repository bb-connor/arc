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


class SupportBoundary1(BaseModel):
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
    supportBoundary: SupportBoundary1
    terms: Terms


class Body3(BaseModel):
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
    body: Body3
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


class ProviderPolicy1(BaseModel):
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


class Summary1(BaseModel):
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


class SupportBoundary2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary1
    supportBoundary: SupportBoundary2


class Exposure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body6
    signature: str
    signerKey: str


class SupportBoundary3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class Terms1(BaseModel):
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
    supportBoundary: SupportBoundary3
    terms: Terms1


class Filters3(BaseModel):
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


class Summary2(BaseModel):
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
    summary: Summary2


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


class Filters4(BaseModel):
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


class Summary3(BaseModel):
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


class SupportBoundary4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters4
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: str = Field(..., alias="schema")
    summary: Summary3
    supportBoundary: SupportBoundary4


class Scorecard2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body7
    signature: str
    signerKey: str


class SupportBoundary5(BaseModel):
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


class Body5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification
    exposure: Exposure
    facilityReport: FacilityReport
    filters: Filters3
    generatedAt: int
    latestFacility: LatestFacility
    recentLossHistory: RecentLossHistory
    runtimeAssurance: RuntimeAssurance
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard2
    subjectKey: str
    supportBoundary: SupportBoundary5


class RiskPackage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body5
    signature: str
    signerKey: str


class Body4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    notes: str
    providerPolicy: ProviderPolicy1
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
    body: Body4
    signature: str
    signerKey: str


class Budget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    ceilingFactor: int
    rationale: str


class Certification1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    checkedAt: int
    publishedAt: int
    state: str
    toolServerId: str
    verdict: str


class Filters5(BaseModel):
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


class Reputation1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedImportedSignalCount: int
    effectiveScore: float
    importedSignalCount: int
    probationary: bool
    resolvedTier: str
    subjectKey: str


class RuntimeAssurance1(BaseModel):
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
    certification: Certification1
    filters: Filters5
    generatedAt: int
    receipts: Receipts
    reputation: Reputation1
    runtimeAssurance: RuntimeAssurance1
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


class Body8(BaseModel):
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
    body: Body8
    signature: str
    signerKey: str


class Body1(BaseModel):
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
    schema_: str = Field(..., alias="schema")
    underwritingDecision: UnderwritingDecision


class Authority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body1
    signature: str
    signerKey: str


class Finding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: str
    description: str


class ProviderPolicy2(BaseModel):
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


class Certification2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    required: bool


class Filters6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int


class Summary4(BaseModel):
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


class SupportBoundary6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters6
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary4
    supportBoundary: SupportBoundary6


class Exposure1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body12
    signature: str
    signerKey: str


class Scorecard3(BaseModel):
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


class SupportBoundary7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class Terms2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalSource: str
    concentrationCapBps: int
    creditLimit: CreditLimit
    reserveRatioBps: int
    ttlSeconds: int
    utilizationCeilingBps: int


class FacilityReport1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    filters: Filters6
    generatedAt: int
    prerequisites: Prerequisites
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard3
    supportBoundary: SupportBoundary7
    terms: Terms2


class Filters8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int
    recentLossLimit: int


class LatestFacility1(BaseModel):
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


class Summary5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    failedSettlementEvents: int
    matchingLossEvents: int
    provisionalLossEvents: int
    recoveredEvents: int
    returnedLossEvents: int


class RecentLossHistory1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    entries: list[dict[str, Any]]
    summary: Summary5


class RuntimeAssurance2(BaseModel):
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


class Filters9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int


class Reputation2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedImportedSignalCount: int
    effectiveScore: float
    importedSignalCount: int
    probationary: bool


class Summary6(BaseModel):
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


class SupportBoundary8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters9
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation2
    schema_: str = Field(..., alias="schema")
    summary: Summary6
    supportBoundary: SupportBoundary8


class Scorecard4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body13
    signature: str
    signerKey: str


class SupportBoundary9(BaseModel):
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


class Body11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification2
    exposure: Exposure1
    facilityReport: FacilityReport1
    filters: Filters8
    generatedAt: int
    latestFacility: LatestFacility1
    recentLossHistory: RecentLossHistory1
    runtimeAssurance: RuntimeAssurance2
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard4
    subjectKey: str
    supportBoundary: SupportBoundary9


class RiskPackage1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body11
    signature: str
    signerKey: str


class Body10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    notes: str
    providerPolicy: ProviderPolicy2
    quoteRequestId: str
    requestedCoverageAmount: RequestedCoverageAmount
    requestedEffectiveFrom: int
    requestedEffectiveUntil: int
    riskPackage: RiskPackage1
    schema_: str = Field(..., alias="schema")


class QuoteRequest1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body10
    signature: str
    signerKey: str


class QuotedCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class QuotedDeductibleAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class QuotedPremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class QuotedTerms(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expiresAt: int
    quotedCoverageAmount: QuotedCoverageAmount
    quotedDeductibleAmount: QuotedDeductibleAmount
    quotedPremiumAmount: QuotedPremiumAmount


class Body9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    issuedAt: int
    providerQuoteRef: str
    quoteRequest: QuoteRequest1
    quoteResponseId: str
    quotedTerms: QuotedTerms
    schema_: str = Field(..., alias="schema")


class QuoteResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body9
    signature: str
    signerKey: str


class ChioMarketAutoBindSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority: Authority
    decisionId: str
    disposition: str
    findings: list[Finding]
    issuedAt: int
    quoteResponse: QuoteResponse
    schema_: Literal["chio.market.auto-bind.v1"] = Field(..., alias="schema")
