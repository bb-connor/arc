# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

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


class Body114(BaseModel):
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
    body: Body114
    signature: str
    signerKey: str


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


class ObservedExecution(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    externalReferenceId: str
    observedAt: int


class AwardedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Exposure(BaseModel):
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
    activeFacilityMet: bool
    activeFacilityRequired: bool
    certificationMet: bool
    certificationRequired: bool
    currencyCoherent: bool
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


class SupportBoundary70(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    autonomyGatingSupported: bool
    externalEscrowExecutionSupported: bool
    reserveAccountingAuthoritative: bool


class CollateralAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class CreditLimit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class OutstandingExposureAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ReserveRequirementAmount(BaseModel):
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
    collateralAmount: CollateralAmount
    coverageRatioBps: int
    creditLimit: CreditLimit
    facilityId: str
    outstandingExposureAmount: OutstandingExposureAmount
    reserveRatioBps: int
    reserveRequirementAmount: ReserveRequirementAmount


class Report(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    exposure: Exposure
    filters: Filters
    generatedAt: int
    latestFacilityId: str
    prerequisites: Prerequisites
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary70
    terms: Terms


class Body121(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    expiresAt: int
    issuedAt: int
    lifecycleState: str
    report: Report
    schema_: str = Field(..., alias="schema")


class Bond(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body121
    signature: str
    signerKey: str


class CoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MaxCoverageAmount(BaseModel):
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


class Summary43(BaseModel):
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


class SupportBoundary71(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body127(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary43
    supportBoundary: SupportBoundary71


class Exposure23(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body127
    signature: str
    signerKey: str


class Prerequisites18(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificationMet: bool
    certificationRequired: bool
    manualReviewRequired: bool
    minimumRuntimeAssuranceTier: str
    runtimeAssuranceMet: bool


class SupportBoundary72(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class Terms18(BaseModel):
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
    prerequisites: Prerequisites18
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary72
    terms: Terms18


class Filters55(BaseModel):
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


class Summary44(BaseModel):
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
    summary: Summary44


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


class Filters56(BaseModel):
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


class Summary45(BaseModel):
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


class SupportBoundary73(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body128(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters56
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: str = Field(..., alias="schema")
    summary: Summary45
    supportBoundary: SupportBoundary73


class Scorecard28(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body128
    signature: str
    signerKey: str


class SupportBoundary74(BaseModel):
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


class Body126(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification
    exposure: Exposure23
    facilityReport: FacilityReport
    filters: Filters55
    generatedAt: int
    latestFacility: LatestFacility
    recentLossHistory: RecentLossHistory
    runtimeAssurance: RuntimeAssurance
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard28
    subjectKey: str
    supportBoundary: SupportBoundary74


class RiskPackage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body126
    signature: str
    signerKey: str


class Body125(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    notes: str
    providerPolicy: ProviderPolicy
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
    body: Body125
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


class Body124(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    issuedAt: int
    providerQuoteRef: str
    quoteRequest: QuoteRequest
    quoteResponseId: str
    quotedTerms: QuotedTerms
    schema_: str = Field(..., alias="schema")


class QuoteResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body124
    signature: str
    signerKey: str


class SelectedCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class SelectedPremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body123(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effectiveFrom: int
    effectiveUntil: int
    issuedAt: int
    placementId: str
    placementRef: str
    quoteResponse: QuoteResponse
    schema_: str = Field(..., alias="schema")
    selectedCoverageAmount: SelectedCoverageAmount
    selectedPremiumAmount: SelectedPremiumAmount


class Placement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body123
    signature: str
    signerKey: str


class PremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body122(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundAt: int
    boundCoverageId: str
    carrierReference: str
    coverageAmount: CoverageAmount
    effectiveFrom: int
    effectiveUntil: int
    issuedAt: int
    placement: Placement
    policyNumber: str
    premiumAmount: PremiumAmount
    schema_: str = Field(..., alias="schema")


class BoundCoverage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body122
    signature: str
    signerKey: str


class ClaimAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Summary46(BaseModel):
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


class SupportBoundary75(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body129(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters56
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary46
    supportBoundary: SupportBoundary75


class Exposure24(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body129
    signature: str
    signerKey: str


class Query14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    bondId: str
    eventKind: str


class CurrentDelinquentAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class EventAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class OutstandingDelinquentAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ReleaseableReserveAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Summary47(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    bondId: str
    capabilityId: str
    currentBondLifecycleState: str
    currentDelinquentAmount: CurrentDelinquentAmount
    eventAmount: EventAmount
    facilityId: str
    outstandingDelinquentAmount: OutstandingDelinquentAmount
    projectedBondLifecycleState: str
    releaseableReserveAmount: ReleaseableReserveAmount
    toolName: str
    toolServer: str


class SupportBoundary76(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    appealWindowSupported: bool
    automaticCapitalExecutionSupported: bool
    bondLifecycleProjectionAuthoritative: bool
    externalClaimAdjudicationSupported: bool
    immutableLifecycleAuthoritative: bool
    reserveControlExecutionSupported: bool


class Report16(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generatedAt: int
    query: Query14
    schema_: str = Field(..., alias="schema")
    summary: Summary47
    supportBoundary: SupportBoundary76


class Body130(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    description: str
    eventId: str
    eventKind: str
    issuedAt: int
    projectedBondLifecycleState: str
    report: Report16
    schema_: str = Field(..., alias="schema")


class LossEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body130
    signature: str
    signerKey: str


class Body120(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bond: Bond
    boundCoverage: BoundCoverage
    claimAmount: ClaimAmount
    claimEventAt: int
    claimId: str
    claimRef: str
    claimant: str
    exposure: Exposure24
    issuedAt: int
    lossEvent: LossEvent
    narrative: str
    receiptIds: list[str]
    schema_: str = Field(..., alias="schema")


class Claim(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body120
    signature: str
    signerKey: str


class CoveredAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body119(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claim: Claim
    claimResponseId: str
    coveredAmount: CoveredAmount
    disposition: str
    issuedAt: int
    providerResponseRef: str
    responseNote: str
    schema_: str = Field(..., alias="schema")


class ProviderResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body119
    signature: str
    signerKey: str


class Body118(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disputeId: str
    issuedAt: int
    openedBy: str
    providerResponse: ProviderResponse
    reason: str
    schema_: str = Field(..., alias="schema")


class Dispute(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body118
    signature: str
    signerKey: str


class Body117(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adjudicationId: str
    adjudicator: str
    awardedAmount: AwardedAmount
    dispute: Dispute
    issuedAt: int
    note: str
    outcome: str
    schema_: str = Field(..., alias="schema")


class Adjudication(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body117
    signature: str
    signerKey: str


class Query15(BaseModel):
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
    jurisdiction: str
    kind: str
    railId: str


class SupportBoundary77(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticDispatchSupported: bool
    capitalBookAuthoritative: bool
    custodyNeutralInstructionSupported: bool
    externalExecutionAuthoritative: bool


class Body131(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    amount: Amount
    authorityChain: list[dict[str, Any]]
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
    query: Query15
    rail: Rail
    reconciledState: str
    schema_: str = Field(..., alias="schema")
    sourceId: str
    sourceKind: str
    subjectKey: str
    supportBoundary: SupportBoundary77


class CapitalInstruction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body131
    signature: str
    signerKey: str


class PayoutAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body116(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adjudication: Adjudication
    capitalInstruction: CapitalInstruction
    issuedAt: int
    payoutAmount: PayoutAmount
    payoutInstructionId: str
    schema_: str = Field(..., alias="schema")


class PayoutInstruction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body116
    signature: str
    signerKey: str


class Body115(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    observedExecution: ObservedExecution
    payoutInstruction: PayoutInstruction
    payoutReceiptId: str
    payoutReceiptRef: str
    reconciliationState: str
    schema_: str = Field(..., alias="schema")


class PayoutReceipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body115
    signature: str
    signerKey: str


class SettlementAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Payee(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    jurisdiction: str
    partyId: str
    role: str


class Payer(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    jurisdiction: str
    partyId: str
    role: str


class Topology(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    payee: Payee
    payer: Payer


class ChioMarketClaimSettlementInstructionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityChain: list[AuthorityChainItem]
    capitalBook: CapitalBook
    executionWindow: ExecutionWindow
    issuedAt: int
    payoutReceipt: PayoutReceipt
    rail: Rail
    schema_: Literal["chio.market.claim-settlement-instruction.v1"] = Field(
        ..., alias="schema"
    )
    settlementAmount: SettlementAmount
    settlementInstructionId: str
    settlementKind: str
    settlementReference: str
    topology: Topology
