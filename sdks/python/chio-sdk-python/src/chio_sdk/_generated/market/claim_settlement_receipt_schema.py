# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


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


class Body134(BaseModel):
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
    body: Body134
    signature: str
    signerKey: str


class ExecutionWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    notAfter: int
    notBefore: int


class ObservedExecution4(BaseModel):
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


class SupportBoundary79(BaseModel):
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
    supportBoundary: SupportBoundary79
    terms: Terms


class Body141(BaseModel):
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
    body: Body141
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


class Summary49(BaseModel):
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


class SupportBoundary80(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body147(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary49
    supportBoundary: SupportBoundary80


class Exposure26(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body147
    signature: str
    signerKey: str


class Prerequisites20(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificationMet: bool
    certificationRequired: bool
    manualReviewRequired: bool
    minimumRuntimeAssuranceTier: str
    runtimeAssuranceMet: bool


class SupportBoundary81(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class Terms20(BaseModel):
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
    prerequisites: Prerequisites20
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary81
    terms: Terms20


class Filters61(BaseModel):
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


class Summary50(BaseModel):
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
    summary: Summary50


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


class Filters62(BaseModel):
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


class Summary51(BaseModel):
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


class SupportBoundary82(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body148(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters62
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: str = Field(..., alias="schema")
    summary: Summary51
    supportBoundary: SupportBoundary82


class Scorecard31(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body148
    signature: str
    signerKey: str


class SupportBoundary83(BaseModel):
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


class Body146(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification
    exposure: Exposure26
    facilityReport: FacilityReport
    filters: Filters61
    generatedAt: int
    latestFacility: LatestFacility
    recentLossHistory: RecentLossHistory
    runtimeAssurance: RuntimeAssurance
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard31
    subjectKey: str
    supportBoundary: SupportBoundary83


class RiskPackage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body146
    signature: str
    signerKey: str


class Body145(BaseModel):
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
    body: Body145
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


class Body144(BaseModel):
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
    body: Body144
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


class Body143(BaseModel):
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
    body: Body143
    signature: str
    signerKey: str


class PremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body142(BaseModel):
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
    body: Body142
    signature: str
    signerKey: str


class ClaimAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Summary52(BaseModel):
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


class SupportBoundary84(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body149(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters62
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary52
    supportBoundary: SupportBoundary84


class Exposure27(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body149
    signature: str
    signerKey: str


class Query17(BaseModel):
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


class Summary53(BaseModel):
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


class SupportBoundary85(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    appealWindowSupported: bool
    automaticCapitalExecutionSupported: bool
    bondLifecycleProjectionAuthoritative: bool
    externalClaimAdjudicationSupported: bool
    immutableLifecycleAuthoritative: bool
    reserveControlExecutionSupported: bool


class Report18(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generatedAt: int
    query: Query17
    schema_: str = Field(..., alias="schema")
    summary: Summary53
    supportBoundary: SupportBoundary85


class Body150(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    description: str
    eventId: str
    eventKind: str
    issuedAt: int
    projectedBondLifecycleState: str
    report: Report18
    schema_: str = Field(..., alias="schema")


class LossEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body150
    signature: str
    signerKey: str


class Body140(BaseModel):
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
    exposure: Exposure27
    issuedAt: int
    lossEvent: LossEvent
    narrative: str
    receiptIds: list[str]
    schema_: str = Field(..., alias="schema")


class Claim(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body140
    signature: str
    signerKey: str


class CoveredAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body139(BaseModel):
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
    body: Body139
    signature: str
    signerKey: str


class Body138(BaseModel):
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
    body: Body138
    signature: str
    signerKey: str


class Body137(BaseModel):
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
    body: Body137
    signature: str
    signerKey: str


class Query18(BaseModel):
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


class SupportBoundary86(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticDispatchSupported: bool
    capitalBookAuthoritative: bool
    custodyNeutralInstructionSupported: bool
    externalExecutionAuthoritative: bool


class Body151(BaseModel):
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
    query: Query18
    rail: Rail
    reconciledState: str
    schema_: str = Field(..., alias="schema")
    sourceId: str
    sourceKind: str
    subjectKey: str
    supportBoundary: SupportBoundary86


class CapitalInstruction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body151
    signature: str
    signerKey: str


class PayoutAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body136(BaseModel):
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
    body: Body136
    signature: str
    signerKey: str


class Body135(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    observedExecution: ObservedExecution4
    payoutInstruction: PayoutInstruction
    payoutReceiptId: str
    payoutReceiptRef: str
    reconciliationState: str
    schema_: str = Field(..., alias="schema")


class PayoutReceipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body135
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


class Body132(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityChain: list[AuthorityChainItem]
    capitalBook: CapitalBook
    executionWindow: ExecutionWindow
    issuedAt: int
    payoutReceipt: PayoutReceipt
    rail: Rail
    schema_: str = Field(..., alias="schema")
    settlementAmount: SettlementAmount
    settlementInstructionId: str
    settlementKind: str
    settlementReference: str
    topology: Topology


class SettlementInstruction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body132
    signature: str
    signerKey: str


class ChioMarketClaimSettlementReceiptSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    observedExecution: ObservedExecution
    observedPayeeId: str
    observedPayerId: str
    reconciliationState: str
    schema_: Literal["chio.market.claim-settlement-receipt.v1"] = Field(
        ..., alias="schema"
    )
    settlementInstruction: SettlementInstruction
    settlementReceiptId: str
    settlementReceiptRef: str
