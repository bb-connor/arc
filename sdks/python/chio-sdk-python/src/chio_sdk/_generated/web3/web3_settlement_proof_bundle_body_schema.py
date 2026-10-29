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


class Certificate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chain_scope: list[str]
    chio_identity: str
    chio_public_key: str
    expires_at: int
    issued_at: int
    nonce: str
    purpose: list[str]
    schema_: str = Field(..., alias="schema")
    settlement_address: str


class BeneficiaryIdentityBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificate: Certificate
    signature: str


class Block(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    block_hash: str
    block_number: int
    transaction_hashes: list[str]


class MinimumRequiredAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class PostedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Bond(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bond_vault_contract: str
    bond_vault_runtime_codehash: str
    minimum_required_amount: MinimumRequiredAmount
    posted_amount: PostedAmount


class LockedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class RefundEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    block: Block
    escrow_id: str
    refund_tx_hash: str


class RemainingAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ReleaseEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    block: Block
    escrow_id: str
    partial: bool
    receipt_hash: str
    release_tx_hash: str
    remaining_amount: RemainingAmount


class ReleasedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Escrow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiary_address: str
    escrow_contract: str
    escrow_id: str
    escrow_runtime_codehash: str
    locked_amount: LockedAmount
    refund_event: RefundEvent | None = None
    refunded: bool
    release_event: ReleaseEvent | None = None
    released_amount: ReleasedAmount
    settlement_token_address: str


class IdentityRegistryOperator(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    active: bool
    block_hash: str
    block_number: int
    identity_registry_contract: str
    operator_address: str
    operator_epoch: int
    operator_key_hash: str
    settlement_key: str


class ChainSnapshot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiary_identity_binding: BeneficiaryIdentityBinding
    block: Block
    bond: Bond
    chain_id: str
    escrow: Escrow
    identity_registry_address: str
    identity_registry_operator: IdentityRegistryOperator | None = None
    identity_registry_runtime_codehash: str
    latest_block_number: int
    max_block_lag: int
    observed_block_number: int
    registry_root: str
    root_registry_address: str
    root_registry_runtime_codehash: str


class DeploymentProvenance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_hash: str
    bond_vault_contract: str
    bond_vault_runtime_codehash: str
    chain_id: str
    contract_package_id: str
    create2_factory: str
    escrow_contract: str
    escrow_runtime_codehash: str
    identity_registry_address: str
    identity_registry_runtime_codehash: str
    provenance_id: str
    reviewed_manifest_hash: str
    root_registry_address: str
    root_registry_runtime_codehash: str
    salt_namespace: str
    settlement_token_address: str


class ChainEventBlock(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    block_hash: str
    block_number: int
    transaction_hashes: list[str]


class DisputeSnapshot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chain_event_blocks: list[ChainEventBlock] | None = None
    chain_event_tx_hashes: list[str]
    challenge_window_secs: int
    dispute_id: str
    linked_receipt_ids: list[str]
    observed_at: int
    open_dispute_count: int
    posture: str
    schema_: str = Field(..., alias="schema")
    window_closed_at: int


class SettlementAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class OrderBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiary_address: str
    chain_id: str
    commerce_order_id: str
    custody_provider_id: str
    escrow_id: str
    settlement_amount: SettlementAmount
    settlement_rail_id: str
    settlement_reference: str
    settlement_tx_hash: str
    transaction_passport_id: str


class PublicWitness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchor_tx_hash: str
    anchored_checkpoint_seq: int
    anchored_merkle_root: str
    body_hash: str
    bond_vault_contract: str
    bond_vault_runtime_codehash: str
    chain_id: str
    escrow_contract: str
    escrow_runtime_codehash: str
    identity_registry_address: str
    identity_registry_operator: IdentityRegistryOperator | None = None
    identity_registry_runtime_codehash: str
    mode: str
    observed_at: int
    registry_root: str
    root_registry_address: str
    root_registry_runtime_codehash: str
    settlement_token_address: str
    witness_id: str


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


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    autonomyGatingSupported: bool
    externalEscrowExecutionSupported: bool
    reserveAccountingAuthoritative: bool


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
    supportBoundary: SupportBoundary


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    expiresAt: int
    issuedAt: int
    lifecycleState: str
    report: Report
    schema_: str = Field(..., alias="schema")


class Bond9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class Body217(BaseModel):
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
    body: Body217
    signature: str
    signerKey: str


class AuthorityChainItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvedAt: int
    authorityProof: AuthorityProof
    expiresAt: int
    note: str
    principalId: str
    role: str


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


class SupportBoundary116(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticDispatchSupported: bool
    capitalBookAuthoritative: bool
    custodyNeutralInstructionSupported: bool
    externalExecutionAuthoritative: bool


class Body216(BaseModel):
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
    evidenceRefs: list[EvidenceRef]
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
    supportBoundary: SupportBoundary116


class CapitalInstruction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body216
    signature: str
    signerKey: str


class SupportBoundary117(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchor_proof_required: bool
    custody_boundary_explicit: bool
    oracle_evidence_required_for_fx: bool
    real_dispatch_supported: bool
    reversal_supported: bool


class Dispatch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiary_address: str
    bond: Bond9 | None = None
    bond_vault_contract: str
    capital_instruction: CapitalInstruction
    chain_id: str
    contract_package_id: str
    dispatch_id: str
    escrow_contract: str
    escrow_id: str
    issued_at: int
    note: str
    operator_key_hash: str
    schema_: str = Field(..., alias="schema")
    settlement_amount: SettlementAmount
    settlement_path: str
    settlement_token_address: str
    support_boundary: SupportBoundary117
    trust_profile_id: str


class IdentityRegistryEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    active: bool
    block_hash: str
    block_number: int
    chain_id: str
    identity_registry_contract: str
    observed_at: int
    operator_address: str
    operator_epoch: int
    operator_key_hash: str
    registered_at: int
    settlement_key: str


class ObservedExecution(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    externalReferenceId: str
    observedAt: int


class OracleEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority: str
    base: str
    cache_age_seconds: int
    converted_cost_units: int
    feed_address: str
    grant_currency: str
    max_age_seconds: int
    oracle_public_key: str
    original_cost_units: int
    original_currency: str
    quote: str
    rate_denominator: int
    rate_numerator: int
    schema_: str = Field(..., alias="schema")
    signature: str
    source: str
    updated_at: int


class ChainAnchor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchored_checkpoint_seq: int
    anchored_merkle_root: str
    block_hash: str
    block_number: int
    chain_id: str
    contract_address: str
    operator_address: str
    operator_epoch: int
    operator_key_hash: str
    tx_hash: str


class CheckpointStatement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    batch_end_seq: int
    batch_start_seq: int
    checkpoint_seq: int
    issued_at: int
    kernel_key: str
    merkle_root: str
    schema_: str = Field(..., alias="schema")
    signature: str
    tree_size: int


class KeyBindingCertificate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificate: Certificate
    signature: str


class Parameters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: int
    currency: str
    to: str


class Action(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameter_hash: str
    parameters: Parameters


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: str


class OracleEvidence1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority: str
    base: str
    cache_age_seconds: int
    converted_cost_units: int
    feed_address: str
    grant_currency: str
    max_age_seconds: int
    oracle_public_key: str | None = None
    original_cost_units: int
    original_currency: str
    quote: str
    rate_denominator: int
    rate_numerator: int
    schema_: str = Field(..., alias="schema")
    signature: str | None = None
    source: str
    updated_at: int


class Financial(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget_remaining: int
    budget_total: int
    cost_charged: int
    currency: str
    delegation_depth: int
    grant_index: int
    oracle_evidence: OracleEvidence1
    payment_reference: str
    root_budget_holder: str
    settlement_status: str


class Metadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chio_receipt_signing_nonce: str
    financial: Financial


class Receipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: Action
    boundary_class: str
    capability_id: str
    content_hash: str
    decision: Decision
    id: str
    kernel_key: str
    metadata: Metadata
    policy_hash: str
    receipt_kind: str
    redaction_mode: str
    signature: str
    timestamp: int
    tool_name: str
    tool_origin: str
    tool_server: str
    trust_level: str


class Proof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_path: list[dict[str, Any]]
    leaf_index: int
    tree_size: int


class ReceiptInclusion(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_seq: int
    merkle_root: str
    proof: Proof


class ReconciledAnchorProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chain_anchor: ChainAnchor
    checkpoint_statement: CheckpointStatement
    key_binding_certificate: KeyBindingCertificate
    receipt: Receipt
    receipt_inclusion: ReceiptInclusion
    schema_: str = Field(..., alias="schema")


class SettledAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class SettlementReceipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dispatch: Dispatch
    execution_receipt_id: str
    failure_reason: str | None = None
    identity_registry_evidence: IdentityRegistryEvidence | None = None
    issued_at: int
    lifecycle_state: str
    note: str
    observed_execution: ObservedExecution
    oracle_evidence: OracleEvidence | None = None
    reconciled_anchor_proof: ReconciledAnchorProof | None = None
    reversal_of: str | None = None
    schema_: str = Field(..., alias="schema")
    settled_amount: SettledAmount
    settlement_reference: str


class ChioWeb3SettlementProofBundleV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bundle_id: str
    chain_id: str
    chain_snapshot: ChainSnapshot
    collateral_position_ref: str | None = None
    commerce_order_id: str
    deployment_provenance: DeploymentProvenance
    dispute_posture: str
    dispute_snapshot: DisputeSnapshot
    guarantee_decision_ref: str | None = None
    observed_confirmations: int
    order_binding: OrderBinding
    public_witness: PublicWitness | None = None
    required_confirmations: int
    schema_: Literal["chio.web3-settlement-proof-bundle.v1"] = Field(
        ..., alias="schema"
    )
    settlement_receipt: SettlementReceipt
    sla_remedy_ref: str | None = None
    slash_authority_ref: str | None = None
    transaction_passport_id: str
