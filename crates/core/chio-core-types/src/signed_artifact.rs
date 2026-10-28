//! Signed-artifact schema registry and fail-closed validation.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::capability::{
    aggregate_invocation::AGGREGATE_BUDGET_ROOT_SCHEMA,
    cumulative_approval::CUMULATIVE_APPROVAL_ROOT_SCHEMA, features::CHIO_CAPABILITIES_SCHEMA,
    governance::THRESHOLD_APPROVAL_PROPOSAL_SCHEMA, token::CHIO_CAPABILITY_SCHEMA,
};
use crate::economic_continuity::{
    CHIO_ECONOMIC_EFFECT_DISPATCH_COMMIT_SCHEMA, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use crate::error::{Error, Result};
use crate::oracle::CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA;
use crate::receipt::{body::CHIO_RECEIPT_SCHEMA, lineage::CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA};
use crate::session::{CHIO_REQUEST_LINEAGE_RECORD_SCHEMA, CHIO_SESSION_ANCHOR_SCHEMA};

/// Anchor-batch signed artifact schema. Defined here so non-anchor verifiers
/// can reject unknown signed artifacts before loading the `chio-anchor` crate.
pub const CHIO_ANCHOR_BATCH_V1_SCHEMA: &str = "chio.anchor_batch.v1";
pub const CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA: &str = "chio.anchor-inclusion-proof.v1";
pub const CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA: &str = "chio.anchor-proof-bundle.v1";
pub const CHIO_BUDGET_SNAPSHOT_ANCHOR_PROVENANCE_V1_SCHEMA: &str =
    "chio.budget-snapshot-anchor-provenance.v1";
pub const CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA: &str = "chio.bilateral-signature-slice.v1";
pub const CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_V1_SCHEMA: &str =
    "chio.frost.authorization-slot-checkpoint.v1";
pub const CHIO_FROST_AUTHORIZATION_V1_SCHEMA: &str = "chio.frost.authorization.v1";
pub const CHIO_FROST_EPOCH_CHECKPOINT_V1_SCHEMA: &str = "chio.frost.epoch-checkpoint.v1";
pub const CHIO_FROST_DKG_ROUND2_SEALED_V1_SCHEMA: &str = "chio.frost.dkg-round2-sealed.v1";
pub const CHIO_FROST_ROSTER_V1_SCHEMA: &str = "chio.frost.roster.v1";
pub const CHIO_CLEARING_PARTICIPANT_SNAPSHOT_V1_SCHEMA: &str =
    "chio.clearing.participant-snapshot.v1";
pub const CHIO_CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    "chio.clearing.participant-snapshot-acknowledgement.v1";
pub const CHIO_CLEARING_INPUT_MANIFEST_V1_SCHEMA: &str = "chio.clearing.input-manifest.v1";
pub const CHIO_CLEARING_NETTING_ROUND_CORE_V1_SCHEMA: &str = "chio.clearing.netting-round-core.v1";
pub const CHIO_CLEARING_PARTICIPANT_STATEMENT_V1_SCHEMA: &str =
    "chio.clearing.participant-statement.v1";
pub const CHIO_CLEARING_SETTLEMENT_INTENT_V1_SCHEMA: &str = "chio.clearing.settlement-intent.v1";
pub const CHIO_CLEARING_SETTLEMENT_RECONCILIATION_V1_SCHEMA: &str =
    "chio.clearing.settlement-reconciliation.v1";
pub const CHIO_CLEARING_ROUND_SATISFACTION_V1_SCHEMA: &str = "chio.clearing.round-satisfaction.v1";
pub const CHIO_CLEARING_ZERO_INTENT_RECONCILIATION_V1_SCHEMA: &str =
    "chio.clearing.zero-intent-reconciliation.v1";
pub const CHIO_CLEARING_ATOM_TRANSFORMATION_V1_SCHEMA: &str =
    "chio.clearing.atom-transformation.v1";
pub const CHIO_CLEARING_OUTPUT_MANIFEST_V1_SCHEMA: &str = "chio.clearing.output-manifest.v1";
pub const CHIO_CLEARING_PARTICIPANT_ACCEPTANCE_V1_SCHEMA: &str =
    "chio.clearing.participant-acceptance.v1";
pub const CHIO_CLEARING_ROUND_FINALIZATION_V1_SCHEMA: &str = "chio.clearing.round-finalization.v1";
pub const CHIO_CLEARING_ZERO_DISPATCH_PROOF_V1_SCHEMA: &str =
    "chio.clearing.zero-dispatch-proof.v1";
pub const CHIO_CLEARING_ROUND_ABORT_V1_SCHEMA: &str = "chio.clearing.round-abort.v1";
pub const CHIO_CHANNEL_FUNDING_EVIDENCE_V1_SCHEMA: &str = "chio.channel.funding-evidence.v1";
pub const CHIO_CHANNEL_OPEN_INTENT_V1_SCHEMA: &str = "chio.channel.open-intent.v1";
pub const CHIO_CHANNEL_FUNDING_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    "chio.channel.funding-acknowledgement.v1";
pub const CHIO_CHANNEL_OPEN_V1_SCHEMA: &str = "chio.channel.open.v1";
pub const CHIO_CHANNEL_RESERVATION_V1_SCHEMA: &str = "chio.channel.reservation.v1";
pub const CHIO_CHANNEL_STATE_V1_SCHEMA: &str = "chio.channel.state.v1";
pub const CHIO_CHANNEL_CLOSE_V1_SCHEMA: &str = "chio.channel.close.v1";
pub const CHIO_CHANNEL_DISPUTE_V1_SCHEMA: &str = "chio.channel.dispute.v1";
pub const CHIO_CHANNEL_RELEASE_AUTHORIZATION_V1_SCHEMA: &str =
    "chio.channel.release-authorization.v1";
pub const CHIO_CHANNEL_TERMINAL_OUTCOME_COMMITMENT_V1_SCHEMA: &str =
    "chio.channel.terminal-outcome-commitment.v1";
pub const CHIO_FINCRED_CREDIT_SCORECARD_V1_SCHEMA: &str = "chio.fincred.credit-scorecard.v1";
pub const CHIO_FINCRED_EXPOSURE_HISTORY_V1_SCHEMA: &str = "chio.fincred.exposure-history.v1";
pub const CHIO_FINCRED_SETTLEMENT_RELIABILITY_V1_SCHEMA: &str =
    "chio.fincred.settlement-reliability.v1";
pub const CHIO_FINCRED_PREMIUM_HISTORY_V1_SCHEMA: &str = "chio.fincred.premium-history.v1";
pub const CHIO_FINCRED_LOSS_HISTORY_V1_SCHEMA: &str = "chio.fincred.loss-history.v1";
pub const CHIO_FINCRED_SOURCE_MEMBER_V1_SCHEMA: &str = "chio.fincred.source-member.v1";
pub const CHIO_FINCRED_SOURCE_CHECKPOINT_V1_SCHEMA: &str = "chio.fincred.source-checkpoint.v1";
pub const CHIO_FINCRED_SOURCE_COMPLETENESS_ATTESTATION_V1_SCHEMA: &str =
    "chio.fincred.source-completeness-attestation.v1";
pub const CHIO_FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_V1_SCHEMA: &str =
    "chio.financial-agent-passport.source-manifest.v1";
pub const CHIO_FINANCIAL_AGENT_PASSPORT_PRESENTATION_CHALLENGE_V1_SCHEMA: &str =
    "chio.financial-agent-passport-presentation-challenge.v1";
/// Cognition-market finding artifact.
pub const CHIO_FINDING_V1_SCHEMA: &str = "chio.finding.v1";
/// Cognition-market venue admission bundle.
pub const CHIO_FINDING_ADMISSION_V1_SCHEMA: &str = "chio.finding.admission.v1";
/// Cognition-market audit-round precommitment.
pub const CHIO_FINDING_AUDIT_EPOCH_V1_SCHEMA: &str = "chio.finding.audit-epoch.v1";
/// Cognition-market audit-round result.
pub const CHIO_FINDING_AUDIT_REPORT_V1_SCHEMA: &str = "chio.finding.audit-report.v1";
/// Cognition-market governance authorization for one audit round.
pub const CHIO_FINDING_AUDIT_ROUND_AUTHORIZATION_V1_SCHEMA: &str =
    "chio.finding.audit-round-authorization.v1";
/// Cognition-market signed authority-revocation status reading.
pub const CHIO_FINDING_AUTHORITY_STATUS_V1_SCHEMA: &str = "chio.finding.authority-status.v1";
/// Cognition-market bond-backing collateral allocation.
pub const CHIO_FINDING_BOND_BACKING_V1_SCHEMA: &str = "chio.finding.bond-backing.v1";
/// Cognition-market challenge enforcement instruction.
pub const CHIO_FINDING_CHALLENGE_ENFORCEMENT_V1_SCHEMA: &str =
    "chio.finding.challenge-enforcement.v1";
/// Cognition-market challenge outcome.
pub const CHIO_FINDING_CHALLENGE_OUTCOME_V1_SCHEMA: &str = "chio.finding.challenge-outcome.v1";
/// Cognition-market reusable challenge-verifier profile.
pub const CHIO_FINDING_CHALLENGE_VERIFIER_PROFILE_V1_SCHEMA: &str =
    "chio.finding.challenge-verifier-profile.v1";
/// Cognition-market challenge submission.
pub const CHIO_FINDING_CHALLENGE_V1_SCHEMA: &str = "chio.finding.challenge.v1";
/// Cognition-market signed claim allocation.
pub const CHIO_FINDING_CLAIM_ALLOCATION_V1_SCHEMA: &str = "chio.finding.claim-allocation.v1";
/// Cognition-market failed-delivery terminal.
pub const CHIO_FINDING_FAILED_DELIVERY_V1_SCHEMA: &str = "chio.finding.failed-delivery.v1";
/// Cognition-market finalized bond snapshot.
pub const CHIO_FINDING_FINALIZED_BOND_SNAPSHOT_V1_SCHEMA: &str =
    "chio.finding.finalized-bond-snapshot.v1";
/// Cognition-market governance statement withdrawing a pinned authority key.
pub const CHIO_FINDING_KEY_REVOCATION_V1_SCHEMA: &str = "chio.finding.key-revocation.v1";
/// Cognition-market signed liability projection.
pub const CHIO_FINDING_LIABILITY_V1_SCHEMA: &str = "chio.finding.liability.v1";
/// Cognition-market signed sparse status-map root.
pub const CHIO_FINDING_STATUS_EPOCH_V1_SCHEMA: &str = "chio.finding.status-epoch.v1";
/// Cognition-market seller market terms.
pub const CHIO_FINDING_MARKET_TERMS_V1_SCHEMA: &str = "chio.finding.market-terms.v1";
/// Cognition-market authenticated pool allocation.
pub const CHIO_FINDING_POOL_ALLOCATION_V1_SCHEMA: &str = "chio.finding.pool-allocation.v1";
/// Cognition-market settled purchase record.
pub const CHIO_FINDING_PURCHASE_RECORD_V1_SCHEMA: &str = "chio.finding.purchase-record.v1";
/// Cognition-market signed hosted purchase terminal.
pub const CHIO_FINDING_PURCHASE_RESULT_V1_SCHEMA: &str = "chio.finding.purchase-result.v1";
/// Cognition-market issuer-signed seller authorization.
pub const CHIO_FINDING_SELLER_AUTHORIZATION_V1_SCHEMA: &str =
    "chio.finding.seller-authorization.v1";
/// Cognition-market seller-signed verified-fix submission.
pub const CHIO_FINDING_VERIFIED_FIX_SUBMISSION_V1_SCHEMA: &str =
    "chio.finding.verified-fix-submission.v1";
/// Cognition-market verifier facet report.
pub const CHIO_FINDING_VERIFIER_REPORT_V1_SCHEMA: &str = "chio.finding.verifier-report.v1";
/// Cognition-market seller-signed voluntary retraction.
pub const CHIO_FINDING_VOLUNTARY_RETRACTION_V1_SCHEMA: &str =
    "chio.finding.voluntary-retraction.v1";
/// Open-market penalty artifact. Its body is frozen camelCase and tolerates
/// unknown members; the registered schema mirrors that shape exactly.
pub const CHIO_REGISTRY_MARKET_PENALTY_V1_SCHEMA: &str = "chio.registry.market-penalty.v1";
pub const CHIO_FISCAL_CHARTER_V1_SCHEMA: &str = "chio.fiscal.charter.v1";
pub const CHIO_FISCAL_SCHEDULE_V1_SCHEMA: &str = "chio.fiscal.schedule.v1";
pub const CHIO_FISCAL_PROPOSAL_V1_SCHEMA: &str = "chio.fiscal.proposal.v1";
pub const CHIO_FISCAL_PROPOSAL_ADMISSION_V1_SCHEMA: &str = "chio.fiscal.proposal-admission.v1";
pub const CHIO_FISCAL_APPROVAL_V1_SCHEMA: &str = "chio.fiscal.approval.v1";
pub const CHIO_FISCAL_ACTIVATION_V1_SCHEMA: &str = "chio.fiscal.activation.v1";
pub const CHIO_FISCAL_CONSUMER_READINESS_V1_SCHEMA: &str = "chio.fiscal.consumer-readiness.v1";
pub const CHIO_FISCAL_CONTINUITY_CHECKPOINT_V1_SCHEMA: &str =
    "chio.fiscal.continuity-checkpoint.v1";
pub const CHIO_ECONSIM_QUALIFICATION_MATRIX_V1_SCHEMA: &str =
    "chio.econsim.qualification-matrix.v1";
pub const CHIO_OBLIGATION_STATUS_PROOF_V1_SCHEMA: &str = "chio.obligation.status-proof.v1";
pub const CHIO_CREDIT_FACILITY_BIND_V1_SCHEMA: &str = "chio.credit.facility-bind.v1";
pub const CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA: &str = "chio.credit.receivable-iou-envelope.v1";
pub const CHIO_FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_V1_SCHEMA: &str =
    "chio.factor.assignment-bind-authorization.v1";
pub const CHIO_FACTOR_ASSIGNMENT_AGREEMENT_V1_SCHEMA: &str = "chio.factor.assignment-agreement.v1";
pub const CHIO_FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    "chio.factor.assignment-acknowledgement.v1";
pub const CHIO_FACTOR_ASSIGNMENT_NOT_APPLIED_V1_SCHEMA: &str =
    "chio.factor.assignment-not-applied.v1";
pub const CHIO_OUTCOME_PREDICATE_V1_SCHEMA: &str = "chio.outcome.predicate.v1";
pub const CHIO_OUTCOME_PRICING_V1_SCHEMA: &str = "chio.outcome.pricing.v1";
pub const CHIO_OUTCOME_SLA_V1_SCHEMA: &str = "chio.outcome.sla.v1";
pub const CHIO_OUTCOME_ELIGIBILITY_V1_SCHEMA: &str = "chio.outcome.eligibility.v1";
pub const CHIO_OUTCOME_DELIVERY_CHECKPOINT_V1_SCHEMA: &str = "chio.outcome.delivery-checkpoint.v1";
pub const CHIO_OUTCOME_DELIVERY_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    "chio.outcome.delivery-acknowledgement.v1";
pub const CHIO_OUTCOME_DELIVERY_NONACCEPTANCE_V1_SCHEMA: &str =
    "chio.outcome.delivery-nonacceptance.v1";
pub const CHIO_OUTCOME_OUTPUT_PROVENANCE_V1_SCHEMA: &str = "chio.outcome.output-provenance.v1";
pub const CHIO_OUTCOME_CONTRACTUAL_ZERO_V1_SCHEMA: &str = "chio.outcome.contractual-zero.v1";
pub const CHIO_PARAMETRIC_POLICY_V1_SCHEMA: &str = "chio.parametric.policy.v1";
pub const CHIO_TRANSACTION_PASSPORT_V1_SCHEMA: &str = "chio.transaction-passport.v1";
pub const CHIO_TRANSACTION_EVIDENCE_GRAPH_V1_SCHEMA: &str = "chio.transaction.evidence-graph.v1";
pub const CHIO_TRANSACTION_CLAIM_SET_V1_SCHEMA: &str = "chio.transaction.claim-set.v1";
pub const CHIO_TRANSACTION_VERIFIER_POLICY_V1_SCHEMA: &str = "chio.transaction.verifier-policy.v1";
pub const CHIO_TRANSACTION_VERIFIER_REPORT_V1_SCHEMA: &str = "chio.transaction.verifier-report.v1";
pub const CHIO_TRANSACTION_RUNTIME_SECURITY_REPORT_V1_SCHEMA: &str =
    "chio.transaction.runtime-security-report.v1";
pub const CHIO_CAPABILITY_PROOF_V1_SCHEMA: &str = "chio.capability.proof.v1";
pub const CHIO_GUARD_DECISION_V1_SCHEMA: &str = "chio.guard.decision.v1";
pub const CHIO_POLICY_BUNDLE_V1_SCHEMA: &str = "chio.policy.bundle.v1";
pub const CHIO_TRUST_ROOT_V1_SCHEMA: &str = "chio.trust.root.v1";
pub const CHIO_REQUEST_DIGEST_V1_SCHEMA: &str = "chio.request.digest.v1";
pub const CHIO_RESPONSE_DIGEST_V1_SCHEMA: &str = "chio.response.digest.v1";
pub const CHIO_COMMERCE_ORDER_CONTEXT_V1_SCHEMA: &str = "chio.commerce.order-context.v1";
pub const CHIO_COMMERCE_EVENT_LOG_V1_SCHEMA: &str = "chio.commerce.event-log.v1";
pub const CHIO_COMMERCE_PAYMENT_LIFECYCLE_V1_SCHEMA: &str = "chio.commerce.payment-lifecycle.v1";
pub const CHIO_COMMERCE_MANDATE_ALLOWANCE_LEDGER_V1_SCHEMA: &str =
    "chio.commerce.mandate-allowance-ledger.v1";
pub const CHIO_COMMERCE_PROTOCOL_PAYLOAD_V1_SCHEMA: &str = "chio.commerce.protocol-payload.v1";
pub const CHIO_COMMERCE_SETTLEMENT_PACKET_V1_SCHEMA: &str = "chio.commerce.settlement-packet.v1";
pub const CHIO_COMMERCE_PROVIDER_PASSPORT_V1_SCHEMA: &str = "chio.commerce.provider-passport.v1";
pub const CHIO_COMMERCE_REPUTATION_SNAPSHOT_V1_SCHEMA: &str =
    "chio.commerce.reputation-snapshot.v1";
pub const CHIO_COMMERCE_FEDERATION_TRUST_BUNDLE_V1_SCHEMA: &str =
    "chio.commerce.federation-trust-bundle.v1";
pub const CHIO_COMMERCE_ORDER_PASSPORT_V1_SCHEMA: &str = "chio.commerce.order-passport.v1";
pub const CHIO_COMMERCE_PROVIDER_DISCOVERY_SNAPSHOT_V1_SCHEMA: &str =
    "chio.commerce.provider-discovery-snapshot.v1";
pub const CHIO_COMMERCE_PROVIDER_SELECTION_REPORT_V1_SCHEMA: &str =
    "chio.commerce.provider-selection-report.v1";
pub const CHIO_COMMERCE_SLA_COMMITMENT_V1_SCHEMA: &str = "chio.commerce.sla-commitment.v1";
pub const CHIO_COMMERCE_SLA_PERFORMANCE_REPORT_V1_SCHEMA: &str =
    "chio.commerce.sla-performance-report.v1";
pub const CHIO_WORKFLOW_PREFLIGHT_PLAN_V1_SCHEMA: &str = "chio.workflow.preflight-plan.v1";
pub const CHIO_WORKFLOW_PREFLIGHT_REPORT_V1_SCHEMA: &str = "chio.workflow.preflight-report.v1";
pub const CHIO_CRYPTO_VERIFICATION_CONTEXT_V1_SCHEMA: &str = "chio.crypto.verification-context.v1";
pub const CHIO_TRUST_KEY_STATE_V1_SCHEMA: &str = "chio.trust.key-state.v1";
pub const CHIO_TRUST_REVOCATION_SNAPSHOT_V1_SCHEMA: &str = "chio.trust.revocation-snapshot.v1";
pub const CHIO_TRUST_SCORECARD_SNAPSHOT_V1_SCHEMA: &str = "chio.trust.scorecard-snapshot.v1";
pub const CHIO_TRUST_REPUTATION_IMPORT_REPORT_V1_SCHEMA: &str =
    "chio.trust.reputation-import-report.v1";
pub const CHIO_DISCLOSURE_VERIFIER_PRIVACY_PROFILE_V1_SCHEMA: &str =
    "chio.disclosure.verifier-privacy-profile.v1";
pub const CHIO_DISCLOSURE_CRYPTO_CONTEXT_REPORT_V1_SCHEMA: &str =
    "chio.disclosure.crypto-context-report.v1";
pub const CHIO_ATTEST_SELECTIVE_DISCLOSURE_PROOF_V1_SCHEMA: &str =
    "chio.attest.selective-disclosure-proof.v1";
pub const CHIO_BBS_PROJECTION_MANIFEST_V1_SCHEMA: &str = "chio.bbs-projection.manifest.v1";
pub const CHIO_DISCLOSURE_CAPSULE_V1_SCHEMA: &str = "chio.disclosure.capsule.v1";
pub const CHIO_LINEAGE_SIGNED_SUBGRAPH_V1_SCHEMA: &str = "chio.lineage.signed-subgraph.v1";
pub const CHIO_DISCLOSURE_LEAKAGE_LEDGER_V1_SCHEMA: &str = "chio.disclosure.leakage-ledger.v1";
pub const CHIO_DISCLOSURE_LINEAGE_VERIFIER_REPORT_V1_SCHEMA: &str =
    "chio.disclosure.lineage-verifier-report.v1";
pub const CHIO_TRANSPARENCY_INCLUSION_PROOF_V1_SCHEMA: &str =
    "chio.transparency.inclusion-proof.v1";
pub const CHIO_TRANSPARENCY_RECEIPT_INCLUSION_PROOF_V1_SCHEMA: &str =
    "chio.transparency.receipt-inclusion-proof.v1";
pub const CHIO_POLICY_ACTIVATION_RECEIPT_V1_SCHEMA: &str = "chio.policy.activation-receipt.v1";
pub const CHIO_RUNTIME_EXECUTION_LEASE_V1_SCHEMA: &str = "chio.runtime.execution-lease.v1";
pub const CHIO_RUNTIME_TOOL_SERVER_ACK_V1_SCHEMA: &str = "chio.runtime.tool-server-ack.v1";
pub const CHIO_RUNTIME_TRUSTED_TIME_PROOF_V1_SCHEMA: &str = "chio.runtime.trusted-time-proof.v1";
pub const CHIO_RUNTIME_REVOCATION_FRESHNESS_PROOF_V1_SCHEMA: &str =
    "chio.runtime.revocation-freshness-proof.v1";
pub const CHIO_RUNTIME_SANDBOX_ATTESTATION_V1_SCHEMA: &str = "chio.runtime.sandbox-attestation.v1";
pub const CHIO_RUNTIME_ATTACK_SIMULATION_REPORT_V1_SCHEMA: &str =
    "chio.runtime.attack-simulation-report.v1";
pub const CHIO_RUNTIME_CHAOS_RUN_REPORT_V1_SCHEMA: &str = "chio.runtime.chaos-run-report.v1";
pub const CHIO_RISK_COMPTROLLER_REPORT_V1_SCHEMA: &str = "chio.risk.comptroller-report.v1";
pub const CHIO_RISK_COLLATERAL_POSITION_REPORT_V1_SCHEMA: &str =
    "chio.risk.collateral-position-report.v1";
pub const CHIO_RISK_GUARANTEE_DECISION_V1_SCHEMA: &str = "chio.risk.guarantee-decision.v1";
pub const CHIO_RISK_ADJUDICATION_JURISDICTION_RECEIPT_V1_SCHEMA: &str =
    "chio.risk.adjudication-jurisdiction-receipt.v1";
/// Schema id for the unified spend/exposure comptroller surface projection.
pub const CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA: &str = "chio.comptroller.surface-report.v1";
pub const CHIO_ENTERPRISE_DATA_GOVERNANCE_REPORT_V1_SCHEMA: &str =
    "chio.enterprise.data-governance-report.v1";
pub const CHIO_ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_V1_SCHEMA: &str =
    "chio.enterprise.evidence-export-bundle.v1";
pub const CHIO_ENTERPRISE_TELEMETRY_PROJECTION_V1_SCHEMA: &str =
    "chio.enterprise.telemetry-projection.v1";
pub const CHIO_ENTERPRISE_APPROVAL_CASE_V1_SCHEMA: &str = "chio.enterprise.approval-case.v1";
pub const CHIO_ENTERPRISE_CONTROL_EVIDENCE_MAP_V1_SCHEMA: &str =
    "chio.enterprise.control-evidence-map.v1";
pub const CHIO_AGENT_WEB_PROOF_ENVELOPE_SCHEMA: &str = "chio.agent-web-proof-envelope.v1";
pub const CHIO_AGENT_WEB_EXTERNAL_PROJECTION_MANIFEST_V1_SCHEMA: &str =
    "chio.agent-web.external-projection-manifest.v1";
pub const CHIO_AGENT_WEB_INTEROP_VERIFIER_REPORT_V1_SCHEMA: &str =
    "chio.agent-web.interop-verifier-report.v1";
pub const CHIO_PROOF_ROOM_BUNDLE_V1_SCHEMA: &str = "chio.proof-room.bundle.v1";
pub const CHIO_PROOF_ROOM_VERIFIER_REPORT_V1_SCHEMA: &str = "chio.proof-room.verifier-report.v1";
pub const CHIO_PROOF_ROOM_FIXTURE_CATALOG_V1_SCHEMA: &str = "chio.proof-room.fixture-catalog.v1";
pub const CHIO_PROOF_ROOM_FIXTURE_ROOT_CATALOG_V1_SCHEMA: &str =
    "chio.proof-room.fixture-root-catalog.v1";
pub const CHIO_PROOF_ROOM_RECEIPT_EVIDENCE_V1_SCHEMA: &str = "chio.proof-room.receipt-evidence.v1";
pub const CHIO_PROOF_DOCKER_QUICKSTART_EVIDENCE_V1_SCHEMA: &str =
    "chio.proof.docker-quickstart-evidence.v1";
pub const CHIO_PROOF_RELEASE_TRUTH_V1_SCHEMA: &str = "chio.proof.release-truth.v1";
pub const CHIO_PROOF_FIRST_RUN_CAPABILITY_PROOF_V1_SCHEMA: &str =
    "chio.proof.first-run.capability-proof.v1";
pub const CHIO_PROOF_FIRST_RUN_GUARD_REPORT_V1_SCHEMA: &str =
    "chio.proof.first-run.guard-report.v1";
pub const CHIO_PROOF_FIRST_RUN_TRUST_ROOTS_V1_SCHEMA: &str = "chio.proof.first-run.trust-roots.v1";
pub const CHIO_PROOF_FIRST_RUN_COMMAND_LOG_V1_SCHEMA: &str = "chio.proof.first-run.command-log.v1";
pub const CHIO_RUNTIME_TERMINAL_RECEIPT_V1_SCHEMA: &str = "chio.runtime.terminal-receipt.v1";
pub const CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA: &str = "chio.web3-settlement-dispatch.v1";
pub const CHIO_WEB3_SETTLEMENT_EXECUTION_RECEIPT_V1_SCHEMA: &str =
    "chio.web3-settlement-execution-receipt.v1";
pub const CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_V1_SCHEMA: &str =
    "chio.web3-settlement-proof-bundle.v1";
pub const CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_V1_SCHEMA: &str =
    "chio.public-settlement-verifier-report.v1";
pub const CHIO_SWARM_TASK_GRAPH_V1_SCHEMA: &str = "chio.swarm.task-graph.v1";
pub const CHIO_SWARM_CONTINUATION_TOKEN_V1_SCHEMA: &str = "chio.swarm.continuation-token.v1";
pub const CHIO_SWARM_DELEGATION_WITNESS_CHAIN_V1_SCHEMA: &str =
    "chio.swarm.delegation-witness-chain.v1";
pub const CHIO_SWARM_JOIN_RECEIPT_V1_SCHEMA: &str = "chio.swarm.join-receipt.v1";
pub const CHIO_SWARM_ROUTE_PLAN_RECEIPT_V1_SCHEMA: &str = "chio.swarm.route-plan-receipt.v1";
pub const CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_V1_SCHEMA: &str =
    "chio.swarm.terminal-graph-receipt.v1";
pub const CHIO_SWARM_BUDGET_POOL_V1_SCHEMA: &str = "chio.swarm.budget-pool.v1";
pub const CHIO_SWARM_REVOCATION_EPOCH_V1_SCHEMA: &str = "chio.swarm.revocation-epoch.v1";
pub const CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_V1_SCHEMA: &str =
    "chio.swarm.authority-verifier-report.v1";
pub const CHIO_TOOL_MANIFEST_SCHEMA: &str = "chio.manifest.v1";
/// Signing-wrapper schema id of a Chio DPoP proof.
pub const CHIO_DPOP_PROOF_SCHEMA: &str = "chio.dpop_proof.v1";

type SignedArtifactSchemaSpec = (&'static str, Option<(&'static str, &'static str)>);

const SIGNED_ARTIFACT_SCHEMA_SPECS: &[SignedArtifactSchemaSpec] = &[
    (
        AGGREGATE_BUDGET_ROOT_SCHEMA,
        Some(("aggregate_budget_root_binding", "protocol-primitives-v1")),
    ),
    (
        CHIO_BUDGET_SNAPSHOT_ANCHOR_PROVENANCE_V1_SCHEMA,
        Some((
            "budget_snapshot_anchor_provenance",
            "economic-state-continuity-v1",
        )),
    ),
    (
        CHIO_CAPABILITIES_SCHEMA,
        Some((
            "capability_negotiation",
            "schema-registry/v1/capability-negotiation",
        )),
    ),
    (
        CHIO_CAPABILITY_SCHEMA,
        Some(("capability_token", "schema-registry/v1/capability-token-v1")),
    ),
    (
        CUMULATIVE_APPROVAL_ROOT_SCHEMA,
        Some(("cumulative_approval_root_binding", "protocol-primitives-v1")),
    ),
    (
        THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
        Some(("threshold_approval_proposal", "protocol-primitives-v1")),
    ),
    (
        CHIO_RECEIPT_SCHEMA,
        Some(("receipt", "schema-registry/v1/receipt-v1")),
    ),
    (
        CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
        Some(("receipt_lineage", "schema-registry/v1/receipt-lineage-v1")),
    ),
    (
        CHIO_ANCHOR_BATCH_V1_SCHEMA,
        Some(("anchor_batch", "schema-registry/v1/anchor-batch-v1")),
    ),
    (
        CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA,
        Some(("anchor_inclusion_proof", "checkpoint-transparency-v1")),
    ),
    (
        CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA,
        Some(("anchor_proof_bundle", "checkpoint-transparency-v1")),
    ),
    (
        CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA,
        Some(("bilateral_dsse_signature_slice", "federation-dsse-slice")),
    ),
    (
        CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_V1_SCHEMA,
        Some((
            "frost_authorization_slot_checkpoint",
            "frost-quorum-substrate-v1",
        )),
    ),
    (
        CHIO_FROST_AUTHORIZATION_V1_SCHEMA,
        Some(("frost_authorization", "frost-quorum-substrate-v1")),
    ),
    (
        CHIO_FROST_EPOCH_CHECKPOINT_V1_SCHEMA,
        Some(("frost_epoch_checkpoint", "frost-quorum-substrate-v1")),
    ),
    (
        CHIO_FROST_DKG_ROUND2_SEALED_V1_SCHEMA,
        Some(("frost_dkg_round2_sealed", "frost-sealed-ceremony-v1")),
    ),
    (
        CHIO_FROST_ROSTER_V1_SCHEMA,
        Some(("frost_roster", "frost-quorum-substrate-v1")),
    ),
    (
        CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
        Some(("economic_resource_head", "economic-state-continuity-v1")),
    ),
    (
        CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
        Some(("economic_state_batch", "economic-state-continuity-v1")),
    ),
    (
        CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
        Some(("economic_effect_slot", "economic-state-continuity-v1")),
    ),
    (
        CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
        Some(("economic_state_anchor_view", "economic-state-continuity-v1")),
    ),
    (
        CHIO_ECONOMIC_EFFECT_DISPATCH_COMMIT_SCHEMA,
        Some((
            "economic_effect_dispatch_commit",
            "economic-state-continuity-v1",
        )),
    ),
    (
        CHIO_CLEARING_PARTICIPANT_SNAPSHOT_V1_SCHEMA,
        Some(("clearing_participant_snapshot", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_V1_SCHEMA,
        Some((
            "clearing_participant_snapshot_acknowledgement",
            "ws4-clearing-v1",
        )),
    ),
    (
        CHIO_CLEARING_INPUT_MANIFEST_V1_SCHEMA,
        Some(("clearing_input_manifest", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_NETTING_ROUND_CORE_V1_SCHEMA,
        Some(("clearing_netting_round_core", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_PARTICIPANT_STATEMENT_V1_SCHEMA,
        Some(("clearing_participant_statement", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_SETTLEMENT_INTENT_V1_SCHEMA,
        Some(("clearing_settlement_intent", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_SETTLEMENT_RECONCILIATION_V1_SCHEMA,
        Some(("clearing_settlement_reconciliation", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ROUND_SATISFACTION_V1_SCHEMA,
        Some(("clearing_round_satisfaction", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ZERO_INTENT_RECONCILIATION_V1_SCHEMA,
        Some(("clearing_zero_intent_reconciliation", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ATOM_TRANSFORMATION_V1_SCHEMA,
        Some(("clearing_atom_transformation", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_OUTPUT_MANIFEST_V1_SCHEMA,
        Some(("clearing_output_manifest", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_PARTICIPANT_ACCEPTANCE_V1_SCHEMA,
        Some(("clearing_participant_acceptance", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ROUND_FINALIZATION_V1_SCHEMA,
        Some(("clearing_round_finalization", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ZERO_DISPATCH_PROOF_V1_SCHEMA,
        Some(("clearing_zero_dispatch_proof", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ROUND_ABORT_V1_SCHEMA,
        Some(("clearing_round_abort", "ws4-clearing-v1")),
    ),
    (
        CHIO_CHANNEL_FUNDING_EVIDENCE_V1_SCHEMA,
        Some(("channel_funding_evidence", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_OPEN_INTENT_V1_SCHEMA,
        Some(("channel_open_intent", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_FUNDING_ACKNOWLEDGEMENT_V1_SCHEMA,
        Some((
            "channel_funding_acknowledgement",
            "micro-escrow-channels-v1",
        )),
    ),
    (
        CHIO_CHANNEL_OPEN_V1_SCHEMA,
        Some(("channel_open", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_RESERVATION_V1_SCHEMA,
        Some(("channel_reservation", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_STATE_V1_SCHEMA,
        Some(("channel_state", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_CLOSE_V1_SCHEMA,
        Some(("channel_close", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_DISPUTE_V1_SCHEMA,
        Some(("channel_dispute", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_RELEASE_AUTHORIZATION_V1_SCHEMA,
        Some(("channel_release_authorization", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_TERMINAL_OUTCOME_COMMITMENT_V1_SCHEMA,
        Some((
            "channel_terminal_outcome_commitment",
            "micro-escrow-channels-v1",
        )),
    ),
    (
        CHIO_FINCRED_CREDIT_SCORECARD_V1_SCHEMA,
        Some(("financial_credit_scorecard", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_EXPOSURE_HISTORY_V1_SCHEMA,
        Some(("financial_exposure_history", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_SETTLEMENT_RELIABILITY_V1_SCHEMA,
        Some((
            "financial_settlement_reliability",
            "financial-credentials-v1",
        )),
    ),
    (
        CHIO_FINCRED_PREMIUM_HISTORY_V1_SCHEMA,
        Some(("financial_premium_history", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_LOSS_HISTORY_V1_SCHEMA,
        Some(("financial_loss_history", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_SOURCE_MEMBER_V1_SCHEMA,
        Some(("financial_source_member", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_SOURCE_CHECKPOINT_V1_SCHEMA,
        Some(("financial_source_checkpoint", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_SOURCE_COMPLETENESS_ATTESTATION_V1_SCHEMA,
        Some((
            "financial_source_completeness_attestation",
            "financial-credentials-v1",
        )),
    ),
    (
        CHIO_FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_V1_SCHEMA,
        Some(("agent_passport_source_manifest", "financial-credentials-v1")),
    ),
    (
        CHIO_FINANCIAL_AGENT_PASSPORT_PRESENTATION_CHALLENGE_V1_SCHEMA,
        Some((
            "agent_passport_presentation_challenge",
            "financial-credentials-v1",
        )),
    ),
    (
        CHIO_FINDING_V1_SCHEMA,
        Some(("finding", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_ADMISSION_V1_SCHEMA,
        Some(("finding_admission", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_AUDIT_EPOCH_V1_SCHEMA,
        Some(("finding_audit_epoch", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_AUDIT_REPORT_V1_SCHEMA,
        Some(("finding_audit_report", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_AUDIT_ROUND_AUTHORIZATION_V1_SCHEMA,
        Some(("finding_audit_round_authorization", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_AUTHORITY_STATUS_V1_SCHEMA,
        Some(("finding_authority_status", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_BOND_BACKING_V1_SCHEMA,
        Some(("finding_bond_backing", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_CHALLENGE_ENFORCEMENT_V1_SCHEMA,
        Some(("finding_challenge_enforcement", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_CHALLENGE_OUTCOME_V1_SCHEMA,
        Some(("finding_challenge_outcome", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_CHALLENGE_VERIFIER_PROFILE_V1_SCHEMA,
        Some(("finding_challenge_verifier_profile", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_CHALLENGE_V1_SCHEMA,
        Some(("finding_challenge", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_CLAIM_ALLOCATION_V1_SCHEMA,
        Some((
            "finding_claim_allocation",
            "cognition-market-hosted-completion",
        )),
    ),
    (
        CHIO_FINDING_FAILED_DELIVERY_V1_SCHEMA,
        Some(("finding_failed_delivery", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_FINALIZED_BOND_SNAPSHOT_V1_SCHEMA,
        Some(("finding_finalized_bond_snapshot", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_KEY_REVOCATION_V1_SCHEMA,
        Some(("finding_key_revocation", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_LIABILITY_V1_SCHEMA,
        Some(("finding_liability", "cognition-market-hosted-completion")),
    ),
    (
        CHIO_FINDING_STATUS_EPOCH_V1_SCHEMA,
        Some(("finding_status_epoch", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_MARKET_TERMS_V1_SCHEMA,
        Some(("finding_market_terms", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_POOL_ALLOCATION_V1_SCHEMA,
        Some(("finding_pool_allocation", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_PURCHASE_RECORD_V1_SCHEMA,
        Some(("finding_purchase_record", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_PURCHASE_RESULT_V1_SCHEMA,
        Some((
            "finding_purchase_result",
            "cognition-market-hosted-completion",
        )),
    ),
    (
        CHIO_FINDING_SELLER_AUTHORIZATION_V1_SCHEMA,
        Some(("finding_seller_authorization", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_VERIFIED_FIX_SUBMISSION_V1_SCHEMA,
        Some((
            "finding_verified_fix_submission",
            "cognition-market-hosted-completion",
        )),
    ),
    (
        CHIO_FINDING_VERIFIER_REPORT_V1_SCHEMA,
        Some(("finding_verifier_report", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_VOLUNTARY_RETRACTION_V1_SCHEMA,
        Some((
            "finding_voluntary_retraction",
            "cognition-market-hosted-completion",
        )),
    ),
    (
        CHIO_REGISTRY_MARKET_PENALTY_V1_SCHEMA,
        Some(("open_market_penalty", "finding-market-v1")),
    ),
    (
        CHIO_FISCAL_CHARTER_V1_SCHEMA,
        Some(("fiscal_charter", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_SCHEDULE_V1_SCHEMA,
        Some(("fiscal_schedule", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_PROPOSAL_V1_SCHEMA,
        Some(("fiscal_proposal", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_PROPOSAL_ADMISSION_V1_SCHEMA,
        Some(("fiscal_proposal_admission", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_APPROVAL_V1_SCHEMA,
        Some(("fiscal_approval", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_ACTIVATION_V1_SCHEMA,
        Some(("fiscal_activation", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_CONSUMER_READINESS_V1_SCHEMA,
        Some(("fiscal_consumer_readiness", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_CONTINUITY_CHECKPOINT_V1_SCHEMA,
        Some(("fiscal_continuity_checkpoint", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_ECONSIM_QUALIFICATION_MATRIX_V1_SCHEMA,
        Some((
            "economic_simulation_qualification_matrix",
            "economic-wind-tunnel-v1",
        )),
    ),
    (
        CHIO_OBLIGATION_STATUS_PROOF_V1_SCHEMA,
        Some(("obligation_status_proof", "receivables-factoring-v1")),
    ),
    (
        CHIO_CREDIT_FACILITY_BIND_V1_SCHEMA,
        Some(("credit_facility_bind", "credit-admission-v1")),
    ),
    (
        CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA,
        Some(("credit_iou_envelope", "receivables-factoring-v1")),
    ),
    (
        CHIO_FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_V1_SCHEMA,
        Some((
            "factor_assignment_bind_authorization",
            "receivables-factoring-v1",
        )),
    ),
    (
        CHIO_FACTOR_ASSIGNMENT_AGREEMENT_V1_SCHEMA,
        Some(("factor_assignment_agreement", "receivables-factoring-v1")),
    ),
    (
        CHIO_FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_V1_SCHEMA,
        Some((
            "factor_assignment_acknowledgement",
            "receivables-factoring-v1",
        )),
    ),
    (
        CHIO_FACTOR_ASSIGNMENT_NOT_APPLIED_V1_SCHEMA,
        Some(("factor_assignment_not_applied", "receivables-factoring-v1")),
    ),
    (
        CHIO_OUTCOME_PREDICATE_V1_SCHEMA,
        Some(("outcome_predicate", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_PRICING_V1_SCHEMA,
        Some(("outcome_pricing", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_SLA_V1_SCHEMA,
        Some(("outcome_sla", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_ELIGIBILITY_V1_SCHEMA,
        Some(("outcome_eligibility", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_DELIVERY_CHECKPOINT_V1_SCHEMA,
        Some(("outcome_delivery_checkpoint", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_DELIVERY_ACKNOWLEDGEMENT_V1_SCHEMA,
        Some((
            "outcome_delivery_acknowledgement",
            "verified-outcome-pricing-v1",
        )),
    ),
    (
        CHIO_OUTCOME_DELIVERY_NONACCEPTANCE_V1_SCHEMA,
        Some((
            "outcome_delivery_nonacceptance",
            "verified-outcome-pricing-v1",
        )),
    ),
    (
        CHIO_OUTCOME_OUTPUT_PROVENANCE_V1_SCHEMA,
        Some(("outcome_output_provenance", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_CONTRACTUAL_ZERO_V1_SCHEMA,
        Some(("outcome_contractual_zero", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_PARAMETRIC_POLICY_V1_SCHEMA,
        Some(("parametric_policy", "parametric-insurance-v1")),
    ),
    (
        CHIO_SESSION_ANCHOR_SCHEMA,
        Some(("session_anchor", "signing-wrapper-v1")),
    ),
    (
        CHIO_REQUEST_LINEAGE_RECORD_SCHEMA,
        Some(("request_lineage_record", "signing-wrapper-v1")),
    ),
    (
        CHIO_TRANSACTION_PASSPORT_V1_SCHEMA,
        Some(("transaction_passport", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_EVIDENCE_GRAPH_V1_SCHEMA,
        Some(("transaction_evidence_graph", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_CLAIM_SET_V1_SCHEMA,
        Some(("transaction_claim_set", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_VERIFIER_POLICY_V1_SCHEMA,
        Some(("transaction_verifier_policy", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_VERIFIER_REPORT_V1_SCHEMA,
        Some(("transaction_verifier_report", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_RUNTIME_SECURITY_REPORT_V1_SCHEMA,
        Some(("transaction_runtime_security_report", "runtime-security-v1")),
    ),
    (
        CHIO_CAPABILITY_PROOF_V1_SCHEMA,
        Some(("capability_proof", "transaction-passport-v1")),
    ),
    (
        CHIO_GUARD_DECISION_V1_SCHEMA,
        Some(("guard_decision", "transaction-passport-v1")),
    ),
    (
        CHIO_POLICY_BUNDLE_V1_SCHEMA,
        Some(("policy_bundle", "transaction-passport-v1")),
    ),
    (
        CHIO_TRUST_ROOT_V1_SCHEMA,
        Some(("trust_root", "transaction-passport-v1")),
    ),
    (
        CHIO_REQUEST_DIGEST_V1_SCHEMA,
        Some(("request_digest", "transaction-passport-v1")),
    ),
    (
        CHIO_RESPONSE_DIGEST_V1_SCHEMA,
        Some(("response_digest", "transaction-passport-v1")),
    ),
    (
        CHIO_COMMERCE_ORDER_CONTEXT_V1_SCHEMA,
        Some(("commerce_order_context", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_EVENT_LOG_V1_SCHEMA,
        Some(("commerce_event_log", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_PAYMENT_LIFECYCLE_V1_SCHEMA,
        Some(("commerce_payment_lifecycle", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_MANDATE_ALLOWANCE_LEDGER_V1_SCHEMA,
        Some(("commerce_mandate_allowance_ledger", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_PROTOCOL_PAYLOAD_V1_SCHEMA,
        Some(("commerce_protocol_payload", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_SETTLEMENT_PACKET_V1_SCHEMA,
        Some(("commerce_settlement_packet", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_PROVIDER_PASSPORT_V1_SCHEMA,
        Some(("commerce_provider_passport", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_REPUTATION_SNAPSHOT_V1_SCHEMA,
        Some(("commerce_reputation_snapshot", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_FEDERATION_TRUST_BUNDLE_V1_SCHEMA,
        Some(("commerce_federation_trust_bundle", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_ORDER_PASSPORT_V1_SCHEMA,
        Some(("commerce_order_passport", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_PROVIDER_DISCOVERY_SNAPSHOT_V1_SCHEMA,
        Some(("commerce_provider_discovery_snapshot", "trust-market-v1")),
    ),
    (
        CHIO_COMMERCE_PROVIDER_SELECTION_REPORT_V1_SCHEMA,
        Some(("commerce_provider_selection_report", "trust-market-v1")),
    ),
    (
        CHIO_COMMERCE_SLA_COMMITMENT_V1_SCHEMA,
        Some(("commerce_sla_commitment", "trust-market-v1")),
    ),
    (
        CHIO_COMMERCE_SLA_PERFORMANCE_REPORT_V1_SCHEMA,
        Some(("commerce_sla_performance_report", "trust-market-v1")),
    ),
    (
        CHIO_WORKFLOW_PREFLIGHT_PLAN_V1_SCHEMA,
        Some(("workflow_preflight_plan", "workflow-preflight-v1")),
    ),
    (
        CHIO_WORKFLOW_PREFLIGHT_REPORT_V1_SCHEMA,
        Some(("workflow_preflight_report", "workflow-preflight-v1")),
    ),
    (
        CHIO_CRYPTO_VERIFICATION_CONTEXT_V1_SCHEMA,
        Some(("crypto_verification_context", "crypto-context-v1")),
    ),
    (
        CHIO_TRUST_KEY_STATE_V1_SCHEMA,
        Some(("trust_key_state", "crypto-context-v1")),
    ),
    (
        CHIO_TRUST_REVOCATION_SNAPSHOT_V1_SCHEMA,
        Some(("trust_revocation_snapshot", "crypto-context-v1")),
    ),
    (
        CHIO_TRUST_SCORECARD_SNAPSHOT_V1_SCHEMA,
        Some(("trust_scorecard_snapshot", "trust-market-v1")),
    ),
    (
        CHIO_TRUST_REPUTATION_IMPORT_REPORT_V1_SCHEMA,
        Some(("trust_reputation_import_report", "trust-market-v1")),
    ),
    (
        CHIO_DISCLOSURE_VERIFIER_PRIVACY_PROFILE_V1_SCHEMA,
        Some(("disclosure_verifier_privacy_profile", "crypto-context-v1")),
    ),
    (
        CHIO_DISCLOSURE_CRYPTO_CONTEXT_REPORT_V1_SCHEMA,
        Some(("disclosure_crypto_context_report", "crypto-context-v1")),
    ),
    (
        CHIO_ATTEST_SELECTIVE_DISCLOSURE_PROOF_V1_SCHEMA,
        Some((
            "chio_attest_selective_disclosure_proof",
            "chio-final-architecture/v1",
        )),
    ),
    (
        CHIO_BBS_PROJECTION_MANIFEST_V1_SCHEMA,
        Some(("bbs_projection_manifest", "crypto-context-v1")),
    ),
    (
        CHIO_DISCLOSURE_CAPSULE_V1_SCHEMA,
        Some(("disclosure_capsule", "disclosure-lineage-v1")),
    ),
    (
        CHIO_LINEAGE_SIGNED_SUBGRAPH_V1_SCHEMA,
        Some(("lineage_signed_subgraph", "disclosure-lineage-v1")),
    ),
    (
        CHIO_DISCLOSURE_LEAKAGE_LEDGER_V1_SCHEMA,
        Some(("disclosure_leakage_ledger", "disclosure-lineage-v1")),
    ),
    (
        CHIO_DISCLOSURE_LINEAGE_VERIFIER_REPORT_V1_SCHEMA,
        Some((
            "disclosure_lineage_verifier_report",
            "disclosure-lineage-v1",
        )),
    ),
    (
        CHIO_TRANSPARENCY_INCLUSION_PROOF_V1_SCHEMA,
        Some(("transparency_inclusion_proof", "crypto-context-v1")),
    ),
    (
        CHIO_TRANSPARENCY_RECEIPT_INCLUSION_PROOF_V1_SCHEMA,
        Some((
            "transparency_anchored_inclusion_proof",
            "checkpoint-transparency-v1",
        )),
    ),
    (
        CHIO_POLICY_ACTIVATION_RECEIPT_V1_SCHEMA,
        Some(("policy_activation_receipt", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_EXECUTION_LEASE_V1_SCHEMA,
        Some(("runtime_execution_lease", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_TOOL_SERVER_ACK_V1_SCHEMA,
        Some(("runtime_tool_server_ack", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_TRUSTED_TIME_PROOF_V1_SCHEMA,
        Some(("runtime_trusted_time_proof", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_REVOCATION_FRESHNESS_PROOF_V1_SCHEMA,
        Some(("runtime_revocation_freshness_proof", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_SANDBOX_ATTESTATION_V1_SCHEMA,
        Some(("runtime_sandbox_attestation", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_ATTACK_SIMULATION_REPORT_V1_SCHEMA,
        Some(("runtime_attack_simulation_report", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_CHAOS_RUN_REPORT_V1_SCHEMA,
        Some(("runtime_chaos_run_report", "runtime-security-v1")),
    ),
    (
        CHIO_RISK_COMPTROLLER_REPORT_V1_SCHEMA,
        Some(("risk_comptroller_report", "enterprise-export-v1")),
    ),
    (
        CHIO_RISK_COLLATERAL_POSITION_REPORT_V1_SCHEMA,
        Some(("risk_collateral_position_report", "trust-market-v1")),
    ),
    (
        CHIO_RISK_GUARANTEE_DECISION_V1_SCHEMA,
        Some(("risk_guarantee_decision", "trust-market-v1")),
    ),
    (
        CHIO_RISK_ADJUDICATION_JURISDICTION_RECEIPT_V1_SCHEMA,
        Some(("risk_adjudication_jurisdiction_receipt", "trust-market-v1")),
    ),
    (
        CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA,
        Some((
            "chio_comptroller_surface_report",
            "chio-comptroller-surface/v1",
        )),
    ),
    (
        CHIO_ENTERPRISE_DATA_GOVERNANCE_REPORT_V1_SCHEMA,
        Some(("enterprise_data_governance_report", "enterprise-export-v1")),
    ),
    (
        CHIO_ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_V1_SCHEMA,
        Some(("enterprise_evidence_export_bundle", "enterprise-export-v1")),
    ),
    (
        CHIO_ENTERPRISE_TELEMETRY_PROJECTION_V1_SCHEMA,
        Some(("enterprise_telemetry_projection", "enterprise-export-v1")),
    ),
    (
        CHIO_ENTERPRISE_APPROVAL_CASE_V1_SCHEMA,
        Some(("enterprise_approval_case", "enterprise-export-v1")),
    ),
    (
        CHIO_ENTERPRISE_CONTROL_EVIDENCE_MAP_V1_SCHEMA,
        Some(("enterprise_control_evidence_map", "enterprise-export-v1")),
    ),
    (
        CHIO_AGENT_WEB_PROOF_ENVELOPE_SCHEMA,
        Some(("agent_web_proof_envelope", "agent-web-interop-v1")),
    ),
    (
        CHIO_AGENT_WEB_EXTERNAL_PROJECTION_MANIFEST_V1_SCHEMA,
        Some((
            "agent_web_external_projection_manifest",
            "agent-web-interop-v1",
        )),
    ),
    (
        CHIO_AGENT_WEB_INTEROP_VERIFIER_REPORT_V1_SCHEMA,
        Some(("agent_web_interop_verifier_report", "agent-web-interop-v1")),
    ),
    (
        CHIO_PROOF_ROOM_BUNDLE_V1_SCHEMA,
        Some(("proof_room_bundle", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_ROOM_VERIFIER_REPORT_V1_SCHEMA,
        Some(("proof_room_verifier_report", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_ROOM_FIXTURE_CATALOG_V1_SCHEMA,
        Some(("proof_room_fixture_catalog", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_ROOM_FIXTURE_ROOT_CATALOG_V1_SCHEMA,
        Some(("proof_room_fixture_root_catalog", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_ROOM_RECEIPT_EVIDENCE_V1_SCHEMA,
        Some(("proof_room_receipt_evidence", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_DOCKER_QUICKSTART_EVIDENCE_V1_SCHEMA,
        Some(("proof_docker_quickstart_evidence", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_RELEASE_TRUTH_V1_SCHEMA,
        Some(("proof_release_truth", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_FIRST_RUN_CAPABILITY_PROOF_V1_SCHEMA,
        Some(("proof_first_run_capability_proof", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_FIRST_RUN_GUARD_REPORT_V1_SCHEMA,
        Some(("proof_first_run_guard_report", "proof-room-v1")),
    ),
    (
        CHIO_RUNTIME_TERMINAL_RECEIPT_V1_SCHEMA,
        Some(("runtime_terminal_receipt", "runtime-security-v1")),
    ),
    (
        CHIO_PROOF_FIRST_RUN_TRUST_ROOTS_V1_SCHEMA,
        Some(("proof_first_run_trust_roots", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_FIRST_RUN_COMMAND_LOG_V1_SCHEMA,
        Some(("proof_first_run_command_log", "proof-room-v1")),
    ),
    (
        CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA,
        Some(("web3_settlement_dispatch", "public-settlement-v1")),
    ),
    (
        CHIO_WEB3_SETTLEMENT_EXECUTION_RECEIPT_V1_SCHEMA,
        Some(("web3_settlement_execution_receipt", "public-settlement-v1")),
    ),
    (
        CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_V1_SCHEMA,
        Some(("web3_settlement_proof_bundle", "public-settlement-v1")),
    ),
    (
        CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_V1_SCHEMA,
        Some(("public_settlement_verifier_report", "public-settlement-v1")),
    ),
    (
        CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA,
        Some(("oracle_conversion_evidence", "public-settlement-v1")),
    ),
    (
        CHIO_SWARM_TASK_GRAPH_V1_SCHEMA,
        Some(("swarm_task_graph", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_CONTINUATION_TOKEN_V1_SCHEMA,
        Some(("swarm_continuation_token", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_DELEGATION_WITNESS_CHAIN_V1_SCHEMA,
        Some(("swarm_delegation_witness_chain", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_JOIN_RECEIPT_V1_SCHEMA,
        Some(("swarm_join_receipt", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_ROUTE_PLAN_RECEIPT_V1_SCHEMA,
        Some(("swarm_route_plan_receipt", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_V1_SCHEMA,
        Some(("swarm_terminal_graph_receipt", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_BUDGET_POOL_V1_SCHEMA,
        Some(("swarm_budget_pool", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_REVOCATION_EPOCH_V1_SCHEMA,
        Some(("swarm_revocation_epoch", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_V1_SCHEMA,
        Some(("swarm_authority_verifier_report", "swarm-authority-v1")),
    ),
    (
        CHIO_TOOL_MANIFEST_SCHEMA,
        Some(("tool_manifest", "manifest-v1")),
    ),
    (
        crate::capability::attenuation::CHIO_DELEGATION_LINK_SCHEMA,
        Some(("delegation_link", "signing-wrapper-v1")),
    ),
    (
        crate::capability::governance::GOVERNED_UPSTREAM_CALL_CHAIN_PROOF_SCHEMA,
        Some(("governed_upstream_call_chain_proof", "signing-wrapper-v1")),
    ),
    (
        crate::capability::governance::CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
        Some(("call_chain_continuation", "signing-wrapper-v1")),
    ),
    (
        crate::capability::governance::GOVERNED_APPROVAL_TOKEN_SCHEMA,
        Some(("governed_approval_token", "signing-wrapper-v1")),
    ),
    (
        crate::receipt::lineage::CHIO_CHILD_REQUEST_RECEIPT_SCHEMA,
        Some(("child_request_receipt", "signing-wrapper-v1")),
    ),
    (
        crate::declassification::CHIO_DECLASSIFICATION_GRANT_SCHEMA,
        Some(("declassification_grant", "signing-wrapper-v1")),
    ),
    (
        crate::security_event::CHIO_SIGNED_SECURITY_EVENT_SCHEMA,
        Some(("signed_security_event", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_GRANT_SCHEMA,
        Some(("recovery_grant", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_AUTHORITY_COVERAGE_SCHEMA,
        Some(("recovery_authority_coverage", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_PROVIDER_FINALITY_SCHEMA,
        Some(("recovery_provider_finality", "signing-wrapper-v1")),
    ),
    (
        crate::message::CHIO_EXECUTION_NONCE_SCHEMA,
        Some(("execution_nonce", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_CONFINED_DISCLOSURE_SCHEMA,
        Some(("recovery_confined_disclosure", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_CONFINED_ENDORSEMENT_SCHEMA,
        Some(("recovery_confined_endorsement", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_EXPLANATION_REPORT_SCHEMA,
        Some(("recovery_explanation_report", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_EXPLANATION_VIEW_SCHEMA,
        Some(("recovery_explanation_view", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_ARTIFACT_CERTIFICATE_SCHEMA,
        Some(("recovery_artifact_certificate", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_ARTIFACT_ARCHIVE_MANIFEST_SCHEMA,
        Some(("recovery_artifact_archive_manifest", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_POLICY_DEPLOYMENT_CHANGE_SCHEMA,
        Some(("recovery_policy_deployment_change", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SETUP_PROBE_SCHEMA,
        Some(("recovery_setup_probe", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SETUP_REPORT_SCHEMA,
        Some(("recovery_setup_report", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SEMANTIC_PACKAGE_SCHEMA,
        Some(("recovery_semantic_package", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SEMANTIC_DEPLOYMENT_SCHEMA,
        Some(("recovery_semantic_deployment", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SEMANTIC_AUDIENCE_SCHEMA,
        Some(("recovery_semantic_audience", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SCOPED_ENDORSEMENT_SCHEMA,
        Some(("recovery_scoped_endorsement", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SEMANTIC_ANNOTATION_SCHEMA,
        Some(("recovery_semantic_annotation", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SEMANTIC_TRANSFORMATION_SCHEMA,
        Some(("recovery_semantic_transformation", "signing-wrapper-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SEMANTIC_PREREQUISITE_SCHEMA,
        Some(("recovery_semantic_prerequisite", "signing-wrapper-v1")),
    ),
    (
        CHIO_DPOP_PROOF_SCHEMA,
        Some(("dpop_proof", "signing-wrapper-v1")),
    ),
    (
        "chio.operation_execution_nonce.v1",
        Some(("operation_execution_nonce", "signing-wrapper-v1")),
    ),
    (
        "chio.signed-admission-terminal-projection.v1",
        Some(("signed_admission_terminal_projection", "signing-wrapper-v1")),
    ),
    (
        "chio.authority-lifecycle.v1",
        Some(("authority_lifecycle", "signing-wrapper-v1")),
    ),
    (
        "chio.authority-snapshot.v1",
        Some(("authority_snapshot", "signing-wrapper-v1")),
    ),
    (
        "chio.caller-dispatch-authorization.v1",
        Some(("caller_dispatch_authorization", "signing-wrapper-v1")),
    ),
    (
        "chio.caller-delivery-report.v1",
        Some(("caller_delivery_report", "signing-wrapper-v1")),
    ),
    (
        "chio.checkpoint_statement.v1",
        Some(("checkpoint_statement", "signing-wrapper-v1")),
    ),
    (
        "chio.session-compliance-certificate.v1",
        Some(("session_compliance_certificate", "signing-wrapper-v1")),
    ),
    (
        "chio.active-response-submission.v1",
        Some(("active_response_submission", "signing-wrapper-v1")),
    ),
    (
        "chio.active-response-artifact-authority-attestation.v1",
        Some((
            "active_response_artifact_authority_attestation",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.stop-operator-config.v1",
        Some(("stop_operator_config", "signing-wrapper-v1")),
    ),
    (
        "chio.stop-operator-config-approval.v1",
        Some(("stop_operator_config_approval", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.pool-debit-authorization.v1",
        Some(("finding_pool_debit_authorization", "signing-wrapper-v1")),
    ),
    (
        "chio.process.container-launch.v1",
        Some(("container_launch", "signing-wrapper-v1")),
    ),
    (
        "chio.swarm.delegation-witness-hop-signature.v1",
        Some((
            "swarm_delegation_witness_hop_signature",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.key-log.checkpoint.v1",
        Some(("key_log_checkpoint", "signing-wrapper-v1")),
    ),
    (
        "chio.key-log.activation-commit.v1",
        Some(("key_log_activation_commit", "signing-wrapper-v1")),
    ),
    (
        "chio.key-log.witness-statement.v1",
        Some(("key_log_witness_statement", "signing-wrapper-v1")),
    ),
    (
        "chio.key-log.enterprise-receipt.v1",
        Some(("key_log_enterprise_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.key-log.event.v1",
        Some(("key_log_event", "signing-wrapper-v1")),
    ),
    (
        "chio.key-log.witness-readiness.v1",
        Some(("key_log_witness_readiness", "signing-wrapper-v1")),
    ),
    (
        "chio.key-log.audit-readiness.v1",
        Some(("key_log_audit_readiness", "signing-wrapper-v1")),
    ),
    (
        "chio.keyring.artifact-signature.v1",
        Some(("keyring_artifact_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.key-log.artifact-time-anchor.v1",
        Some(("key_log_artifact_time_anchor", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-audit-runner-authorization.v1",
        Some(("broker_audit_runner_authorization", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-audit-comparison.v1",
        Some(("broker_audit_comparison", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-authority-request.v1",
        Some(("broker_authority_request", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-authority-response.v1",
        Some(("broker_authority_response", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-capability.v1",
        Some(("broker_capability", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-privileged-audit-challenge.v1",
        Some(("broker_privileged_audit_challenge", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-request-proof.v1",
        Some(("broker_request_proof", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-admin-mutation-receipt.v1",
        Some(("broker_admin_mutation_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-admin-control-receipt.v1",
        Some(("broker_admin_control_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-execution-receipt.v1",
        Some(("broker_execution_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-execution-failure-receipt.v1",
        Some(("broker_execution_failure_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.broker-register-attempt-authorization.v1",
        Some((
            "broker_register_attempt_authorization",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.signed-watermark-envelope.v1",
        Some(("signed_watermark_envelope", "signing-wrapper-v1")),
    ),
    (
        "chio.active-response-policy-authority-request.v1",
        Some((
            "active_response_policy_authority_request",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.active-response-policy-authority-response.v1",
        Some((
            "active_response_policy_authority_response",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.ag-ui-receipt.v1",
        Some(("ag_ui_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.agent-passport-presentation-response.v1",
        Some(("agent_passport_presentation_response", "signing-wrapper-v1")),
    ),
    (
        "chio.autonomous-comparison-report.v1",
        Some(("autonomous_comparison_report", "signing-wrapper-v1")),
    ),
    (
        "chio.autonomous-drift-report.v1",
        Some(("autonomous_drift_report", "signing-wrapper-v1")),
    ),
    (
        "chio.autonomous-execution-decision.v1",
        Some(("autonomous_execution_decision", "signing-wrapper-v1")),
    ),
    (
        "chio.autonomous-pricing-authority-envelope.v1",
        Some((
            "autonomous_pricing_authority_envelope",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.autonomous-pricing-decision.v1",
        Some(("autonomous_pricing_decision", "signing-wrapper-v1")),
    ),
    (
        "chio.autonomous-pricing-input.v1",
        Some(("autonomous_pricing_input", "signing-wrapper-v1")),
    ),
    (
        "chio.autonomous-rollback-plan.v1",
        Some(("autonomous_rollback_plan", "signing-wrapper-v1")),
    ),
    (
        "chio.budget-snapshot-anchor-commitment.v1",
        Some(("budget_snapshot_anchor_commitment", "signing-wrapper-v1")),
    ),
    (
        "chio.capability-lease.v1",
        Some((
            "chio_federation_capability_lease",
            "chio-final-architecture/v1",
        )),
    ),
    (
        "chio.capital-pool-optimization.v1",
        Some(("capital_pool_optimization", "signing-wrapper-v1")),
    ),
    (
        "chio.capital-pool-simulation-report.v1",
        Some(("capital_pool_simulation_report", "signing-wrapper-v1")),
    ),
    (
        "chio.certify.check.v1",
        Some(("certify_check", "signing-wrapper-v1")),
    ),
    (
        "chio.compliance.certificate.v1",
        Some(("compliance_certificate", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.bond.v1",
        Some(("credit_bond", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.capital-allocation.v1",
        Some(("credit_capital_allocation", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.capital-authority-step-proof.v1",
        Some(("credit_capital_authority_step_proof", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.capital-book.v1",
        Some(("credit_capital_book", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.capital-instruction.v1",
        Some(("credit_capital_instruction", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.exposure-ledger.v1",
        Some(("credit_exposure_ledger", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.facility.v1",
        Some(("credit_facility", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.iou-envelope.v1",
        Some(("credit_iou_envelope", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.loss-lifecycle.v1",
        Some(("credit_loss_lifecycle", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.provider-risk-package.v1",
        Some(("credit_provider_risk_package", "signing-wrapper-v1")),
    ),
    (
        "chio.credit.scorecard.v1",
        Some(("credit_scorecard", "signing-wrapper-v1")),
    ),
    (
        "chio.cross-issuer-migration.v1",
        Some(("cross_issuer_migration", "signing-wrapper-v1")),
    ),
    (
        "chio.enterprise-migration-transition.v1",
        Some(("enterprise_migration_transition", "signing-wrapper-v1")),
    ),
    (
        "chio.evidence_export_commitment.v1",
        Some(("evidence_export_commitment", "signing-wrapper-v1")),
    ),
    (
        "chio.federated-delegation-policy.v1",
        Some(("federated_delegation_policy", "signing-wrapper-v1")),
    ),
    (
        "chio.federation-activation-exchange.v1",
        Some(("federation_activation_exchange", "signing-wrapper-v1")),
    ),
    (
        "chio.federation-kernel-handshake.v1",
        Some(("federation_kernel_handshake", "signing-wrapper-v1")),
    ),
    (
        "chio.federation-open-admission-policy.v1",
        Some(("federation_open_admission_policy", "signing-wrapper-v1")),
    ),
    (
        "chio.federation-policy.v1",
        Some(("federation_policy", "signing-wrapper-v1")),
    ),
    (
        "chio.federation-qualification-matrix.v1",
        Some(("federation_qualification_matrix", "signing-wrapper-v1")),
    ),
    (
        "chio.federation-quorum-report.v1",
        Some(("federation_quorum_report", "signing-wrapper-v1")),
    ),
    (
        "chio.federation-reputation-clearing.v1",
        Some(("federation_reputation_clearing", "signing-wrapper-v1")),
    ),
    (
        "chio.federation.revocation-checkpoint.v1",
        Some((
            "chio_federation_revocation_checkpoint",
            "chio-final-architecture/v1",
        )),
    ),
    (
        "chio.federation.transport.iroh.peer-directory-bundle.v1",
        Some((
            "federation_transport_iroh_peer_directory_bundle",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.financial-agent-passport-presentation-response.v1",
        Some((
            "financial_agent_passport_presentation_response",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.financial.cross-issuer-entry-activation-decision.v1",
        Some((
            "financial_cross_issuer_entry_activation_decision",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.financial.cross-issuer-migration.v1",
        Some(("financial_cross_issuer_migration", "signing-wrapper-v1")),
    ),
    (
        "chio.financial.cross-issuer-trust-pack.v1",
        Some(("financial_cross_issuer_trust_pack", "signing-wrapper-v1")),
    ),
    (
        "chio.financial.cross-issuer.lifecycle-checkpoint-pin.v1",
        Some((
            "financial_cross_issuer_lifecycle_checkpoint_pin",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.financial.cross-issuer.lifecycle-checkpoint.v1",
        Some((
            "financial_cross_issuer_lifecycle_checkpoint",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.financial.cross-issuer.lifecycle-generation-pin.v1",
        Some((
            "financial_cross_issuer_lifecycle_generation_pin",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.financial.cross-issuer.lifecycle-result.v1",
        Some((
            "financial_cross_issuer_lifecycle_result",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.finding-pool.store-identity-proof.v1",
        Some(("finding_pool_store_identity_proof", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.anchor-checkpoint-publication.v1",
        Some((
            "finding_anchor_checkpoint_publication",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.finding.audit-seed-witness.v1",
        Some(("finding_audit_seed_witness", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.bond-store-snapshot.v1",
        Some(("finding_bond_store_snapshot", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.current-listing-assertion.v1",
        Some(("finding_current_listing_assertion", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-api-key-lifecycle.v1",
        Some(("finding_hosted_api_key_lifecycle", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-canary-observation.v1",
        Some(("finding_hosted_canary_observation", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.operator-purchase-job.v1",
        Some(("finding_operator_purchase_job", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.status-intent-submission.v1",
        Some(("finding_status_intent_submission", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.voluntary-retraction-receipt.v1",
        Some(("finding_voluntary_retraction_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.frost.dkg-package.v1",
        Some(("frost_dkg_package", "signing-wrapper-v1")),
    ),
    (
        "chio.governance-receipt.v1",
        Some((
            "chio_federation_governance_receipt",
            "chio-final-architecture/v1",
        )),
    ),
    (
        "chio.http-receipt.v1",
        Some(("http_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.iroh.revocation-signer-endorsement.v1",
        Some(("iroh_revocation_signer_endorsement", "signing-wrapper-v1")),
    ),
    (
        "chio.iroh.transport-endorsement.v1",
        Some(("iroh_transport_endorsement", "signing-wrapper-v1")),
    ),
    (
        "chio.key-binding-certificate.v1",
        Some(("key_binding_certificate", "signing-wrapper-v1")),
    ),
    (
        "chio.market.auto-bind.v1",
        Some(("market_auto_bind", "signing-wrapper-v1")),
    ),
    (
        "chio.market.bound-coverage.v1",
        Some(("market_bound_coverage", "signing-wrapper-v1")),
    ),
    (
        "chio.market.claim-adjudication.v1",
        Some(("market_claim_adjudication", "signing-wrapper-v1")),
    ),
    (
        "chio.market.claim-dispute.v1",
        Some(("market_claim_dispute", "signing-wrapper-v1")),
    ),
    (
        "chio.market.claim-package.v1",
        Some(("market_claim_package", "signing-wrapper-v1")),
    ),
    (
        "chio.market.claim-payout-instruction.v1",
        Some(("market_claim_payout_instruction", "signing-wrapper-v1")),
    ),
    (
        "chio.market.claim-payout-receipt.v1",
        Some(("market_claim_payout_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.market.claim-response.v1",
        Some(("market_claim_response", "signing-wrapper-v1")),
    ),
    (
        "chio.market.claim-settlement-instruction.v1",
        Some(("market_claim_settlement_instruction", "signing-wrapper-v1")),
    ),
    (
        "chio.market.claim-settlement-receipt.v1",
        Some(("market_claim_settlement_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.market.placement.v1",
        Some(("market_placement", "signing-wrapper-v1")),
    ),
    (
        "chio.market.pricing-authority.v1",
        Some(("market_pricing_authority", "signing-wrapper-v1")),
    ),
    (
        "chio.market.provider.v1",
        Some(("market_provider", "signing-wrapper-v1")),
    ),
    (
        "chio.market.quote-request.v1",
        Some(("market_quote_request", "signing-wrapper-v1")),
    ),
    (
        "chio.market.quote-response.v1",
        Some(("market_quote_response", "signing-wrapper-v1")),
    ),
    (
        "chio.marketplace.accepted-bid.v1",
        Some(("marketplace_accepted_bid", "signing-wrapper-v1")),
    ),
    (
        "chio.marketplace.ask-response.v1",
        Some(("marketplace_ask_response", "signing-wrapper-v1")),
    ),
    (
        "chio.marketplace.bid-request.v1",
        Some(("marketplace_bid_request", "signing-wrapper-v1")),
    ),
    (
        "chio.marketplace.listing-pricing-hint.v1",
        Some(("marketplace_listing_pricing_hint", "signing-wrapper-v1")),
    ),
    (
        "chio.marketplace.reservation-receipt.v1",
        Some(("marketplace_reservation_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.mcp.cage-launch-policy.v1",
        Some(("mcp_cage_launch_policy", "enterprise-security-execution-v1")),
    ),
    (
        "chio.mcp.operator-approval.v1",
        Some(("mcp_operator_approval", "signing-wrapper-v1")),
    ),
    (
        "chio.mcp.session-credential-call.v1",
        Some(("mcp_session_credential_call", "signing-wrapper-v1")),
    ),
    (
        "chio.mcp.session-credential.v1",
        Some(("mcp_session_credential", "signing-wrapper-v1")),
    ),
    (
        "chio.parametric.contest.v1",
        Some(("parametric_contest", "signing-wrapper-v1")),
    ),
    (
        "chio.parametric.evidence-source-checkpoint.v1",
        Some((
            "parametric_evidence_source_checkpoint",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.parametric.payout-intent.v1",
        Some(("parametric_payout_intent", "signing-wrapper-v1")),
    ),
    (
        "chio.passkey-capability.v1",
        Some(("passkey_capability", "signing-wrapper-v1")),
    ),
    (
        "chio.passport-verifier-policy.v1",
        Some(("passport_verifier_policy", "signing-wrapper-v1")),
    ),
    (
        "chio.pheromone-deposit.v1",
        Some(("chio_pheromone_deposit", "chio-pheromone-transit/v1")),
    ),
    (
        "chio.pheromone-observation-cost-statement.v1",
        Some((
            "chio_pheromone_observation_cost_statement",
            "chio-final-architecture/v1",
        )),
    ),
    (
        "chio.pheromone-observation-cost-verifier-root.v1",
        Some((
            "chio_pheromone_observation_cost_verifier_root",
            "chio-final-architecture/v1",
        )),
    ),
    (
        "chio.pheromone-transit-policy.v1",
        Some(("chio_pheromone_transit_policy", "chio-pheromone-transit/v1")),
    ),
    (
        "chio.pheromone.peer-directory-bundle.v1",
        Some((
            "chio_pheromone_peer_directory_bundle",
            "chio-pheromone-relay-operations/v1",
        )),
    ),
    (
        "chio.pheromone.relay-alert-assurance-archive-package-manifest.v1",
        Some((
            "chio_pheromone_relay_alert_assurance_archive_package_manifest",
            "chio-pheromone-relay-alert-assurance-archive-package/v1",
        )),
    ),
    (
        "chio.pheromone.relay-alert-assurance-export-manifest.v1",
        Some((
            "chio_pheromone_relay_alert_assurance_export_manifest",
            "chio-pheromone-relay-alert-assurance-export/v1",
        )),
    ),
    (
        "chio.pheromone.relay-http-request.v1",
        Some((
            "chio_pheromone_relay_http_request",
            "chio-pheromone-relay/v1",
        )),
    ),
    (
        "chio.policy.activation-receipt-signature.v1",
        Some(("policy_activation_receipt_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.portable-negative-event.v1",
        Some(("portable_negative_event", "signing-wrapper-v1")),
    ),
    (
        "chio.portable-reputation-summary.v1",
        Some(("portable_reputation_summary", "signing-wrapper-v1")),
    ),
    (
        "chio.process.swarm-profile.v1",
        Some(("process_swarm_profile", "signing-wrapper-v1")),
    ),
    (
        "chio.provenance-stamp.v1",
        Some(("provenance_stamp", "signing-wrapper-v1")),
    ),
    (
        "chio.public-discovery-transparency.v1",
        Some(("public_discovery_transparency", "signing-wrapper-v1")),
    ),
    (
        "chio.public-issuer-discovery.v1",
        Some(("public_issuer_discovery", "signing-wrapper-v1")),
    ),
    (
        "chio.public-verifier-discovery.v1",
        Some(("public_verifier_discovery", "signing-wrapper-v1")),
    ),
    (
        "chio.registry.governance-case.v1",
        Some(("registry_governance_case", "signing-wrapper-v1")),
    ),
    (
        "chio.registry.governance-charter.v1",
        Some(("registry_governance_charter", "signing-wrapper-v1")),
    ),
    (
        "chio.registry.listing.v1",
        Some(("registry_listing", "signing-wrapper-v1")),
    ),
    (
        "chio.registry.market-fee-schedule.v1",
        Some(("registry_market_fee_schedule", "signing-wrapper-v1")),
    ),
    (
        "chio.registry.namespace.v1",
        Some(("registry_namespace", "signing-wrapper-v1")),
    ),
    (
        "chio.registry.trust-activation.v1",
        Some(("registry_trust_activation", "signing-wrapper-v1")),
    ),
    (
        "chio.regulatory.receipt-export.v1",
        Some(("regulatory_receipt_export", "signing-wrapper-v1")),
    ),
    (
        "chio.release-qualification-manifest.v1",
        Some(("release_qualification_manifest", "signing-wrapper-v1")),
    ),
    (
        "chio.reputation-credential.v1",
        Some(("reputation_credential", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime-attestation.appraisal-report.v1",
        Some(("runtime_attestation_appraisal_report", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime-attestation.appraisal-result.v1",
        Some(("runtime_attestation_appraisal_result", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime-attestation.reference-values.v1",
        Some(("runtime_attestation_reference_values", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime-attestation.trust-bundle.v1",
        Some(("runtime_attestation_trust_bundle", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime-attestation.verifier-descriptor.v1",
        Some((
            "runtime_attestation_verifier_descriptor",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.runtime.attack-simulation-report-signature.v1",
        Some((
            "runtime_attack_simulation_report_signature",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.runtime.chaos-run-report-signature.v1",
        Some(("runtime_chaos_run_report_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime.execution-lease-signature.v1",
        Some(("runtime_execution_lease_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime.revocation-freshness-proof-signature.v1",
        Some((
            "runtime_revocation_freshness_proof_signature",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.runtime.sandbox-attestation-signature.v1",
        Some((
            "runtime_sandbox_attestation_signature",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.runtime.terminal-receipt-signature.v1",
        Some(("runtime_terminal_receipt_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime.tool-server-ack-signature.v1",
        Some(("runtime_tool_server_ack_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime.trusted-time-proof-signature.v1",
        Some(("runtime_trusted_time_proof_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.signer-readiness-probe.v1",
        Some(("signer_readiness_probe", "signing-wrapper-v1")),
    ),
    (
        "chio.swarm.route-plan-receipt-signature.v1",
        Some(("swarm_route_plan_receipt_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.tee-bless-audit.v1",
        Some(("tee_bless_audit", "signing-wrapper-v1")),
    ),
    (
        "chio.tee-capture-frame.v1",
        Some(("tee_capture_frame", "signing-wrapper-v1")),
    ),
    (
        "chio.trace-observation.v1",
        Some(("trace_observation", "signing-wrapper-v1")),
    ),
    (
        "chio.trust.passport-revocation-root.v1",
        Some(("trust_passport_revocation_root", "signing-wrapper-v1")),
    ),
    (
        "chio.underwriting.decision.v1",
        Some(("underwriting_decision", "signing-wrapper-v1")),
    ),
    (
        "chio.underwriting.policy-input.v1",
        Some(("underwriting_policy_input", "signing-wrapper-v1")),
    ),
    (
        "chio.wasm-module.v1",
        Some(("wasm_module", "signing-wrapper-v1")),
    ),
    (
        "chio.work-dispatch-permit.v1",
        Some(("work_dispatch_permit", "signing-wrapper-v1")),
    ),
    (
        "chio.work-offer.v1",
        Some(("work_offer", "signing-wrapper-v1")),
    ),
    (
        "chio.work-selection.v1",
        Some(("work_selection", "signing-wrapper-v1")),
    ),
    (
        "chio.work-subdivision.v1",
        Some(("work_subdivision", "signing-wrapper-v1")),
    ),
    (
        "chio.workflow-receipt.v1",
        Some(("workflow_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime-attestation-evidence.v1",
        Some(("runtime_attestation_evidence", "signing-wrapper-v1")),
    ),
    (
        "chio.lineage.frontier-signature.v1",
        Some(("lineage_frontier_signature", "signing-wrapper-v1")),
    ),
    (
        "chio.portable-agent-passport.v1",
        Some(("portable_agent_passport", "signing-wrapper-v1")),
    ),
    (
        "chio.root-policy.v1",
        Some(("root_policy", "root-authority-v1")),
    ),
    (
        "chio.idp-key-snapshot.v1",
        Some(("idp_key_snapshot", "root-authority-v1")),
    ),
    (
        "chio.revocation-request.v1",
        Some(("revocation_request", "root-authority-v1")),
    ),
    (
        "chio.settlement-closure.v1",
        Some(("settlement_closure", "root-authority-v1")),
    ),
    (
        "chio.runtime.admission-report.v1",
        Some(("runtime_admission_report", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime.verifier-trust-bundle.v1",
        Some(("runtime_verifier_trust_bundle", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime.pheromone-policy.v1",
        Some(("runtime_pheromone_policy", "signing-wrapper-v1")),
    ),
    (
        "chio.runtime.peer-weights.v1",
        Some(("runtime_peer_weights", "signing-wrapper-v1")),
    ),
    (
        "chio.pheromone.query-report.v1",
        Some(("pheromone_query_report", "signing-wrapper-v1")),
    ),
    (
        "chio.behavioral-feed.v1",
        Some(("behavioral_feed", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-principal-lifecycle.v1",
        Some(("hosted_principal_lifecycle", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted.aggregate-checkpoint.v1",
        Some(("hosted_aggregate_checkpoint", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-sqlite-import-batch.v1",
        Some(("hosted_sqlite_import_batch", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-replication-event.v1",
        Some(("hosted_replication_event", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-principal-replication-event.v1",
        Some(("hosted_principal_replication_event", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-replication-check.v1",
        Some(("hosted_replication_check", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-authority-transition.v1",
        Some(("hosted_authority_transition", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-journal-checkpoint.v1",
        Some(("hosted_journal_checkpoint", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-archive-manifest.v1",
        Some(("hosted_archive_manifest", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-legal-hold.v1",
        Some(("hosted_legal_hold", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-restore-verification.v1",
        Some(("hosted_restore_verification", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-quota-alert.v1",
        Some(("hosted_quota_alert", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.hosted-gc-receipt.v1",
        Some(("hosted_gc_receipt", "signing-wrapper-v1")),
    ),
    (
        "chio.finding-status-operator-authorization.v1",
        Some((
            "finding_status_operator_authorization",
            "signing-wrapper-v1",
        )),
    ),
    (
        "chio.finding.worker-capability.v1",
        Some(("finding_worker_capability", "signing-wrapper-v1")),
    ),
    (
        "chio.finding.worker-attested-result.v1",
        Some(("finding_worker_attested_result", "signing-wrapper-v1")),
    ),
];

#[allow(
    clippy::indexing_slicing,
    reason = "Both fixed arrays have SIGNED_ARTIFACT_SCHEMA_SPECS.len() elements and the loop checks the index against that length."
)]
const fn known_signed_artifact_schemas() -> [&'static str; SIGNED_ARTIFACT_SCHEMA_SPECS.len()] {
    let mut schemas = [""; SIGNED_ARTIFACT_SCHEMA_SPECS.len()];
    let mut index = 0;
    while index < SIGNED_ARTIFACT_SCHEMA_SPECS.len() {
        schemas[index] = SIGNED_ARTIFACT_SCHEMA_SPECS[index].0;
        index += 1;
    }
    schemas
}

const KNOWN_SIGNED_ARTIFACT_SCHEMA_LIST: [&str; SIGNED_ARTIFACT_SCHEMA_SPECS.len()] =
    known_signed_artifact_schemas();

/// Known signed artifacts accepted by core validation.
pub const KNOWN_SIGNED_ARTIFACT_SCHEMAS: &[&str] = &KNOWN_SIGNED_ARTIFACT_SCHEMA_LIST;

/// Lightweight registry entry for schema-aware verifiers and reports.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedArtifactSchemaEntry {
    pub schema: String,
    pub artifact_kind: String,
    pub introduced_by: String,
}

/// Return whether a schema ID is known to this verifier build.
#[must_use]
pub fn is_supported_signed_artifact_schema(schema: &str) -> bool {
    KNOWN_SIGNED_ARTIFACT_SCHEMAS.contains(&schema)
}

/// Whether the signing wrapper may sign or verify under `schema_id`.
#[must_use]
pub fn registered_wrapper_schema(schema_id: &str) -> bool {
    KNOWN_SIGNED_ARTIFACT_SCHEMAS.contains(&schema_id)
}

/// Fail closed on unknown signed-artifact schema IDs.
pub fn validate_signed_artifact_schema(schema: &str) -> Result<()> {
    if is_supported_signed_artifact_schema(schema) {
        Ok(())
    } else {
        Err(Error::CanonicalJson(format!(
            "unsupported signed-artifact schema: {schema}"
        )))
    }
}

/// Built-in registry entries mirrored by `spec/schemas/registry.json`.
#[must_use]
pub fn built_in_signed_artifact_registry() -> Vec<SignedArtifactSchemaEntry> {
    SIGNED_ARTIFACT_SCHEMA_SPECS
        .iter()
        .filter_map(|(schema, registry)| {
            registry.map(|(artifact_kind, introduced_by)| SignedArtifactSchemaEntry {
                schema: schema.to_string(),
                artifact_kind: artifact_kind.to_string(),
                introduced_by: introduced_by.to_string(),
            })
        })
        .collect()
}
