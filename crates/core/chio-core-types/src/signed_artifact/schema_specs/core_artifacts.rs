//! Schemas declared by the core artifact types.

use super::super::*;

pub(super) const SCHEMAS: &[SignedArtifactSchemaSpec] = &[
    (
        AGGREGATE_BUDGET_ROOT_SCHEMA,
        Some(("aggregate_budget_root_binding", "protocol-primitives-v1")),
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
        CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
        Some(("economic_state_batch", "economic-state-continuity-v1")),
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
        CHIO_COMMERCE_RESERVATION_RECEIPT_V1_SCHEMA,
        Some(("commerce_reservation_receipt", "signing-wrapper-v1")),
    ),
    (
        CHIO_COMMERCE_ESCROW_ACCEPTANCE_V1_SCHEMA,
        Some(("commerce_escrow_acceptance", "signing-wrapper-v1")),
    ),
    (
        CHIO_CLUSTER_BUDGET_ANCHOR_V1_SCHEMA,
        Some(("cluster_budget_anchor", "signing-wrapper-v1")),
    ),
    (
        CHIO_CLUSTER_PEER_REQUEST_V1_SCHEMA,
        Some(("cluster_peer_request", "signing-wrapper-v1")),
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
        Some(("security_declassification_grant", "active-defense-v1")),
    ),
    (
        crate::security_event::CHIO_SIGNED_SECURITY_EVENT_SCHEMA,
        Some(("signed_security_event", "active-defense-v1")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_GRANT_SCHEMA,
        Some(("recovery_grant", "recovery-authority")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_AUTHORITY_COVERAGE_SCHEMA,
        Some(("recovery_signed_authority_coverage", "recovery-authority")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_PROVIDER_FINALITY_SCHEMA,
        Some(("recovery_signed_provider_finality", "recovery-authority")),
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
        Some(("recovery_signed_explanation_report", "recovery-explanation")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_EXPLANATION_VIEW_SCHEMA,
        Some(("recovery_signed_explanation_view", "recovery-explanation")),
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
        Some(("recovery_setup_probe", "recovery-product")),
    ),
    (
        crate::recovery::CHIO_RECOVERY_SETUP_REPORT_SCHEMA,
        Some(("recovery_setup_report", "recovery-product")),
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
        Some(("invocation_sender_proof", "inbound-authority-ap5")),
    ),
];
