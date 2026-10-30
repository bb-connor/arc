//! Signing-wrapper schemas owned by runtime, service and ecosystem artifacts.

use super::super::SignedArtifactSchemaSpec;

pub(super) const SCHEMAS: &[SignedArtifactSchemaSpec] = &[
    signing_wrapper(
        "chio.operation_execution_nonce.v1",
        "operation_execution_nonce",
    ),
    signing_wrapper(
        "chio.signed-admission-terminal-projection.v1",
        "signed_admission_terminal_projection",
    ),
    signing_wrapper("chio.authority-lifecycle.v1", "authority_lifecycle"),
    signing_wrapper("chio.authority-snapshot.v1", "authority_snapshot"),
    (
        "chio.caller-dispatch-authorization.v1",
        Some((
            "caller_dispatch_authorization",
            "authenticated-caller-delivery-v1",
        )),
    ),
    (
        "chio.caller-delivery-report.v1",
        Some(("caller_delivery_report", "authenticated-caller-delivery-v1")),
    ),
    signing_wrapper("chio.checkpoint_statement.v1", "checkpoint_statement"),
    signing_wrapper(
        "chio.session-compliance-certificate.v1",
        "session_compliance_certificate",
    ),
    signing_wrapper(
        "chio.active-response-submission.v1",
        "active_response_submission",
    ),
    signing_wrapper(
        "chio.active-response-artifact-authority-attestation.v1",
        "active_response_artifact_authority_attestation",
    ),
    signing_wrapper("chio.stop-operator-config.v1", "stop_operator_config"),
    signing_wrapper(
        "chio.stop-operator-config-approval.v1",
        "stop_operator_config_approval",
    ),
    signing_wrapper(
        "chio.finding.pool-debit-authorization.v1",
        "finding_pool_debit_authorization",
    ),
    signing_wrapper("chio.process.container-launch.v1", "container_launch"),
    signing_wrapper(
        "chio.swarm.delegation-witness-hop-signature.v1",
        "swarm_delegation_witness_hop_signature",
    ),
    (
        "chio.key-log.checkpoint.v1",
        Some(("key_log_checkpoint", "enterprise-security-execution-v1")),
    ),
    (
        "chio.key-log.activation-commit.v1",
        Some((
            "key_log_activation_commit",
            "enterprise-security-execution-v1",
        )),
    ),
    signing_wrapper(
        "chio.key-log.witness-statement.v1",
        "key_log_witness_statement",
    ),
    (
        "chio.key-log.enterprise-receipt.v1",
        Some((
            "key_log_enterprise_receipt",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.key-log.event.v1",
        Some(("key_log_event", "enterprise-security-execution-v1")),
    ),
    (
        "chio.key-log.witness-readiness.v1",
        Some((
            "key_log_witness_readiness",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.key-log.audit-readiness.v1",
        Some((
            "key_log_audit_readiness",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.keyring.artifact-signature.v1",
        Some((
            "keyring_artifact_signature",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.key-log.artifact-time-anchor.v1",
        Some((
            "key_log_artifact_time_anchor",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-audit-runner-authorization.v1",
        Some((
            "broker_audit_runner_authorization",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-audit-comparison.v1",
        Some((
            "broker_audit_comparison",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-authority-request.v1",
        Some((
            "broker_authority_request",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-authority-response.v1",
        Some((
            "broker_authority_response",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-capability.v1",
        Some(("broker_capability", "enterprise-security-execution-v1")),
    ),
    (
        "chio.broker-privileged-audit-challenge.v1",
        Some((
            "broker_privileged_audit_challenge",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-request-proof.v1",
        Some(("broker_request_proof", "enterprise-security-execution-v1")),
    ),
    (
        "chio.broker-admin-mutation-receipt.v1",
        Some((
            "broker_admin_mutation_receipt",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-admin-control-receipt.v1",
        Some((
            "broker_admin_control_receipt",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-execution-receipt.v1",
        Some((
            "broker_execution_receipt",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-execution-failure-receipt.v1",
        Some((
            "broker_execution_failure_receipt",
            "enterprise-security-execution-v1",
        )),
    ),
    (
        "chio.broker-register-attempt-authorization.v1",
        Some((
            "broker_register_attempt_authorization",
            "enterprise-security-execution-v1",
        )),
    ),
    signing_wrapper(
        "chio.signed-watermark-envelope.v1",
        "signed_watermark_envelope",
    ),
    signing_wrapper(
        "chio.active-response-policy-authority-request.v1",
        "active_response_policy_authority_request",
    ),
    signing_wrapper(
        "chio.active-response-policy-authority-response.v1",
        "active_response_policy_authority_response",
    ),
    signing_wrapper("chio.ag-ui-receipt.v1", "ag_ui_receipt"),
    signing_wrapper(
        "chio.agent-passport-presentation-response.v1",
        "agent_passport_presentation_response",
    ),
    signing_wrapper(
        "chio.autonomous-comparison-report.v1",
        "autonomous_comparison_report",
    ),
    signing_wrapper("chio.autonomous-drift-report.v1", "autonomous_drift_report"),
    signing_wrapper(
        "chio.autonomous-execution-decision.v1",
        "autonomous_execution_decision",
    ),
    signing_wrapper(
        "chio.autonomous-pricing-authority-envelope.v1",
        "autonomous_pricing_authority_envelope",
    ),
    signing_wrapper(
        "chio.autonomous-pricing-decision.v1",
        "autonomous_pricing_decision",
    ),
    signing_wrapper(
        "chio.autonomous-pricing-input.v1",
        "autonomous_pricing_input",
    ),
    signing_wrapper(
        "chio.autonomous-rollback-plan.v1",
        "autonomous_rollback_plan",
    ),
    signing_wrapper(
        "chio.budget-snapshot-anchor-commitment.v1",
        "budget_snapshot_anchor_commitment",
    ),
    (
        "chio.capability-lease.v1",
        Some((
            "chio_federation_capability_lease",
            "chio-final-architecture/v1",
        )),
    ),
    signing_wrapper(
        "chio.capital-pool-optimization.v1",
        "capital_pool_optimization",
    ),
    signing_wrapper(
        "chio.capital-pool-simulation-report.v1",
        "capital_pool_simulation_report",
    ),
    signing_wrapper("chio.certify.check.v1", "certify_check"),
    signing_wrapper("chio.compliance.certificate.v1", "compliance_certificate"),
    signing_wrapper("chio.credit.bond.v1", "credit_bond"),
    signing_wrapper(
        "chio.credit.capital-allocation.v1",
        "credit_capital_allocation",
    ),
    signing_wrapper(
        "chio.credit.capital-authority-step-proof.v1",
        "credit_capital_authority_step_proof",
    ),
    signing_wrapper("chio.credit.capital-book.v1", "credit_capital_book"),
    signing_wrapper(
        "chio.credit.capital-instruction.v1",
        "credit_capital_instruction",
    ),
    signing_wrapper("chio.credit.exposure-ledger.v1", "credit_exposure_ledger"),
    signing_wrapper("chio.credit.facility.v1", "credit_facility"),
    signing_wrapper("chio.credit.iou-envelope.v1", "credit_iou_envelope"),
    signing_wrapper("chio.credit.loss-lifecycle.v1", "credit_loss_lifecycle"),
    signing_wrapper(
        "chio.credit.provider-risk-package.v1",
        "credit_provider_risk_package",
    ),
    signing_wrapper("chio.credit.scorecard.v1", "credit_scorecard"),
    signing_wrapper("chio.cross-issuer-migration.v1", "cross_issuer_migration"),
    signing_wrapper(
        "chio.enterprise-migration-transition.v1",
        "enterprise_migration_transition",
    ),
    signing_wrapper(
        "chio.evidence_export_commitment.v1",
        "evidence_export_commitment",
    ),
    signing_wrapper(
        "chio.federated-delegation-policy.v1",
        "federated_delegation_policy",
    ),
    signing_wrapper(
        "chio.federation-activation-exchange.v1",
        "federation_activation_exchange",
    ),
    signing_wrapper(
        "chio.federation-kernel-handshake.v1",
        "federation_kernel_handshake",
    ),
    signing_wrapper(
        "chio.federation-open-admission-policy.v1",
        "federation_open_admission_policy",
    ),
    signing_wrapper("chio.federation-policy.v1", "federation_policy"),
    signing_wrapper(
        "chio.federation-qualification-matrix.v1",
        "federation_qualification_matrix",
    ),
    signing_wrapper(
        "chio.federation-quorum-report.v1",
        "federation_quorum_report",
    ),
    signing_wrapper(
        "chio.federation-reputation-clearing.v1",
        "federation_reputation_clearing",
    ),
    (
        "chio.federation.revocation-checkpoint.v1",
        Some((
            "chio_federation_revocation_checkpoint",
            "chio-final-architecture/v1",
        )),
    ),
    signing_wrapper(
        "chio.federation.transport.iroh.peer-directory-bundle.v1",
        "federation_transport_iroh_peer_directory_bundle",
    ),
    signing_wrapper(
        "chio.financial-agent-passport-presentation-response.v1",
        "financial_agent_passport_presentation_response",
    ),
    signing_wrapper(
        "chio.financial.cross-issuer-entry-activation-decision.v1",
        "financial_cross_issuer_entry_activation_decision",
    ),
    signing_wrapper(
        "chio.financial.cross-issuer-migration.v1",
        "financial_cross_issuer_migration",
    ),
    signing_wrapper(
        "chio.financial.cross-issuer-trust-pack.v1",
        "financial_cross_issuer_trust_pack",
    ),
    signing_wrapper(
        "chio.financial.cross-issuer.lifecycle-checkpoint-pin.v1",
        "financial_cross_issuer_lifecycle_checkpoint_pin",
    ),
    signing_wrapper(
        "chio.financial.cross-issuer.lifecycle-checkpoint.v1",
        "financial_cross_issuer_lifecycle_checkpoint",
    ),
    signing_wrapper(
        "chio.financial.cross-issuer.lifecycle-generation-pin.v1",
        "financial_cross_issuer_lifecycle_generation_pin",
    ),
    signing_wrapper(
        "chio.financial.cross-issuer.lifecycle-result.v1",
        "financial_cross_issuer_lifecycle_result",
    ),
    signing_wrapper(
        "chio.finding-pool.store-identity-proof.v1",
        "finding_pool_store_identity_proof",
    ),
    signing_wrapper(
        "chio.finding.anchor-checkpoint-publication.v1",
        "finding_anchor_checkpoint_publication",
    ),
    signing_wrapper(
        "chio.finding.audit-seed-witness.v1",
        "finding_audit_seed_witness",
    ),
    signing_wrapper(
        "chio.finding.bond-store-snapshot.v1",
        "finding_bond_store_snapshot",
    ),
    signing_wrapper(
        "chio.finding.current-listing-assertion.v1",
        "finding_current_listing_assertion",
    ),
    signing_wrapper(
        "chio.finding.hosted-api-key-lifecycle.v1",
        "finding_hosted_api_key_lifecycle",
    ),
    signing_wrapper(
        "chio.finding.hosted-canary-observation.v1",
        "finding_hosted_canary_observation",
    ),
    signing_wrapper(
        "chio.finding.operator-purchase-job.v1",
        "finding_operator_purchase_job",
    ),
    signing_wrapper(
        "chio.finding.status-intent-submission.v1",
        "finding_status_intent_submission",
    ),
    signing_wrapper(
        "chio.finding.voluntary-retraction-receipt.v1",
        "finding_voluntary_retraction_receipt",
    ),
    signing_wrapper("chio.frost.dkg-package.v1", "frost_dkg_package"),
    (
        "chio.governance-receipt.v1",
        Some((
            "chio_federation_governance_receipt",
            "chio-final-architecture/v1",
        )),
    ),
    signing_wrapper("chio.http-receipt.v1", "http_receipt"),
    signing_wrapper(
        "chio.iroh.revocation-signer-endorsement.v1",
        "iroh_revocation_signer_endorsement",
    ),
    signing_wrapper(
        "chio.iroh.transport-endorsement.v1",
        "iroh_transport_endorsement",
    ),
    signing_wrapper("chio.key-binding-certificate.v1", "key_binding_certificate"),
    signing_wrapper("chio.market.auto-bind.v1", "market_auto_bind"),
    signing_wrapper("chio.market.bound-coverage.v1", "market_bound_coverage"),
    signing_wrapper(
        "chio.market.claim-adjudication.v1",
        "market_claim_adjudication",
    ),
    signing_wrapper("chio.market.claim-dispute.v1", "market_claim_dispute"),
    signing_wrapper("chio.market.claim-package.v1", "market_claim_package"),
    signing_wrapper(
        "chio.market.claim-payout-instruction.v1",
        "market_claim_payout_instruction",
    ),
    signing_wrapper(
        "chio.market.claim-payout-receipt.v1",
        "market_claim_payout_receipt",
    ),
    signing_wrapper("chio.market.claim-response.v1", "market_claim_response"),
    signing_wrapper(
        "chio.market.claim-settlement-instruction.v1",
        "market_claim_settlement_instruction",
    ),
    signing_wrapper(
        "chio.market.claim-settlement-receipt.v1",
        "market_claim_settlement_receipt",
    ),
    signing_wrapper("chio.market.placement.v1", "market_placement"),
    signing_wrapper(
        "chio.market.pricing-authority.v1",
        "market_pricing_authority",
    ),
    signing_wrapper("chio.market.provider.v1", "market_provider"),
    signing_wrapper("chio.market.quote-request.v1", "market_quote_request"),
    signing_wrapper("chio.market.quote-response.v1", "market_quote_response"),
    signing_wrapper(
        "chio.marketplace.accepted-bid.v1",
        "marketplace_accepted_bid",
    ),
    signing_wrapper(
        "chio.marketplace.ask-response.v1",
        "marketplace_ask_response",
    ),
    signing_wrapper("chio.marketplace.bid-request.v1", "marketplace_bid_request"),
    signing_wrapper(
        "chio.marketplace.listing-pricing-hint.v1",
        "marketplace_listing_pricing_hint",
    ),
    signing_wrapper(
        "chio.marketplace.reservation-receipt.v1",
        "marketplace_reservation_receipt",
    ),
    (
        "chio.mcp.cage-launch-policy.v1",
        Some(("mcp_cage_launch_policy", "enterprise-security-execution-v1")),
    ),
    signing_wrapper("chio.mcp.operator-approval.v1", "mcp_operator_approval"),
    signing_wrapper(
        "chio.mcp.session-credential-call.v1",
        "mcp_session_credential_call",
    ),
    signing_wrapper("chio.mcp.session-credential.v1", "mcp_session_credential"),
    signing_wrapper("chio.parametric.contest.v1", "parametric_contest"),
    signing_wrapper(
        "chio.parametric.evidence-source-checkpoint.v1",
        "parametric_evidence_source_checkpoint",
    ),
    signing_wrapper(
        "chio.parametric.payout-intent.v1",
        "parametric_payout_intent",
    ),
    signing_wrapper("chio.passkey-capability.v1", "passkey_capability"),
    signing_wrapper(
        "chio.passport-verifier-policy.v1",
        "passport_verifier_policy",
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
    signing_wrapper(
        "chio.policy.activation-receipt-signature.v1",
        "policy_activation_receipt_signature",
    ),
    signing_wrapper("chio.portable-negative-event.v1", "portable_negative_event"),
    signing_wrapper(
        "chio.portable-reputation-summary.v1",
        "portable_reputation_summary",
    ),
    signing_wrapper("chio.process.swarm-profile.v1", "process_swarm_profile"),
    signing_wrapper("chio.provenance-stamp.v1", "provenance_stamp"),
    signing_wrapper(
        "chio.public-discovery-transparency.v1",
        "public_discovery_transparency",
    ),
    signing_wrapper("chio.public-issuer-discovery.v1", "public_issuer_discovery"),
    signing_wrapper(
        "chio.public-verifier-discovery.v1",
        "public_verifier_discovery",
    ),
    signing_wrapper(
        "chio.registry.governance-case.v1",
        "registry_governance_case",
    ),
    signing_wrapper(
        "chio.registry.governance-charter.v1",
        "registry_governance_charter",
    ),
    signing_wrapper("chio.registry.listing.v1", "registry_listing"),
    signing_wrapper(
        "chio.registry.market-fee-schedule.v1",
        "registry_market_fee_schedule",
    ),
    signing_wrapper("chio.registry.namespace.v1", "registry_namespace"),
    signing_wrapper(
        "chio.registry.trust-activation.v1",
        "registry_trust_activation",
    ),
    signing_wrapper(
        "chio.regulatory.receipt-export.v1",
        "regulatory_receipt_export",
    ),
    signing_wrapper(
        "chio.release-qualification-manifest.v1",
        "release_qualification_manifest",
    ),
    signing_wrapper("chio.reputation-credential.v1", "reputation_credential"),
    signing_wrapper(
        "chio.runtime-attestation.appraisal-report.v1",
        "runtime_attestation_appraisal_report",
    ),
    signing_wrapper(
        "chio.runtime-attestation.appraisal-result.v1",
        "runtime_attestation_appraisal_result",
    ),
    signing_wrapper(
        "chio.runtime-attestation.reference-values.v1",
        "runtime_attestation_reference_values",
    ),
    signing_wrapper(
        "chio.runtime-attestation.trust-bundle.v1",
        "runtime_attestation_trust_bundle",
    ),
    signing_wrapper(
        "chio.runtime-attestation.verifier-descriptor.v1",
        "runtime_attestation_verifier_descriptor",
    ),
    signing_wrapper(
        "chio.runtime.attack-simulation-report-signature.v1",
        "runtime_attack_simulation_report_signature",
    ),
    signing_wrapper(
        "chio.runtime.chaos-run-report-signature.v1",
        "runtime_chaos_run_report_signature",
    ),
    signing_wrapper(
        "chio.runtime.execution-lease-signature.v1",
        "runtime_execution_lease_signature",
    ),
    signing_wrapper(
        "chio.runtime.revocation-freshness-proof-signature.v1",
        "runtime_revocation_freshness_proof_signature",
    ),
    signing_wrapper(
        "chio.runtime.sandbox-attestation-signature.v1",
        "runtime_sandbox_attestation_signature",
    ),
    signing_wrapper(
        "chio.runtime.terminal-receipt-signature.v1",
        "runtime_terminal_receipt_signature",
    ),
    signing_wrapper(
        "chio.runtime.tool-server-ack-signature.v1",
        "runtime_tool_server_ack_signature",
    ),
    signing_wrapper(
        "chio.runtime.trusted-time-proof-signature.v1",
        "runtime_trusted_time_proof_signature",
    ),
    signing_wrapper("chio.signer-readiness-probe.v1", "signer_readiness_probe"),
    signing_wrapper(
        "chio.swarm.route-plan-receipt-signature.v1",
        "swarm_route_plan_receipt_signature",
    ),
    signing_wrapper("chio.tee-bless-audit.v1", "tee_bless_audit"),
    signing_wrapper("chio.tee-capture-frame.v1", "tee_capture_frame"),
    signing_wrapper("chio.trace-observation.v1", "trace_observation"),
    (
        "chio.treaty-epoch.v1",
        Some(("treaty_epoch", "treaty-epoch-commit-v1")),
    ),
    (
        "chio.trust.passport-revocation-root.v1",
        Some((
            "trust_passport_revocation_root",
            "federated-passport-revocation-v1",
        )),
    ),
    signing_wrapper("chio.underwriting.decision.v1", "underwriting_decision"),
    signing_wrapper(
        "chio.underwriting.policy-input.v1",
        "underwriting_policy_input",
    ),
    signing_wrapper("chio.wasm-module.v1", "wasm_module"),
    signing_wrapper("chio.work-dispatch-permit.v1", "work_dispatch_permit"),
    signing_wrapper("chio.work-offer.v1", "work_offer"),
    signing_wrapper("chio.work-selection.v1", "work_selection"),
    signing_wrapper("chio.work-subdivision.v1", "work_subdivision"),
    signing_wrapper("chio.workflow-receipt.v1", "workflow_receipt"),
    signing_wrapper(
        "chio.runtime-attestation-evidence.v1",
        "runtime_attestation_evidence",
    ),
    signing_wrapper(
        "chio.lineage.frontier-signature.v1",
        "lineage_frontier_signature",
    ),
    signing_wrapper("chio.portable-agent-passport.v1", "portable_agent_passport"),
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
        Some((
            "chio_runtime_admission_report",
            "chio-runtime-admission-schema-cutover/v1",
        )),
    ),
    (
        "chio.runtime.verifier-trust-bundle.v1",
        Some((
            "chio_runtime_verifier_trust_bundle",
            "chio-runtime-policy-schema-cutover/v1",
        )),
    ),
    (
        "chio.runtime.pheromone-policy.v1",
        Some((
            "chio_runtime_pheromone_policy",
            "chio-runtime-policy-schema-cutover/v1",
        )),
    ),
    (
        "chio.runtime.peer-weights.v1",
        Some((
            "chio_runtime_peer_weights",
            "chio-runtime-policy-schema-cutover/v1",
        )),
    ),
    (
        "chio.pheromone.query-report.v1",
        Some(("chio_pheromone_query_report", "chio-pheromone-runtime/v1")),
    ),
    signing_wrapper("chio.behavioral-feed.v1", "behavioral_feed"),
    signing_wrapper(
        "chio.finding.hosted-principal-lifecycle.v1",
        "hosted_principal_lifecycle",
    ),
    signing_wrapper(
        "chio.finding.hosted.aggregate-checkpoint.v1",
        "hosted_aggregate_checkpoint",
    ),
    signing_wrapper(
        "chio.finding.hosted-sqlite-import-batch.v1",
        "hosted_sqlite_import_batch",
    ),
    signing_wrapper(
        "chio.finding.hosted-replication-event.v1",
        "hosted_replication_event",
    ),
    signing_wrapper(
        "chio.finding.hosted-principal-replication-event.v1",
        "hosted_principal_replication_event",
    ),
    signing_wrapper(
        "chio.finding.hosted-replication-check.v1",
        "hosted_replication_check",
    ),
    signing_wrapper(
        "chio.finding.hosted-authority-transition.v1",
        "hosted_authority_transition",
    ),
    signing_wrapper(
        "chio.finding.hosted-journal-checkpoint.v1",
        "hosted_journal_checkpoint",
    ),
    signing_wrapper(
        "chio.finding.hosted-archive-manifest.v1",
        "hosted_archive_manifest",
    ),
    signing_wrapper("chio.finding.hosted-legal-hold.v1", "hosted_legal_hold"),
    signing_wrapper(
        "chio.finding.hosted-restore-verification.v1",
        "hosted_restore_verification",
    ),
    signing_wrapper("chio.finding.hosted-quota-alert.v1", "hosted_quota_alert"),
    signing_wrapper("chio.finding.hosted-gc-receipt.v1", "hosted_gc_receipt"),
    signing_wrapper(
        "chio.finding-status-operator-authorization.v1",
        "finding_status_operator_authorization",
    ),
    signing_wrapper(
        "chio.finding.worker-capability.v1",
        "finding_worker_capability",
    ),
    signing_wrapper(
        "chio.finding.worker-attested-result.v1",
        "finding_worker_attested_result",
    ),
];

const fn signing_wrapper(
    schema: &'static str,
    artifact_kind: &'static str,
) -> SignedArtifactSchemaSpec {
    (schema, Some((artifact_kind, "signing-wrapper-v1")))
}
