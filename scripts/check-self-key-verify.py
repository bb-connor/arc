#!/usr/bin/env python3
"""Fail on any production verify call that trusts a key the verified artifact carries itself.

Two kinds of site are tracked outside tests, each keyed by (file, enclosing fn) with its class
and call count:

  SELF_KEY_SITES        a verify entry point (verify_wrapped, verify_wrapped_bytes,
                        verify_wrapper, verify_exempt, verify_signature*) whose key argument is
                        a member path rooted in the same binding as the receiver, the artifact
                        or the signature argument, outside a verify_integrity_embedded_key* body
  EMBEDDED_KEY_CALLERS  a call to a verify_integrity_embedded_key* method; those methods verify
                        under the key the artifact carries, so each caller is classified

Classes:

  PINNED                         the carried key is compared with a trusted key first
  GUARDED                        a trusted key or membership check on the carried key gates use
  INTEGRITY-ONLY                 no authorization decision depends on the result
  NEEDS-TRUST-CONTEXT:<row id>   an authorization path whose trusted key arrives in <row id>

Code compiled only for tests or the fuzz feature is skipped. Sites under crates/kernel/ must
be PINNED or GUARDED. Each observed multiset must equal its
list: a new site fails, a removed site fails until its entry is deleted, so the lists only
shrink.

Usage: check-self-key-verify.py [--root DIR] [--print]
"""

import argparse
import bisect
import collections
import re
import sys
from pathlib import Path

CLASSES = re.compile(r"^(PINNED|GUARDED|INTEGRITY-ONLY|NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-[A-Z0-9-]+)$")
KERNEL_CLASSES = ("PINNED", "GUARDED")
KERNEL_PATH = "crates/kernel/"

VERIFY = re.compile(
    r"\b(verify_wrapped_bytes|verify_wrapped|verify_wrapper|verify_exempt|verify_signature\w*)\s*\("
)
EMBEDDED = re.compile(r"\bverify_integrity_embedded_key\w*\s*\(")
# (file, enclosing fn): (class, count)
SELF_KEY_SITES: dict[tuple[str, str], tuple[str, int]] = {
    ("crates/economy/chio-appraisal/src/appraisal.rs", "evaluate_imported_runtime_attestation_appraisal"): ("GUARDED", 1),
    ("crates/economy/chio-appraisal/src/attestation_verification.rs", "verify_signed_runtime_attestation_record"): ("GUARDED", 1),
    ("crates/economy/chio-appraisal/src/descriptor.rs", "verify_signed_runtime_attestation_reference_value_set"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-appraisal/src/descriptor.rs", "verify_signed_runtime_attestation_trust_bundle"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-appraisal/src/descriptor.rs", "verify_signed_runtime_attestation_verifier_descriptor"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-credit/src/credit/capital_execution_authority.rs", "validate_capital_execution_authority_step_proof"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-credit/src/factor/authorization.rs", "verify"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/factor/authorization.rs", "verify_assignment_bind_authorization"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/factor/result.rs", "verify_result_authority"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/financial_credentials.rs", "inspect_financial_source_member"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/financial_credentials.rs", "prepare_credit_scorecard_financial_source"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/financial_credentials.rs", "prepare_exposure_history_financial_source"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/financial_credentials.rs", "validate_scorecard_exposure_binding"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/financial_credentials/disclosure.rs", "validate_financial_source_disclosure"): ("GUARDED", 2),
    ("crates/economy/chio-credit/src/financial_credentials/projection.rs", "ordered_loss_events"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/financial_credentials/projection.rs", "ordered_underwriting_decisions"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/obligation/credit_admission.rs", "validate_facility_artifact"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/obligation/credit_facility_bind.rs", "verify"): ("GUARDED", 1),
    ("crates/economy/chio-credit/src/obligation/status.rs", "verify_obligation_status_proof"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/receivable_iou.rs", "verify_receipt"): ("GUARDED", 1),
    ("crates/economy/chio-fiscal/src/fiscal.rs", "verify"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-fiscal/src/lifecycle/support.rs", "verify_envelope"): ("GUARDED", 1),
    ("crates/economy/chio-listing/src/discovery.rs", "search"): ("GUARDED", 1),
    ("crates/economy/chio-listing/src/outcome/contract.rs", "authenticate_outcome_eligibility_at"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-listing/src/outcome/contract.rs", "verify_provider_envelope"): ("GUARDED", 1),
    ("crates/economy/chio-listing/src/outcome/delivery.rs", "authenticate_outcome_delivery_acknowledgement"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-listing/src/outcome/delivery.rs", "authenticate_outcome_delivery_checkpoint"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-listing/src/outcome/delivery.rs", "authenticate_outcome_delivery_nonacceptance"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-listing/src/outcome/evidence.rs", "verify_evidence_envelope"): ("GUARDED", 1),
    ("crates/economy/chio-listing/src/outcome/predicate.rs", "verify_outcome_predicate"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-listing/src/trust_activation.rs", "evaluate_generic_trust_activation"): ("GUARDED", 1),
    ("crates/economy/chio-listing/src/util.rs", "ensure_generic_listing_signed_by_namespace_owner"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-listing/src/util.rs", "validate_generic_listing_report"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-market/src/insurance_flow.rs", "receipt_signature_verifies"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-market/src/lib.rs", "verify_signed_artifact"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-market/src/parametric.rs", "verify"): ("GUARDED", 1),
    ("crates/economy/chio-market/src/parametric.rs", "verify_bound_coverage"): ("GUARDED", 1),
    ("crates/economy/chio-market/src/parametric/claim.rs", "validate_capital_instruction"): ("GUARDED", 1),
    ("crates/economy/chio-market/src/parametric/claim.rs", "validate_pre_reservation"): ("GUARDED", 1),
    ("crates/economy/chio-market/src/parametric/claim.rs", "verify"): ("GUARDED", 1),
    ("crates/economy/chio-market/src/parametric/evidence.rs", "verify_source_range"): ("GUARDED", 1),
    ("crates/economy/chio-market/src/parametric/lifecycle.rs", "validate"): ("GUARDED", 1),
    ("crates/economy/chio-market/src/placement.rs", "validate"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 6),
    ("crates/economy/chio-market/src/quote.rs", "validate"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 6),
    ("crates/economy/chio-market/src/settlement.rs", "validate"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 2),
    ("crates/economy/chio-open-market/src/authority.rs", "verify_signed_activation"): ("GUARDED", 1),
    ("crates/economy/chio-open-market/src/authority.rs", "verify_signed_case"): ("GUARDED", 1),
    ("crates/economy/chio-open-market/src/authority.rs", "verify_signed_charter"): ("GUARDED", 1),
    ("crates/economy/chio-open-market/src/authority.rs", "verify_signed_fee_schedule"): ("GUARDED", 1),
    ("crates/economy/chio-open-market/src/authority.rs", "verify_signed_penalty"): ("GUARDED", 1),
    ("crates/economy/chio-open-market/src/bidding.rs", "accept"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 2),
    ("crates/economy/chio-open-market/src/bidding.rs", "bid"): ("GUARDED", 2),
    ("crates/economy/chio-open-market/src/purchase_verification.rs", "verify_purchase_context_pure"): ("GUARDED", 4),
    ("crates/economy/chio-settle/src/evm/prepare.rs", "prepare_bond_lock"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-settle/src/evm/sign.rs", "ensure_instruction_ready"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-settle/src/finding_enforcement/plan.rs", "require_anchor_publisher_lifecycle"): ("GUARDED", 1),
    ("crates/economy/chio-web3/src/anchors.rs", "verify_checkpoint_statement"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-web3/src/identity.rs", "verify_web3_identity_binding"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-web3/src/settlement.rs", "validate_web3_settlement_dispatch"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 2),
    ("crates/kernel/chio-kernel-core/src/passport_verify.rs", "verify_parsed_passport"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/checkpoint.rs", "verify_checkpoint_signature"): ("INTEGRITY-ONLY", 1),
    ("crates/kernel/chio-kernel/src/compliance_certificate.rs", "verify_session_compliance_certificate"): ("INTEGRITY-ONLY", 1),
    ("crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs", "validate_completed_durable_receipt"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/kernel/effect_obligation/recovery.rs", "flush_locked"): ("GUARDED", 1),
    ("crates/kernel/chio-runtime-core/src/admission.rs", "validate_runtime_trust_input"): ("UNCLASSIFIED", 1),
    ("crates/kernel/chio-runtime-core/src/pheromone_policy.rs", "evaluate_runtime_pheromone_policy"): ("UNCLASSIFIED", 2),
    ("crates/kernel/chio-runtime-core/src/serde_io.rs", "verify_signed_runtime_admission_report"): ("UNCLASSIFIED", 1),
    ("crates/platform/chio-control-plane/src/attestation/model.rs", "verify_and_appraise"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/certify/verify.rs", "verify_signed_certification_check"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-PLATFORM", 1),
    ("crates/platform/chio-control-plane/src/evidence_export.rs", "verify_federation_policy"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-PLATFORM", 1),
    ("crates/platform/chio-control-plane/src/evidence_export/envelope.rs", "verify_manifest"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/evidence_export/verification.rs", "evidence_receipt_semantic_summary"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-control-plane/src/evidence_export/verification.rs", "verify_child_receipts"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/evidence_export/verification.rs", "verify_tool_receipts"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/federation_policy.rs", "verify_federation_admission_policy_record"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-PLATFORM", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator/governance_pins.rs", "require_pinned_governance"): ("GUARDED", 5),
    ("crates/platform/chio-control-plane/src/trust_control/finding_handlers.rs", "handle_activate_finding"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_operator_bundle.rs", "verify_at"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_purchase_coordinator.rs", "reserve_inner"): ("GUARDED", 2),
    ("crates/platform/chio-control-plane/src/trust_control/finding_purchase_routes.rs", "validate_shape"): ("GUARDED", 2),
    ("crates/platform/chio-control-plane/src/trust_control/finding_status_handlers.rs", "validate_intent_submission"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_status_publisher.rs", "current_epoch_for_point_proof"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_verified_fix.rs", "verify_listing"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/trust_control/service_types/requests.rs", "verify_federated_delegation_policy"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-PLATFORM", 1),
    ("crates/platform/chio-finding-hosted-edge/src/lifecycle.rs", "sign_event"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/fiscal_store/fee_schedule_binding.rs", "bind_fee_schedule_admitted"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_claims.rs", "record_liability_claim_adjudication"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_claims.rs", "record_liability_claim_dispute"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_claims.rs", "record_liability_claim_package"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_claims.rs", "record_liability_claim_payout_instruction"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_claims.rs", "record_liability_claim_payout_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_claims.rs", "record_liability_claim_response"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_claims.rs", "record_liability_claim_settlement_instruction"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_claims.rs", "record_liability_claim_settlement_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_market.rs", "record_liability_auto_bind_decision"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_market.rs", "record_liability_bound_coverage"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_market.rs", "record_liability_placement"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_market.rs", "record_liability_pricing_authority"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_market.rs", "record_liability_provider"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_market.rs", "record_liability_quote_request"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/liability_market.rs", "record_liability_quote_response"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs", "ensure_child_receipt_verified_with_context"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs", "ensure_chio_receipt_verified_with_context"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/support/signed_readback.rs", "decode_verified_signed_export"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/underwriting_credit.rs", "record_credit_bond"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/underwriting_credit.rs", "record_credit_facility"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/underwriting_credit.rs", "record_credit_loss_lifecycle"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/underwriting_credit.rs", "record_underwriting_decision"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-workflow/src/receipt.rs", "verify_vendor_signatures"): ("GUARDED", 1),
    ("crates/products/chio-cli/src/cli/dispatch/finding.rs", "verify_status_projection"): ("GUARDED", 1),
    ("crates/protocol/chio-acp-proxy/src/compliance.rs", "verify_compliance_certificate_at_time"): ("GUARDED", 1),
    ("crates/protocol/chio-tool-call-fabric/src/provenance.rs", "verify_signed_provenance"): ("INTEGRITY-ONLY", 1),
    ("crates/sdk/chio-binding-helpers/src/manifest.rs", "verify_signed_manifest"): ("INTEGRITY-ONLY", 1),
    ("crates/security/chio-secret-broker/src/audit.rs", "sign"): ("INTEGRITY-ONLY", 1),
    ("crates/security/chio-secret-broker/src/audit.rs", "sign_broker_audit_comparison"): ("INTEGRITY-ONLY", 1),
    ("crates/security/chio-secret-broker/src/privileged_audit.rs", "sign_challenge"): ("INTEGRITY-ONLY", 1),
    ("crates/security/chio-secret-broker/src/proof.rs", "verify_request_proof"): ("GUARDED", 1),
    ("crates/security/chio-secret-broker/src/receipt.rs", "sign_execution_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/security/chio-secret-broker/src/receipt.rs", "sign_failure_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/tooling/chio-release-evidence/src/main.rs", "validate_signed_manifest"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TOOLING-RELEASE-EVIDENCE", 1),
    ("crates/tooling/chio-trace-validate/src/observation.rs", "verify"): ("GUARDED", 1),
    ("crates/trust/chio-attest-buyer-core/src/revocation.rs", "validate_revocation_checkpoint"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 1),
    ("crates/trust/chio-credentials/src/cross_issuer.rs", "verify_signed_cross_issuer_migration"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 1),
    ("crates/trust/chio-credentials/src/discovery.rs", "verify_signed_public_discovery_transparency"): ("INTEGRITY-ONLY", 1),
    ("crates/trust/chio-credentials/src/discovery.rs", "verify_signed_public_issuer_discovery"): ("INTEGRITY-ONLY", 1),
    ("crates/trust/chio-credentials/src/discovery.rs", "verify_signed_public_verifier_discovery"): ("INTEGRITY-ONLY", 1),
    ("crates/trust/chio-credentials/src/financial.rs", "inspect_financial_credential_signature"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 1),
    ("crates/trust/chio-credentials/src/financial/agent_passport.rs", "inspect_financial_passport_source_manifest_signature"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 1),
    ("crates/trust/chio-credentials/src/financial/agent_passport.rs", "validate_financial_passport_presentation_challenge_contract"): ("INTEGRITY-ONLY", 1),
    ("crates/trust/chio-credentials/src/financial/authority/evaluation.rs", "evaluate_financial_credentials"): ("GUARDED", 1),
    ("crates/trust/chio-credentials/src/financial/authority/lifecycle.rs", "verify_checkpoint_pin"): ("GUARDED", 1),
    ("crates/trust/chio-credentials/src/financial/authority/lifecycle.rs", "verify_generation_pin"): ("GUARDED", 1),
    ("crates/trust/chio-credentials/src/financial/authority/lifecycle.rs", "verify_lifecycle_checkpoint"): ("GUARDED", 1),
    ("crates/trust/chio-credentials/src/financial/authority/lifecycle.rs", "verify_lifecycle_result"): ("GUARDED", 1),
    ("crates/trust/chio-credentials/src/financial/authority/trust/artifacts.rs", "verify_activation_decision_signature"): ("GUARDED", 1),
    ("crates/trust/chio-credentials/src/financial/authority/trust/artifacts.rs", "verify_financial_cross_issuer_migration"): ("GUARDED", 1),
    ("crates/trust/chio-credentials/src/financial/authority/trust/artifacts.rs", "verify_financial_cross_issuer_trust_pack"): ("GUARDED", 1),
    ("crates/trust/chio-credentials/src/financial/validation.rs", "validate_bundled_source_signers"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 5),
    ("crates/trust/chio-credentials/src/financial/validation.rs", "validate_financial_evidence"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 1),
    ("crates/trust/chio-credentials/src/portable_reputation.rs", "evaluate_portable_reputation"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 2),
    ("crates/trust/chio-credentials/src/registry.rs", "verify_signed_passport_verifier_policy"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 1),
    ("crates/trust/chio-federation-transport-iroh/src/identity.rs", "verify_bundle_inner"): ("PINNED", 1),
    ("crates/trust/chio-federation/src/bilateral_dsse/typestate_handlers.rs", "request_cosignature"): ("PINNED", 1),
    ("crates/trust/chio-finding-challenge/src/standing.rs", "authenticate_bid_and_reservation"): ("GUARDED", 2),
    ("crates/trust/chio-finding-verifier/src/checkpoints.rs", "has_strict_checkpoint_signature"): ("GUARDED", 1),
    ("crates/trust/chio-finding-verifier/src/receipts.rs", "verify_receipt_strict"): ("GUARDED", 1),
    ("crates/trust/chio-governance/src/authorization.rs", "verify_destructive_authorization"): ("GUARDED", 1),
    ("crates/trust/chio-governance/src/authorization.rs", "verify_step_governance_boundary"): ("GUARDED", 1),
    ("crates/trust/chio-governance/src/evaluation.rs", "evaluate_generic_governance_case"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 5),
    ("crates/trust/chio-governance/src/generic.rs", "validate"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 3),
    ("crates/trust/chio-governance/src/lease.rs", "verify_capability_lease"): ("GUARDED", 1),
    ("crates/trust/chio-pheromone-runtime/src/lib.rs", "runtime_policy_from_json"): ("GUARDED", 1),
}
EMBEDDED_KEY_CALLERS: dict[tuple[str, str], tuple[str, int]] = {
    ("crates/core/chio-core-types/src/capability/aggregate_invocation.rs", "verify_aggregate_invocation_budget"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/aggregate_invocation.rs", "verify_binding_matches_root"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/aggregate_invocation.rs", "verify_descendant"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/attenuation.rs", "delegate"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/attenuation.rs", "validate_delegation_chain"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/cumulative_approval.rs", "delegation_binding_marker"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/cumulative_approval.rs", "validate_scope_shape"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/cumulative_approval.rs", "verified_descendant"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/cumulative_approval.rs", "verify_binding_matches_root"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/cumulative_approval.rs", "verify_cumulative_approval_constraints"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/capability/token.rs", "validate_schema"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/receipt/authoritative_spend.rs", "is_authoritative_spend_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/core/chio-core-types/src/recovery/knowledge.rs", "verify_artifact_archive"): ("GUARDED", 1),
    ("crates/core/chio-core-types/src/recovery/knowledge.rs", "verify_artifact_certificate"): ("GUARDED", 1),
    ("crates/economy/chio-anchor/src/batch.rs", "verify_anchor_batch"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-anchor/src/functions.rs", "prepare_functions_batch_verification"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-credit/src/clearing/abort.rs", "verify_abort_burn"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/abort.rs", "verify_clearing_round_abort"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/abort.rs", "verify_clearing_zero_dispatch_proof"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/engine.rs", "validate_input_manifest"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/engine.rs", "validate_participant_acknowledgements"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/engine.rs", "validate_participant_snapshot"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/engine.rs", "verified_body"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/finalization.rs", "verify_clearing_participant_acceptances"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/finalization.rs", "verify_clearing_round_finalization_envelope"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/lifecycle/reconciliation.rs", "verify_reconciliation"): ("UNCLASSIFIED", 2),
    ("crates/economy/chio-credit/src/clearing/lifecycle/replay.rs", "verify_satisfaction_replay"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/lifecycle/replay.rs", "verify_zero_intent_reconciliation_replay"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/lifecycle/satisfaction.rs", "compose_clearing_satisfaction_transition"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/clearing/lifecycle/zero_intent.rs", "compose_clearing_zero_intent_reconciliation_transition"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-credit/src/local_account.rs", "evaluate"): ("PINNED", 1),
    ("crates/economy/chio-credit/src/obligation/credit_admission.rs", "validate_capability_artifact"): ("PINNED", 1),
    ("crates/economy/chio-finding/src/audit_epoch.rs", "validate"): ("UNCLASSIFIED", 1),
    ("crates/economy/chio-open-market/src/bidding.rs", "accept"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-open-market/src/recovery.rs", "verify_finding_recovery_context"): ("GUARDED", 2),
    ("crates/economy/chio-settle/src/channel/state.rs", "verify_channel_receipt_binding"): ("PINNED", 1),
    ("crates/economy/chio-settle/src/channel/terminal_outcome.rs", "verify_channel_terminal_outcome_commitment"): ("PINNED", 2),
    ("crates/economy/chio-settle/src/evm/prepare.rs", "prepare_dual_sign_release"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-settle/src/solana.rs", "verify_solana_binding_and_receipt"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/economy/chio-web3/src/anchors.rs", "verify_anchor_inclusion_proof"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-ECONOMY", 1),
    ("crates/kernel/chio-kernel-browser/src/pure.rs", "verify_receipt_pure"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel-core/src/capability_verify.rs", "verify_capability_base"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/admission_operation/governed_approval_claim.rs", "from_token"): ("INTEGRITY-ONLY", 1),
    ("crates/kernel/chio-kernel/src/admission_operation/projection.rs", "validate_receipt_projection"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/admission_operation/projection/authorization.rs", "from_signed_source"): ("GUARDED", 2),
    ("crates/kernel/chio-kernel/src/admission_operation/projection/channel_terminal_authority.rs", "commit_prepared_channel_terminal_projection"): ("UNCLASSIFIED", 1),
    ("crates/kernel/chio-kernel/src/admission_operation/remote_projection.rs", "from_verified"): ("UNCLASSIFIED", 1),
    ("crates/kernel/chio-kernel/src/approval.rs", "verify_against"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/approval/collector.rs", "validate"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/approval/collector.rs", "validate_new"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/authority.rs", "validate_issued_response_at"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/capability_lineage.rs", "validate_signed_token"): ("INTEGRITY-ONLY", 1),
    ("crates/kernel/chio-kernel/src/kernel/active_response_admission.rs", "new"): ("UNCLASSIFIED", 1),
    ("crates/kernel/chio-kernel/src/kernel/active_response_admission.rs", "validate_active_response_submission"): ("UNCLASSIFIED", 1),
    ("crates/kernel/chio-kernel/src/kernel/active_response_artifact.rs", "verify_active_response_artifact_authority_attestation"): ("UNCLASSIFIED", 1),
    ("crates/kernel/chio-kernel/src/kernel/admission_terminal_receipt.rs", "validate_terminal_receipt_payload"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/kernel/credential_reservation/preparation.rs", "valid_until_unix_ms"): ("INTEGRITY-ONLY", 1),
    ("crates/kernel/chio-kernel/src/kernel/governed_validation.rs", "validate_governed_call_chain_upstream_proof"): ("GUARDED", 2),
    ("crates/kernel/chio-kernel/src/kernel/governed_validation.rs", "verify_governed_approval_signature"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs", "record_finding_memory_write_lineage"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs", "revalidate_finding_memory_write_status_before_dispatch"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs", "validate_finding_memory_write_admission"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/kernel/settlement_observer.rs", "build_observation"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/receipt_store.rs", "new"): ("GUARDED", 2),
    ("crates/kernel/chio-kernel/src/response_simulation_report.rs", "verify_response_simulation_receipt"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/threshold_approval/collector_validation.rs", "validate_restored"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/threshold_approval/collector_validation.rs", "validate_token_binding"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/threshold_approval/verification.rs", "verify_threshold_approval_proposal"): ("GUARDED", 1),
    ("crates/kernel/chio-kernel/src/threshold_approval/verification.rs", "verify_threshold_approval_set_with_requirement"): ("GUARDED", 1),
    ("crates/kernel/chio-process/src/lib.rs", "validate_child"): ("GUARDED", 1),
    ("crates/kernel/chio-process/src/lib.rs", "verify_capability"): ("GUARDED", 1),
    ("crates/kernel/chio-runtime-core/src/buyer/proof_package.rs", "proof_package_contains_signed_receipt"): ("GUARDED", 1),
    ("crates/kernel/chio-runtime-core/src/buyer/proof_package.rs", "proof_package_receipt_subject"): ("GUARDED", 1),
    ("crates/observability/chio-lineage/src/ingest_active_defense.rs", "verify"): ("GUARDED", 1),
    ("crates/observability/chio-lineage/src/ingest_replay_corpus.rs", "signed_lineage_statement_verifies"): ("INTEGRITY-ONLY", 1),
    ("crates/observability/chio-siem/src/alerting.rs", "derive_severity"): ("INTEGRITY-ONLY", 1),
    ("crates/observability/chio-siem/src/alerting.rs", "should_alert"): ("GUARDED", 1),
    ("crates/observability/chio-siem/src/event.rs", "new"): ("GUARDED", 1),
    ("crates/platform/chio-agent-web-interop/src/interop.rs", "validate_agent_web_receipt"): ("GUARDED", 1),
    ("crates/platform/chio-commerce-order/src/replay.rs", "validate_event_authority_receipt"): ("GUARDED", 1),
    ("crates/platform/chio-commerce-order/src/settlement.rs", "validate_settlement_dispatch_receipt"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/economic_admission_cancellation.rs", "cancel_after_handoff"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-control-plane/src/security/adapters/native_evidence.rs", "verify_native_security_receipt"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/security/adapters/native_flow.rs", "validate_declassification_issuer"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/security/event_consumer/admission.rs", "verify_authority_attestation"): ("GUARDED", 2),
    ("crates/platform/chio-control-plane/src/security/event_consumer/verification.rs", "verify_receipt_event"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_purchase_coordinator.rs", "reserve_inner"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_purchase_coordinator.rs", "verify_terminal"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_purchase_routes.rs", "validate_shape"): ("GUARDED", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_retraction_resolver.rs", "verified_finding_parent"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_retraction_resolver.rs", "verify_retained_child_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-control-plane/src/trust_control/finding_retraction_resolver.rs", "verify_retained_parent_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-enterprise-export/src/artifacts.rs", "validate_telemetry_projection"): ("GUARDED", 1),
    ("crates/platform/chio-finding-hosted-edge/src/auth.rs", "authenticate_capability"): ("GUARDED", 1),
    ("crates/platform/chio-finding-market-store-postgres/src/domain.rs", "parse_authenticated_delivery"): ("GUARDED", 1),
    ("crates/platform/chio-http-core/src/authority.rs", "validate_capability_token"): ("GUARDED", 1),
    ("crates/platform/chio-http-core/src/evaluation.rs", "from_http_receipt"): ("GUARDED", 1),
    ("crates/platform/chio-http-core/src/receipt.rs", "to_chio_receipt_with_keypair"): ("GUARDED", 1),
    ("crates/platform/chio-http-core/src/receipt.rs", "verify_chio_receipt_projection"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/admission_operation_store.rs", "commit_signed_terminal_projection"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-PLATFORM", 1),
    ("crates/platform/chio-store-sqlite/src/admission_operation_store.rs", "decode_projection_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/admission_operation_store/participant.rs", "stage_anchored_terminal_projection"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/policy.rs", "validate_live_declassification"): ("GUARDED", 1),
    ("crates/platform/chio-store-sqlite/src/economic_state_cache.rs", "admission_terminal_projection_effect_result"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/economic_state_cache.rs", "load_anchored_terminal_projection_in_transaction"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/economic_state_cache.rs", "record_anchor_advanced"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/economic_state_cache.rs", "stage_admission_terminal_projection"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/finding_pool_ledger.rs", "record_mutation_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/finding_pool_ledger/outbox.rs", "claim_pending_mutation_receipts"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/iou_store.rs", "verify_envelope"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/reports/behavioral.rs", "behavioral_feed_receipt_row_from_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/receipt_store/support/signed_readback.rs", "decode_verified_lineage_statement"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-store-sqlite/src/security_state/native_egress.rs", "declassified"): ("INTEGRITY-ONLY", 1),
    ("crates/platform/chio-workflow/src/delegation/transition.rs", "select"): ("GUARDED", 2),
    ("crates/platform/chio-workflow/src/delegation/transition.rs", "subdivide"): ("GUARDED", 1),
    ("crates/platform/chio-workflow/src/delegation/transition.rs", "verify_historical_permit"): ("GUARDED", 1),
    ("crates/platform/chio-workflow/src/delegation/types.rs", "verify_dispatch_permit"): ("GUARDED", 3),
    ("crates/products/chio-api-protect/src/proxy/sidecar.rs", "sidecar_chio_receipt_report"): ("GUARDED", 1),
    ("crates/products/chio-api-protect/src/proxy/sidecar.rs", "sidecar_validate_capability_handler"): ("GUARDED", 1),
    ("crates/products/chio-cli/src/active_defense_migration.rs", "verify_backfill_receipts"): ("PINNED", 1),
    ("crates/products/chio-cli/src/cli/replay/verify.rs", "verify_receipt"): ("PINNED", 1),
    ("crates/products/chio-cli/src/cli/trust/receipt/explain.rs", "explain_receipt_value"): ("PINNED", 1),
    ("crates/products/chio-mercury-core/src/proof_package.rs", "verify_chio_bundle"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-PRODUCTS", 2),
    ("crates/protocol/chio-acp-edge/src/edge.rs", "evaluate_permission_with_kernel"): ("GUARDED", 1),
    ("crates/protocol/chio-acp-proxy/src/compliance.rs", "validate_compliance_receipt"): ("GUARDED", 1),
    ("crates/protocol/chio-acp-proxy/src/kernel_signer.rs", "verify_live_authorization_receipt"): ("GUARDED", 1),
    ("crates/protocol/chio-acp-proxy/src/telemetry.rs", "verify"): ("INTEGRITY-ONLY", 1),
    ("crates/protocol/chio-ag-ui-proxy/src/receipt.rs", "verify_with_trusted_kernel_keys"): ("GUARDED", 1),
    ("crates/protocol/chio-mcp-remote/src/remote_mcp/approvals/redemption.rs", "redeem"): ("GUARDED", 1),
    ("crates/protocol/chio-mcp-remote/src/remote_mcp/approvals/validation.rs", "decision"): ("GUARDED", 1),
    ("crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials/completed_result.rs", "verified_receipt"): ("PINNED", 1),
    ("crates/sdk/chio-binding-helpers/src/capability.rs", "verify_capability"): ("INTEGRITY-ONLY", 1),
    ("crates/sdk/chio-binding-helpers/src/receipt.rs", "verify_receipt_with_trusted_signers"): ("GUARDED", 1),
    ("crates/sdk/chio-eval-receipt/src/verify.rs", "verify_chio_receipt_payload"): ("INTEGRITY-ONLY", 1),
    ("crates/security/chio-cage/src/confinement.rs", "bound_launch_is_fully_enforced"): ("GUARDED", 1),
    ("crates/security/chio-cage/src/receipt.rs", "verify_signed_cage_receipt"): ("INTEGRITY-ONLY", 1),
    ("crates/security/chio-flow/src/declassification.rs", "verify_declassification"): ("GUARDED", 1),
    ("crates/security/chio-flow/src/declassification.rs", "verify_recovery_declassification"): ("GUARDED", 1),
    ("crates/security/chio-flow/src/recovery_authority.rs", "verify_coverage"): ("GUARDED", 1),
    ("crates/security/chio-recovery/src/report.rs", "verify_explanation_report"): ("GUARDED", 1),
    ("crates/security/chio-recovery/src/report.rs", "verify_explanation_view"): ("GUARDED", 1),
    ("crates/security/chio-secret-broker/src/audit.rs", "canonical_bytes"): ("UNCLASSIFIED", 2),
    ("crates/security/chio-secret-broker/src/audit.rs", "from_canonical_bytes"): ("UNCLASSIFIED", 2),
    ("crates/security/chio-secret-broker/src/audit.rs", "runner_authorization_digest"): ("UNCLASSIFIED", 1),
    ("crates/security/chio-secret-broker/src/audit.rs", "verify_broker_audit_evidence"): ("UNCLASSIFIED", 1),
    ("crates/security/chio-secret-broker/src/audit.rs", "verify_broker_audit_runner_authorization"): ("UNCLASSIFIED", 1),
    ("crates/security/chio-secret-broker/src/provision.rs", "verify_governed_admin_authorization_inner"): ("GUARDED", 1),
    ("crates/security/chio-semantic-contracts/src/registry.rs", "compile_semantic_registry"): ("GUARDED", 2),
    ("crates/security/chio-semantic-contracts/src/verification.rs", "verify_invocation"): ("GUARDED", 5),
    ("crates/tooling/chio-conformance/src/native_suite.rs", "evaluate_artifact_assertion"): ("INTEGRITY-ONLY", 3),
    ("crates/tooling/chio-conformance/src/native_suite.rs", "evaluate_message_assertion"): ("INTEGRITY-ONLY", 1),
    ("crates/tooling/chio-trace-validate/src/map/revocation.rs", "project_revocation_trace"): ("INTEGRITY-ONLY", 1),
    ("crates/trust/chio-attest-buyer-core/src/report.rs", "verify_package_inner"): ("GUARDED", 1),
    ("crates/trust/chio-attest-loopback/src/runtime_validation.rs", "validate_runtime_receipt_for_vendor"): ("PINNED", 1),
    ("crates/trust/chio-federation/src/bilateral_dsse/verify.rs", "verify_dsse_envelope"): ("PINNED", 1),
    ("crates/trust/chio-federation/src/bilateral_verifier/cosign.rs", "verify_bilateral_cosign_invocation"): ("PINNED", 1),
    ("crates/trust/chio-federation/src/bilateral_verifier/cosign.rs", "verify_chio_bilateral_invocation_inner"): ("PINNED", 1),
    ("crates/trust/chio-federation/src/trust_establishment.rs", "accept_envelope_with_policy"): ("GUARDED", 1),
    ("crates/trust/chio-reputation/src/lib.rs", "receipt_integrity_valid"): ("PINNED", 1),
    ("crates/trust/chio-selective-disclosure/src/lib.rs", "receipt_signed_projection"): ("NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-TRUST", 1),
}

TEST_PATH = re.compile(r"(^|/)(tests|benches|examples|fixtures)/|(^|/)tests\.rs$|_tests?\.rs$|_tests/|test_support")
CFG_ATTR = re.compile(r"#\[cfg\(")
IDENT = re.compile(r"[A-Za-z_]\w*")
RAW_OPEN = re.compile(r'r(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\.|[^'\\])'")
FN_KEYWORD_BEFORE = re.compile(r"\bfn\s*$")


def balanced_end(text, open_index):
    """Index just past the bracket that closes text[open_index]."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[text[open_index]]]
    i = open_index + 1
    while i < len(text) and stack:
        c = text[i]
        if c in pairs:
            stack.append(pairs[c])
        elif stack and c == stack[-1]:
            stack.pop()
        i += 1
    return i


def requires_test(predicate):
    predicate = predicate.strip()
    if predicate in ("test", 'feature = "fuzz"'):
        return True
    m = re.match(r"^(all|any)\((.*)\)$", predicate, re.S)
    if not m:
        return False
    depth, parts, start = 0, [], 0
    body = m.group(2)
    for i, c in enumerate(body):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(body[start:i])
            start = i + 1
    parts.append(body[start:])
    if m.group(1) == "all":
        return any(requires_test(p) for p in parts)
    return any(p.strip() in ("test", 'feature = "fuzz"') for p in parts)


def test_cfg_spans(text):
    """(start, end) of every attribute plus item gated on a cfg that requires test."""
    spans = []
    for m in CFG_ATTR.finditer(text):
        close = balanced_end(text, m.end() - 1)
        if not requires_test(text[m.end() : close - 1]):
            continue
        i = close
        while i < len(text) and text[i] not in "{;":
            i += 1
        end = balanced_end(text, i) if i < len(text) and text[i] == "{" else i + 1
        spans.append((m.start(), end))
    return spans


def blank(text, spans):
    out = list(text)
    for start, end in spans:
        for j in range(start, min(end, len(out))):
            if out[j] != "\n":
                out[j] = " "
    return "".join(out)


def strip_comments_and_strings(text):
    """Blank comment bodies and string or char literal contents, keeping offsets and newlines."""
    out = list(text)
    i, n = 0, len(text)

    def wipe(a, b):
        for j in range(a, min(b, n)):
            if out[j] != "\n":
                out[j] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            wipe(i, end)
            i = end
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            wipe(i, j)
            i = j
        elif c == "r" and RAW_OPEN.match(text, i) and not (i and (text[i - 1].isalnum() or text[i - 1] == "_")):
            hashes = RAW_OPEN.match(text, i).group(1)
            close = text.find('"' + hashes, i + 2 + len(hashes))
            close = n if close < 0 else close
            wipe(i + 2 + len(hashes), close)
            i = close + 1 + len(hashes)
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            wipe(i + 1, j)
            i = j + 1
        elif c == "'" and CHAR_LITERAL.match(text, i):
            j = CHAR_LITERAL.match(text, i).end()
            wipe(i + 1, j - 1)
            i = j
        else:
            i += 1
    return "".join(out)


def split_args(args):
    depth, parts, start = 0, [], 0
    for i, c in enumerate(args):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(args[start:i])
            start = i + 1
    parts.append(args[start:])
    return [p.strip() for p in parts if p.strip()]


def root_of(expr):
    expr = re.sub(r"^(?:&\s*(?:mut\s+)?|\*|\()*\s*", "", expr)
    m = IDENT.match(expr)
    return m.group(0) if m else None


def is_member_path(expr):
    expr = re.sub(r"^(?:&\s*(?:mut\s+)?|\*|\()*\s*", "", expr)
    return re.match(r"^[A-Za-z_]\w*(?:\(\))?\s*\.", expr) is not None


def receiver_root(text, name_start):
    """Root binding of the receiver when the call is `<receiver>.name(`, else None."""
    i = name_start - 1
    while i >= 0 and text[i].isspace():
        i -= 1
    if i < 0 or text[i] != ".":
        return None
    i -= 1
    root = None
    while i >= 0:
        while i >= 0 and text[i].isspace():
            i -= 1
        if i >= 0 and text[i] == "?":
            i -= 1
            continue
        if i >= 0 and text[i] in ")]":
            depth = 0
            while i >= 0:
                if text[i] in ")]":
                    depth += 1
                elif text[i] in "([":
                    depth -= 1
                    if depth == 0:
                        i -= 1
                        break
                i -= 1
            continue
        end = i + 1
        while i >= 0 and (text[i].isalnum() or text[i] == "_"):
            i -= 1
        if end == i + 1:
            return root
        root = text[i + 1 : end]
        j = i
        while j >= 0 and text[j].isspace():
            j -= 1
        if j >= 0 and text[j] == "." and not (j > 0 and text[j - 1] == "."):
            i = j - 1
            continue
        return root
    return root


def is_self_key(text, m):
    open_index = m.end() - 1
    args = split_args(text[open_index + 1 : balanced_end(text, open_index) - 1])
    if not args:
        return False
    key, rest = args[0], args[1:]
    if not is_member_path(key):
        return False
    roots = {root_of(arg) for arg in rest}
    receiver = receiver_root(text, m.start(1))
    if receiver is not None:
        roots.add(receiver)
    return root_of(key) in roots


def gated_module_files(root):
    gated = set()
    for path in root.joinpath("crates").rglob("*.rs"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "mod " not in text:
            continue
        for start, end in test_cfg_spans(text):
            m = re.match(r"#\[cfg\(.*?\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", text[start:end], re.S)
            if not m:
                continue
            name = m.group(1)
            explicit = re.search(r"#\[path\s*=\s*\"([^\"]+)\"\]", text[start:end])
            base = path.parent if path.stem in ("mod", "lib", "main") else path.parent / path.stem
            candidates = [path.parent / explicit.group(1)] if explicit else []
            candidates += [base / f"{name}.rs", base / name / "mod.rs", path.parent / f"{name}.rs"]
            for cand in candidates:
                if cand.exists():
                    gated.add(cand.resolve())
                    if cand.name == "mod.rs":
                        gated.update(p.resolve() for p in cand.parent.rglob("*.rs"))
    return gated


def occurrences(root):
    """Yield (kind, file, enclosing fn, line) for every tracked production site."""
    gated = gated_module_files(root)
    for path in sorted(root.joinpath("crates").rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if TEST_PATH.search(rel) or path.resolve() in gated:
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        if "verify_" not in raw:
            continue
        text = strip_comments_and_strings(blank(raw, test_cfg_spans(raw)))
        fns = [(m.start(), m.group(1)) for m in re.finditer(r"\bfn\s+(\w+)", text)]
        starts = [start for start, _ in fns]

        def enclosing(pos):
            index = bisect.bisect_left(starts, pos)
            return fns[index - 1][1] if index else "<module>"

        def is_definition(pos):
            return FN_KEYWORD_BEFORE.search(text, max(0, pos - 16), pos) is not None

        for m in VERIFY.finditer(text):
            if is_definition(m.start()):
                continue
            fn = enclosing(m.start())
            if fn.startswith("verify_integrity_embedded_key"):
                continue
            if is_self_key(text, m):
                yield "self-key", rel, fn, text.count("\n", 0, m.start()) + 1
        for m in EMBEDDED.finditer(text):
            if is_definition(m.start()):
                continue
            fn = enclosing(m.start())
            if fn.startswith("verify_integrity_embedded_key"):
                continue
            yield "embedded", rel, fn, text.count("\n", 0, m.start()) + 1


def scan(root):
    self_key = collections.Counter()
    embedded = collections.Counter()
    for kind, rel, fn, _ in occurrences(root):
        (self_key if kind == "self-key" else embedded)[(rel, fn)] += 1
    return self_key, embedded


def check(self_key, embedded, self_key_list=None, embedded_list=None):
    tracked = (
        ("SELF_KEY_SITES", "self-key verify", self_key, SELF_KEY_SITES if self_key_list is None else self_key_list),
        ("EMBEDDED_KEY_CALLERS", "embedded-key verify", embedded, EMBEDDED_KEY_CALLERS if embedded_list is None else embedded_list),
    )
    errors = []
    for list_name, label, observed, allowlist in tracked:
        for key, (cls, _) in sorted(allowlist.items()):
            if not CLASSES.match(cls):
                errors.append(f"{list_name} {key}: invalid class {cls}")
            elif key[0].startswith(KERNEL_PATH) and cls not in KERNEL_CLASSES:
                errors.append(f"{list_name} {key}: kernel sites must be PINNED or GUARDED, not {cls}")
        for key in sorted(set(observed) | set(allowlist)):
            allowed = allowlist.get(key, (None, 0))[1]
            if observed[key] != allowed:
                errors.append(f"{list_name} {key}: observed {observed[key]} {label} call(s), allowed {allowed}")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--print", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    self_key, embedded = scan(root)
    if args.print:
        for list_name, observed in (("SELF_KEY_SITES", self_key), ("EMBEDDED_KEY_CALLERS", embedded)):
            print(f"{list_name} = {{")
            for (rel, fn), count in sorted(observed.items()):
                print(f'    ("{rel}", "{fn}"): ("UNCLASSIFIED", {count}),')
            print("}")
        return 0
    errors = check(self_key, embedded)
    if errors:
        print("check-self-key-verify: FAIL", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(
        f"check-self-key-verify: ok ({sum(self_key.values())} self-key sites, "
        f"{sum(embedded.values())} embedded-key callers)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
