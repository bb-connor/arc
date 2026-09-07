#![allow(deprecated)]

use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureInvocationRequest,
    BudgetCapturedBeforeDispatchCancellationDecision, BudgetInvocationCaptureDecision,
    BudgetMutationKind, BudgetReconcileHoldRequest, BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest,
};

include!("tests/support.rs");
include!("tests/support_providers.rs");
include!("tests/support_receipt_store_extensions.rs");
include!("tests/support_delegation_plain.rs");
include!("tests/support_budget_store_impls.rs");
include!("tests/support_monetary.rs");
include!("tests/settlement_routing.rs");
include!("tests/capability_validation.rs");
include!("tests/guard_pipeline.rs");
include!("tests/hot_path_deadlines.rs");
include!("tests/receipts.rs");
include!("tests/session.rs");
include!("tests/session_security_context.rs");
include!("tests/session_sampling_elicitation.rs");
include!("tests/budget.rs");
include!("tests/budget_cross_currency.rs");
include!("tests/budget_governed_fallback.rs");
include!("tests/budget_governed_call_chain.rs");
include!("tests/budget_governed_assurance.rs");
include!("tests/emergency.rs");
include!("tests/constraint_variants.rs");
include!("tests/plan_evaluation.rs");
include!("tests/approval_flow.rs");
#[path = "tests/boot_receipts.rs"]
mod boot_receipts;
#[path = "tests/session_reports.rs"]
mod session_reports;
#[path = "tests/threshold_crypto_floor.rs"]
mod threshold_crypto_floor;
#[path = "tests/threshold_issuance.rs"]
mod threshold_issuance;
include!("tests/execution_nonce_support.rs");
include!("tests/execution_nonce.rs");
include!("tests/execution_nonce_transient_settle.rs");
#[path = "tests/nonce_admission.rs"]
mod nonce_admission;
include!("tests/dispatch_credentials.rs");
include!("tests/immediate_dispatch_revalidation.rs");
include!("tests/post_payment_revalidation.rs");
include!("tests/payment_ambiguity.rs");
include!("tests/nested_url_side_effects.rs");
include!("tests/session_nonce_binding.rs");
include!("tests/compliance_score.rs");
include!("tests/multi_tenant_receipt.rs");
#[path = "tests/receipt_scope_isolation.rs"]
mod receipt_scope_isolation;
include!("tests/memory_provenance.rs");
include!("tests/federation_cosign.rs");
include!("tests/revocation_durability.rs");
include!("tests/durable_admission.rs");
include!("tests/durable_admission_url_elicitation_support.rs");
include!("tests/chio_runtime.rs");
include!("tests/chio_runtime_url_elicitation.rs");
include!("tests/drop_guard_proptest.rs");
include!("tests/formal_closure.rs");

#[path = "tests/automatic_active_response_fence.rs"]
mod automatic_active_response_fence;
include!("tests/sim_payment.rs");
