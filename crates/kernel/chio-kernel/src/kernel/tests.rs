#![allow(deprecated)]

include!("tests/support.rs");
include!("tests/support_delegation_plain.rs");
include!("tests/support_monetary.rs");
include!("tests/capability_validation.rs");
include!("tests/guard_pipeline.rs");
include!("tests/hot_path_deadlines.rs");
include!("tests/receipts.rs");
include!("tests/session.rs");
mod budget {
    use super::*;

    include!("tests/budget.rs");
}

mod budget_governed_call_chain {
    use super::*;

    include!("tests/budget_governed_call_chain.rs");
}
include!("tests/settlement_routing.rs");
include!("tests/budget_governed_assurance.rs");
include!("tests/emergency.rs");
include!("tests/constraint_variants.rs");
include!("tests/plan_evaluation.rs");
mod approval_flow {
    use super::*;

    include!("tests/approval_flow.rs");
}
include!("tests/admission_saga.rs");
include!("tests/ordinary_request_fingerprint.rs");
include!("tests/admission_payment_cleanup.rs");
include!("tests/execution_nonce.rs");
include!("tests/threshold_approval.rs");
include!("tests/threshold_coordinator.rs");
include!("tests/threshold_caller_reservation.rs");
include!("tests/authority_composition.rs");
include!("tests/compliance_score.rs");
include!("tests/multi_tenant_receipt.rs");
include!("tests/dispatch_intent_wiring.rs");
include!("tests/memory_provenance.rs");
include!("tests/federation_cosign.rs");
include!("tests/revocation_durability.rs");
include!("tests/chio_runtime.rs");
include!("tests/drop_guard_proptest.rs");
include!("tests/formal_closure.rs");
include!("tests/security_pre_dispatch.rs");
include!("tests/manifest_security.rs");

#[path = "tests/active_response_admission.rs"]
mod active_response_admission;

#[path = "tests/automatic_active_response_fence.rs"]
mod automatic_active_response_fence;
include!("tests/sim_payment.rs");
