//! (a)-(f) predicate matrix with a real kernel-signed nonce, R1-R6 negatives,
//! and the structural greppable invariant.
//!
//! R2 (committed-cost integration): authoritative_spend_enforcement.rs
//! R3 (reaper crash-safety): task-11 crate tests
//! R5 (advisory visible failure): authoritative_spend_double_spend.rs +
//!     hot_path_enforcement.rs + task-8/9/10
//! R6 (profile freeze): task-2/3 chio-kernel crate tests
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::authoritative_spend::{
    is_authoritative_spend_receipt, NotAuthoritativeReason,
};
use chio_core::receipt::kinds::TrustLevel;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_kernel::runtime::ToolCallRequest;
use std::sync::Arc;

mod support;
use support::{issue_cost_bearing_capability, mediation_kernel, MonetaryCostServer};

fn mediated_case() -> (
    Keypair,
    chio_core::receipt::body::ChioReceipt,
    Box<chio_kernel::execution_nonce::SignedExecutionNonce>,
) {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let mut kernel = mediation_kernel(&signer, Arc::clone(&budget), false);
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 50, "USD")));
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let request = ToolCallRequest {
        request_id: "req-matrix".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({ "k": "v" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let nonce = response.execution_nonce.clone().expect("nonce");
    (signer, response.receipt, nonce)
}

#[test]
fn baseline_passes() {
    let (signer, receipt, nonce) = mediated_case();
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()),
        Ok(())
    );
}

#[test]
fn e_signer_not_admitted_is_rejected() {
    let (_signer, receipt, nonce) = mediated_case();
    assert_eq!(
        is_authoritative_spend_receipt(
            &receipt,
            &[Keypair::generate().public_key()],
            nonce.as_ref()
        ),
        Err(NotAuthoritativeReason::SignerNotAdmitted)
    );
}

#[test]
fn a_non_mediated_trust_level_is_rejected() {
    let (signer, mut receipt, nonce) = mediated_case();
    receipt.trust_level = TrustLevel::Advisory;
    let receipt = support::resign(&signer, receipt);
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()),
        Err(NotAuthoritativeReason::NotMediatedTrustLevel)
    );
}

#[test]
fn b_missing_budget_authority_is_rejected() {
    let (signer, mut receipt, nonce) = mediated_case();
    receipt.metadata = Some(serde_json::json!({}));
    let receipt = support::resign(&signer, receipt);
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()),
        Err(NotAuthoritativeReason::MissingBudgetAuthority)
    );
}

#[test]
fn r1_forged_label_with_real_signer_but_no_hold_is_rejected() {
    // R1 end to end: even an admitted-key signature over a Mediated label fails
    // without a reconciled hold + bound nonce.
    let (signer, mut receipt, nonce) = mediated_case();
    if let Some(obj) = receipt.metadata.as_mut().and_then(|m| m.as_object_mut()) {
        obj.remove("budget_authority");
    }
    let receipt = support::resign(&signer, receipt);
    assert!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()).is_err()
    );
}

#[test]
fn cd_nonce_binding_or_link_mismatch_is_rejected() {
    // (c)/(d): a nonce from a different call fails link/binding.
    let (signer, receipt, _nonce) = mediated_case();
    let (_other_signer, _r2, other_nonce) = mediated_case();
    let result =
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], other_nonce.as_ref());
    assert!(matches!(
        result,
        Err(NotAuthoritativeReason::NonceLinkMismatch)
            | Err(NotAuthoritativeReason::NonceBindingMismatch { .. })
            | Err(NotAuthoritativeReason::NonceSignatureInvalid)
    ));
}

#[test]
fn structural_invariant_advisory_receipt_has_no_allow_decision() {
    // Acceptance 4: advisory is structurally constrained to decision: None; only
    // the mediated handler emits decision: Some(Allow) for a tool call.
    let signer = Keypair::generate();
    let advisory = support::standalone_advisory_receipt(&signer, "cap-x", "cost-srv", "compute");
    assert!(
        advisory.decision.is_none(),
        "advisory receipts must not carry a decision"
    );
}
