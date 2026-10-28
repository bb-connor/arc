use std::sync::Arc;

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, GovernedTransactionIntentBody,
};
use chio_core::crypto::Keypair;
use chio_security_types::clock::FixedClock;
use chio_test_support::prelude::*;

use super::settle_api::{
    verify_governed_approval, ApprovalBinding, InMemoryApprovalReplayStore, VerifiedApproval,
};

pub fn witness(binding: &ApprovalBinding) -> VerifiedApproval {
    let approver = Keypair::from_seed(&[81; 32]);
    let subject = Keypair::from_seed(&[82; 32]);
    let intent = GovernedTransactionIntent {
        id: "approval-binding-intent".to_string(),
        server_id: "settlement".to_string(),
        tool_name: "prepare".to_string(),
        purpose: "approved artifact".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({"chioSettlementBinding": binding})),
        body: GovernedTransactionIntentBody::ToolInvocation,
    };
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval-binding-token".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: intent.binding_hash().test_unwrap(),
            request_id: "approval-binding-request".to_string(),
            threshold_proposal_hash: None,
            issued_at: 90,
            expires_at: 200,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .test_unwrap();
    verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        "approval-binding-request",
        Arc::new(FixedClock::new(100)),
        Arc::new(InMemoryApprovalReplayStore::default()),
    )
    .test_unwrap()
}
