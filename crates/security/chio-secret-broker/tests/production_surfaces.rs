#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core_types::{Keypair, PublicKey};
use chio_secret_broker::protocol::{
    BrokerExecutionEvidence, CredentialRef, BROKER_EVIDENCE_SCHEMA,
};
use chio_secret_broker::provision::{
    governed_admin_intent_digest, AdminAuthorization, AdminAuthorizer, AdminClock, AdminOperation,
    GovernedAdminAuthorizationEnvelope, GovernedAdminAuthorizer, GovernedAdminPolicy,
};
use chio_secret_broker::receipt::{
    sign_execution_receipt, BrokerReceiptBody, BrokerReceiptSink, SqliteBrokerReceiptSink,
    BROKER_RECEIPT_SCHEMA,
};

struct FixedClock(u64);

impl AdminClock for FixedClock {
    fn now_unix_seconds(&self) -> chio_secret_broker::Result<u64> {
        Ok(self.0)
    }
}

fn credential() -> CredentialRef {
    CredentialRef {
        provider: "generic-https".to_string(),
        credential_id: "credential-production".to_string(),
        version: 1,
    }
}

fn approval(
    signer: &Keypair,
    subject: &PublicKey,
    id: &str,
    request_id: &str,
    intent_digest: &str,
) -> GovernedApprovalToken {
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: id.to_string(),
            approver: signer.public_key(),
            subject: subject.clone(),
            governed_intent_hash: intent_digest.to_string(),
            threshold_proposal_hash: Some("7a".repeat(32)),
            request_id: request_id.to_string(),
            issued_at: 90,
            expires_at: 110,
            decision: GovernedApprovalDecision::Approved,
        },
        signer,
    )
    .expect("signed approval")
}

#[test]
fn governed_admin_authorization_is_threshold_bound_and_durably_single_use() {
    let directory = tempfile::tempdir().expect("tempdir");
    let first = Keypair::from_seed(&[31; 32]);
    let second = Keypair::from_seed(&[32; 32]);
    let subject = Keypair::from_seed(&[33; 32]).public_key();
    let credential = credential();
    let intent_digest =
        governed_admin_intent_digest(AdminOperation::Rotate, "tenant-production", &credential)
            .expect("intent digest");
    let envelope = GovernedAdminAuthorizationEnvelope::new(vec![
        approval(
            &first,
            &subject,
            "approval-production-1",
            "request-production-1",
            &intent_digest,
        ),
        approval(
            &second,
            &subject,
            "approval-production-2",
            "request-production-1",
            &intent_digest,
        ),
    ])
    .expect("envelope");
    let authorization =
        AdminAuthorization::new(envelope.canonical_bytes().expect("canonical envelope"))
            .expect("authorization");
    let authorizer = GovernedAdminAuthorizer::open(
        directory.path().join("admin-replay.sqlite3"),
        GovernedAdminPolicy {
            trusted_approvers: vec![first.public_key(), second.public_key()],
            subject,
            threshold: 2,
            maximum_token_lifetime_seconds: 60,
        },
        Arc::new(FixedClock(100)),
    )
    .expect("authorizer");

    let digest = authorizer
        .authorize(
            &authorization,
            AdminOperation::Rotate,
            "tenant-production",
            &credential,
        )
        .expect("authorized once");
    assert_eq!(digest.len(), 64);
    assert!(authorizer
        .authorize(
            &authorization,
            AdminOperation::Rotate,
            "tenant-production",
            &credential,
        )
        .is_err());

    let reopened = GovernedAdminAuthorizer::open(
        directory.path().join("admin-replay.sqlite3"),
        GovernedAdminPolicy {
            trusted_approvers: vec![first.public_key(), second.public_key()],
            subject: Keypair::from_seed(&[33; 32]).public_key(),
            threshold: 2,
            maximum_token_lifetime_seconds: 60,
        },
        Arc::new(FixedClock(100)),
    )
    .expect("reopened authorizer");
    assert!(reopened
        .authorize(
            &authorization,
            AdminOperation::Rotate,
            "tenant-production",
            &credential,
        )
        .is_err());
}

fn signed_receipt(signer: &Keypair) -> chio_secret_broker::receipt::SignedBrokerReceipt {
    sign_execution_receipt(
        BrokerReceiptBody {
            schema: BROKER_RECEIPT_SCHEMA.to_string(),
            receipt_id: "broker-receipt-production-1".to_string(),
            issued_at_unix_seconds: 100,
            evidence: BrokerExecutionEvidence {
                schema: BROKER_EVIDENCE_SCHEMA.to_string(),
                attempt_id: "attempt-production-1".to_string(),
                invocation_id: "invocation-production-1".to_string(),
                hold_id: "hold-production-1".to_string(),
                request_digest: "11".repeat(32),
                capability_digest: "22".repeat(32),
                revocation_set_digest: "33".repeat(32),
                budget_commit_index: 10,
                revocation_commit_index: 11,
                authority_commit_index: 12,
                leader_epoch: 13,
                upstream_status: 200,
                response_body_sha256: "44".repeat(32),
            },
            outcome: "completed".to_string(),
        },
        signer,
    )
    .expect("signed receipt")
}

#[test]
fn durable_receipt_sink_is_append_only_idempotent_and_restart_safe() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("broker-receipts.sqlite3");
    let signer = Keypair::from_seed(&[41; 32]);
    let receipt = signed_receipt(&signer);
    let sink = SqliteBrokerReceiptSink::open(&path, signer.public_key()).expect("sink");
    let first = sink.persist(&receipt).expect("first append");
    let retry = sink.persist(&receipt).expect("exact retry");
    assert_eq!(first, retry);
    drop(sink);

    let reopened = SqliteBrokerReceiptSink::open(&path, signer.public_key()).expect("reopen");
    let loaded = reopened
        .load(&receipt.body.receipt_id)
        .expect("load")
        .expect("persisted receipt");
    assert_eq!(loaded, receipt);

    let mut conflicting_body = receipt.body.clone();
    conflicting_body.evidence.upstream_status = 201;
    let conflicting =
        sign_execution_receipt(conflicting_body, &signer).expect("conflicting signed receipt");
    assert!(reopened.persist(&conflicting).is_err());
}
