//! Durable ordinary decisions retain the original request and authentic signer.
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core::Keypair;
use std::sync::{Arc, Barrier};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request_and_decision() -> Result<(ApprovalRequest, ApprovalDecision), Box<dyn std::error::Error>>
{
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    let request = ApprovalRequest {
        approval_id: "ap23-persisted".into(),
        policy_id: "policy-a".into(),
        subject_id: subject.public_key().to_hex(),
        capability_id: "cap-a".into(),
        subject_public_key: Some(subject.public_key()),
        tool_server: "srv".into(),
        tool_name: "effect".into(),
        action: "invoke".into(),
        parameter_hash: "a".repeat(64),
        expires_at: 400,
        callback_hint: None,
        created_at: 100,
        summary: "approve one exact call".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: Vec::new(),
    };
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "ap23-token".into(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: request.parameter_hash.clone(),
            request_id: request.approval_id.clone(),
            threshold_proposal_hash: None,
            issued_at: 100,
            expires_at: 400,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )?;
    let decision = ApprovalDecision {
        approval_id: request.approval_id.clone(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
        received_at: 100,
    };
    Ok((request, decision))
}

#[test]
fn ap23_concurrent_resolution_retains_one_signed_decision_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approvals.db");
    let (request, decision) = request_and_decision()?;
    let store = Arc::new(SqliteApprovalStore::open(&path)?);
    store.store_pending(&request)?;
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            let decision = decision.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.resolve(&decision.approval_id, &decision)
            })
        })
        .collect();
    let mut successes = 0;
    for worker in workers {
        match worker.join().map_err(|_| "decision worker panicked")? {
            Ok(()) => successes += 1,
            Err(ApprovalStoreError::NotFound(id)) => assert_eq!(id, request.approval_id),
            result => panic!("unexpected decision race result: {result:?}"),
        }
    }
    assert_eq!(successes, 1);
    drop(store);
    let reopened = SqliteApprovalStore::open(&path)?;
    assert!(reopened.get_pending(&request.approval_id)?.is_none());
    let retained = reopened
        .get_resolution(&request.approval_id)?
        .ok_or("resolution missing")?;
    assert_eq!(retained.request, Some(request));
    assert_eq!(retained.token, Some(decision.token.clone()));
    assert_eq!(retained.approver_hex, decision.approver.to_hex());
    assert!(retained.token.ok_or("token missing")?.verify_signature()?);
    Ok(())
}

#[test]
fn ap23_store_rejects_unsigned_outcome_substitution_without_mutating_pending() -> TestResult {
    let store = SqliteApprovalStore::open_in_memory()?;
    let (request, mut decision) = request_and_decision()?;
    store.store_pending(&request)?;
    decision.outcome = ApprovalOutcome::Denied;
    let rejected = store.resolve(&request.approval_id, &decision);
    assert!(
        matches!(rejected, Err(ApprovalStoreError::Invalid(ref reason)) if reason == "signed decision disagrees with resolution")
    );
    assert_eq!(
        store.get_pending(&request.approval_id)?,
        Some(request.clone())
    );
    assert!(store.get_resolution(&request.approval_id)?.is_none());
    assert!(!store.is_consumed(&decision.token.id, &request.parameter_hash)?);
    Ok(())
}
