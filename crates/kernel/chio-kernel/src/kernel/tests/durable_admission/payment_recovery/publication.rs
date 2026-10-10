//! Genuine purchase admission freezes finances without freezing output authority.
use super::*;
use crate::finding_purchase::{
    VerifiedFindingStatusProof, FINDING_PURCHASE_CONTEXT_KEY, FINDING_STATUS_PROOF_CONTEXT_KEY,
};
use crate::tool_outcome::PostReturnEvaluationStateV1;
use base64::Engine as _;
use chio_core::capability::scope::{FindingPurchaseMarkerV1, FindingSettlementSelector};
#[path = "publication_support.rs"]
mod support;
use support::*;

#[test]
fn review_target_current_finding_status_withholds_resolved_output() -> TestResult {
    let (mut kernel, mut request, store, invocations) =
        super::super::dpop_acquisition::selected_profile_fixture();
    let output = serde_json::json!({
        "media_type": "application/json",
        "payload_b64": base64::engine::general_purpose::STANDARD.encode(b"{\"finding\":true}"),
    });
    assert_eq!(
        crate::kernel::delivery_contract::check_reveal_envelope(
            &canonical_json_bytes(&output)?,
            "application/json",
        ),
        crate::kernel::delivery_contract::RevealEnvelopeCheck::Matched
    );
    let output_digest = sha256_hex(&canonical_json_bytes(&output)?);
    let mut grant = make_governed_monetary_grant("durable-server", "mutate", 10, 10, "USD", 4);
    grant.max_invocations = Some(1);
    grant.dpop_required = Some(true);
    grant
        .constraints
        .push(Constraint::RequireFindingPurchase(Box::new(
            FindingPurchaseMarkerV1 {
                finding_id: "a".repeat(64),
                listing_id: "review-publication-listing".into(),
                settlement: FindingSettlementSelector::LocalReversibleHold,
            },
        )));
    grant
        .constraints
        .push(Constraint::OutputDigestSha256(output_digest));
    let buyer = Keypair::generate();
    request.capability =
        kernel.issue_capability(&buyer.public_key(), make_scope(vec![grant]), 300)?;
    request.agent_id = buyer.public_key().to_hex();
    request.request_id = "review-publication-current-status".into();
    request.arguments = serde_json::json!({"finding_id": "a".repeat(64)});
    let authority = kernel
        .dpop_authority
        .clone()
        .ok_or("original DPoP authority")?;
    request.dpop_proof = Some(crate::dpop::DpopProof::sign(
        crate::dpop::DpopProofBody {
            schema: crate::dpop::authority::DPOP_AUTHORITY_SCHEMA.into(),
            replay_authority: Some(authority),
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action_hash: sha256_hex(&canonical_json_bytes(&request.arguments)?),
            nonce: "review-publication-proof".into(),
            issued_at: current_unix_timestamp(),
            agent_key: buyer.public_key(),
        },
        &buyer,
    )?);
    let proof_bytes = b"review-verified-status-proof";
    let proof = VerifiedFindingStatusProof {
        feed_id: "status-feed/review-publication".into(),
        key_domain_nonce: 1,
        map_epoch: 1,
        status_epoch_id: "c".repeat(64),
        status_epoch_artifact_sha256: "d".repeat(64),
        proof_sha256: sha256_hex(proof_bytes),
        root_hash: "e".repeat(64),
        non_inclusion_checked_at: current_unix_timestamp(),
        operator_authorization_sha256: "f".repeat(64),
        service_bond_evidence_sha256: "0".repeat(64),
    };
    let status = Arc::new(StatusVerifier {
        proof: proof.clone(),
        revoked: std::sync::atomic::AtomicBool::new(false),
        calls: AtomicU64::new(0),
    });
    kernel.set_finding_purchase_verifier(Arc::new(PurchaseVerifier(proof)));
    kernel.set_finding_status_proof_verifier(status.clone());
    let mut intent = make_mustprepay_intent(
        "review-publication-current-status",
        "durable-server",
        "mutate",
        10,
        "USD",
    );
    intent.metered_billing = None;
    intent.context = Some(serde_json::json!({
        FINDING_PURCHASE_CONTEXT_KEY: base64::engine::general_purpose::STANDARD.encode(b"review-purchase-carrier"),
        FINDING_STATUS_PROOF_CONTEXT_KEY: base64::engine::general_purpose::STANDARD.encode(proof_bytes),
    }));
    bind_test_tool_approval(
        &mut kernel,
        &request.capability,
        &request.arguments,
        &request.request_id,
        &mut intent,
    );
    request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &buyer.public_key(),
        &intent,
        &request.request_id,
    ));
    request.governed_intent = Some(intent);
    let rail = Arc::new(RailCalls::default());
    rail.capture_pending.store(true, Ordering::SeqCst);
    kernel.set_payment_adapter(Box::new(RecoveryRail {
        prepaid: false,
        calls: rail.clone(),
    }));
    kernel.register_tool_server(Box::new(RevealServer {
        output,
        invocations: invocations.clone(),
    }));
    let first = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(&first, Err(KernelError::AdmissionRecovery(failure))
        if matches!(failure.as_ref(), crate::admission_operation::AdmissionRecoveryError::Item {
            kind: crate::admission_operation::AdmissionRecoveryFailureKind::PaymentPending,
            detail,
        } if detail == "payment settlement remains pending")),
        "purchase must reach pending settlement: {first:?}"
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    let evaluation = store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .post_return_evaluation
        .clone()
        .ok_or("resolved evaluation")?;
    assert!(matches!(
        evaluation.state(),
        PostReturnEvaluationStateV1::Resolved { .. }
    ));
    let before = status.calls.load(Ordering::SeqCst);
    status.revoked.store(true, Ordering::SeqCst);
    let resumed = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(
        resumed.verdict,
        Verdict::Deny,
        "current authority must withhold historical output"
    );
    assert!(resumed.output.is_none());
    assert!(resumed.execution_nonce.is_none());
    assert!(status.calls.load(Ordering::SeqCst) > before);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(
        store
            .payment_journal()
            .ok_or("settled journal")?
            .settle_amount_units,
        Some(10)
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        rail.authorizations
            .lock()
            .map_err(|_| "authorization lock")?
            .len(),
        1
    );
    assert!(rail.refunds.lock().map_err(|_| "refund lock")?.is_empty());
    Ok(())
}
