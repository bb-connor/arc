use super::*;

// ---------------------------------------------------------------------------
// Time-checked verify entry points fold the validity window into the
// signature-verification path so "signature-valid" cannot diverge from
// "unexpired". Each checked entry point is fail-closed and signature-first.
// ---------------------------------------------------------------------------

fn bac573_capability_token(issued_at: u64, expires_at: u64) -> (Keypair, CapabilityToken) {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "bac573-cap".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![make_grant(
            "srv-a",
            "file_read",
            vec![Operation::Invoke],
        )]),
        issued_at,
        expires_at,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();
    (kp, token)
}

#[test]
fn bac573_capability_token_verify_at_within_window_passes() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    assert!(token.verify_integrity_embedded_key_at(1500).unwrap());
    // Boundaries: issued_at is inclusive, expires_at is exclusive.
    assert!(token.verify_integrity_embedded_key_at(1000).unwrap());
}

#[test]
fn bac573_capability_token_verify_at_expired_is_rejected() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    // now == expires_at and now > expires_at both reject (fail-closed).
    assert!(matches!(
        token.verify_integrity_embedded_key_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_integrity_embedded_key_at(9999),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
}

#[test]
fn bac573_capability_token_verify_at_not_yet_valid_is_rejected() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    assert!(matches!(
        token.verify_integrity_embedded_key_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_capability_token_verify_at_bad_signature_fails_before_time_check() {
    // An expired token whose signature is ALSO invalid must report the
    // signature failure (Ok(false)), not the time error: signature is checked
    // first, so the time window cannot leak through a forged token.
    let (_kp, mut token) = bac573_capability_token(1000, 2000);
    token.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!token.verify_integrity_embedded_key_at(9999).unwrap());
    // And in-window with a broken signature is still a plain rejection.
    assert!(!token.verify_integrity_embedded_key_at(1500).unwrap());
}

#[test]
fn bac573_capability_token_verify_with_floor_at_folds_time_and_floor() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    // In-window + allowed floor verifies.
    assert!(matches!(
        token.verify_integrity_embedded_key_with_floor_at(
            CapabilityCryptoFloor::AllowClassical,
            1500
        ),
        Ok(true)
    ));
    // In-window but floor rejects classical: floor error, not a time error.
    assert!(matches!(
        token.verify_integrity_embedded_key_with_floor_at(CapabilityCryptoFloor::PqRequired, 1500),
        Err(CapabilityFloorVerifyError::RejectedByCryptoFloor { .. })
    ));
    // Floor + signature pass but expired: surfaced as Crypto(CapabilityExpired).
    assert!(matches!(
        token.verify_integrity_embedded_key_with_floor_at(
            CapabilityCryptoFloor::AllowClassical,
            2000
        ),
        Err(CapabilityFloorVerifyError::Crypto(
            Error::CapabilityExpired { expires_at: 2000 }
        ))
    ));
    // Not yet valid: surfaced as Crypto(CapabilityNotYetValid).
    assert!(matches!(
        token.verify_integrity_embedded_key_with_floor_at(
            CapabilityCryptoFloor::AllowClassical,
            999
        ),
        Err(CapabilityFloorVerifyError::Crypto(
            Error::CapabilityNotYetValid { not_before: 1000 }
        ))
    ));
}

#[test]
fn bac573_capability_token_verify_with_floor_at_bad_signature_fails_first() {
    let (_kp, mut token) = bac573_capability_token(1000, 2000);
    // Break the signature, then verify an expired window.
    token.subject = Keypair::generate().public_key();
    // Expired AND broken signature: floor ok, signature fails -> Ok(false),
    // never the time error.
    assert!(matches!(
        token.verify_integrity_embedded_key_with_floor_at(
            CapabilityCryptoFloor::AllowClassical,
            9999
        ),
        Ok(false)
    ));
}

fn bac573_approval_token(issued_at: u64, expires_at: u64) -> (Keypair, GovernedApprovalToken) {
    let approver = Keypair::generate();
    let body = GovernedApprovalTokenBody {
        id: "bac573-approval".to_string(),
        approver: approver.public_key(),
        subject: Keypair::generate().public_key(),
        governed_intent_hash: "intent-hash".to_string(),
        request_id: "req-1".to_string(),
        threshold_proposal_hash: None,
        issued_at,
        expires_at,
        decision: GovernedApprovalDecision::Approved,
    };
    let token = GovernedApprovalToken::sign(body, &approver).unwrap();
    (approver, token)
}

#[test]
fn bac573_approval_token_verify_at_window_enforced() {
    let (_approver, token) = bac573_approval_token(1000, 2000);
    assert!(token.verify_integrity_embedded_key_at(1500).unwrap());
    assert!(matches!(
        token.verify_integrity_embedded_key_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_integrity_embedded_key_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_approval_token_verify_at_bad_signature_fails_first() {
    let (_approver, mut token) = bac573_approval_token(1000, 2000);
    // Break the signature; expired and forged -> signature failure first.
    token.subject = Keypair::generate().public_key();
    assert!(!token.verify_integrity_embedded_key_at(9999).unwrap());
}

fn bac573_upstream_proof(
    issued_at: u64,
    expires_at: u64,
) -> (Keypair, GovernedUpstreamCallChainProof) {
    let signer = Keypair::generate();
    let proof = GovernedUpstreamCallChainProof::sign(
        GovernedUpstreamCallChainProofBody {
            signer: signer.public_key(),
            subject: Keypair::generate().public_key(),
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
            issued_at,
            expires_at,
        },
        &signer,
    )
    .unwrap();
    (signer, proof)
}

#[test]
fn bac573_upstream_proof_verify_at_window_enforced() {
    let (_signer, proof) = bac573_upstream_proof(1000, 2000);
    assert!(proof.verify_integrity_embedded_key_at(1500).unwrap());
    assert!(matches!(
        proof.verify_integrity_embedded_key_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        proof.verify_integrity_embedded_key_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_upstream_proof_verify_at_bad_signature_fails_first() {
    let (_signer, mut proof) = bac573_upstream_proof(1000, 2000);
    proof.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!proof.verify_integrity_embedded_key_at(9999).unwrap());
}

fn bac573_continuation_token(
    issued_at: u64,
    expires_at: u64,
) -> (Keypair, CallChainContinuationToken) {
    let signer = Keypair::generate();
    let subject = Keypair::generate();
    let token = CallChainContinuationToken::sign(
        CallChainContinuationTokenBody {
            schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
            token_id: "continuation-1".to_string(),
            signer: signer.public_key(),
            subject: subject.public_key(),
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            parent_receipt_hash: Some("receipt-hash-1".to_string()),
            parent_session_anchor: None,
            current_subject: subject.public_key().to_hex(),
            delegator_subject: "delegator-subject".to_string(),
            origin_subject: "origin-subject".to_string(),
            parent_capability_id: Some("cap-parent-1".to_string()),
            delegation_link_hash: Some("delegation-link-hash-1".to_string()),
            governed_intent_hash: Some("intent-hash-1".to_string()),
            audience: None,
            nonce: Some("nonce-1".to_string()),
            issued_at,
            expires_at,
        },
        &signer,
    )
    .unwrap();
    (signer, token)
}

#[test]
fn bac573_continuation_token_verify_at_window_enforced() {
    let (_signer, token) = bac573_continuation_token(1000, 2000);
    assert!(token.verify_integrity_embedded_key_at(1500).unwrap());
    assert!(matches!(
        token.verify_integrity_embedded_key_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_integrity_embedded_key_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_continuation_token_verify_at_bad_signature_fails_first() {
    let (_signer, mut token) = bac573_continuation_token(1000, 2000);
    token.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!token.verify_integrity_embedded_key_at(9999).unwrap());
}

#[test]
fn capability_token_pinned_verify_refuses_another_issuer_key() {
    let (kp, token) = bac573_capability_token(1000, 2000);
    let other = Keypair::from_seed(&[0x5a; 32]).public_key();
    let floor = CapabilityCryptoFloor::AllowClassical;

    assert!(matches!(
        token.verify_signature(&other),
        Err(Error::SignerKeyMismatch)
    ));
    assert!(matches!(
        token.verify_signature_at(&other, 1500),
        Err(Error::SignerKeyMismatch)
    ));
    assert!(matches!(
        token.verify_signature_with_floor(&other, floor),
        Err(CapabilityFloorVerifyError::Crypto(Error::SignerKeyMismatch))
    ));
    assert!(matches!(
        token.verify_signature_with_floor_at(&other, floor, 1500),
        Err(CapabilityFloorVerifyError::Crypto(Error::SignerKeyMismatch))
    ));

    let issuer = kp.public_key();
    assert!(token.verify_signature(&issuer).unwrap());
    assert!(token.verify_signature_at(&issuer, 1500).unwrap());
    assert!(token.verify_signature_with_floor(&issuer, floor).unwrap());
    assert!(token
        .verify_signature_with_floor_at(&issuer, floor, 1500)
        .unwrap());
}
