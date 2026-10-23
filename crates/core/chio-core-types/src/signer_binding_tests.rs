//! Backend-signed artifacts stamp the identity that produced the signature.
use crate::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use crate::crypto::{sha256_hex, Ed25519Backend, Keypair, SigningAlgorithm};
use crate::error::Result;
use crate::receipt::lineage::{ChildRequestReceipt, ChildRequestReceiptBody, SignedExportEnvelope};
use crate::session::{OperationKind, OperationTerminalState, RequestId, SessionId};

#[test]
fn governed_approval_token_stamps_the_signing_identity() -> Result<()> {
    let backend = Ed25519Backend::new(Keypair::from_seed(&[82; 32]));
    let token = GovernedApprovalToken::sign_with_backend(
        GovernedApprovalTokenBody {
            id: "approval-rotated".to_string(),
            approver: backend.keypair().public_key(),
            subject: Keypair::from_seed(&[83; 32]).public_key(),
            governed_intent_hash: "a".repeat(64),
            request_id: "req-rotated".to_string(),
            threshold_proposal_hash: None,
            issued_at: 100,
            expires_at: 200,
            decision: GovernedApprovalDecision::Approved,
        },
        &backend,
    )?;
    assert_eq!(token.approver, backend.keypair().public_key());
    assert_eq!(token.signature.algorithm(), SigningAlgorithm::Ed25519);
    assert!(token.verify_signature()?);
    Ok(())
}

#[test]
fn threshold_approval_proposal_stamps_the_signing_identity() -> Result<()> {
    let backend = Ed25519Backend::new(Keypair::from_seed(&[82; 32]));
    let proposal = ThresholdApprovalProposal::sign_with_backend(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "proposal-rotated".to_string(),
            request_id: "req-rotated".to_string(),
            governed_intent_hash: "a".repeat(64),
            subject: Keypair::from_seed(&[83; 32]).public_key(),
            authorizing_capability_digest: "b".repeat(64),
            policy_hash: "c".repeat(64),
            threshold: 1,
            eligible_set_digest: "d".repeat(64),
            proposal_created_at: 100,
            proposal_deadline: 200,
            policy_authority: backend.keypair().public_key(),
        },
        &backend,
    )?;
    assert_eq!(proposal.signature.algorithm(), SigningAlgorithm::Ed25519);
    assert!(proposal.verify_signature()?);
    Ok(())
}

#[test]
fn child_request_receipt_stamps_the_signing_identity() -> Result<()> {
    let backend = Ed25519Backend::new(Keypair::from_seed(&[82; 32]));
    let receipt = ChildRequestReceipt::sign_with_backend(
        ChildRequestReceiptBody {
            id: "child-rotated".to_string(),
            timestamp: 1_710_000_001,
            session_id: SessionId::new("sess-rotated"),
            parent_request_id: RequestId::new("parent-rotated"),
            request_id: RequestId::new("child-rotated"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: sha256_hex(b"rotated"),
            policy_hash: "c".repeat(64),
            metadata: None,
            kernel_key: backend.keypair().public_key(),
        },
        &backend,
    )?;
    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Ed25519);
    assert!(receipt.verify_signature()?);
    Ok(())
}

#[test]
fn signed_export_envelope_stamps_the_signing_identity() -> Result<()> {
    let backend = Ed25519Backend::new(Keypair::from_seed(&[82; 32]));
    #[derive(Clone, serde::Serialize)]
    struct RotatedExport(&'static str);
    impl crate::receipt::lineage::SignedExportPayload for RotatedExport {
        const SCHEMA_ID: &'static str = crate::CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA;
    }
    let envelope =
        SignedExportEnvelope::sign_with_backend(RotatedExport("export-rotated"), &backend)?;
    assert_eq!(envelope.signer_key, backend.keypair().public_key());
    assert!(envelope.verify_signature(&backend.keypair().public_key())?);
    Ok(())
}
