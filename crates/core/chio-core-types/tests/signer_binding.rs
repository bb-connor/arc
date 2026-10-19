use chio_core_types::capability::{
    attenuation::{DelegationLink, DelegationLinkBody},
    governance::{
        CallChainContinuationToken, CallChainContinuationTokenBody, GovernedApprovalDecision,
        GovernedApprovalToken, GovernedApprovalTokenBody, GovernedUpstreamCallChainProof,
        GovernedUpstreamCallChainProofBody, CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
    },
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::receipt::lineage::{
    ReceiptLineageEndpoints, ReceiptLineageRelationKind, ReceiptLineageStatement,
    ReceiptLineageStatementBody,
};
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    lineage::{ChildRequestReceipt, ChildRequestReceiptBody, SignedExportEnvelope},
};
use chio_core_types::session::{SessionAnchor, SessionAnchorBody, SessionAnchorContext};
use chio_core_types::{
    sha256_hex, Ed25519Backend, Keypair, OperationKind, OperationTerminalState, RequestId,
    SessionAuthContext, SessionId, SigningBackend, ToolManifest, ToolManifestBody,
};

fn capability_body(
    issuer: chio_core_types::PublicKey,
    subject: chio_core_types::PublicKey,
) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "cap-mismatch".to_string(),
        issuer,
        subject,
        scope: ChioScope::default(),
        issued_at: 1_710_000_000,
        expires_at: 1_710_003_600,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    }
}

fn receipt_body(
    kernel_key: chio_core_types::PublicKey,
) -> chio_core_types::Result<ChioReceiptBody> {
    Ok(ChioReceiptBody {
        id: "receipt-mismatch".to_string(),
        timestamp: 1_710_000_000,
        capability_id: "cap-mismatch".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({
            "path": "/app/src/main.rs"
        }))?,
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "policy-hash".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key,
        bbs_projection_version: None,
    })
}

fn session_anchor_body(
    kernel_key: chio_core_types::PublicKey,
) -> chio_core_types::Result<SessionAnchorBody> {
    let auth = SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("https://app.example".to_string()),
    );
    SessionAnchorBody::new(
        "anchor-mismatch",
        SessionAnchorContext::new(
            SessionId::new("sess-mismatch"),
            "agent-mismatch".to_string(),
            auth,
            None,
        ),
        1,
        1_710_000_000,
        kernel_key,
    )
}

fn child_request_receipt_body(kernel_key: chio_core_types::PublicKey) -> ChildRequestReceiptBody {
    ChildRequestReceiptBody {
        id: "child-receipt-mismatch".to_string(),
        timestamp: 1_710_000_000,
        session_id: SessionId::new("sess-mismatch"),
        parent_request_id: RequestId::new("parent-req-mismatch"),
        request_id: RequestId::new("child-req-mismatch"),
        operation_kind: OperationKind::ToolCall,
        terminal_state: OperationTerminalState::Completed,
        outcome_hash: sha256_hex(br#"{"child":true}"#),
        policy_hash: "policy-hash".to_string(),
        metadata: None,
        kernel_key,
    }
}

fn receipt_lineage_statement_body(
    kernel_key: chio_core_types::PublicKey,
) -> ReceiptLineageStatementBody {
    let endpoints = ReceiptLineageEndpoints::new(
        "parent-receipt-mismatch",
        "child-receipt-mismatch",
        RequestId::new("parent-req-mismatch"),
        RequestId::new("child-req-mismatch"),
        chio_core_types::session::SessionAnchorReference::new(
            "parent-anchor-mismatch",
            sha256_hex(b"parent-anchor"),
        ),
        chio_core_types::session::SessionAnchorReference::new(
            "child-anchor-mismatch",
            sha256_hex(b"child-anchor"),
        ),
    );

    ReceiptLineageStatementBody::new(
        "lineage-mismatch",
        endpoints,
        ReceiptLineageRelationKind::LocalChild,
        1_710_000_000,
        kernel_key,
    )
}

fn approval_token_body(
    approver: chio_core_types::PublicKey,
    subject: chio_core_types::PublicKey,
) -> GovernedApprovalTokenBody {
    GovernedApprovalTokenBody {
        id: "approval-mismatch".to_string(),
        approver,
        subject,
        governed_intent_hash: sha256_hex(b"governed-intent"),
        request_id: "req-mismatch".to_string(),
        threshold_proposal_hash: None,
        issued_at: 1_710_000_000,
        expires_at: 1_710_003_600,
        decision: GovernedApprovalDecision::Approved,
    }
}

fn upstream_call_chain_proof_body(
    signer: chio_core_types::PublicKey,
    subject: chio_core_types::PublicKey,
) -> GovernedUpstreamCallChainProofBody {
    GovernedUpstreamCallChainProofBody {
        signer,
        subject,
        chain_id: "chain-mismatch".to_string(),
        parent_request_id: "parent-req-mismatch".to_string(),
        parent_receipt_id: Some("parent-receipt-mismatch".to_string()),
        origin_subject: "origin-subject".to_string(),
        delegator_subject: "delegator-subject".to_string(),
        issued_at: 1_710_000_000,
        expires_at: 1_710_003_600,
    }
}

fn continuation_token_body(
    signer: chio_core_types::PublicKey,
    subject: chio_core_types::PublicKey,
) -> CallChainContinuationTokenBody {
    CallChainContinuationTokenBody {
        schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
        token_id: "continuation-mismatch".to_string(),
        signer,
        subject,
        chain_id: "chain-mismatch".to_string(),
        parent_request_id: "parent-req-mismatch".to_string(),
        parent_receipt_id: Some("parent-receipt-mismatch".to_string()),
        parent_receipt_hash: Some(sha256_hex(b"parent-receipt")),
        parent_session_anchor: None,
        current_subject: "current-subject".to_string(),
        delegator_subject: "delegator-subject".to_string(),
        origin_subject: "origin-subject".to_string(),
        parent_capability_id: Some("cap-parent".to_string()),
        delegation_link_hash: Some(sha256_hex(b"delegation-link")),
        governed_intent_hash: Some(sha256_hex(b"governed-intent")),
        audience: None,
        nonce: Some("nonce-mismatch".to_string()),
        issued_at: 1_710_000_000,
        expires_at: 1_710_003_600,
    }
}

fn assert_signer_mismatch<T>(result: chio_core_types::Result<T>, artifact: &str, field: &str) {
    match result {
        Err(chio_core_types::Error::InvalidPublicKey(message)) => {
            assert_eq!(
                message,
                format!("{artifact} {field} does not match signing key")
            );
        }
        Err(other) => panic!("expected signer mismatch for {artifact} {field}, got {other:?}"),
        Ok(_) => panic!("expected signer mismatch for {artifact} {field}, signing succeeded"),
    }
}

#[test]
fn capability_sign_rejects_embedded_issuer_mismatch() -> chio_core_types::Result<()> {
    let embedded_issuer = Keypair::generate();
    let actual_signer = Keypair::generate();
    let subject = Keypair::generate();

    assert_signer_mismatch(
        CapabilityToken::sign(
            capability_body(embedded_issuer.public_key(), subject.public_key()),
            &actual_signer,
        ),
        "capability token",
        "issuer",
    );
    CapabilityToken::sign(
        capability_body(embedded_issuer.public_key(), subject.public_key()),
        &embedded_issuer,
    )?;
    Ok(())
}

#[test]
fn capability_backend_sign_rejects_embedded_issuer_mismatch() -> chio_core_types::Result<()> {
    let embedded_issuer = Keypair::generate();
    let backend = Ed25519Backend::generate();
    let subject = Keypair::generate();

    assert_ne!(embedded_issuer.public_key(), backend.public_key());
    assert_signer_mismatch(
        CapabilityToken::sign_with_backend(
            capability_body(embedded_issuer.public_key(), subject.public_key()),
            &backend,
        ),
        "capability token",
        "issuer",
    );
    CapabilityToken::sign_with_backend(
        capability_body(backend.public_key(), subject.public_key()),
        &backend,
    )?;
    Ok(())
}

#[test]
fn delegated_artifact_signers_reject_embedded_key_mismatches() -> chio_core_types::Result<()> {
    let embedded_signer = Keypair::generate();
    let actual_signer = Keypair::generate();
    let subject = Keypair::generate();

    assert_signer_mismatch(
        GovernedUpstreamCallChainProof::sign(
            upstream_call_chain_proof_body(embedded_signer.public_key(), subject.public_key()),
            &actual_signer,
        ),
        "call-chain proof",
        "signer",
    );
    GovernedUpstreamCallChainProof::sign(
        upstream_call_chain_proof_body(embedded_signer.public_key(), subject.public_key()),
        &embedded_signer,
    )?;

    assert_signer_mismatch(
        CallChainContinuationToken::sign(
            continuation_token_body(embedded_signer.public_key(), subject.public_key()),
            &actual_signer,
        ),
        "continuation token",
        "signer",
    );
    CallChainContinuationToken::sign(
        continuation_token_body(embedded_signer.public_key(), subject.public_key()),
        &embedded_signer,
    )?;
    Ok(())
}

#[test]
fn approval_signers_reject_embedded_approver_mismatches() -> chio_core_types::Result<()> {
    let embedded_approver = Keypair::generate();
    let actual_signer = Keypair::generate();
    let backend = Ed25519Backend::generate();
    let subject = Keypair::generate();

    assert_signer_mismatch(
        GovernedApprovalToken::sign(
            approval_token_body(embedded_approver.public_key(), subject.public_key()),
            &actual_signer,
        ),
        "governed approval token",
        "approver",
    );
    GovernedApprovalToken::sign(
        approval_token_body(embedded_approver.public_key(), subject.public_key()),
        &embedded_approver,
    )?;

    assert_ne!(embedded_approver.public_key(), backend.public_key());
    assert_signer_mismatch(
        GovernedApprovalToken::sign_with_backend(
            approval_token_body(embedded_approver.public_key(), subject.public_key()),
            &backend,
        ),
        "governed approval token",
        "approver",
    );
    GovernedApprovalToken::sign_with_backend(
        approval_token_body(backend.public_key(), subject.public_key()),
        &backend,
    )?;
    Ok(())
}

#[test]
fn delegation_link_sign_rejects_embedded_delegator_mismatch() -> chio_core_types::Result<()> {
    let embedded_delegator = Keypair::generate();
    let actual_signer = Keypair::generate();
    let delegatee = Keypair::generate();

    let body = || DelegationLinkBody {
        capability_id: "cap-parent".to_string(),
        delegator: embedded_delegator.public_key(),
        delegatee: delegatee.public_key(),
        attenuations: Vec::new(),
        timestamp: 1_710_000_000,
        scope_hash: None,
        aggregate_budget: None,
        cumulative_approval: None,
    };

    assert_signer_mismatch(
        DelegationLink::sign(body(), &actual_signer),
        "delegation link",
        "delegator",
    );
    DelegationLink::sign(body(), &embedded_delegator)?;
    Ok(())
}

#[test]
fn receipt_sign_rejects_embedded_kernel_key_mismatch() -> chio_core_types::Result<()> {
    let embedded_kernel = Keypair::generate();
    let actual_signer = Keypair::generate();

    assert_signer_mismatch(
        ChioReceipt::sign(receipt_body(embedded_kernel.public_key())?, &actual_signer),
        "receipt",
        "kernel_key",
    );
    ChioReceipt::sign(
        receipt_body(embedded_kernel.public_key())?,
        &embedded_kernel,
    )?;
    Ok(())
}

#[test]
fn child_receipt_signers_reject_embedded_kernel_key_mismatches() -> chio_core_types::Result<()> {
    let embedded_kernel = Keypair::generate();
    let actual_signer = Keypair::generate();
    let backend = Ed25519Backend::generate();

    assert_signer_mismatch(
        ChildRequestReceipt::sign(
            child_request_receipt_body(embedded_kernel.public_key()),
            &actual_signer,
        ),
        "child request receipt",
        "kernel_key",
    );
    ChildRequestReceipt::sign(
        child_request_receipt_body(embedded_kernel.public_key()),
        &embedded_kernel,
    )?;

    assert_ne!(embedded_kernel.public_key(), backend.public_key());
    assert_signer_mismatch(
        ChildRequestReceipt::sign_with_backend(
            child_request_receipt_body(embedded_kernel.public_key()),
            &backend,
        ),
        "child request receipt",
        "kernel_key",
    );
    ChildRequestReceipt::sign_with_backend(
        child_request_receipt_body(backend.public_key()),
        &backend,
    )?;
    Ok(())
}

#[test]
fn receipt_lineage_sign_rejects_embedded_kernel_key_mismatch() -> chio_core_types::Result<()> {
    let embedded_kernel = Keypair::generate();
    let actual_signer = Keypair::generate();

    assert_signer_mismatch(
        ReceiptLineageStatement::sign(
            receipt_lineage_statement_body(embedded_kernel.public_key()),
            &actual_signer,
        ),
        "receipt lineage statement",
        "kernel_key",
    );
    ReceiptLineageStatement::sign(
        receipt_lineage_statement_body(embedded_kernel.public_key()),
        &embedded_kernel,
    )?;
    Ok(())
}

#[test]
fn session_anchor_sign_rejects_embedded_kernel_key_mismatch() -> chio_core_types::Result<()> {
    let embedded_kernel = Keypair::generate();
    let actual_signer = Keypair::generate();

    assert_signer_mismatch(
        SessionAnchor::sign(
            session_anchor_body(embedded_kernel.public_key())?,
            &actual_signer,
        ),
        "session anchor",
        "kernel_key",
    );
    SessionAnchor::sign(
        session_anchor_body(embedded_kernel.public_key())?,
        &embedded_kernel,
    )?;
    Ok(())
}

#[test]
fn manifest_sign_rejects_embedded_server_key_mismatch() -> chio_core_types::Result<()> {
    let embedded_server = Keypair::generate();
    let actual_signer = Keypair::generate();

    let body = || ToolManifestBody {
        server_id: "srv-files".to_string(),
        server_key: embedded_server.public_key(),
        tools: Vec::new(),
        required_capabilities: Vec::new(),
    };

    assert_signer_mismatch(
        ToolManifest::sign(body(), &actual_signer),
        "tool manifest",
        "server_key",
    );
    ToolManifest::sign(body(), &embedded_server)?;
    Ok(())
}

#[test]
fn export_envelope_backend_path_matches_keypair_signing() -> chio_core_types::Result<()> {
    let keypair = Keypair::from_seed(&[88_u8; 32]);
    let backend = Ed25519Backend::new(keypair.clone());
    let body = serde_json::json!({"schema": "chio.test.export.v1", "value": 9});

    let local = SignedExportEnvelope::sign(body.clone(), &keypair)?;
    let external = SignedExportEnvelope::sign_with_backend(body, &backend)?;

    assert_eq!(local, external);
    assert!(external.verify_signature()?);
    Ok(())
}
