//! Each in-session receipt carries its own signed session anchor, and a
//! continuation from a persisted parent is verified against that block only.

use super::*;

const PARENT_TIMESTAMP: u64 = 1_800_000_000;
const DENIED: &str = "governed transaction denied: ";

fn anchor_block(reference: &SessionAnchorReference) -> serde_json::Value {
    chio_core::receipt::metadata::ReceiptSessionAnchorV1::commit(reference)
        .unwrap()
        .to_metadata_value()
        .unwrap()
}

fn session_anchor_of(kernel: &ChioKernel, session_id: &SessionId) -> SessionAnchorReference {
    kernel
        .with_session(session_id, |session| {
            Ok(session.session_anchor().reference())
        })
        .unwrap()
}

fn open_anchored_session(kernel: &ChioKernel, agent: &Keypair) -> SessionId {
    let session_id = kernel
        .open_session(agent.public_key().to_hex(), Vec::new())
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    session_id
}

fn parent_body(
    kernel_key: chio_core::PublicKey,
    decision: Decision,
    metadata: Option<serde_json::Value>,
) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rc-parent-session-anchor".to_string(),
        timestamp: PARENT_TIMESTAMP,
        capability_id: "cap-parent-session-anchor".to_string(),
        tool_server: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({ "stage": "parent" })).unwrap(),
        decision: Some(decision),
        receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
        boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
        redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: chio_core::crypto::sha256_hex(br#"{"ok":true}"#),
        policy_hash: "policy-parent-session-anchor".to_string(),
        evidence: Vec::new(),
        metadata,
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key,
        bbs_projection_version: None,
    }
}

fn signed_parent(
    signer: &Keypair,
    decision: Decision,
    metadata: Option<serde_json::Value>,
) -> ChioReceipt {
    ChioReceipt::sign(parent_body(signer.public_key(), decision, metadata), signer).unwrap()
}

fn receipt_hash(receipt: &ChioReceipt) -> String {
    chio_core::crypto::sha256_hex(&chio_core::canonical::canonical_json_bytes(receipt).unwrap())
}

struct Continuation<'a> {
    kernel: &'a ChioKernel,
    token_signer: &'a Keypair,
    agent: &'a Keypair,
    capability: CapabilityToken,
    parent: &'a ChioReceipt,
    token_anchor: SessionAnchorReference,
    parent_receipt_hash: Option<String>,
}

fn continue_from_persisted_parent(continuation: Continuation<'_>) -> ToolCallResponse {
    continuation
        .kernel
        .record_chio_receipt(continuation.parent)
        .unwrap();
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-session-anchor-block".to_string(),
        parent_request_id: "req-parent-session-anchor".to_string(),
        parent_receipt_id: Some(continuation.parent.id.clone()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    };
    let mut intent = GovernedTransactionIntent {
        id: "intent-session-anchor-block".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue from a persisted parent receipt".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let token =
        make_governed_call_chain_continuation_token(GovernedCallChainContinuationTokenFixture {
            signer: continuation.token_signer,
            subject: &continuation.agent.public_key(),
            call_chain: &call_chain,
            parent_session_anchor: continuation.token_anchor,
            parent_receipt_hash: continuation.parent_receipt_hash.as_deref(),
            server_id: "srv-echo",
            tool_name: "delegate",
            governed_intent_hash: None,
        });
    attach_governed_call_chain_continuation_token(&mut intent, &token);
    continuation
        .kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-child-session-anchor".to_string(),
            capability: continuation.capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: continuation.agent.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "child" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap()
}

fn echo_kernel() -> (ChioKernel, Keypair) {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));
    (kernel, make_keypair())
}

fn delegate_capability(kernel: &ChioKernel, agent: &Keypair) -> CapabilityToken {
    make_capability(
        kernel,
        agent,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    )
}

fn assert_denied(response: &ToolCallResponse, reason: &str) {
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(
        response.reason.as_deref(),
        Some(format!("{DENIED}{reason}").as_str())
    );
}

/// Persisted parent signed by this kernel, with its own anchor block, after
/// the request that produced it is gone: accepted with the block's anchor.
#[test]
fn persisted_parent_from_this_kernel_continues_with_its_own_anchor() {
    let (kernel, agent) = echo_kernel();
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let parent = signed_parent(
        &kernel.config.keypair,
        Decision::Allow,
        Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) })),
    );
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &kernel.config.keypair,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: anchor.clone(),
        parent_receipt_hash: Some(receipt_hash(&parent)),
    });
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let governed = &response.receipt.metadata.as_ref().unwrap()["governed_transaction"];
    assert_eq!(
        governed["call_chain"]["sessionAnchorId"],
        serde_json::json!(anchor.session_anchor_id)
    );
}

/// The kernel trusts its receipt-signing backend key, not the classical
/// capability-authority key, once a separate receipt backend is installed.
#[test]
fn persisted_parent_signed_by_a_replacement_receipt_backend_continues() {
    let (mut kernel, agent) = echo_kernel();
    let authority =
        crate::kernel::signing_authority::KernelSigningAuthority::classical(&Keypair::generate());
    kernel.signing_task = Arc::new(
        kernel
            .signing_task
            .reconfigured_with_backend(authority.backend.clone()),
    );
    kernel.signing_authority = authority;
    let receipt_key = kernel.receipt_signing_public_key().unwrap();
    assert_ne!(receipt_key, kernel.config.keypair.public_key());
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let parent = ChioReceipt::sign_with_backend(
        parent_body(
            receipt_key,
            Decision::Allow,
            Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) })),
        ),
        kernel.signing_authority.backend.as_ref(),
    )
    .unwrap();
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &kernel.config.keypair,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: anchor,
        parent_receipt_hash: Some(receipt_hash(&parent)),
    });
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
}

/// A key trusted only as a capability issuer cannot sign a persisted parent.
#[test]
fn persisted_parent_signed_by_a_capability_authority_key_is_refused() {
    let issuer = make_keypair();
    let agent = make_keypair();
    let (mut kernel, _) = echo_kernel();
    kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(issuer.clone())));
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let parent = signed_parent(
        &issuer,
        Decision::Allow,
        Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) })),
    );
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &issuer,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: anchor,
        parent_receipt_hash: Some(receipt_hash(&parent)),
    });
    assert_denied(
        &response,
        "governed call_chain continuation parent receipt signer is not trusted",
    );
}

/// A receipt that verifies only under its own embedded key is not a trusted
/// parent, even when the continuation token signer is trusted.
#[test]
fn persisted_parent_signed_by_an_untrusted_key_is_refused() {
    let (kernel, agent) = echo_kernel();
    let rogue = make_keypair();
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let parent = signed_parent(
        &rogue,
        Decision::Allow,
        Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) })),
    );
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &kernel.config.keypair,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: anchor,
        parent_receipt_hash: Some(receipt_hash(&parent)),
    });
    assert_denied(
        &response,
        "governed call_chain parent receipt signer is not trusted",
    );
}

#[test]
fn persisted_parent_without_a_session_anchor_block_is_refused() {
    let (kernel, agent) = echo_kernel();
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let parent = signed_parent(&kernel.config.keypair, Decision::Allow, None);
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &kernel.config.keypair,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: anchor,
        parent_receipt_hash: Some(receipt_hash(&parent)),
    });
    assert_denied(
        &response,
        "governed call_chain continuation parent receipt carries no session anchor",
    );
}

#[test]
fn persisted_parent_continuation_requires_the_parent_receipt_hash() {
    let (kernel, agent) = echo_kernel();
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let parent = signed_parent(
        &kernel.config.keypair,
        Decision::Allow,
        Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) })),
    );
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &kernel.config.keypair,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: anchor,
        parent_receipt_hash: None,
    });
    assert_denied(
        &response,
        "governed call_chain continuation token parent_receipt_hash is required for a persisted parent",
    );
}

#[test]
fn token_anchor_must_equal_the_parent_block_in_id_and_hash() {
    for (id_suffix, hash) in [("", "00".repeat(32)), ("-other", String::new())] {
        let (kernel, agent) = echo_kernel();
        let session_id = open_anchored_session(&kernel, &agent);
        let anchor = session_anchor_of(&kernel, &session_id);
        let parent = signed_parent(
            &kernel.config.keypair,
            Decision::Allow,
            Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) })),
        );
        let token_anchor = SessionAnchorReference::new(
            format!("{}{id_suffix}", anchor.session_anchor_id),
            if hash.is_empty() {
                anchor.session_anchor_hash.clone()
            } else {
                hash
            },
        );
        let response = continue_from_persisted_parent(Continuation {
            kernel: &kernel,
            token_signer: &kernel.config.keypair,
            agent: &agent,
            capability: delegate_capability(&kernel, &agent),
            parent: &parent,
            token_anchor,
            parent_receipt_hash: Some(receipt_hash(&parent)),
        });
        assert_denied(
            &response,
            "governed call_chain continuation token session anchor does not match the parent receipt",
        );
    }
}

/// The token names another live session of the same kernel; the parent
/// receipt binds only its own session.
#[test]
fn token_naming_another_session_anchor_is_refused() {
    let (kernel, agent) = echo_kernel();
    let parent_session = open_anchored_session(&kernel, &agent);
    let other_session = open_anchored_session(&kernel, &agent);
    let parent_anchor = session_anchor_of(&kernel, &parent_session);
    let other_anchor = session_anchor_of(&kernel, &other_session);
    assert_ne!(parent_anchor, other_anchor);
    let parent = signed_parent(
        &kernel.config.keypair,
        Decision::Allow,
        Some(serde_json::json!({ "session_anchor": anchor_block(&parent_anchor) })),
    );
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &kernel.config.keypair,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: other_anchor,
        parent_receipt_hash: Some(receipt_hash(&parent)),
    });
    assert_denied(
        &response,
        "governed call_chain continuation token session anchor does not match the parent receipt",
    );
}

#[test]
fn malformed_parent_session_anchor_block_is_refused() {
    let (kernel, agent) = echo_kernel();
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let mut extra_member = anchor_block(&anchor);
    extra_member["session_id"] = serde_json::json!(session_id.to_string());
    let mut wrong_schema = anchor_block(&anchor);
    wrong_schema["schema"] = serde_json::json!("chio.receipt-session-anchor.v2");
    let mut short_commitment = anchor_block(&anchor);
    short_commitment["session_anchor_commitment"] = serde_json::json!("abcd");
    let mut uppercase_commitment = anchor_block(&anchor);
    uppercase_commitment["session_anchor_commitment"] = serde_json::json!("AB".repeat(32));
    let mut missing_commitment = anchor_block(&anchor);
    missing_commitment
        .as_object_mut()
        .unwrap()
        .remove("session_anchor_commitment");
    for block in [
        extra_member,
        wrong_schema,
        short_commitment,
        uppercase_commitment,
        missing_commitment,
        serde_json::json!("not-an-object"),
    ] {
        let parent = signed_parent(
            &kernel.config.keypair,
            Decision::Allow,
            Some(serde_json::json!({ "session_anchor": block })),
        );
        let response = continue_from_persisted_parent(Continuation {
            kernel: &kernel,
            token_signer: &kernel.config.keypair,
            agent: &agent,
            capability: delegate_capability(&kernel, &agent),
            parent: &parent,
            token_anchor: anchor.clone(),
            parent_receipt_hash: Some(receipt_hash(&parent)),
        });
        assert_denied(
            &response,
            "governed call_chain continuation parent session anchor block is malformed",
        );
    }
}

#[test]
fn denied_parent_receipt_cannot_start_a_continuation() {
    let (kernel, agent) = echo_kernel();
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let parent = signed_parent(
        &kernel.config.keypair,
        Decision::Deny {
            reason: "denied parent".to_string(),
            guard: "policy".to_string(),
        },
        Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) })),
    );
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &kernel.config.keypair,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: anchor,
        parent_receipt_hash: Some(receipt_hash(&parent)),
    });
    assert_denied(
        &response,
        "governed call_chain continuation parent receipt is not an allowed decision",
    );
}

fn evaluate_in_session(
    kernel: &ChioKernel,
    agent: &Keypair,
    session_id: &SessionId,
    request_id: &str,
) -> ToolCallResponse {
    let context = make_operation_context(session_id, request_id, &agent.public_key().to_hex());
    kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .unwrap();
    let mut request = make_request(
        &format!("{request_id}-call"),
        &delegate_capability(kernel, agent),
        "delegate",
        "srv-echo",
    );
    request.agent_id = agent.public_key().to_hex();
    kernel
        .evaluate_tool_call_with_nested_flow_client(
            &context,
            &request,
            &mut NoopNestedFlowClient,
            None,
        )
        .unwrap()
}

#[test]
fn in_session_receipts_carry_exactly_their_current_session_anchor() {
    let (kernel, agent) = echo_kernel();
    let session_id = open_anchored_session(&kernel, &agent);
    let first_anchor = session_anchor_of(&kernel, &session_id);
    let first = evaluate_in_session(&kernel, &agent, &session_id, "req-anchor-first");
    assert_eq!(first.verdict, Verdict::Allow, "{:?}", first.reason);
    assert_eq!(
        first.receipt.metadata.as_ref().unwrap()["session_anchor"],
        anchor_block(&first_anchor)
    );

    kernel
        .with_session_mut(&session_id, |session| {
            assert!(
                session
                    .set_auth_context(SessionAuthContext::streamable_http_static_bearer(
                        "static-bearer:reanchored",
                        "token-reanchored",
                        Some("https://reanchored.example".to_string()),
                    ))
                    .unwrap()
                    .0
            );
            Ok(())
        })
        .unwrap();
    let second_anchor = session_anchor_of(&kernel, &session_id);
    assert_ne!(first_anchor, second_anchor);
    let second = evaluate_in_session(&kernel, &agent, &session_id, "req-anchor-second");
    assert_eq!(second.verdict, Verdict::Allow, "{:?}", second.reason);
    assert_eq!(
        second.receipt.metadata.as_ref().unwrap()["session_anchor"],
        anchor_block(&second_anchor)
    );
}

#[test]
fn receipts_outside_a_session_carry_no_session_anchor() {
    let (kernel, agent) = echo_kernel();
    let request = make_request(
        "req-no-session",
        &delegate_capability(&kernel, &agent),
        "delegate",
        "srv-echo",
    );
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert!(response
        .receipt
        .metadata
        .as_ref()
        .is_none_or(|metadata| metadata.get("session_anchor").is_none()));
}

#[test]
fn session_anchor_is_a_reserved_kernel_written_key() {
    assert!(
        chio_core::receipt::metadata::reserved_receipt_metadata_keys()
            .any(|key| key == "session_anchor")
    );
}

/// A `session_anchor` block forwarded into the signing boundary by any layer
/// other than the session scope is refused, so a signed receipt can only ever
/// carry the anchor of the session it was evaluated in.
#[test]
fn forwarded_session_anchor_metadata_is_refused_at_signing() {
    let (kernel, agent) = echo_kernel();
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let result = kernel.build_and_sign_receipt(ReceiptParams {
        request_id: Some("req-forwarded-anchor"),
        capability_id: "cap-forwarded-anchor",
        tool_name: "delegate",
        server_id: "srv-echo",
        decision: Decision::Allow,
        action: ToolCallAction::from_parameters(serde_json::json!({ "stage": "forwarded" }))
            .unwrap(),
        content_hash: chio_core::crypto::sha256_hex(b"forwarded-anchor"),
        canonical_content: b"forwarded-anchor".to_vec(),
        metadata: Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) })),
        timestamp: PARENT_TIMESTAMP,
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
    });
    assert!(
        matches!(
            &result,
            Err(KernelError::ReceiptSigningFailed(reason))
                if reason == "receipt metadata already carries a session anchor block"
        ),
        "{result:?}"
    );
    assert!(kernel.receipt_log().is_empty());
}

/// A parent carrying a valid session anchor block whose signature covers the
/// bare canonical body instead of the signing wrapper is refused before the
/// block is read.
#[test]
fn persisted_parent_signed_without_the_wrapper_is_refused() {
    let (kernel, agent) = echo_kernel();
    let session_id = open_anchored_session(&kernel, &agent);
    let anchor = session_anchor_of(&kernel, &session_id);
    let metadata = Some(serde_json::json!({ "session_anchor": anchor_block(&anchor) }));
    let mut parent = signed_parent(&kernel.config.keypair, Decision::Allow, metadata.clone());
    let bare_body = chio_core::canonical::canonical_json_bytes(&parent_body(
        kernel.config.keypair.public_key(),
        Decision::Allow,
        metadata,
    ))
    .unwrap();
    parent.signature = kernel
        .config
        .keypair
        .sign_exempt(chio_core::crypto::ExemptFormat::JwsSigningInput, &bare_body);
    let response = continue_from_persisted_parent(Continuation {
        kernel: &kernel,
        token_signer: &kernel.config.keypair,
        agent: &agent,
        capability: delegate_capability(&kernel, &agent),
        parent: &parent,
        token_anchor: anchor,
        parent_receipt_hash: Some(receipt_hash(&parent)),
    });
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with(&format!(
                "{DENIED}governed call_chain parent receipt failed signature verification"
            ))),
        "{:?}",
        response.reason
    );
}
