//! Governed call-chain continuation tokens: session anchors and signer trust.

use super::*;

#[test]
fn live_parent_continuation_token_verifies_session_anchor() {
    let mut config = make_config();
    config.ca_public_keys.push(config.keypair.public_key());
    let mut kernel = make_kernel(config);
    let agent_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![capability.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let parent_anchor = kernel
        .with_session(&session_id, |session| {
            Ok(session.session_anchor().reference())
        })
        .unwrap();
    let parent_context = make_operation_context(
        &session_id,
        "req-parent-live-continuation",
        &agent_kp.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let call_chain = GovernedCallChainContext {
        chain_id: "chain-live-continuation".to_string(),
        parent_request_id: parent_context.request_id.to_string(),
        parent_receipt_id: None,
        origin_subject: "origin-subject".to_string(),
        delegator_subject: "delegator-subject".to_string(),
    };
    let mut intent = GovernedTransactionIntent {
        id: "intent-live-continuation".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue a live parent with a continuation token".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let continuation_token =
        make_governed_call_chain_continuation_token(GovernedCallChainContinuationTokenFixture {
            signer: &kernel.config.keypair,
            subject: &agent_kp.public_key(),
            call_chain: &call_chain,
            parent_session_anchor: parent_anchor.clone(),
            parent_receipt_hash: None,
            server_id: "srv-echo",
            tool_name: "delegate",
            governed_intent_hash: None,
        });
    attach_governed_call_chain_continuation_token(&mut intent, &continuation_token);

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-child-live-continuation".to_string(),
                capability,
                tool_name: "delegate".to_string(),
                server_id: "srv-echo".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
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
            },
            &mut NoopNestedFlowClient,
            None,
        )
        .unwrap();

    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "live-parent continuation token should allow; reason: {:?}",
        response.reason
    );
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(
        governed["call_chain"]["continuationTokenId"],
        serde_json::json!("continuation-token-1")
    );
    assert_eq!(
        governed["call_chain"]["sessionAnchorId"],
        serde_json::json!(parent_anchor.session_anchor_id)
    );
}

#[test]
/// A parent receipt's top-level `lineageReferences` is caller-settable metadata
/// that no kernel writes, so it never vouches for a continuation token's
/// `parent_session_anchor`.
fn continuation_token_session_anchor_ignores_top_level_lineage_references() {
    let parent_kernel = make_kernel(make_config());
    let mut child_kernel = make_kernel(make_config());
    child_kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
        parent_kernel.config.keypair.clone(),
    )));
    let child_kp = make_keypair();
    child_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let delegated_capability = make_capability(
        &child_kernel,
        &child_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );

    let parent_session_id = parent_kernel
        .open_session(child_kp.public_key().to_hex(), Vec::new())
        .unwrap();
    parent_kernel.activate_session(&parent_session_id).unwrap();
    parent_kernel
        .with_session_mut(&parent_session_id, |session| {
            assert!(
                session
                    .set_auth_context(SessionAuthContext::streamable_http_static_bearer(
                        "static-bearer:parent",
                        "token-parent",
                        Some("https://parent.example".to_string()),
                    ))
                    .unwrap()
                    .0
            );
            Ok(())
        })
        .unwrap();
    let parent_anchor = parent_kernel
        .with_session(&parent_session_id, |session| {
            Ok(session.session_anchor().reference())
        })
        .unwrap();

    let parent_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rc-parent-continuation".to_string(),
            timestamp: current_unix_timestamp(),
            capability_id: "cap-parent-continuation".to_string(),
            tool_server: "srv-echo".to_string(),
            tool_name: "delegate".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({ "stage": "parent" }))
                .unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core::crypto::sha256_hex(br#"{"ok":true}"#),
            policy_hash: "policy-parent-continuation".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "lineageReferences": {
                    "sessionAnchorId": parent_anchor.session_anchor_id.clone(),
                    "sessionAnchorHash": parent_anchor.session_anchor_hash.clone(),
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: child_kernel.public_key(),
            bbs_projection_version: None,
        },
        &child_kernel.config.keypair,
    )
    .unwrap();
    let parent_receipt_hash = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&parent_receipt).unwrap(),
    );
    child_kernel.record_chio_receipt(&parent_receipt).unwrap();

    let call_chain = GovernedCallChainContext {
        chain_id: "chain-cross-kernel-continuation".to_string(),
        parent_request_id: "req-parent-continuation".to_string(),
        parent_receipt_id: Some(parent_receipt.id.clone()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    };
    let mut intent = GovernedTransactionIntent {
        id: "intent-continuation".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow with continuation token".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let continuation_token =
        make_governed_call_chain_continuation_token(GovernedCallChainContinuationTokenFixture {
            signer: &parent_kernel.config.keypair,
            subject: &child_kp.public_key(),
            call_chain: &call_chain,
            parent_session_anchor: parent_anchor.clone(),
            parent_receipt_hash: Some(&parent_receipt_hash),
            server_id: "srv-echo",
            tool_name: "delegate",
            governed_intent_hash: None,
        });
    attach_governed_call_chain_continuation_token(&mut intent, &continuation_token);

    let response = child_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-child-continuation".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
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
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("governed transaction denied: governed call_chain continuation parent receipt carries no session anchor")
    );
}

#[test]
fn continuation_token_self_signed_by_an_untrusted_key_is_refused() {
    let parent_kernel = make_kernel(make_config());
    let mut child_config = make_config();
    child_config.ca_public_keys.push(parent_kernel.public_key());
    let mut child_kernel = make_kernel(child_config);
    let child_kp = make_keypair();
    child_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let delegated_capability = make_capability(
        &child_kernel,
        &child_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );

    let parent_session_id = parent_kernel
        .open_session(child_kp.public_key().to_hex(), Vec::new())
        .unwrap();
    parent_kernel.activate_session(&parent_session_id).unwrap();
    parent_kernel
        .with_session_mut(&parent_session_id, |session| {
            assert!(
                session
                    .set_auth_context(SessionAuthContext::streamable_http_static_bearer(
                        "static-bearer:parent",
                        "token-parent",
                        Some("https://parent.example".to_string()),
                    ))
                    .unwrap()
                    .0
            );
            Ok(())
        })
        .unwrap();
    let parent_anchor = parent_kernel
        .with_session(&parent_session_id, |session| {
            Ok(session.session_anchor().reference())
        })
        .unwrap();

    let parent_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rc-parent-continuation".to_string(),
            timestamp: current_unix_timestamp(),
            capability_id: "cap-parent-continuation".to_string(),
            tool_server: "srv-echo".to_string(),
            tool_name: "delegate".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({ "stage": "parent" }))
                .unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core::crypto::sha256_hex(br#"{"ok":true}"#),
            policy_hash: "policy-parent-continuation".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "lineageReferences": {
                    "sessionAnchorId": parent_anchor.session_anchor_id.clone(),
                    "sessionAnchorHash": parent_anchor.session_anchor_hash.clone(),
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: parent_kernel.public_key(),
            bbs_projection_version: None,
        },
        &parent_kernel.config.keypair,
    )
    .unwrap();
    let parent_receipt_hash = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&parent_receipt).unwrap(),
    );
    child_kernel.record_chio_receipt(&parent_receipt).unwrap();

    let call_chain = GovernedCallChainContext {
        chain_id: "chain-cross-kernel-continuation".to_string(),
        parent_request_id: "req-parent-continuation".to_string(),
        parent_receipt_id: Some(parent_receipt.id.clone()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    };
    let mut intent = GovernedTransactionIntent {
        id: "intent-continuation".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow with continuation token".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let untrusted_signer = make_keypair();
    let continuation_token =
        make_governed_call_chain_continuation_token(GovernedCallChainContinuationTokenFixture {
            signer: &untrusted_signer,
            subject: &child_kp.public_key(),
            call_chain: &call_chain,
            parent_session_anchor: parent_anchor.clone(),
            parent_receipt_hash: Some(&parent_receipt_hash),
            server_id: "srv-echo",
            tool_name: "delegate",
            governed_intent_hash: None,
        });
    attach_governed_call_chain_continuation_token(&mut intent, &continuation_token);

    let response = child_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-child-continuation".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
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
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason
            .contains("governed call_chain continuation token signer is not trusted")));
}
