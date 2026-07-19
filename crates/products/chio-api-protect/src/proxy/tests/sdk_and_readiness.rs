// -------------------------------------------------------------
// SDK-shape body tests for the proxy routes.
// -------------------------------------------------------------

fn loopback_post(uri: &str, body: serde_json::Value) -> Request<Body> {
    with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
            .test_unwrap(),
    )
}

fn parse_advisory_evaluation_body(bytes: &[u8]) -> (serde_json::Value, ChioReceipt) {
    let body: serde_json::Value = serde_json::from_slice(bytes).test_unwrap();
    assert_eq!(
        body["schema"],
        serde_json::json!("chio.sidecar.advisory-evaluation.v1")
    );
    assert_eq!(body["authorization"], serde_json::json!(false));
    assert_eq!(body["authorizationBasis"], "advisory_only");
    let receipt: ChioReceipt = serde_json::from_value(body["receipt"].clone()).test_unwrap();
    (body, receipt)
}

#[tokio::test]
async fn sidecar_capabilities_alias_accepts_sdk_body_shape() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let subject = Keypair::generate();

    let body = serde_json::json!({
        "subject": subject.public_key().to_hex(),
        "scope": {
            "grants": [],
            "resource_grants": [],
            "prompt_grants": [],
        },
        "ttl_seconds": 600,
    });

    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(&bytes).test_unwrap();
    assert!(!token.id.is_empty());
    assert!(token.verify_signature().test_unwrap());
}

#[tokio::test]
async fn sidecar_capabilities_alias_accepts_canonical_body_shape() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    let body = serde_json::json!({
        "subject": "agent-via-canonical",
        "scopes": ["filesystem:read"],
        "ttl_seconds": 600,
        "job_uid": "job-canonical-1",
    });

    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(&bytes).test_unwrap();
    assert!(token.verify_signature().test_unwrap());
}

#[tokio::test]
async fn sidecar_capabilities_alias_rejects_blank_subject() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let body = serde_json::json!({
        "subject": "   ",
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 60,
    });
    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sidecar_validate_capability_returns_valid_for_freshly_minted_token() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let mint_bytes = to_bytes(mint_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(&mint_bytes).test_unwrap();

    let validate_body = serde_json::to_value(&token).test_unwrap();
    let validate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(validate_response.status(), StatusCode::OK);

    let bytes = to_bytes(validate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], true);
    assert_eq!(json["capability_id"], token.id);
    assert!(json.get("reason").is_none() || json["reason"].is_null());
}

#[tokio::test]
async fn sidecar_validate_capability_rejects_relaxed_expected_scope_constraints() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": {
            "grants": [{
                "server_id": "files",
                "tool_name": "read",
                "operations": ["invoke"],
                "constraints": [{"type": "path_prefix", "value": "/secret"}]
            }],
            "resource_grants": [],
            "prompt_grants": []
        },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let mint_bytes = to_bytes(mint_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(&mint_bytes).test_unwrap();

    let validate_body = serde_json::json!({
        "id": token.id,
        "issuer": token.issuer.to_hex(),
        "subject": token.subject.to_hex(),
        "scope": token.scope,
        "issued_at": token.issued_at,
        "expires_at": token.expires_at,
        "delegation_chain": token.delegation_chain,
        "signature": token.signature.to_hex(),
        "expected_scope": {
            "grants": [{
                "server_id": "files",
                "tool_name": "read",
                "operations": ["invoke"],
                "constraints": []
            }],
            "resource_grants": [],
            "prompt_grants": []
        }
    });
    let validate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(validate_response.status(), StatusCode::OK);

    let bytes = to_bytes(validate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], false);
    assert_eq!(
        json["reason"].as_str(),
        Some("expected_scope is not a subset of capability scope")
    );
}

#[tokio::test]
async fn sidecar_validate_capability_reports_revoked_capability() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );

    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    // Revoke the capability via the existing release route, then
    // validate.
    let release_body = serde_json::json!({
        "capability_id": token.id,
        "reason": "test",
    });
    let release_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/release", release_body))
        .await
        .test_unwrap();
    assert_eq!(release_response.status(), StatusCode::OK);

    let validate_body = serde_json::to_value(&token).test_unwrap();
    let validate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    let bytes = to_bytes(validate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], false);
    assert!(json["reason"].as_str().test_unwrap().contains("revoked"));

    let _ = std::fs::remove_file(receipt_db);
}

/// Build a leaf capability token whose delegation chain records `parent_id` as
/// an ancestor. The leaf is signed by the trusted issuer so it passes the
/// issuer-trust, signature, and expiry gates; only the ancestor's revocation
/// status is left for the validate handler to weigh.
fn child_token_with_chain_ancestor(
    state: &ProxyState,
    leaf_id: &str,
    parent_id: &str,
) -> CapabilityToken {
    let now = chrono::Utc::now().timestamp() as u64;
    let delegator = Keypair::generate();
    let delegatee = Keypair::generate();
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: delegator.public_key(),
            delegatee: delegatee.public_key(),
            attenuations: Vec::new(),
            timestamp: now,
            scope_hash: None,
        },
        &delegator,
    )
    .test_unwrap();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: leaf_id.to_string(),
            issuer: state.signer_keypair.public_key(),
            subject: delegatee.public_key(),
            scope: ChioScope::default(),
            issued_at: now.saturating_sub(60),
            expires_at: now + 3600,
            delegation_chain: vec![link],
        },
        &state.signer_keypair,
    )
    .test_unwrap()
}

#[tokio::test]
async fn sidecar_validate_capability_rejects_revoked_delegation_chain_ancestor() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let parent_id = "cap-parent-delegator";
    let child = child_token_with_chain_ancestor(&state, "cap-child-leaf", parent_id);

    // Revoke the parent capability while the leaf itself stays live: the
    // validate handler must still refuse the delegated child.
    state
        .revoked_capability_ids
        .lock()
        .await
        .insert(parent_id.to_string());

    let validate_body = serde_json::to_value(&child).test_unwrap();
    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], false);
    assert!(json["reason"].as_str().test_unwrap().contains("chain"));
}

#[tokio::test]
async fn sidecar_validate_capability_accepts_live_delegation_chain() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let child = child_token_with_chain_ancestor(&state, "cap-child-live", "cap-parent-live");

    let validate_body = serde_json::to_value(&child).test_unwrap();
    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], true);
    assert_eq!(json["capability_id"], "cap-child-live");
}

/// An untrusted token must be rejected on issuer trust before its delegation
/// chain is walked, so an unauthenticated caller cannot force one revocation
/// lookup per fabricated ancestor. The leaf carries a revoked ancestor, so a
/// handler that walked the chain first would report the chain-revoked reason;
/// the correct order reports the untrusted-issuer reason and never consults the
/// ancestor's revocation status.
#[tokio::test]
async fn sidecar_validate_capability_checks_issuer_trust_before_walking_chain() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let untrusted_issuer = Keypair::generate();
    let parent_id = "cap-parent-untrusted";

    let now = chrono::Utc::now().timestamp() as u64;
    let delegator = Keypair::generate();
    let delegatee = Keypair::generate();
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: delegator.public_key(),
            delegatee: delegatee.public_key(),
            attenuations: Vec::new(),
            timestamp: now,
            scope_hash: None,
        },
        &delegator,
    )
    .test_unwrap();
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-child-untrusted".to_string(),
            issuer: untrusted_issuer.public_key(),
            subject: delegatee.public_key(),
            scope: ChioScope::default(),
            issued_at: now.saturating_sub(60),
            expires_at: now + 3600,
            delegation_chain: vec![link],
        },
        &untrusted_issuer,
    )
    .test_unwrap();

    // Revoke the ancestor. A handler that walks the chain before the issuer
    // gate would surface this; the correct order never reaches it.
    state
        .revoked_capability_ids
        .lock()
        .await
        .insert(parent_id.to_string());

    let validate_body = serde_json::to_value(&child).test_unwrap();
    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], false);
    let reason = json["reason"].as_str().test_unwrap();
    assert!(
        reason.contains("issuer is not trusted"),
        "an untrusted token must be rejected on issuer trust before its chain is walked, got: {reason}"
    );
    assert!(
        !reason.contains("chain"),
        "the delegation chain must not be consulted for an untrusted token, got: {reason}"
    );
}

#[tokio::test]
async fn sidecar_validate_capability_rejects_untrusted_issuer() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let untrusted_issuer = Keypair::generate();
    let token_json = signed_capability_token_json(&untrusted_issuer, "cap-untrusted");
    let validate_body: serde_json::Value = serde_json::from_str(&token_json).test_unwrap();

    let validate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(validate_response.status(), StatusCode::OK);

    let bytes = to_bytes(validate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], false);
    assert!(json["reason"]
        .as_str()
        .test_unwrap()
        .contains("issuer is not trusted"));
}

#[tokio::test]
async fn sidecar_attenuate_capability_fails_closed_without_subject_signer() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let body = serde_json::json!({
        "parent_capability_id": "anything",
        "attenuated_scope": {},
    });

    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/attenuate", body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["error"], "chio_attenuation_requires_subject_signer");
    assert_eq!(json["authorization"], false);
}

#[tokio::test]
async fn sidecar_verify_receipt_round_trips_a_signed_chio_receipt() {
    let state = make_test_state(Vec::new(), "http://127.0.0.1:1".to_string(), None, true);

    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    let evaluate_body = serde_json::json!({
        "capability_id": token.id,
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {"path": "/etc/hostname"},
    });
    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    assert_eq!(
        evaluate_response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);
    assert!(receipt.verify_signature().test_unwrap());
    assert_eq!(receipt.capability_id, token.id);
    // The sidecar advisory path emits advisory receipts (no decision)
    // so v1 authority gates cannot mistake the result for a kernel-
    // mediated authorization.
    assert!(receipt.decision.is_none());
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
    assert_eq!(receipt.boundary_class, BoundaryClass::AdvisoryOnly);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert_eq!(
        receipt.observation_outcome,
        Some(ObservationOutcome::Evaluated)
    );
    assert!(!receipt.is_allowed());

    // Now feed it back through `/v1/receipts/verify`.
    let verify_body = serde_json::to_value(&receipt).test_unwrap();
    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    let verification: VerifyReceiptResponse = serde_json::from_value(verify_json).test_unwrap();
    assert!(verification.signature_valid);
    assert!(verification.signer_trusted);
    assert!(!verification.authorized);
    assert!(!verification.ok);
    assert_eq!(verification.receipt_kind, "advisory_evaluation");
    assert_eq!(verification.boundary_class, "advisory_only");
    assert_eq!(verification.trust_level, "advisory");
    assert_eq!(verification.result, "none");
}

#[tokio::test]
async fn sidecar_evaluate_advisory_route_wraps_non_authorization_response() {
    let state = make_test_state(Vec::new(), "http://127.0.0.1:1".to_string(), None, true);
    let evaluate_body = serde_json::json!({
        "capability_id": "cap-advisory-route",
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {"path": "/etc/hostname"},
    });
    // /v1/evaluate is the kernel-mediated route; this body uses capability_id
    // (advisory shape) rather than a full capability token, so the mediated
    // handler rejects it with 400 before reaching the kernel.
    let mediated_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate", evaluate_body.clone()))
        .await
        .test_unwrap();
    assert_eq!(mediated_response.status(), StatusCode::BAD_REQUEST);

    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();

    assert_eq!(evaluate_response.status(), StatusCode::OK);
    assert_eq!(
        evaluate_response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&bytes);
    assert_eq!(receipt.capability_id, "cap-advisory-route");
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
    assert_eq!(receipt.boundary_class, BoundaryClass::AdvisoryOnly);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert!(receipt.decision.is_none());
}

include!("advisory_and_receipt.rs");

#[tokio::test]
async fn sidecar_advisory_json_fallback_preserves_trust_header() {
    let signer = Keypair::generate();
    let parameters = serde_json::json!({"path": "/etc/hostname"});
    let parameter_hash = chio_core_types::canonical_json_bytes(&parameters)
        .map(|canonical| chio_core_types::sha256_hex(&canonical))
        .test_unwrap();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: "cap-advisory".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read".to_string(),
            action: ToolCallAction {
                parameters,
                parameter_hash,
            },
            decision: None,
            receipt_kind: ReceiptKind::AdvisoryEvaluation,
            boundary_class: BoundaryClass::AdvisoryOnly,
            observation_outcome: Some(ObservationOutcome::Evaluated),
            tool_origin: ToolOrigin::HostExecutedUnmediated,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"test"),
            policy_hash: manual_receipt_policy_hash(
                "advisory_json_fallback_preserves_trust_header",
            ),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Advisory,
            tenant_id: None,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        &signer,
    )
    .test_unwrap();

    let receipt_id = receipt.id.clone();
    let response = sidecar_advisory_tool_call_evaluate_json_response(receipt);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, wrapped_receipt) = parse_advisory_evaluation_body(&body);
    assert_eq!(wrapped_receipt.id, receipt_id);
}

#[tokio::test]
async fn sidecar_verify_receipt_rejects_untrusted_signer() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let attacker = Keypair::generate();
    let parameters = serde_json::json!({"path": "/etc/hostname"});
    let parameter_hash = chio_core_types::canonical_json_bytes(&parameters)
        .map(|canonical| chio_core_types::sha256_hex(&canonical))
        .test_unwrap();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: "cap-attacker".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read".to_string(),
            action: ToolCallAction {
                parameters,
                parameter_hash,
            },
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"forged-request-body"),
            policy_hash: manual_receipt_policy_hash("forged_sidecar_receipt_test"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: attacker.public_key(),
            bbs_projection_version: None,
        },
        &attacker,
    )
    .test_unwrap();
    assert!(receipt.verify_signature().test_unwrap());

    let verify_body = serde_json::to_value(&receipt).test_unwrap();
    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    assert!(verify_json["reason"]
        .as_str()
        .test_unwrap()
        .contains("signer is not trusted"));

    let verification: VerifyReceiptResponse = serde_json::from_value(verify_json).test_unwrap();
    assert!(verification.signature_valid);
    assert!(!verification.signer_trusted);
    assert!(!verification.authorized);
    assert!(!verification.ok);
}

#[tokio::test]
async fn sidecar_verify_receipt_rejects_capability_issuer_as_receipt_signer() {
    let attacker = Keypair::generate();
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    Arc::get_mut(&mut state)
        .test_expect("state is not shared yet")
        .trusted_capability_issuers
        .push(attacker.public_key());

    let parameters = serde_json::json!({"path": "/etc/hostname"});
    let action = ToolCallAction::from_parameters(parameters).test_unwrap();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: "cap-attacker".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"forged-request-body"),
            policy_hash: manual_receipt_policy_hash("forged_capability_issuer_receipt_test"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: attacker.public_key(),
            bbs_projection_version: None,
        },
        &attacker,
    )
    .test_unwrap();

    let verify_body = serde_json::to_value(&receipt).test_unwrap();
    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    assert!(verify_json["reason"]
        .as_str()
        .test_unwrap()
        .contains("signer is not trusted"));

    let verification: VerifyReceiptResponse = serde_json::from_value(verify_json).test_unwrap();
    assert!(verification.signature_valid);
    assert!(!verification.signer_trusted);
    assert!(!verification.authorized);
    assert!(!verification.ok);
}

#[tokio::test]
async fn sidecar_verify_receipt_rejects_action_parameter_hash_mismatch() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let parameters = serde_json::json!({"path": "/etc/hostname"});
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: "cap-sidecar".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read".to_string(),
            action: ToolCallAction {
                parameters,
                parameter_hash: "0".repeat(64),
            },
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"trusted-request-body"),
            policy_hash: manual_receipt_policy_hash("bad_action_hash_receipt_test"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: state.signer_keypair.public_key(),
            bbs_projection_version: None,
        },
        &state.signer_keypair,
    )
    .test_unwrap();
    assert!(receipt.verify_signature().test_unwrap());

    let verify_body = serde_json::to_value(&receipt).test_unwrap();
    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    assert!(verify_json["reason"]
        .as_str()
        .test_unwrap()
        .contains("parameter_hash"));

    let verification: VerifyReceiptResponse = serde_json::from_value(verify_json).test_unwrap();
    assert!(verification.signature_valid);
    assert!(verification.signer_trusted);
    assert!(verification.receipt_id_valid);
    assert!(!verification.parameter_hash_valid);
    assert!(!verification.authorized);
    assert!(!verification.ok);
}

#[tokio::test]
async fn sidecar_verify_receipt_rejects_expected_decision_mismatch() {
    let state = make_test_state(Vec::new(), "http://127.0.0.1:1".to_string(), None, true);

    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    let evaluate_body = serde_json::json!({
        "capability_id": token.id,
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {"path": "/etc/hostname"},
    });
    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);

    let mut verify_body = serde_json::to_value(&receipt).test_unwrap();
    verify_body
        .as_object_mut()
        .test_unwrap()
        .insert("expected_decision".to_string(), serde_json::json!("deny"));

    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    assert!(verify_json["reason"]
        .as_str()
        .test_unwrap()
        .contains("does not match"));
}

#[tokio::test]
async fn sidecar_evaluate_tool_call_denies_revoked_capability() {
    let receipt_db = temp_receipt_db_path();
    let state = make_test_state(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
        true,
    );

    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    let release_body = serde_json::json!({"capability_id": token.id});
    let release_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/release", release_body))
        .await
        .test_unwrap();
    assert_eq!(release_response.status(), StatusCode::OK);

    let evaluate_body = serde_json::json!({
        "capability_id": token.id,
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {},
    });
    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    assert_eq!(
        evaluate_response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);
    assert!(receipt.decision.is_none());
    assert!(!receipt.is_allowed());
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert_eq!(
        receipt.observation_outcome,
        Some(ObservationOutcome::Dropped)
    );
    let alias_outcome = receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("advisory_check_outcome"))
        .and_then(|v| v.as_str());
    assert_eq!(alias_outcome, Some("capability_revoked"));
    assert!(receipt.verify_signature().test_unwrap());

    let log = state.tool_receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt.id);
    drop(log);

    let reloaded = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let persisted = reloaded.tool_receipt_log.lock().await;
    assert_eq!(persisted.receipts.len(), 1);
    assert_eq!(persisted.receipts[0].id, receipt.id);

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test]
async fn sidecar_evaluate_tool_call_denies_parameter_hash_mismatch() {
    let state = make_test_state(Vec::new(), "http://127.0.0.1:1".to_string(), None, true);

    let evaluate_body = serde_json::json!({
        "capability_id": "cap-test",
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {"path": "/etc/hostname"},
        "parameter_hash": "deadbeef".to_string(),
    });
    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    assert_eq!(
        evaluate_response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);
    assert!(receipt.decision.is_none());
    assert!(!receipt.is_allowed());
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert_eq!(
        receipt.observation_outcome,
        Some(ObservationOutcome::Dropped)
    );
    let alias_outcome = receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("advisory_check_outcome"))
        .and_then(|v| v.as_str());
    assert_eq!(alias_outcome, Some("parameter_hash_mismatch"));
}

#[tokio::test]
async fn advisory_route_is_non_authorizing_when_advisory_disabled() {
    // Advisory is off by default; production stops emitting advisory
    // receipts that agents could skip the sidecar with.
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let payload = serde_json::json!({
        "capability_id": "cap-x", "tool_server": "fs",
        "tool_name": "read_file", "parameters": {}
    });
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/evaluate/advisory")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).test_unwrap()))
            .test_unwrap(),
    );
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = to_bytes(response.into_body(), 1 << 20).await.test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["authorization"], false);
    assert_eq!(json["replacement"], "/v1/evaluate");
}

#[tokio::test]
async fn live_route_reports_process_healthy_without_consulting_dependencies() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = Request::builder()
        .method("GET")
        .uri("/chio/live")
        .body(Body::empty())
        .test_unwrap();

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let health: HealthResponse = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(health.status, SidecarStatus::Healthy);
}

#[tokio::test]
async fn health_route_reports_ready_when_the_receipt_store_is_reachable() {
    let db_path = temp_receipt_db_path();
    let state =
        test_state_with_receipt_db(Vec::new(), "http://127.0.0.1:1".to_string(), Some(&db_path));
    let request = Request::builder()
        .method("GET")
        .uri("/chio/health")
        .body(Body::empty())
        .test_unwrap();

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let health: HealthResponse = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(health.status, SidecarStatus::Healthy);
}

#[tokio::test]
async fn readiness_consults_the_store_reachability_signal() {
    // With no store there is no dependency to fail, so readiness is healthy. The
    // reachability signal it consults is true for a working store; a store whose
    // connection could no longer answer this query drives readiness to unhealthy.
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    assert_eq!(state.readiness_status().await, SidecarStatus::Healthy);

    let db_path = temp_receipt_db_path();
    let store = SqliteReceiptStore::open(&db_path).test_unwrap();
    assert!(
        store.is_reachable(),
        "a freshly opened store must be reachable"
    );
}

#[tokio::test]
async fn reachability_probe_touches_the_write_path_and_persists_nothing() {
    let db_path = temp_receipt_db_path();
    let store = SqliteReceiptStore::open(&db_path).test_unwrap();

    // A healthy store probes reachable, and the probe rolls back: exercising the
    // write path must not leave a durable receipt behind.
    assert!(
        store.is_reachable(),
        "a freshly opened store must be reachable"
    );
    assert!(
        store.load_receipts().test_unwrap().is_empty(),
        "the readiness probe must not persist a receipt"
    );

    // Drop the receipt table out of band, as a bad migration or schema corruption
    // would. A bare connection check would still answer here; the write-path probe
    // must not, so an instance that can no longer persist receipts leaves rotation.
    let side = rusqlite::Connection::open(&db_path).test_unwrap();
    side.execute("DROP TABLE http_receipts", []).test_unwrap();
    drop(side);

    assert!(
        !store.is_reachable(),
        "a store that can no longer persist receipts must fail readiness"
    );
}
