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
