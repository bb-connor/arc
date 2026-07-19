#[test]
fn ttl_seconds_from_wire_accepts_seconds_and_nanoseconds() {
    assert_eq!(ttl_seconds_from_wire(None, None), 3600);
    assert_eq!(ttl_seconds_from_wire(Some(3600), None), 3600);
    assert_eq!(ttl_seconds_from_wire(None, Some(500_000_000)), 1);
}

#[test]
fn parse_sidecar_operation_shorthand_read_preserves_read_scope() {
    assert_eq!(
        parse_sidecar_operation("read", true).test_unwrap(),
        Operation::Read
    );
}

#[tokio::test]
async fn sidecar_release_persists_revocation_and_blocks_reuse() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );

    let release_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                    "job_uid": "job-uid-1",
                    "reason": "completed",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::OK);

    let reloaded = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&reloaded.signer_keypair, "cap-revoked"),
        )
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();
    let response = proxy_handler(State(Arc::clone(&reloaded)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["message"], "capability token has been revoked");

    let _ = std::fs::remove_file(&receipt_db);
    let _ = std::fs::remove_file(format!("{receipt_db}.revocations"));
}

#[tokio::test]
async fn sidecar_release_reaches_a_replica_booted_before_the_revocation() {
    // A sibling replica that started before the revocation keeps a stale, empty
    // in-memory set. It must still deny the released capability by reading the
    // shared durable revocation store the release path writes to.
    let receipt_db = temp_receipt_db_path();
    let routes = || {
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }]
    };

    // Replica B boots first, before any capability has been revoked.
    let replica_b = test_state_with_receipt_db(
        routes(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );

    // Replica A handles the release while replica B is already serving.
    let replica_a = test_state_with_receipt_db(
        routes(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let release_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                    "job_uid": "job-uid-1",
                    "reason": "completed",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&replica_a)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::OK);

    // Replica B never reloaded its in-memory set...
    assert!(replica_b.revoked_capability_ids.lock().await.is_empty());
    // ...yet the shared durable store makes the revocation visible to it.
    let found = find_revoked_capability_id(&replica_b, None, Some("cap-revoked")).await;
    assert_eq!(found, Some("cap-revoked".to_string()));

    let _ = std::fs::remove_file(&receipt_db);
    let _ = std::fs::remove_file(format!("{receipt_db}.revocations"));
}

#[tokio::test]
async fn sidecar_validate_capability_honors_a_durable_only_revocation() {
    let receipt_db = temp_receipt_db_path();

    // Replica B mints a token and keeps serving; its in-memory revocation set is
    // never reloaded after boot.
    let replica_b = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let mint_response = build_app(Arc::clone(&replica_b))
        .oneshot(loopback_post(
            "/v1/capabilities",
            serde_json::json!({
                "subject": Keypair::generate().public_key().to_hex(),
                "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
                "ttl_seconds": 600,
            }),
        ))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    // Replica A releases the capability on the shared durable store.
    let replica_a = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let release_response = build_app(Arc::clone(&replica_a))
        .oneshot(loopback_post(
            "/v1/capabilities/release",
            serde_json::json!({ "capability_id": token.id, "reason": "completed" }),
        ))
        .await
        .test_unwrap();
    assert_eq!(release_response.status(), StatusCode::OK);

    // Replica B never reloaded its in-memory set, yet validate consults the
    // durable store and reports the token as revoked. Without that lookup the
    // freshly minted, trusted, signed token would validate as live.
    assert!(replica_b.revoked_capability_ids.lock().await.is_empty());
    let validate_response = build_app(Arc::clone(&replica_b))
        .oneshot(loopback_post(
            "/v1/capabilities/validate",
            serde_json::to_value(&token).test_unwrap(),
        ))
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(
        &to_bytes(validate_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(json["valid"], false);
    assert!(json["reason"].as_str().test_unwrap().contains("revoked"));

    let _ = std::fs::remove_file(&receipt_db);
    let _ = std::fs::remove_file(format!("{receipt_db}.revocations"));
}

#[tokio::test]
async fn sidecar_evaluate_tool_call_honors_a_durable_only_revocation() {
    let receipt_db = temp_receipt_db_path();

    // Replica B serves the advisory route, which is off by default; opt it in so
    // this exercises the advisory path's durable-revocation consultation rather
    // than the disabled-advisory 409.
    let replica_b = make_test_state(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
        true,
    );
    let replica_a = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );

    // Replica A releases the capability on the shared durable store.
    let release_response = build_app(Arc::clone(&replica_a))
        .oneshot(loopback_post(
            "/v1/capabilities/release",
            serde_json::json!({ "capability_id": "cap-durable-revoked" }),
        ))
        .await
        .test_unwrap();
    assert_eq!(release_response.status(), StatusCode::OK);

    // Replica B never reloaded its in-memory set, yet the advisory evaluation
    // consults the durable store and drops the call as revoked. Without that
    // lookup the advisory checks would report as passed.
    assert!(replica_b.revoked_capability_ids.lock().await.is_empty());
    let evaluate_response = build_app(Arc::clone(&replica_b))
        .oneshot(loopback_post(
            "/v1/evaluate/advisory",
            serde_json::json!({
                "capability_id": "cap-durable-revoked",
                "tool_server": "fs",
                "tool_name": "read",
                "parameters": {},
            }),
        ))
        .await
        .test_unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);
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

    let _ = std::fs::remove_file(&receipt_db);
    let _ = std::fs::remove_file(format!("{receipt_db}.revocations"));
}

/// Durable-by-default for embedders: constructing `ProtectConfig` with no
/// receipt store and no explicit ephemeral opt-in must refuse to start, so a
/// library user cannot silently run with in-memory receipts. The gate runs
/// before any listener bind, so the durable-store error surfaces regardless of
/// the listen address.
#[tokio::test]
async fn run_refuses_to_start_without_durable_receipts_unless_opted_in() {
    let config = ProtectConfig {
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some(PETSTORE_YAML.to_string()),
        spec_path: None,
        listen_addr: "127.0.0.1:1".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: false,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        control_url: None,
        control_token: None,
        budget_db: None,
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let error = ProtectProxy::new(config).run().await.test_unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("durable receipt store"),
        "an embedded proxy without a durable store must refuse to start, got: {message}"
    );
}

/// Durable-by-default for embedders: an in-memory receipt path (`:memory:` or a
/// `file:...?mode=memory` URI) opens a SQLite database that vanishes on restart,
/// so the boot gate must treat it like a missing store and refuse to start
/// without the explicit ephemeral opt-in. Otherwise the proxy would open
/// in-memory stores yet advertise a durable receipt backend and silently lose
/// audit evidence.
#[tokio::test]
async fn run_refuses_to_start_with_an_in_memory_receipt_path_unless_opted_in() {
    for receipt_db in [":memory:", "file:receipts.db?mode=memory"] {
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some(PETSTORE_YAML.to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:1".to_string(),
            receipt_db: Some(receipt_db.to_string()),
            allow_ephemeral_receipts: false,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: None,
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let error = ProtectProxy::new(config).run().await.test_unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("durable receipt store"),
            "an in-memory receipt path ({receipt_db}) must refuse to start without an opt-in, got: {message}"
        );
    }
}

/// In ephemeral mode there is no durable receipt database, but the sidecar
/// still shares an in-memory revocation store with the embedded kernel, so a
/// release must succeed and revoke the capability in-process rather than fail
/// and leave the token authorizing until it expires.
#[tokio::test]
async fn sidecar_release_revokes_in_process_without_a_receipt_store() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    assert!(
        state.receipt_store.is_none(),
        "ephemeral serving mode has no durable receipt store"
    );

    let release_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                    "job_uid": "job-uid-1",
                    "reason": "completed",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::OK);

    let bytes = to_bytes(release_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["released"], true);

    // The release takes effect in-process for both the validate path (in-memory
    // set) and the mediated path (the shared revocation store).
    assert!(state
        .revoked_capability_ids
        .lock()
        .await
        .contains("cap-revoked"));
    let store = state.revocation_store.as_ref().test_unwrap();
    assert!(
        chio_kernel::RevocationStore::is_revoked(store.as_ref(), "cap-revoked").test_unwrap(),
        "the shared revocation store must record the release"
    );
}

#[tokio::test]
async fn durable_revocation_db_id_is_enforced_by_proxy_state() {
    let dir = std::env::temp_dir().join(format!("chio-revocation-state-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).test_unwrap();
    let db = dir.join("revocations.sqlite3");

    // An operator revokes through the durable store that
    // `chio trust revoke --revocation-db <path>` writes and the sidecar used to
    // never read; the sidecar must now enforce it on every revoked path.
    let store = chio_store_sqlite::SqliteRevocationStore::open(&db).test_unwrap();
    assert!(chio_kernel::RevocationStore::revoke(&store, "cap-operator-revoked").test_unwrap());
    drop(store);

    let config = ProtectConfig {
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        control_url: None,
        control_token: None,
        budget_db: None,
        revocation_db: Some(db.to_string_lossy().to_string()),
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };

    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    // Mirror the sidecar startup merge: durable operator revocations join the
    // shared set that the mediated, validate, and proxy paths all consult.
    let durable = load_revocation_db_ids(&config).test_unwrap();
    state.revoked_capability_ids.lock().await.extend(durable);

    assert!(
        state
            .revoked_capability_ids
            .lock()
            .await
            .contains("cap-operator-revoked"),
        "durable --revocation-db revocation must land in the enforced set"
    );
    assert_eq!(
        find_revoked_capability_id(&state, None, Some("cap-operator-revoked")).await,
        Some("cap-operator-revoked".to_string()),
        "a capability revoked via --revocation-db must be rejected on the request path"
    );
}

#[tokio::test]
async fn sidecar_submit_receipt_persists_submitted_job_receipt() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/receipts")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "job_name": "demo",
                    "namespace": "default",
                    "job_uid": "job-uid-1",
                    "capability_id": "cap-1",
                    "outcome": "succeeded",
                    "started_at": "2026-04-17T10:00:00Z",
                    "completed_at": "2026-04-17T10:05:00Z",
                    "steps": [{
                        "pod_name": "demo-pod",
                        "phase": "Succeeded",
                        "payload": "{\"ok\":true}",
                        "observed_at": "2026-04-17T10:05:00Z"
                    }]
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let response = sidecar_submit_receipt_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let submit_response: SidecarSubmitReceiptResponse =
        serde_json::from_slice(&bytes).test_unwrap();

    let reloaded = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let log = reloaded.receipt_log.lock().await;
    let stored = log
        .receipts
        .iter()
        .find(|receipt| receipt.id == submit_response.receipt_id)
        .test_unwrap();
    assert_eq!(stored.capability_id.as_deref(), Some("cap-1"));
    assert_eq!(
        stored.metadata.as_ref().test_unwrap()["job_uid"],
        "job-uid-1"
    );
    assert_eq!(
        stored.metadata.as_ref().test_unwrap()["steps"][0]["pod_name"],
        "demo-pod"
    );
    assert!(stored.verify_signature().test_unwrap());
    // The returned id must be the content-addressed signed id (64-char
    // SHA-256 hex), not the pre-sign UUID. This guarantees clients can
    // look up the submitted job receipt in the receipt log.
    assert_eq!(submit_response.receipt_id, stored.id);
    assert_eq!(
        submit_response.receipt_id,
        stored.recompute_id().test_unwrap()
    );
    assert_eq!(submit_response.receipt_id.len(), 64);
    assert!(submit_response
        .receipt_id
        .chars()
        .all(|c| c.is_ascii_hexdigit()));

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test]
async fn sidecar_control_endpoints_reject_non_loopback_callers() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let mint_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

    let release_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::FORBIDDEN);

    let receipt_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/receipts")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "job_name": "demo",
                    "namespace": "default",
                    "job_uid": "job-uid-1",
                    "outcome": "succeeded",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let receipt_response =
        sidecar_submit_receipt_handler(State(Arc::clone(&state)), receipt_request).await;
    assert_eq!(receipt_response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(receipt_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_control_forbidden");
    assert_eq!(
        json["message"],
        "sidecar control endpoints require a loopback caller"
    );
}

#[tokio::test]
async fn sidecar_control_endpoints_allow_authenticated_non_loopback_callers() {
    let receipt_db = temp_receipt_db_path();
    let mut state = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
        Some("cluster-control-token".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let mint_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .header("authorization", "Bearer cluster-control-token")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::OK);

    let release_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .header("authorization", "Bearer cluster-control-token")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::OK);

    let receipt_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/receipts")
            .header("content-type", "application/json")
            .header("authorization", "Bearer cluster-control-token")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "job_name": "demo",
                    "namespace": "default",
                    "job_uid": "job-uid-1",
                    "outcome": "succeeded",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let receipt_response =
        sidecar_submit_receipt_handler(State(Arc::clone(&state)), receipt_request).await;
    assert_eq!(receipt_response.status(), StatusCode::OK);

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test]
async fn sidecar_control_endpoints_accept_lowercase_bearer_scheme() {
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
        Some("cluster-control-token".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let mint_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .header("authorization", "bearer cluster-control-token")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );

    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn sidecar_control_endpoints_require_bearer_auth_for_loopback_when_configured() {
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
        Some("cluster-control-token".to_string());

    let mint_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(mint_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_control_forbidden");
    assert_eq!(
        json["message"],
        "sidecar control endpoints require a loopback caller or valid bearer token"
    );
}

#[tokio::test]
async fn sidecar_control_endpoints_reject_blank_control_token_configuration() {
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token = Some("   ".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let mint_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .header("authorization", "Bearer ")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );

    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(mint_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_control_forbidden");
}

#[test]
fn sidecar_control_bearer_token_compare_is_constant_time_safe() {
    // Regression test: bearer-token comparison must use a constant-time
    // primitive so callers cannot recover the configured token through
    // response timing differences. We exercise both equal and prefix-
    // matching tokens to confirm the byte compare path is reached.
    let request = |header: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("authorization", header)
            .body(Body::empty())
            .test_unwrap()
    };

    let configured = "cluster-control-token";
    assert!(sidecar_control_bearer_token_matches(
        &request(&format!("Bearer {configured}")),
        configured,
    ));
    assert!(!sidecar_control_bearer_token_matches(
        &request("Bearer cluster-control-toxen"),
        configured,
    ));
    assert!(!sidecar_control_bearer_token_matches(
        &request("Bearer cluster-control"),
        configured,
    ));
    assert!(!sidecar_control_bearer_token_matches(
        &request("Bearer "),
        configured,
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_persists_receipts_when_receipt_db_configured() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let reloaded = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let log = reloaded.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert!(log.receipts[0].verify_signature().test_unwrap());

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persisted_receipts_are_visible_across_proxy_and_sidecar_flows() {
    let receipt_db = temp_receipt_db_path();
    let proxy_state = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let denied_request = Request::builder()
        .method("POST")
        .uri("/pets")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();
    let denied_response = proxy_handler(State(Arc::clone(&proxy_state)), denied_request).await;
    assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);

    let sidecar_state = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    {
        let log = sidecar_state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
    }

    let body = ChioHttpRequest::new(
        "req-sidecar-persisted".to_string(),
        HttpMethod::Get,
        "/pets".to_string(),
        "/pets".to_string(),
        chio_http_core::CallerIdentity::anonymous(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
        .test_unwrap();

    let response = sidecar_evaluate_handler(State(Arc::clone(&sidecar_state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let reloaded = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let log = reloaded.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 2);

    let _ = std::fs::remove_file(receipt_db);
}
