#[test]
fn build_routes_from_petstore() {
    let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
    assert!(!routes.is_empty());

    // Should have GET and POST for /pets, GET and DELETE for /pets/{petId}
    let get_pets = routes.iter().find(|r| {
        r.method == HttpMethod::Get && r.pattern.contains("/pets") && !r.pattern.contains("{petId}")
    });
    assert!(get_pets.is_some());

    let post_pets = routes.iter().find(|r| r.method == HttpMethod::Post);
    assert!(post_pets.is_some());
    assert_eq!(
        post_pets.map(|r| r.policy),
        Some(PolicyDecision::DenyByDefault)
    );

    let delete_pet = routes.iter().find(|r| r.method == HttpMethod::Delete);
    assert!(delete_pet.is_some());
}

#[test]
fn get_routes_allowed_by_default() {
    let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
    let get_routes: Vec<_> = routes
        .iter()
        .filter(|r| r.method == HttpMethod::Get)
        .collect();
    for route in get_routes {
        assert_eq!(route.policy, PolicyDecision::SessionAllow);
    }
}

#[test]
fn side_effect_routes_denied_by_default() {
    let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
    let mut_routes: Vec<_> = routes
        .iter()
        .filter(|r| r.method.requires_capability())
        .collect();
    for route in mut_routes {
        assert_eq!(route.policy, PolicyDecision::DenyByDefault);
    }
}

#[test]
fn x_chio_side_effects_true_overrides_safe_method() {
    let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /dangerous-read:
    get:
      operationId: dangerousRead
      x-chio-side-effects: true
      responses:
        "200":
          description: ok
"#;

    let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
    let route = routes
        .iter()
        .find(|route| route.pattern == "/dangerous-read" && route.method == HttpMethod::Get)
        .test_unwrap();

    assert_eq!(route.policy, PolicyDecision::DenyByDefault);
}

#[test]
fn x_chio_side_effects_false_overrides_mutating_method() {
    let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /safe-post:
    post:
      operationId: safePost
      x-chio-side-effects: false
      responses:
        "200":
          description: ok
"#;

    let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
    let route = routes
        .iter()
        .find(|route| route.pattern == "/safe-post" && route.method == HttpMethod::Post)
        .test_unwrap();

    assert_eq!(route.policy, PolicyDecision::SessionAllow);
}

#[test]
fn x_chio_approval_required_forces_deny() {
    let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /approved-read:
    get:
      operationId: approvedRead
      x-chio-side-effects: false
      x-chio-approval-required: true
      responses:
        "200":
          description: ok
"#;

    let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
    let route = routes
        .iter()
        .find(|route| route.pattern == "/approved-read" && route.method == HttpMethod::Get)
        .test_unwrap();

    assert_eq!(route.policy, PolicyDecision::DenyByDefault);
}

#[test]
fn forwarded_query_string_strips_chio_capability() {
    let token = signed_capability_token_json(&Keypair::generate(), "cap-query");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("source", "test")
        .append_pair("chio_capability", &token)
        .append_pair("mode", "full")
        .finish();

    assert_eq!(
        forwarded_query_string(Some(&query)).as_deref(),
        Some("source=test&mode=full")
    );
}

#[test]
fn extract_caller_identity_rejects_blank_or_padded_credentials() {
    for (header_name, header_value) in [
        ("authorization", "Bearer "),
        ("authorization", "Bearer token-with-padding "),
        ("authorization", "Bearer token\nwith-control"),
        ("x-api-key", ""),
        ("x-api-key", " api-key-with-padding"),
        ("x-api-key", "api-key\nwith-control"),
    ] {
        let mut headers = HashMap::new();
        headers.insert(header_name.to_string(), header_value.to_string());

        let caller = extract_caller_identity(&headers);

        assert!(
            matches!(caller.auth_method, AuthMethod::Anonymous),
            "expected anonymous caller for {header_name}: {header_value:?}, got {caller:?}"
        );
        assert_eq!(caller.subject, "anonymous");
    }
}

#[test]
fn chio_transport_header_helpers_are_case_insensitive() {
    let token = signed_capability_token_json(&Keypair::generate(), "cap-header-case");
    let mut headers = HashMap::new();
    headers.insert("X-CHIO-CAPABILITY".to_string(), token.clone());
    let query = HashMap::new();

    assert_eq!(
        extract_presented_capability_from_maps(&headers, &query),
        Some(token.as_str())
    );
    assert!(!should_forward_request_header("X-CHIO-CAPABILITY"));
}

#[tokio::test]
async fn evaluation_error_response_surfaces_pending_approval_state() {
    let response = evaluation_error_response(&ProtectError::PendingApproval {
        approval_id: Some("ap-123".to_string()),
        kernel_receipt_id: "kr-456".to_string(),
    });
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_approval_required");
    assert_eq!(json["approval_id"], "ap-123");
    assert_eq!(json["kernel_receipt_id"], "kr-456");
    assert_eq!(json["resume_path"], "/approvals/ap-123/respond");
}

#[tokio::test]
async fn approval_routes_are_handled_before_proxy_catch_all() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let (approval, subject, approver) = pending_approval_request("ap-route-1");
    state
        .approval_admin
        .store()
        .store_pending(&approval)
        .test_unwrap();

    let token = signed_approval_response_token(
        &approval.approval_id,
        &subject,
        &approver,
        GovernedApprovalDecision::Approved,
    );
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri(format!("/approvals/{}/respond", approval.approval_id))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&RespondRequest {
                    outcome: ApprovalOutcome::Approved,
                    reason: Some("approved".to_string()),
                    approver: approver.public_key(),
                    token,
                })
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: RespondResponse = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json.approval_id, "ap-route-1");
    assert_eq!(json.outcome, ApprovalOutcome::Approved);
    assert!(state
        .approval_admin
        .store()
        .get_pending("ap-route-1")
        .test_unwrap()
        .is_none());
}

#[tokio::test]
async fn threshold_approval_routes_collect_and_deliver_original_tokens() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let policy_authority = Keypair::generate();
    let subject = Keypair::generate();
    let submitter = Keypair::generate();
    let second = Keypair::generate();
    let third = Keypair::generate();
    let policy_hash = "ab".repeat(32);
    let intent_hash = "cd".repeat(32);
    let requirement = ThresholdApprovalRequirement::new(
        2,
        BTreeMap::from([
            ("submitter".to_string(), submitter.public_key()),
            ("second".to_string(), second.public_key()),
            ("third".to_string(), third.public_key()),
        ]),
        300,
        policy_hash.clone(),
        1,
    )
    .test_unwrap();
    let now = chrono::Utc::now().timestamp() as u64;
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody::new(
            "proposal-product-route",
            "request-product-route",
            intent_hash.clone(),
            subject.public_key(),
            "ef".repeat(32),
            policy_hash.clone(),
            requirement.required(),
            requirement.eligible_set_digest(),
            now.saturating_sub(1),
            requirement.proposal_timeout_seconds(),
            now + 600,
            now + 600,
        )
        .test_unwrap(),
        &policy_authority,
    )
    .test_unwrap();
    let approval_store = Arc::clone(state.approval_admin.store());
    let matched_request =
        ThresholdApprovalRequest::new(proposal.body().request_id(), "payments", "transfer")
            .test_unwrap();
    let resolved_context = AuthenticatedThresholdApprovalRequestContext::new(
        matched_request.clone(),
        ThresholdApprovalProposalCreationContext::new(
            ThresholdApprovalProposalCreationParameters {
                matched_request,
                requirement: requirement.clone(),
                subject: subject.public_key(),
                governed_intent_hash: intent_hash.clone(),
                authorization_capability_hash: "ef".repeat(32),
                authorizing_capability_expires_at: now + 600,
                governed_operation_expires_at: now + 600,
                submitter: Some(submitter.public_key()),
                separation_of_duties: true,
            },
        )
        .test_unwrap(),
    );
    let resolved_request_id = proposal.body().request_id().to_string();
    let resolved_policy_hash = policy_hash.clone();
    let admin = ApprovalAdmin::new_with_threshold_policy(
        approval_store,
        policy_hash.clone(),
        vec![policy_authority.public_key()],
        Arc::new(move |request_id: &str, current_policy_hash: &str| {
            if request_id != resolved_request_id || current_policy_hash != resolved_policy_hash {
                return Err(
                    chio_core_types::capability::threshold_approval::ThresholdApprovalResolutionError::Missing,
                );
            }
            Ok(resolved_context.clone())
        }),
    )
    .test_unwrap();
    let mut state = Arc::try_unwrap(state).ok().test_unwrap();
    state.approval_admin = admin;
    let state = Arc::new(state);

    let create = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/threshold/proposals")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreateThresholdApprovalProposalRequest {
                    proposal: proposal.clone(),
                })
                .test_unwrap(),
            ))
            .test_unwrap(),
    );
    let response = build_app(Arc::clone(&state))
        .oneshot(create)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let sign_vote = |id: &str, approver: &Keypair| {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_string(),
                approver: approver.public_key(),
                subject: subject.public_key(),
                governed_intent_hash: intent_hash.clone(),
                threshold_proposal_hash: Some(proposal.proposal_hash().test_unwrap()),
                request_id: proposal.body().request_id().to_string(),
                issued_at: now,
                expires_at: now + 200,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .test_unwrap()
    };
    let first = sign_vote("threshold-product-1", &second);
    let second_token = sign_vote("threshold-product-2", &third);
    for token in [&first, &second_token] {
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/approvals/threshold/proposals/proposal-product-route/votes")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&AppendThresholdApprovalVoteRequest {
                        token: token.clone(),
                    })
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );
        let response = build_app(Arc::clone(&state))
            .oneshot(request)
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let deliver = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/threshold/proposals/proposal-product-route/deliver")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&DeliverThresholdApprovalResponseRequest {}).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let response = build_app(state).oneshot(deliver).await.test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["proposal"]["status"], "delivered");
    assert_eq!(
        json["approval_tokens"],
        serde_json::to_value(vec![first, second_token]).test_unwrap()
    );
}

#[tokio::test]
async fn threshold_approval_routes_are_unmounted_when_policy_authority_is_unconfigured() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let response = build_app(state)
        .oneshot(with_loopback_peer(
            Request::builder()
                .method("GET")
                .uri("/approvals/threshold/proposals/unknown")
                .body(Body::empty())
                .test_unwrap(),
        ))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "not_found");
}

#[tokio::test]
async fn threshold_approval_production_config_rejects_ephemeral_store() {
    let policy_authority = Keypair::generate();
    let config = ProtectConfig {
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some(PETSTORE_YAML.to_string()),
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: false,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        trusted_historical_receipt_signers: Vec::new(),
        control_url: None,
        control_token: None,
        budget_db: None,
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let threshold = ThresholdApprovalCollectorConfig::new(
        "ab".repeat(32),
        vec![policy_authority.public_key()],
        Arc::new(
            |_: &str,
             _: &str|
             -> Result<
                AuthenticatedThresholdApprovalRequestContext,
                chio_core_types::capability::threshold_approval::ThresholdApprovalResolutionError,
            > {
                Err(
                chio_core_types::capability::threshold_approval::ThresholdApprovalResolutionError::Missing,
            )
            },
        ),
    );
    let Err(error) = ProtectProxy::new(config)
        .with_threshold_approval_collector(threshold)
        .run_with_observer(|_| panic!("ephemeral collector must fail before binding"))
        .await
    else {
        panic!("ephemeral threshold collector must be rejected");
    };
    assert!(
        matches!(error, ProtectError::Config(message) if message.contains("durable approval store"))
    );
}

#[tokio::test]
async fn metrics_route_serves_rule_pack_families_when_authorized() {
    // Drive at least one guard family so the body is non-trivial.
    chio_metrics_spec::runtime::families::GUARD_VERDICT.incr(&["route-test-guard", "allow"]);
    chio_metrics_spec::runtime::preregister_known_label_sets();

    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = with_loopback_peer(
        Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .test_unwrap(),
    );
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let body = String::from_utf8(bytes.to_vec()).test_unwrap();
    assert!(
        body.contains("chio_guard_verdict_total"),
        "guard family missing: {body}"
    );
    assert!(
        body.contains("chio_fail_open_suspected_total"),
        "alert-pack family missing: {body}"
    );
    assert!(
        body.contains("chio_dispatch_failure_total"),
        "alert-pack family missing: {body}"
    );
}

#[tokio::test]
async fn metrics_route_is_gated() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    // No loopback peer and no bearer token: the sidecar-control gate must refuse.
    let request = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .test_unwrap();
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "unauthenticated scrape must be refused"
    );
}

#[tokio::test]
async fn submit_approval_creates_pending_record_signed_by_sidecar() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let subject = Keypair::generate();
    let payload = serde_json::json!({
        "capability_id": "cap-submit-1",
        "tool_server": "shell",
        "tool_name": "run_command",
        "parameter_hash": "a".repeat(64),
        "requested_by": subject.public_key().to_hex(),
        "summary": "rm -rf old_build/",
        "ttl_seconds": 300,
        "triggered_by": ["shell.requires_approval"],
    });
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/submit")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).test_unwrap()))
            .test_unwrap(),
    );

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    let approval_id = json["approval_id"].as_str().test_unwrap().to_string();
    assert!(approval_id.starts_with("ap-"));
    assert_eq!(
        json["trusted_approvers"][0],
        state.signer_keypair.public_key().to_hex()
    );

    let stored = state
        .approval_admin
        .store()
        .get_pending(&approval_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(stored.tool_server, "shell");
    assert_eq!(stored.tool_name, "run_command");
    assert_eq!(stored.subject_id, subject.public_key().to_hex());
    assert!(stored
        .trusted_approvers
        .contains(&state.signer_keypair.public_key()));
}

#[tokio::test]
async fn operator_respond_resolves_pending_via_sidecar_signature() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let subject = Keypair::generate();

    // Submit a pending approval first.
    let submit_payload = serde_json::json!({
        "capability_id": "cap-op-1",
        "tool_server": "shell",
        "tool_name": "run_command",
        "parameter_hash": "b".repeat(64),
        "requested_by": subject.public_key().to_hex(),
        "ttl_seconds": 300,
    });
    let submit_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/submit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&submit_payload).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let submit_response = build_app(Arc::clone(&state))
        .oneshot(submit_request)
        .await
        .test_unwrap();
    assert_eq!(submit_response.status(), StatusCode::CREATED);
    let submit_body = to_bytes(submit_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let submit_json: serde_json::Value = serde_json::from_slice(&submit_body).test_unwrap();
    let approval_id = submit_json["approval_id"]
        .as_str()
        .test_unwrap()
        .to_string();

    // Operator-respond approves with sidecar-signed token.
    let respond_payload = serde_json::json!({
        "outcome": "approved",
        "reason": "ok via slash command",
    });
    let respond_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri(format!("/approvals/{approval_id}/operator-respond"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&respond_payload).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let respond_response = build_app(Arc::clone(&state))
        .oneshot(respond_request)
        .await
        .test_unwrap();
    assert_eq!(respond_response.status(), StatusCode::OK);

    let respond_body = to_bytes(respond_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let resolved: RespondResponse = serde_json::from_slice(&respond_body).test_unwrap();
    assert_eq!(resolved.approval_id, approval_id);
    assert_eq!(resolved.outcome, ApprovalOutcome::Approved);

    // Pending must be cleared.
    assert!(state
        .approval_admin
        .store()
        .get_pending(&approval_id)
        .test_unwrap()
        .is_none());
}

#[tokio::test]
async fn submit_then_operator_respond_works_without_subject_pubkey() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    // requested_by left blank: the sidecar must fall back to its
    // own pubkey for both subject_id and subject_public_key so the
    // operator-respond shortcut can sign a binding token.
    let submit_payload = serde_json::json!({
        "capability_id": "cap-no-sub",
        "tool_server": "shell",
        "tool_name": "run_command",
        "parameter_hash": "c".repeat(64),
        "requested_by": "",
        "ttl_seconds": 300,
    });
    let submit_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/submit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&submit_payload).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let submit_response = build_app(Arc::clone(&state))
        .oneshot(submit_request)
        .await
        .test_unwrap();
    assert_eq!(submit_response.status(), StatusCode::CREATED);
    let submit_body = to_bytes(submit_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let submit_json: serde_json::Value = serde_json::from_slice(&submit_body).test_unwrap();
    let approval_id = submit_json["approval_id"]
        .as_str()
        .test_unwrap()
        .to_string();

    let stored = state
        .approval_admin
        .store()
        .get_pending(&approval_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        stored.subject_id,
        state.signer_keypair.public_key().to_hex()
    );

    let respond_payload = serde_json::json!({"outcome": "approved"});
    let respond_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri(format!("/approvals/{approval_id}/operator-respond"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&respond_payload).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let respond_response = build_app(Arc::clone(&state))
        .oneshot(respond_request)
        .await
        .test_unwrap();
    assert_eq!(respond_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn operator_respond_rejects_unknown_approval() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let payload = serde_json::json!({"outcome": "approved"});
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/ap-missing/operator-respond")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).test_unwrap()))
            .test_unwrap(),
    );
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approval_routes_reject_remote_callers_without_control_access() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let request = with_peer_addr(
        Request::builder()
            .method("GET")
            .uri("/approvals/pending")
            .body(Body::empty())
            .test_unwrap(),
        remote,
    );

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_control_forbidden");
}

#[test]
fn evaluator_and_approval_routes_share_the_same_store() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let evaluator_store = state.evaluator.approval_store();

    assert!(Arc::ptr_eq(&evaluator_store, state.approval_admin.store()));
}

// These proxy/sidecar handlers reach the kernel through Chio's sync
// tool-dispatch bridge, which requires a multi-thread runtime (the
// documented host requirement); a current-thread test runtime cannot
// drive the async tool server and the handler surfaces a 500 instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_denies_without_capability_and_records_receipt() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let receipt_id = response
        .headers()
        .get("x-chio-receipt-id")
        .and_then(|value| value.to_str().ok())
        .test_unwrap()
        .to_string();
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_access_denied");
    assert_eq!(
            json["suggestion"],
            "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter"
        );
    assert!(json["receipt_id"].as_str().is_some());

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt_id);
    assert_eq!(log.receipts[0].response_status, 403);
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
    assert!(log.receipts[0].verify_signature().test_unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_forwards_allowed_requests_and_end_to_end_headers() {
    let Some(server) = MockUpstreamServer::spawn(
        201,
        vec![("content-type", "application/json"), ("x-upstream", "ok")],
        r#"{"ok":true}"#,
    ) else {
        return;
    };
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        server.base_url(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets?source=test")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("user-agent", "chio-test")
        .header("authorization", "Bearer upstream-token")
        .header("x-request-id", "req-123")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&state.signer_keypair, "cap-proxy"),
        )
        .header("x-custom-app", "secret")
        .header("connection", "keep-alive")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    let receipt_id = response
        .headers()
        .get("x-chio-receipt-id")
        .and_then(|value| value.to_str().ok())
        .test_unwrap()
        .to_string();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("x-upstream")
            .and_then(|value| value.to_str().ok()),
        Some("ok")
    );

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    assert_eq!(body.as_ref(), br#"{"ok":true}"#);

    let requests = server.requests();
    server.join();

    assert_eq!(requests.len(), 1);
    let request_text = requests[0].to_ascii_lowercase();
    assert!(request_text.contains("post /pets?source=test http/1.1"));
    assert!(request_text.contains("content-type: application/json"));
    assert!(request_text.contains("accept: application/json"));
    assert!(request_text.contains("user-agent: chio-test"));
    assert!(request_text.contains("authorization: bearer upstream-token"));
    assert!(request_text.contains("x-request-id: req-123"));
    assert!(request_text.contains("x-custom-app: secret"));
    assert!(!request_text.contains("x-chio-capability:"));
    assert!(!request_text.contains("connection: keep-alive"));
    assert!(request_text.contains(r#"{"name":"fido"}"#));

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt_id);
    assert_eq!(log.receipts[0].response_status, 201);
    assert_eq!(log.receipts[0].capability_id.as_deref(), Some("cap-proxy"));
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_strips_query_capability_before_forwarding_upstream() {
    let Some(server) =
        MockUpstreamServer::spawn(200, vec![("content-type", "application/json")], "{}")
    else {
        return;
    };
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        server.base_url(),
    );
    let token = signed_capability_token_json(&state.signer_keypair, "cap-query");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("source", "test")
        .append_pair("chio_capability", &token)
        .append_pair("mode", "full")
        .finish();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/pets?{query}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let requests = server.requests();
    server.join();

    assert_eq!(requests.len(), 1);
    let request_text = requests[0].to_ascii_lowercase();
    assert!(request_text.contains("post /pets?source=test&mode=full http/1.1"));
    assert!(!request_text.contains("chio_capability"));

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].capability_id.as_deref(), Some("cap-query"));
}

#[tokio::test]
async fn proxy_handler_rejects_unsupported_methods_before_evaluation() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = Request::builder()
        .method("TRACE")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    assert_eq!(body.as_ref(), b"unsupported method");
    let log = state.receipt_log.lock().await;
    assert!(log.receipts.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_surfaces_upstream_failures_after_allowing_request() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let request = Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let text = String::from_utf8(body.to_vec()).test_unwrap();
    assert_eq!(text, "upstream request failed");

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].response_status, 502);
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_records_receipt_when_upstream_times_out() {
    // An allowed request whose upstream accepts the connection but never responds
    // must still finalize a receipt. The per-hop client timeout fires inside the
    // handler, so the stall is recorded as a bad-gateway receipt rather than
    // leaving the handler parked for an outer timeout to drop mid-flight.
    let Some(server) = MockUpstreamServer::spawn_unresponsive() else {
        return;
    };
    let state = test_state_with_client_timeout(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        server.base_url(),
        std::time::Duration::from_millis(150),
    );
    let request = Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap();

    // The handler must return on its own once the upstream call times out; the
    // outer guard only trips (failing the test) if it never does.
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        proxy_handler(State(Arc::clone(&state)), request),
    )
    .await
    .test_unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let receipt_id = response
        .headers()
        .get("x-chio-receipt-id")
        .and_then(|value| value.to_str().ok())
        .test_unwrap()
        .to_string();

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt_id);
    assert_eq!(log.receipts[0].response_status, 502);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_denies_invalid_capability_tokens() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("x-chio-capability", "not-json")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_access_denied");

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert!(log.receipts[0].capability_id.is_none());
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_auth_failures_never_query_caller_controlled_revocation_ids() {
    let observed = Arc::new(ObservedRevocationStore::with_revoked(["cap-proxy-revoked"]));
    let revocation_store: Arc<dyn chio_kernel::RevocationStore> = observed.clone();
    let state = make_test_state_with_revocation_store(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        None,
        false,
        Some(revocation_store),
    );

    let malformed = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("x-chio-capability", "not-json")
        .body(Body::empty())
        .test_unwrap();
    assert_eq!(
        proxy_handler(State(Arc::clone(&state)), malformed)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    // The kernel may query its own freshly minted receipt-denial capability,
    // but malformed caller bytes never become a revocation lookup key.
    assert!(!observed.queried_ids().iter().any(|id| id == "not-json"));
    observed.clear_queries();

    let untrusted_id = "cap-proxy-untrusted";
    let untrusted = Request::builder()
        .method("POST")
        .uri("/pets")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&Keypair::generate(), untrusted_id),
        )
        .body(Body::empty())
        .test_unwrap();
    assert_eq!(
        proxy_handler(State(Arc::clone(&state)), untrusted)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(!observed.queried_ids().iter().any(|id| id == untrusted_id));
    observed.clear_queries();

    let revoked = Request::builder()
        .method("POST")
        .uri("/pets")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&state.signer_keypair, "cap-proxy-revoked"),
        )
        .body(Body::empty())
        .test_unwrap();
    assert_eq!(
        proxy_handler(State(Arc::clone(&state)), revoked)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        observed
            .queried_ids()
            .iter()
            .filter(|id| id.as_str() == "cap-proxy-revoked")
            .count(),
        1,
        "a trusted authenticated leaf is queried exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_denies_get_on_reserved_tools_path_without_capability() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = Request::builder()
        .method("GET")
        .uri("/chio/tools/billing/read")
        .body(Body::empty())
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_access_denied");

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert!(log.receipts[0].capability_id.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_evaluate_returns_200_with_deny_verdict() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let body = ChioHttpRequest::new(
        "req-sidecar-deny".to_string(),
        HttpMethod::Post,
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

    let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let evaluation: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(evaluation.receipt.verify_signature().test_unwrap());
    assert!(evaluation.verdict.is_denied());
    assert!(evaluation.receipt.is_denied());
    assert_eq!(
        http_status_scope(evaluation.receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_evaluate_validates_transport_capability_header() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let token = signed_capability_token_json(&state.signer_keypair, "cap-sidecar");
    let mut body = ChioHttpRequest::new(
        "req-sidecar-allow".to_string(),
        HttpMethod::Post,
        "/pets".to_string(),
        "/pets".to_string(),
        chio_http_core::CallerIdentity::anonymous(),
    );
    body.capability_id = Some("cap-sidecar".to_string());
    let request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .header("x-chio-capability", token)
        .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
        .test_unwrap();

    let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let evaluation: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(evaluation.verdict.is_allowed());
    assert_eq!(
        evaluation.receipt.capability_id.as_deref(),
        Some("cap-sidecar")
    );
    assert_eq!(
        http_status_scope(evaluation.receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_http_evaluate_auth_failures_never_query_caller_controlled_revocation_ids() {
    let observed = Arc::new(ObservedRevocationStore::with_revoked(["cap-evaluate-revoked"]));
    let revocation_store: Arc<dyn chio_kernel::RevocationStore> = observed.clone();
    let state = make_test_state_with_revocation_store(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        None,
        false,
        Some(revocation_store),
    );

    let evaluate_body = || {
        ChioHttpRequest::new(
            uuid::Uuid::now_v7().to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            chio_http_core::CallerIdentity::anonymous(),
        )
    };

    let malformed = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .header("x-chio-capability", "not-json")
        .body(Body::from(
            serde_json::to_vec(&evaluate_body()).test_unwrap(),
        ))
        .test_unwrap();
    let response = sidecar_evaluate_handler(State(Arc::clone(&state)), malformed).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!observed.queried_ids().iter().any(|id| id == "not-json"));
    observed.clear_queries();

    let untrusted_id = "cap-evaluate-untrusted";
    let untrusted = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&Keypair::generate(), untrusted_id),
        )
        .body(Body::from(
            serde_json::to_vec(&evaluate_body()).test_unwrap(),
        ))
        .test_unwrap();
    let response = sidecar_evaluate_handler(State(Arc::clone(&state)), untrusted).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!observed.queried_ids().iter().any(|id| id == untrusted_id));
    observed.clear_queries();

    let mut revoked_body = evaluate_body();
    revoked_body.capability_id = Some("cap-evaluate-revoked".to_string());
    let revoked = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&state.signer_keypair, "cap-evaluate-revoked"),
        )
        .body(Body::from(
            serde_json::to_vec(&revoked_body).test_unwrap(),
        ))
        .test_unwrap();
    let response = sidecar_evaluate_handler(State(Arc::clone(&state)), revoked).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        observed
            .queried_ids()
            .iter()
            .filter(|id| id.as_str() == "cap-evaluate-revoked")
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_backend_failure_is_normalized_in_http_evaluation_receipt() {
    let observed = Arc::new(ObservedRevocationStore::failing("cap-query-failure"));
    let revocation_store: Arc<dyn chio_kernel::RevocationStore> = observed;
    let state = make_test_state_with_revocation_store(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        None,
        false,
        Some(revocation_store),
    );
    let mut body = ChioHttpRequest::new(
        "req-revocation-unavailable".to_string(),
        HttpMethod::Post,
        "/pets".to_string(),
        "/pets".to_string(),
        chio_http_core::CallerIdentity::anonymous(),
    );
    body.capability_id = Some("cap-query-failure".to_string());
    let request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&state.signer_keypair, "cap-query-failure"),
        )
        .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
        .test_unwrap();

    let response = sidecar_evaluate_handler(State(state), request).await;
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let body = String::from_utf8(bytes.to_vec()).test_unwrap();
    assert!(body.contains("capability revocation status unavailable"));
    assert!(!body.contains("/var/lib/chio"));
    assert!(!body.contains("sensitive revocation backend"));
}

#[tokio::test]
async fn sidecar_verify_reports_signature_validity() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let receipt = HttpReceipt::sign(
        chio_http_core::HttpReceiptBody {
            id: "receipt-verify".to_string(),
            request_id: "req-verify".to_string(),
            route_pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            caller_identity_hash: "caller-hash".to_string(),
            session_id: None,
            verdict: chio_http_core::Verdict::Allow,
            receipt_kind: chio_core_types::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core_types::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core_types::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core_types::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: Vec::new(),
            response_status: 200,
            timestamp: 1_700_000_000,
            content_hash: chio_core_types::sha256_hex(b"test-content"),
            policy_hash: "policy".to_string(),
            trust_level: chio_core_types::receipt::kinds::TrustLevel::Mediated,
            capability_id: None,
            metadata: None,
            kernel_key: state.signer_keypair.public_key(),
        },
        &state.signer_keypair,
    )
    .test_unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/chio/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&receipt).test_unwrap()))
        .test_unwrap();

    let response = sidecar_verify_handler(State(state), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let verification: VerifyReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(verification.signature_valid);
    assert!(verification.signer_trusted);
    assert!(verification.authorized);
    assert!(verification.ok);
}

#[tokio::test]
async fn sidecar_verify_does_not_authorize_self_signed_receipts() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let keypair = Keypair::generate();
    let receipt = HttpReceipt::sign(
        chio_http_core::HttpReceiptBody {
            id: "receipt-self-signed".to_string(),
            request_id: "req-self-signed".to_string(),
            route_pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            caller_identity_hash: "caller-hash".to_string(),
            session_id: None,
            verdict: chio_http_core::Verdict::Allow,
            receipt_kind: chio_core_types::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core_types::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core_types::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core_types::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: Vec::new(),
            response_status: 200,
            timestamp: 1_700_000_000,
            content_hash: chio_core_types::sha256_hex(b"test-content"),
            policy_hash: "policy".to_string(),
            trust_level: chio_core_types::receipt::kinds::TrustLevel::Mediated,
            capability_id: None,
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .test_unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/chio/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&receipt).test_unwrap()))
        .test_unwrap();

    let response = sidecar_verify_handler(State(state), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let verification: VerifyReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(verification.signature_valid);
    assert!(!verification.signer_trusted);
    assert!(!verification.authorized);
    assert!(!verification.ok);
}

#[tokio::test]
async fn sidecar_mint_returns_canonical_capability_tokens() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search", "tool:server-a:fetch:invoke"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let response = sidecar_mint_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let mint: SidecarMintResponse = serde_json::from_slice(&bytes).test_unwrap();

    assert_eq!(mint.capability.issuer, state.signer_keypair.public_key());
    assert_eq!(mint.capability.scope.grants.len(), 2);
    assert_eq!(mint.capability.scope.grants[0].server_id, "*");
    assert_eq!(mint.capability.scope.grants[0].tool_name, "search");
    assert!(mint.capability.verify_signature().test_unwrap());
}

#[tokio::test]
async fn sidecar_mint_reuses_capability_id_for_retry_requests() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request_body = serde_json::to_vec(&serde_json::json!({
        "subject": "job/default/demo",
        "scopes": ["tools:search", "tool:server-a:fetch:invoke"],
        "job_uid": "job-uid-1",
        "ttl_seconds": 300,
    }))
    .test_unwrap();

    let first_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(request_body.clone()))
            .test_unwrap(),
    );
    let second_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(request_body))
            .test_unwrap(),
    );

    let first_response = sidecar_mint_handler(State(Arc::clone(&state)), first_request).await;
    let second_response = sidecar_mint_handler(State(Arc::clone(&state)), second_request).await;
    assert_eq!(first_response.status(), StatusCode::OK);
    assert_eq!(second_response.status(), StatusCode::OK);

    let first_bytes = to_bytes(first_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let second_bytes = to_bytes(second_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let first_mint: SidecarMintResponse = serde_json::from_slice(&first_bytes).test_unwrap();
    let second_mint: SidecarMintResponse = serde_json::from_slice(&second_bytes).test_unwrap();

    assert_eq!(
        first_mint.capability.body().id,
        second_mint.capability.body().id
    );
}

#[tokio::test]
async fn sidecar_mint_changes_capability_id_for_different_scope_requests() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    let search_request = with_loopback_peer(
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
    let fetch_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tool:server-a:fetch:invoke"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let search_response = sidecar_mint_handler(State(Arc::clone(&state)), search_request).await;
    let fetch_response = sidecar_mint_handler(State(Arc::clone(&state)), fetch_request).await;
    assert_eq!(search_response.status(), StatusCode::OK);
    assert_eq!(fetch_response.status(), StatusCode::OK);

    let search_bytes = to_bytes(search_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let fetch_bytes = to_bytes(fetch_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let search_mint: SidecarMintResponse = serde_json::from_slice(&search_bytes).test_unwrap();
    let fetch_mint: SidecarMintResponse = serde_json::from_slice(&fetch_bytes).test_unwrap();

    assert_ne!(
        search_mint.capability.body().id,
        fetch_mint.capability.body().id
    );
}

#[tokio::test]
async fn sidecar_submit_receipt_accepts_controller_job_receipts() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
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

    let response = sidecar_submit_receipt_handler(State(state), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let receipt: SidecarSubmitReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(receipt.accepted);
    assert!(!receipt.receipt_id.is_empty());
}
