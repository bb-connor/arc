use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const CLAIMED_SAFE_POST: &str = r#"openapi: 3.1.0
info: {title: Untrusted, version: '1'}
paths:
  /safe-post:
    post:
      x-chio-side-effects: false
      responses: {'200': {description: ok}}
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_authority_defaults_refuse_without_upstream_effects() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let upstream = Router::new().fallback(any(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        async { StatusCode::OK }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .test_unwrap();
    let url = format!("http://{}", listener.local_addr().test_unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await });
    for (method, path, spec) in [
        ("GET", "/unknown", PETSTORE_YAML),
        ("POST", "/unknown", PETSTORE_YAML),
        ("GET", "/pets", PETSTORE_YAML),
        ("POST", "/safe-post", CLAIMED_SAFE_POST),
    ] {
        let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
        let mut state = test_state(routes, url.clone());
        // The shared legacy fixture explicitly enables reads for forwarding tests.
        // Restore the production default for this boundary control.
        let inner = Arc::get_mut(&mut state).test_unwrap();
        inner.evaluator = RequestEvaluator::new_ephemeral(
            ProtectProxy::routes_from_spec(spec).test_unwrap(),
            inner.signer_keypair.clone(),
            "test-policy".into(),
        );
        let response = build_app(state)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .test_unwrap(),
            )
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "denial forwarded {method} {path}"
        );
    }
    server.abort();
}

#[test]
fn inbound_authority_unknown_routes_refuse_even_a_valid_capability() {
    let issuer = Keypair::generate();
    let capability = signed_capability_token_json(&issuer, "unknown-route");
    let evaluator = RequestEvaluator::new_ephemeral_with_trusted_capability_issuers(
        vec![],
        Keypair::generate(),
        "route-policy".into(),
        vec![issuer.public_key()],
    );
    for method in [
        HttpMethod::Get,
        HttpMethod::Post,
        HttpMethod::Head,
        HttpMethod::Options,
    ] {
        for path in [
            "/unknown",
            "/chio/tools/chio_http_authority/authorize_http_request",
        ] {
            let result = evaluator
                .evaluate(
                    method,
                    path,
                    &HashMap::new(),
                    &HashMap::from([("x-chio-capability".into(), capability.clone())]),
                    None,
                    0,
                )
                .test_unwrap();
            assert!(
                matches!(result.verdict, Verdict::Deny { .. }),
                "{method:?} {path}"
            );
            assert!(result.receipt.verify_signature().test_unwrap());
        }
    }
}

#[test]
fn inbound_authority_local_anonymous_opt_in_never_opens_unknown_routes() {
    let evaluator = RequestEvaluator::new_ephemeral(
        ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap(),
        Keypair::generate(),
        "local-policy".into(),
    )
    .with_anonymous_reads(true);
    let known = evaluator
        .evaluate(
            HttpMethod::Get,
            "/pets",
            &HashMap::new(),
            &HashMap::new(),
            None,
            0,
        )
        .test_unwrap();
    assert_eq!(known.verdict, Verdict::Allow);
    let unknown = evaluator
        .evaluate(
            HttpMethod::Get,
            "/unknown",
            &HashMap::new(),
            &HashMap::new(),
            None,
            0,
        )
        .test_unwrap();
    assert!(matches!(unknown.verdict, Verdict::Deny { .. }));
    let mut forged = ChioHttpRequest::new(
        "forged-route".into(),
        HttpMethod::Get,
        "/pets".into(),
        "/unknown".into(),
        CallerIdentity::anonymous(),
    );
    forged.route_pattern = "/pets".into();
    let denied = evaluator.evaluate_chio_request(forged, None).test_unwrap();
    assert!(matches!(denied.verdict, Verdict::Deny { .. }));
}

fn spec_config() -> ProtectConfig {
    ProtectConfig {
        upstream: "http://127.0.0.1:9".into(),
        spec_content: None,
        spec_path: None,
        spec_sha256: None,
        allow_anonymous_reads: true,
        listen_addr: "127.0.0.1:0".into(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: vec![],
        approval: None,
        control_url: None,
        control_token: None,
        budget_db: None,
        revocation_db: None,
        require_nonce: true,
        allow_advisory: false,
        upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_authority_only_exact_local_pin_relaxes_side_effects() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("openapi.yaml");
    std::fs::write(&path, CLAIMED_SAFE_POST).test_unwrap();
    let mut config = spec_config();
    config.spec_path = Some(path.to_string_lossy().into_owned());
    let unpinned = spec_authority::load(&config).await.test_unwrap();
    assert!(!unpinned.is_pinned());
    assert_eq!(
        ProtectProxy::build_routes(unpinned.content(), unpinned.is_pinned()).test_unwrap()[0]
            .policy,
        PolicyDecision::DenyByDefault
    );
    config.spec_sha256 = Some(chio_core_types::sha256_hex(CLAIMED_SAFE_POST.as_bytes()));
    let pinned = spec_authority::load(&config).await.test_unwrap();
    assert!(pinned.is_pinned());
    assert_ne!(
        pinned.policy_hash(true).test_unwrap(),
        pinned.policy_hash(false).test_unwrap()
    );
    assert_ne!(
        pinned.policy_hash(true).test_unwrap(),
        unpinned.policy_hash(true).test_unwrap()
    );
    let routes = ProtectProxy::build_routes(pinned.content(), pinned.is_pinned()).test_unwrap();
    let evaluator = RequestEvaluator::new_ephemeral(routes, Keypair::generate(), "pinned".into())
        .with_anonymous_reads(true);
    assert_eq!(
        evaluator
            .evaluate(
                HttpMethod::Post,
                "/safe-post",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0
            )
            .test_unwrap()
            .verdict,
        Verdict::Allow
    );
    std::fs::write(&path, format!("{CLAIMED_SAFE_POST}\n")).test_unwrap();
    assert!(
        matches!(spec_authority::load(&config).await, Err(ProtectError::Config(message)) if message == "local spec SHA-256 does not match the operator pin")
    );
    // The already loaded snapshot retains its original verified bytes.
    assert_eq!(pinned.content(), CLAIMED_SAFE_POST);
    config.spec_content = Some(CLAIMED_SAFE_POST.into());
    assert!(
        matches!(spec_authority::load(&config).await, Err(ProtectError::Config(message)) if message == "spec content and path are mutually exclusive")
    );
    config.spec_path = None;
    assert!(
        matches!(spec_authority::load(&config).await, Err(ProtectError::Config(message)) if message == "spec SHA-256 requires a local spec path")
    );
}

#[test]
fn inbound_authority_specific_route_denial_cannot_be_shadowed_by_read_template() {
    let evaluator = RequestEvaluator::new_ephemeral(
        vec![
            RouteEntry {
                pattern: "/pets/{id}".into(),
                method: HttpMethod::Get,
                operation_id: None,
                policy: PolicyDecision::SessionAllow,
            },
            RouteEntry {
                pattern: "/pets/export".into(),
                method: HttpMethod::Get,
                operation_id: None,
                policy: PolicyDecision::DenyByDefault,
            },
        ],
        Keypair::generate(),
        "explicit".into(),
    )
    .with_anonymous_reads(true);
    let result = evaluator
        .evaluate(
            HttpMethod::Get,
            "/pets/export",
            &HashMap::new(),
            &HashMap::new(),
            None,
            0,
        )
        .test_unwrap();
    assert!(matches!(result.verdict, Verdict::Deny { .. }));
}

#[tokio::test]
async fn inbound_authority_threshold_readers_retain_original_rejection() {
    for (path, body) in [
        (
            "/approvals/threshold/proposals",
            r#"{"proposal":{"private_marker":1,"private_marker":2}}"#,
        ),
        (
            "/approvals/threshold/proposals/missing/respond",
            r#"{"token":{"private_marker":1,"private_marker":2}}"#,
        ),
        (
            "/approvals/threshold/proposals",
            r#"{"proposal":{"private_marker":0.123456789012345678901}}"#,
        ),
        (
            "/approvals/threshold/proposals/missing/respond",
            r#"{"token":{"private_marker":0.123456789012345678901}}"#,
        ),
    ] {
        let state = test_state(vec![], "http://127.0.0.1:1".into());
        let response = build_app(state.clone())
            .oneshot(with_authenticated_control_peer(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .test_unwrap(),
            ))
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response
                .extensions()
                .get::<Arc<chio_core_types::canonical::UntrustedJsonError>>()
                .is_some(),
            "original cause missing at {path}"
        );
        let bytes = to_bytes(response.into_body(), 4096).await.test_unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("private_marker"));
        assert!(state.receipt_log.lock().await.receipts.is_empty());
    }
}

#[tokio::test]
async fn inbound_authority_threshold_routes_admit_signed_proposal_and_approvals() {
    use chio_core_types::capability::{
        governance::{
            GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
            ThresholdApprovalProposal, ThresholdApprovalProposalBody,
            THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
        },
        threshold_approval::{ThresholdApprovalRequirement, ThresholdApproverIdentity},
    };
    use chio_core_types::sha256_hex;
    use chio_kernel::{InMemoryThresholdApprovalCollectorStore, ThresholdApprovalCollector};
    let mut state = test_state(vec![], "http://127.0.0.1:1".into());
    let now = state.clock.seconds().test_unwrap();
    let legacy_store = Arc::new(InMemoryApprovalStore::new());
    let authority = Keypair::generate();
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let subject = Keypair::generate();
    let policy_hash = sha256_hex(b"http-threshold-policy");
    let requirement = ThresholdApprovalRequirement::new(
        policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "alice".to_string(),
                public_key: alice.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "bob".to_string(),
                public_key: bob.public_key(),
            },
        ],
        "directory-v1".to_string(),
        100,
    )
    .test_unwrap();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "http-proposal".to_string(),
            request_id: "http-request".to_string(),
            governed_intent_hash: sha256_hex(b"http-intent"),
            subject: subject.public_key(),
            authorizing_capability_digest: sha256_hex(b"http-capability"),
            policy_hash: policy_hash.clone(),
            threshold: 2,
            eligible_set_digest: requirement.eligible_set_digest.clone(),
            proposal_created_at: now,
            proposal_deadline: now + 100,
            policy_authority: authority.public_key(),
        },
        &authority,
    )
    .test_unwrap();
    let context = chio_kernel::approval::ThresholdApprovalProposalCreationContext::new(
        chio_kernel::approval::ThresholdApprovalProposalCreationParameters {
            matched_request:
                chio_core_types::capability::threshold_approval::ThresholdApprovalRequest::new(
                    "http-request",
                    "server",
                    "tool",
                )
                .test_unwrap(),
            requirement,
            subject: subject.public_key(),
            governed_intent_hash: sha256_hex(b"http-intent"),
            authorization_capability_hash: sha256_hex(b"http-capability"),
            authorizing_capability_expires_at: now + 100,
            governed_operation_expires_at: now + 100,
            submitter: None,
            separation_of_duties: false,
        },
    )
    .test_unwrap();
    let resolver_context = context.clone();
    let collector = ThresholdApprovalCollector::new(
        Arc::new(InMemoryThresholdApprovalCollectorStore::new()),
        policy_hash,
        vec![authority.public_key()],
        Arc::new(move |_: &str, _: u64| Ok(resolver_context.clone())),
    );
    let admin = ApprovalAdmin::with_threshold_collector(legacy_store, collector);
    Arc::get_mut(&mut state).test_unwrap().approval_admin = admin;
    let app = build_app(state);
    let make_token = |approver: &Keypair, id: &str| {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_string(),
                approver: approver.public_key(),
                subject: proposal.body.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                request_id: proposal.body.request_id.clone(),
                threshold_proposal_hash: Some(proposal.artifact_digest().test_unwrap()),
                issued_at: now,
                expires_at: now + 99,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .test_unwrap()
    };
    let valid = serde_json::to_string(&serde_json::json!({"proposal":proposal})).test_unwrap();
    for (body, status) in [
        (
            valid.replace("\"proposal\":", "\"proposal\":null,\"proposal\":"),
            StatusCode::BAD_REQUEST,
        ),
        (valid, StatusCode::CREATED),
    ] {
        let response = app
            .clone()
            .oneshot(with_authenticated_control_peer(
                Request::builder()
                    .method("POST")
                    .uri("/approvals/threshold/proposals")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .test_unwrap(),
            ))
            .await
            .test_unwrap();
        assert_eq!(response.status(), status);
    }
    for (approver, id) in [(&alice, "alice-token"), (&bob, "bob-token")] {
        let token = make_token(approver, id);
        let body = serde_json::to_string(&serde_json::json!({"token":token})).test_unwrap();
        let malformed = format!("{{\"ignored\":1,\"ignored\":2,{}", &body[1..]);
        for (body, status) in [(malformed, StatusCode::BAD_REQUEST), (body, StatusCode::OK)] {
            let response = app
                .clone()
                .oneshot(with_authenticated_control_peer(
                    Request::builder()
                        .method("POST")
                        .uri("/approvals/threshold/proposals/http-proposal/respond")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .test_unwrap(),
                ))
                .await
                .test_unwrap();
            assert_eq!(response.status(), status);
        }
    }
    let response = app
        .oneshot(with_authenticated_control_peer(
            Request::builder()
                .method("POST")
                .uri("/approvals/threshold/proposals/http-proposal/deliver")
                .body(Body::empty())
                .test_unwrap(),
        ))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_authority_dot_segments_never_reach_unregistered_upstream_route() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let upstream = Router::new().fallback(any(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        async { StatusCode::OK }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .test_unwrap();
    let url = format!("http://{}", listener.local_addr().test_unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await });
    let spec="openapi: 3.1.0\ninfo: {title: Path, version: '1'}\npaths:\n  /safe/{id}/{tail}:\n    get:\n      responses: {'200': {description: ok}}\n";
    let state = test_state(ProtectProxy::routes_from_spec(spec).test_unwrap(), url);
    for path in ["/safe/%2e%2e/admin", "/safe/../admin", "/safe/%2E./admin"] {
        let response = build_app(state.clone())
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .test_unwrap(),
            )
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    server.abort();
}
