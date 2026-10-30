//! Admin backend, session delivery and token introspection failures answer
//! fixed URN bodies. Each cause can name a store path, a peer URL or a backend
//! response body, so it stays in the server log.

use super::*;
use axum::body::Body;
use tower::ServiceExt;

const ADMIN_BACKEND_FAILED: &str = "urn:chio:error:transport:admin-backend-failed";
const SESSION_SEND_FAILED: &str = "urn:chio:error:transport:session-send-failed";
const INTROSPECTION_UNAVAILABLE: &str = "urn:chio:error:transport:token-introspection-unavailable";
const BACKEND_DETAIL: &str = "private-backend-detail /srv/chio/authority.sqlite3";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn the_fixed_body_urns_are_registered_for_this_crate() {
    for (urn, string_code) in [
        (ADMIN_BACKEND_FAILED, "CHIO-TRANSPORT-ADMIN-BACKEND-FAILED"),
        (SESSION_SEND_FAILED, "CHIO-TRANSPORT-SESSION-SEND-FAILED"),
        (
            "urn:chio:error:transport:approval-storage-failed",
            "CHIO-TRANSPORT-APPROVAL-STORAGE-FAILED",
        ),
        (
            "urn:chio:error:transport:approval-intent-unbound",
            "CHIO-TRANSPORT-APPROVAL-INTENT-UNBOUND",
        ),
        (
            INTROSPECTION_UNAVAILABLE,
            "CHIO-TRANSPORT-TOKEN-INTROSPECTION-UNAVAILABLE",
        ),
    ] {
        let spec = chio_errors::lookup_error_code(urn).unwrap();
        assert_eq!(spec.domain, chio_errors::Domain::Transport);
        assert_eq!(spec.severity, chio_errors::Severity::Error);
        assert_eq!(spec.string_code, string_code);
        assert!(spec.consumed_by.contains(&"chio-mcp-remote"));
    }
}

fn admin_state(
    directory: &FsPath,
    configure: impl FnOnce(&mut RemoteServeHttpConfig),
) -> TestResult<RemoteAppState> {
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(&config.policy_path, "kernel:\n  allow_ephemeral_receipt_log: true\n  allow_ephemeral_revocation_store: true\n  durable_admission_mode: off\n  allow_unsafe_durable_admission_off: true\n")?;
    config.wrapped_args.clear();
    config.test_transport = Some(Arc::new(TestSessionTransport));
    configure_signed_manifest(&mut config, directory);
    let mut factory = RemoteSessionFactory::new(config.clone())?;
    configure(&mut factory.config);
    let sessions = Arc::new(RemoteSessionLedger::new(
        config.clock.clone(),
        config.lifecycle_policy()?,
        None,
        None,
    )?);
    Ok(RemoteAppState {
        sessions,
        factory: Arc::new(factory),
        auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
            token: "remote-auth-token".into(),
        }),
        enterprise_provider_registry: None,
        admin_token: Some("admin-token".into()),
        protected_resource_metadata: None,
        authorization_server_metadata: None,
        local_auth_server: None,
    })
}

async fn insert_terminal_session(state: &RemoteAppState) -> TestResult {
    let now = state.factory.config.clock.millis()?;
    state.sessions.terminal.lock().await.insert(
        "terminal".into(),
        Arc::new(RemoteSessionDiagnosticRecord {
            session_id: "terminal".into(),
            auth_context: SessionAuthContext::streamable_http_static_bearer("test", "test", None),
            capabilities: vec![RemoteSessionCapability {
                id: "cap-1".into(),
                issuer_public_key: "issuer".into(),
                subject_public_key: "subject".into(),
            }],
            lifecycle: RemoteSessionLifecycleSnapshot {
                deadline: None,
                state: RemoteSessionState::Closed,
                created_at: now,
                last_seen_at: now,
                idle_expires_at: now,
                drain_deadline_at: None,
            },
            protocol_version: None,
            ownership: Default::default(),
            terminal_at: now,
            terminal_reason: None,
        }),
    );
    Ok(())
}

async fn admin(
    state: &RemoteAppState,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> TestResult<(StatusCode, String)> {
    let router = remote_mcp_admin::install_admin_routes(Router::new()).with_state(state.clone());
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(AUTHORIZATION, "Bearer admin-token");
    let request = match body {
        Some(body) => request
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body)?))?,
        None => request.body(Body::empty())?,
    };
    let response = router.oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok((status, String::from_utf8(bytes.to_vec())?))
}

fn assert_admin_backend_failed(route: &str, status: StatusCode, body: &str, detail: &str) {
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{route}: {body}");
    assert_eq!(body, ADMIN_BACKEND_FAILED, "{route}");
    assert!(!body.contains(detail), "{route}");
}

async fn failing_backend() -> TestResult<(String, tokio::task::JoinHandle<std::io::Result<()>>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .fallback(|| async { (StatusCode::INTERNAL_SERVER_ERROR, BACKEND_DETAIL).into_response() });
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    Ok((endpoint, server))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_control_backend_failure_answers_the_fixed_urn_without_the_backend_body() -> TestResult
{
    let (endpoint, server) = failing_backend().await?;
    let directory = chio_test_support::private_tempdir()?;
    let state = admin_state(directory.path(), |config| {
        config.control_url = Some(endpoint.clone());
        config.control_token = Some("separate-control-token".into());
    })?;
    insert_terminal_session(&state).await?;
    let client =
        trust_control::service_runtime::client::build_client(&endpoint, "separate-control-token")?;
    let cause = tokio::task::spawn_blocking(move || {
        client
            .list_budgets(&trust_control::BudgetQuery {
                capability_id: None,
                limit: Some(1),
            })
            .err()
            .map(|error| error.to_string())
    })
    .await?
    .ok_or("the failing backend answered a budget list")?;
    assert!(cause.contains(BACKEND_DETAIL), "{cause}");

    let trust_path = ADMIN_SESSION_TRUST_PATH.replace("{session_id}", "terminal");
    for (method, path, body) in [
        ("GET", ADMIN_HEALTH_PATH, None),
        ("GET", ADMIN_AUTHORITY_PATH, None),
        ("POST", ADMIN_AUTHORITY_PATH, None),
        ("GET", ADMIN_TOOL_RECEIPTS_PATH, None),
        ("GET", ADMIN_CHILD_RECEIPTS_PATH, None),
        ("GET", ADMIN_BUDGETS_PATH, None),
        ("GET", ADMIN_REVOCATIONS_PATH, None),
        (
            "POST",
            ADMIN_REVOCATIONS_PATH,
            Some(json!({
                "target": {"kind": "capability_id", "capability_id": "cap-1"},
                "reason": "operator_request"
            })),
        ),
        ("GET", trust_path.as_str(), None),
    ] {
        let (status, response) = admin(&state, method, path, body).await?;
        assert_admin_backend_failed(
            &format!("{method} {path}"),
            status,
            &response,
            "private-backend-detail",
        );
    }
    server.abort();
    Ok(())
}

#[tokio::test]
async fn a_local_authority_store_failure_answers_the_fixed_urn_without_its_cause() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let store = directory.path().join("authority.sqlite3");
    std::fs::create_dir(&store)?;
    let path_text = directory.path().to_string_lossy().into_owned();
    let cause = match chio_store_sqlite::SqliteCapabilityAuthority::open(&store) {
        Ok(_) => return Err("a directory opened as an authority store".into()),
        Err(error) => error.to_string(),
    };
    assert!(cause.contains("authority file custody"), "{cause}");
    let state = admin_state(directory.path(), |config| {
        config.authority_db_path = Some(store.clone());
    })?;
    for (method, path) in [
        ("GET", ADMIN_HEALTH_PATH),
        ("GET", ADMIN_AUTHORITY_PATH),
        ("POST", ADMIN_AUTHORITY_PATH),
    ] {
        let (status, response) = admin(&state, method, path, None).await?;
        assert_admin_backend_failed(&format!("{method} {path}"), status, &response, &cause);
        assert!(!response.contains(&path_text));
    }
    Ok(())
}

#[tokio::test]
async fn an_invalid_authority_seed_file_answers_the_fixed_urn_without_its_cause() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let seed = directory.path().join("authority.seed");
    std::fs::write(&seed, "not-a-seed")?;
    let cause = match authority_public_key_from_seed_file(&seed) {
        Ok(_) => return Err("an invalid seed file loaded".into()),
        Err(error) => error.to_string(),
    };
    let state = admin_state(directory.path(), |config| {
        config.authority_seed_path = Some(seed.clone());
    })?;
    let (status, response) = admin(&state, "GET", ADMIN_AUTHORITY_PATH, None).await?;
    assert_admin_backend_failed("GET authority", status, &response, &cause);
    Ok(())
}

#[tokio::test]
async fn a_local_budget_store_failure_answers_the_fixed_urn_without_its_path() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let store = directory.path().join("budgets.sqlite3");
    std::fs::create_dir(&store)?;
    let path_text = directory.path().to_string_lossy().into_owned();
    let state = admin_state(directory.path(), |config| {
        config.budget_db_path = Some(store.clone());
    })?;
    let (status, response) = admin(&state, "GET", ADMIN_BUDGETS_PATH, None).await?;
    assert_admin_backend_failed("GET budgets", status, &response, &path_text);
    Ok(())
}

#[tokio::test]
async fn a_malformed_control_url_answers_the_fixed_urn_without_its_cause() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let state = admin_state(directory.path(), |config| {
        config.control_url = Some(" , ".into());
        config.control_token = Some("separate-control-token".into());
    })?;
    for path in [
        ADMIN_AUTHORITY_PATH,
        ADMIN_TOOL_RECEIPTS_PATH,
        ADMIN_BUDGETS_PATH,
        ADMIN_REVOCATIONS_PATH,
    ] {
        let (status, response) = admin(&state, "GET", path, None).await?;
        assert_admin_backend_failed(path, status, &response, "control URL");
    }
    Ok(())
}

#[tokio::test]
async fn an_unopenable_receipt_store_answers_the_fixed_urn_without_its_path() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let store = directory.path().join("receipts.sqlite3");
    std::fs::create_dir(&store)?;
    let path_text = directory.path().to_string_lossy().into_owned();
    let state = admin_state(directory.path(), |config| {
        config.receipt_db_path = Some(store.clone());
    })?;
    for path in [ADMIN_TOOL_RECEIPTS_PATH, ADMIN_CHILD_RECEIPTS_PATH] {
        let (status, response) = admin(&state, "GET", path, None).await?;
        assert_admin_backend_failed(path, status, &response, &path_text);
    }
    Ok(())
}

#[tokio::test]
async fn a_session_send_failure_answers_the_fixed_urn_without_its_cause() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let cause = format!(
        "failed to persist {}/sessions.sqlite3",
        directory.path().display()
    );
    let response = remote_session_send_error(CliError::cli_other_error(cause.clone()));
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert_eq!(body, SESSION_SEND_FAILED);
    assert!(!body.contains(&cause));
    Ok(())
}

#[tokio::test]
async fn governed_denial_details_never_enter_the_http_body() -> TestResult {
    for detail in [
        "verifier rejected /srv/chio/private-key.json for tenant secret-tenant",
        "governed approval token verification failed: bearer secret-token",
        "unknown future denial containing https://private.example/authority",
        "denied",
        "",
    ] {
        let response = remote_session_send_error(CliError::Kernel(
            chio_kernel::KernelError::GovernedTransactionDenied(detail.to_owned()),
        ));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        let value: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            value,
            json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32003,
                    "message": "Governed transaction denied",
                    "data": { "reason": "denied" }
                }
            }),
            "detail: {detail}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn ingress_capacity_keeps_its_distinct_public_refusal() -> TestResult {
    let response = remote_session_send_error(CliError::Adapter(AdapterError::IngressCapacity));
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let value: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        value,
        json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "urn:chio:error:transport:stream-capacity-exceeded"
            }
        })
    );
    Ok(())
}

fn introspection_verifier(url: &str, contract: bool) -> TestResult<IntrospectionBearerVerifier> {
    let url = Url::parse(url)?;
    let authority = format!(
        "{}:{}",
        url.host_str().ok_or("introspection host")?,
        url.port_or_known_default().ok_or("introspection port")?
    );
    let egress = HttpEgressContract::permissive_for_tests(&authority);
    Ok(IntrospectionBearerVerifier {
        clock: RemoteClock::default(),
        client: client_builder_with_contract(&egress).build()?,
        introspection_url: url,
        client_id: Some("introspection-client".into()),
        client_secret: Some("introspection-secret".into()),
        issuer: None,
        audience: None,
        required_scopes: Vec::new(),
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        egress_contract: contract.then_some(egress),
    })
}

async fn introspection_refusal(verifier: &IntrospectionBearerVerifier, detail: &str) -> TestResult {
    let headers = HeaderMap::new();
    let response = match verifier
        .authenticate_token("opaque-token", &headers, None, None)
        .await
    {
        Ok(_) => return Err("introspection admitted a token".into()),
        Err(response) => response,
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert_eq!(body, INTROSPECTION_UNAVAILABLE);
    assert!(!body.contains(detail));
    Ok(())
}

async fn introspection_endpoint(
    status: StatusCode,
    body: &'static str,
) -> TestResult<(String, tokio::task::JoinHandle<std::io::Result<()>>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/introspect", listener.local_addr()?);
    let router = Router::new().fallback(move || async move { (status, body).into_response() });
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    Ok((endpoint, server))
}

#[tokio::test]
async fn every_introspection_failure_answers_the_fixed_urn_without_its_cause() -> TestResult {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let closed = format!("http://{}/introspect", reservation.local_addr()?);
    drop(reservation);
    introspection_refusal(
        &introspection_verifier(&closed, false)?,
        "HttpEgressContract",
    )
    .await?;
    introspection_refusal(&introspection_verifier(&closed, true)?, &closed).await?;

    let (endpoint, server) =
        introspection_endpoint(StatusCode::INTERNAL_SERVER_ERROR, "private-backend-detail").await?;
    introspection_refusal(
        &introspection_verifier(&endpoint, true)?,
        "private-backend-detail",
    )
    .await?;
    server.abort();

    let (endpoint, server) = introspection_endpoint(StatusCode::OK, "not-json").await?;
    introspection_refusal(&introspection_verifier(&endpoint, true)?, "expected").await?;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn admin_health_reports_only_local_store_members() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let state = admin_state(directory.path(), |_| {})?;
    let (status, body) = admin(&state, "GET", ADMIN_HEALTH_PATH, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let health: Value = serde_json::from_str(&body)?;
    let sections: Vec<&str> = health
        .as_object()
        .ok_or("health is not an object")?
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        sections,
        [
            "auth",
            "authority",
            "federation",
            "oauth",
            "ok",
            "server",
            "sessions",
            "stores"
        ]
    );
    let stores: Vec<&str> = health["stores"]
        .as_object()
        .ok_or("stores is not an object")?
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        stores,
        [
            "authorityDbConfigured",
            "authoritySeedConfigured",
            "receiptsConfigured",
            "sessionTombstonesConfigured"
        ]
    );
    Ok(())
}
