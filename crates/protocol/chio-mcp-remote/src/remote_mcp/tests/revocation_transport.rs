use super::*;
use axum::body::Body;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

async fn state(directory: &FsPath, remote: Option<String>) -> TestResult<RemoteAppState> {
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(&config.policy_path, "kernel:\n  allow_ephemeral_receipt_log: true\n  allow_ephemeral_revocation_store: true\n  durable_admission_mode: off\n  allow_unsafe_durable_admission_off: true\n")?;
    config.wrapped_args.clear();
    config.test_transport = Some(Arc::new(TestSessionTransport));
    configure_signed_manifest(&mut config, directory);
    // The test owns a terminal diagnostic record, without launching an upstream.
    let mut factory = RemoteSessionFactory::new(config.clone())?;
    factory.config.control_url = remote;
    factory.config.control_token = Some("separate-control-token".into());
    factory.config.revocation_db_path = Some(directory.join("revocations.db"));
    let sessions = Arc::new(RemoteSessionLedger::new(
        config.clock.clone(),
        config.lifecycle_policy(),
        None,
        None,
    )?);
    let now = config.clock.millis()?;
    sessions.terminal.lock().await.insert(
        "terminal".into(),
        Arc::new(RemoteSessionDiagnosticRecord {
            session_id: "terminal".into(),
            auth_context: SessionAuthContext::streamable_http_static_bearer("test", "test", None),
            capabilities: ["a", "b"]
                .into_iter()
                .map(|id| RemoteSessionCapability {
                    id: id.into(),
                    issuer_public_key: "issuer".into(),
                    subject_public_key: "subject".into(),
                })
                .collect(),
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
        }),
    );
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

async fn revoke(state: &RemoteAppState, status: StatusCode) -> TestResult<Value> {
    let router = remote_mcp_admin::install_admin_routes(Router::new()).with_state(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri(
            ADMIN_SESSION_TRUST_PATH
                .replace("{session_id}", "terminal")
                .replace("{sessionId}", "terminal"),
        )
        .header(AUTHORIZATION, "Bearer admin-token")
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;
    let actual = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    assert_eq!(actual, status, "{}", String::from_utf8_lossy(&bytes));
    assert!(!String::from_utf8_lossy(&bytes).contains("private-backend-detail"));
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Default)]
struct Backend {
    mode: std::sync::atomic::AtomicUsize,
    revoked: StdMutex<std::collections::HashSet<String>>,
}

async fn mock_write(State(backend): State<Arc<Backend>>, Json(body): Json<Value>) -> Response {
    let id = body["capabilityId"].as_str().unwrap_or_default();
    if backend.mode.load(Ordering::SeqCst) == 1 && id == "b" {
        return (StatusCode::INTERNAL_SERVER_ERROR, "private-backend-detail").into_response();
    }
    let newly_revoked = backend.revoked.lock().unwrap().insert(id.into());
    Json(json!({"capabilityId": id, "revoked": true, "newlyRevoked": newly_revoked}))
        .into_response()
}

async fn mock_read(
    State(backend): State<Arc<Backend>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if backend.mode.load(Ordering::SeqCst) == 2 {
        return (StatusCode::INTERNAL_SERVER_ERROR, "private-backend-detail").into_response();
    }
    let id = query.get("capabilityId").cloned().unwrap_or_default();
    let revoked =
        backend.mode.load(Ordering::SeqCst) != 3 && backend.revoked.lock().unwrap().contains(&id);
    Json(json!({"configured": true, "backend": "test", "capabilityId": id, "revoked": revoked, "count": 0, "revocations": []})).into_response()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_revocation_remote_failures_partial_retry_and_readback() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let backend = Arc::new(Backend::default());
    let router = Router::new()
        .route("/v1/revocations", post(mock_write).get(mock_read))
        .with_state(backend.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let directory = tempfile::tempdir()?;
    let state = state(directory.path(), Some(endpoint)).await?;
    backend.mode.store(1, Ordering::SeqCst);
    let partial = revoke(&state, StatusCode::SERVICE_UNAVAILABLE).await?;
    assert_eq!(partial["revoked"], false);
    assert_eq!(partial["newlyRevokedCount"], 1);
    assert_eq!(partial["capabilities"][0]["revoked"], true);
    assert_eq!(partial["capabilities"][1]["failure"], "write_failed");
    backend.mode.store(0, Ordering::SeqCst);
    let retry = revoke(&state, StatusCode::OK).await?;
    assert_eq!(retry["revoked"], true);
    assert_eq!(retry["newlyRevokedCount"], 1);
    assert_eq!(
        revoke(&state, StatusCode::OK).await?["newlyRevokedCount"],
        0
    );
    for (mode, failure) in [(2, "readback_failed"), (3, "not_confirmed")] {
        backend.mode.store(mode, Ordering::SeqCst);
        let failed = revoke(&state, StatusCode::SERVICE_UNAVAILABLE).await?;
        assert_eq!(failed["revoked"], false);
        assert_eq!(failed["capabilities"][0]["failure"], failure);
    }
    server.abort();
    Ok(())
}

#[tokio::test]
async fn session_revocation_local_write_failure_is_partial_and_retryable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let state = state(directory.path(), None).await?;
    let path = directory.path().join("revocations.db");
    let store = chio_store_sqlite::SqliteRevocationStore::open(&path)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("CREATE TRIGGER refuse_b BEFORE INSERT ON revoked_capabilities WHEN NEW.capability_id = 'b' BEGIN SELECT RAISE(ABORT, 'private-backend-detail'); END;")?;
    let partial = revoke(&state, StatusCode::SERVICE_UNAVAILABLE).await?;
    assert_eq!(partial["revoked"], false);
    assert_eq!(partial["newlyRevokedCount"], 1);
    assert!(store.is_revoked("a")?);
    assert!(!store.is_revoked("b")?);
    connection.execute_batch("DROP TRIGGER refuse_b;")?;
    assert_eq!(
        revoke(&state, StatusCode::OK).await?["newlyRevokedCount"],
        1
    );
    assert_eq!(
        revoke(&state, StatusCode::OK).await?["newlyRevokedCount"],
        0
    );
    Ok(())
}

#[tokio::test]
async fn mcp_transport_denies_public_plaintext_before_policy_or_store_work() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("must-not-exist.db");
    let mut config = test_remote_config();
    config.listen = "0.0.0.0:0".parse()?;
    config.policy_path = directory.path().join("missing-policy.yaml");
    config.session_db_path = Some(database.clone());
    let error = serve_http_async(config)
        .await
        .err()
        .ok_or("unsafe listener started")?;
    assert!(error.to_string().contains("non-loopback"));
    assert!(!database.exists());
    Ok(())
}

#[tokio::test]
async fn mcp_transport_serves_admin_over_tls() -> TestResult {
    let directory = tempfile::tempdir()?;
    let fixture = state(directory.path(), None).await?;
    let mut config = fixture.factory.config.clone();
    config.control_token = None;
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    std::fs::write(&cert, identity.cert.pem())?;
    std::fs::write(&key, identity.key_pair.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    drop(reservation);
    config.listen = address;
    config.transport = chio_http_serve::ServerTransportConfig {
        tls_cert: Some(cert),
        tls_key: Some(key),
        allow_plaintext: false,
    };
    let server = tokio::spawn(serve_http_async(config));
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(
            identity.cert.pem().as_bytes(),
        )?)
        .build()?;
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = client
                .get(format!(
                    "https://localhost:{}/admin/sessions",
                    address.port()
                ))
                .bearer_auth("admin-token")
                .send()
                .await
            {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.abort();
    let _ = server.await;
    Ok(())
}
