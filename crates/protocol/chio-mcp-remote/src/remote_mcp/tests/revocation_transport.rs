use super::*;
use axum::body::Body;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

async fn state(directory: &FsPath) -> TestResult<RemoteAppState> {
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(&config.policy_path, "kernel:\n  allow_ephemeral_receipt_log: true\n  allow_ephemeral_revocation_store: true\n  durable_admission_mode: off\n  allow_unsafe_durable_admission_off: true\n")?;
    config.wrapped_args.clear();
    config.test_transport = Some(Arc::new(TestSessionTransport));
    configure_signed_manifest(&mut config, directory);
    // The test owns a terminal diagnostic record, without launching an upstream.
    let mut factory = RemoteSessionFactory::new(config.clone())?;
    factory.config.revocation_db_path = Some(directory.join("revocations.db"));
    let sessions = Arc::new(RemoteSessionLedger::new(
        config.clock.clone(),
        config.lifecycle_policy()?,
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
            terminal_reason: None,
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

async fn send_revoke(state: &RemoteAppState) -> TestResult<(StatusCode, String)> {
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
    let body = String::from_utf8(bytes.to_vec())?;
    assert!(!body.contains("private-backend-detail"));
    Ok((actual, body))
}

async fn revoke(state: &RemoteAppState, status: StatusCode) -> TestResult<Value> {
    let (actual, body) = send_revoke(state).await?;
    assert_eq!(actual, status, "{body}");
    Ok(serde_json::from_str(&body)?)
}

#[tokio::test]
async fn session_revocation_needs_the_durable_local_store() -> TestResult {
    let directory = tempfile::tempdir()?;
    let state = state(directory.path()).await?;
    let (status, body) = send_revoke(&state).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, "remote trust admin requires durable revocation state");
    assert!(!directory.path().join("revocations.db").exists());
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
    let fixture = state(directory.path()).await?;
    let mut config = fixture.factory.config.clone();
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
