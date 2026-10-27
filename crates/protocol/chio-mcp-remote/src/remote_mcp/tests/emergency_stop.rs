//! The mounted stop routes authenticate, reach every session kernel, and drive
//! a durable stop that a rebuilt edge loads stopped.
use super::*;
use axum::body::Body;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn state(directory: &FsPath) -> TestResult<RemoteAppState> {
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(
        &config.policy_path,
        "kernel:\n  allow_ephemeral_receipt_log: true\n  durable_admission_mode: all\n",
    )?;
    config.session_db_path = Some(directory.join("sessions.db"));
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(directory));
    config.wrapped_args.clear();
    config.test_transport = Some(Arc::new(TestSessionTransport));
    configure_signed_manifest(&mut config, directory);
    let factory = RemoteSessionFactory::new(config.clone())?;
    Ok(RemoteAppState {
        sessions: Arc::new(RemoteSessionLedger::new(
            config.clock.clone(),
            config.lifecycle_policy()?,
            None,
            None,
        )?),
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

async fn call(
    state: &RemoteAppState,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> TestResult<(StatusCode, Value)> {
    let router = remote_mcp_admin::install_admin_routes(Router::new()).with_state(state.clone());
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => request
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body)?))?,
        None => request.body(Body::empty())?,
    };
    let response = router.oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, value))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn emergency_routes_authenticate_and_survive_an_edge_rebuild() -> TestResult {
    let directory = tempfile::tempdir()?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let first = state(directory.path())?;

    for token in [None, Some("wrong-token"), Some("remote-auth-token")] {
        let (status, _) = call(
            &first,
            "POST",
            ADMIN_EMERGENCY_STOP_PATH,
            token,
            Some(json!({"reason": "incident"})),
        )
        .await?;
        assert_ne!(status, StatusCode::OK, "{token:?}");
    }
    assert!(!first.factory.stop.heads().is_stopped());

    let (status, stopped) = call(
        &first,
        "POST",
        ADMIN_EMERGENCY_STOP_PATH,
        Some("admin-token"),
        Some(json!({"reason": "incident"})),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{stopped}");
    assert_eq!(stopped["durability"], "durable", "{stopped}");
    assert_eq!(stopped["head"]["epoch"], 1, "{stopped}");
    assert_eq!(
        stopped["head"]["requested_via"],
        json!({"kind": "route", "host_id": first.factory.config.server_id})
    );
    drop(first);

    let second = state(directory.path())?;
    let (status, status_body) = call(
        &second,
        "GET",
        ADMIN_EMERGENCY_STATUS_PATH,
        Some("admin-token"),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        status_body["readiness"]["state"], "ready_stopped",
        "{status_body}"
    );
    assert!(second.factory.stop.heads().is_stopped());

    let (status, moved) = call(
        &second,
        "POST",
        ADMIN_EMERGENCY_RESUME_PATH,
        Some("admin-token"),
        Some(json!({"expected_epoch": {"chain_generation": 1, "epoch": 5}})),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{moved}");
    assert_eq!(moved["error"], "stop_head_moved");

    let (status, resumed) = call(
        &second,
        "POST",
        ADMIN_EMERGENCY_RESUME_PATH,
        Some("admin-token"),
        Some(json!({"expected_epoch": {"chain_generation": 1, "epoch": 1}})),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{resumed}");
    assert_eq!(resumed["stopped"], false);
    assert!(!second.factory.stop.heads().is_stopped());
    Ok(())
}

#[tokio::test]
async fn stop_routes_redact_failed_store_appends() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let state = state(directory.path())?;
    let database =
        chio_control_plane::durable_admission_sidecar_path(&directory.path().join("sessions.db"))?;
    let connection = rusqlite::Connection::open(database)?;
    let (status, stopped) = call(
        &state,
        "POST",
        ADMIN_EMERGENCY_STOP_PATH,
        Some("admin-token"),
        Some(serde_json::json!({"reason": "incident"})),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    connection.execute_batch("CREATE TABLE stop_test_external_write (value INTEGER);")?;
    let (status, body) = call(&state, "POST", ADMIN_EMERGENCY_RESUME_PATH, Some("admin-token"),
        Some(serde_json::json!({"expected_epoch": {"chain_generation": stopped["head"]["chain_generation"], "epoch": stopped["head"]["epoch"]}}))).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        serde_json::json!({"error": "resume_refused", "message": "Resume was refused.", "urn": "urn:chio:error:kernel:resume-refused"})
    );
    assert!(state.factory.stop.heads().is_stopped());
    let (status, body) = call(
        &state,
        "POST",
        ADMIN_EMERGENCY_STOP_PATH,
        Some("admin-token"),
        Some(serde_json::json!({"reason": "incident"})),
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "stop_not_durable");
    assert_eq!(
        body["message"],
        "Stop holds in this process but could not be made durable."
    );
    assert_eq!(body["urn"], "urn:chio:error:kernel:stop-not-durable");
    assert_eq!(body["status"]["stopped"], true);
    assert_eq!(body["status"]["durability"], "process_only");
    assert!(!body.to_string().contains("authority database changed"));
    assert!(!body.to_string().contains("serving-owner"));
    Ok(())
}
