//! Operator stop routes on trust control: a durable stop survives restart and
//! the admission authority refuses to begin admissions until resume.
use super::*;
use tower::ServiceExt;

const TOKEN: &str = "emergency-stop-service-token";

struct Authority {
    _directory: tempfile::TempDir,
    database: std::path::PathBuf,
    locks: std::path::PathBuf,
}

impl Authority {
    fn provision() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = crate::durable_admission::private_tempdir()?;
        let database = directory.path().join("authority.db");
        let locks = directory.path().join("locks");
        crate::create_private_directory(&locks)?;
        SqliteAuthorityStore::provision(&database, &locks)?;
        Ok(Self {
            _directory: directory,
            database,
            locks,
        })
    }

    fn state(&self) -> Result<TrustServiceState, Box<dyn std::error::Error>> {
        let authority = Arc::new(SqliteAuthorityStore::open_serving_with_clock(
            &self.database,
            &self.locks,
            Arc::new(chio_security_types::clock::FixedClock::new(1_800_000_000)),
        )?);
        let mut state = metrics_state(TOKEN);
        state.stop = TrustStop::for_authority(Some(&authority));
        state.joint_authority_store = Some(authority);
        Ok(state)
    }
}

async fn call(
    state: &TrustServiceState,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), Box<dyn std::error::Error>> {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let body = if method == "GET" {
        axum::body::Body::empty()
    } else {
        axum::body::Body::from(serde_json::to_vec(&body)?)
    };
    let router = if uri.starts_with("/v1/internal/") {
        super::super::build_internal_router(state.clone())
    } else {
        super::super::build_router(state.clone())
    };
    let response = router.oneshot(request.body(body)?).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    ))
}

async fn begin_error_code(
    state: &TrustServiceState,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let fence = state
        .joint_authority_store
        .as_ref()
        .ok_or("joint authority")?
        .mutation_fence();
    let (status, response) = call(
        state,
        "POST",
        INTERNAL_ADMISSION_AUTHORITY_PATH,
        Some(TOKEN),
        serde_json::json!({
            "schema": "chio.admission-authority-request.v1",
            "expected_fence": fence,
            "action": "begin",
            "payload": {},
        }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{response}");
    Ok(response["error"]["code"].clone())
}

#[tokio::test]
async fn a_trust_control_stop_survives_restart_and_refuses_new_admissions(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Authority::provision()?;
    {
        let state = authority.state()?;
        let (status, _) = call(
            &state,
            "POST",
            EMERGENCY_STOP_PATH,
            None,
            serde_json::json!({"reason": "incident"}),
        )
        .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(begin_error_code(&state).await?, "stopped");

        let (status, stopped) = call(
            &state,
            "POST",
            EMERGENCY_STOP_PATH,
            Some(TOKEN),
            serde_json::json!({"reason": "incident"}),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{stopped}");
        assert_eq!(stopped["stopped"], true);
        assert_eq!(stopped["durability"], "durable");
        assert_eq!(begin_error_code(&state).await?, "stopped");
    }

    let state = authority.state()?;
    let (status, current) = call(
        &state,
        "GET",
        EMERGENCY_STATUS_PATH,
        Some(TOKEN),
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current["stopped"], true);
    assert_eq!(current["readiness"]["state"], "ready_stopped");
    assert_eq!(begin_error_code(&state).await?, "stopped");

    let (status, moved) = call(
        &state,
        "POST",
        EMERGENCY_RESUME_PATH,
        Some(TOKEN),
        serde_json::json!({"expected_epoch": {"chain_generation": 1, "epoch": 9}}),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{moved}");
    let (status, resumed) = call(
        &state,
        "POST",
        EMERGENCY_RESUME_PATH,
        Some(TOKEN),
        serde_json::json!({"expected_epoch": {
            "chain_generation": current["head"]["chain_generation"],
            "epoch": current["head"]["epoch"],
        }}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{resumed}");
    assert_eq!(resumed["stopped"], false);
    assert_ne!(begin_error_code(&state).await?, "stopped");
    Ok(())
}

#[tokio::test]
async fn stop_routes_redact_failed_store_appends() -> Result<(), Box<dyn std::error::Error>> {
    let authority = Authority::provision()?;
    let state = authority.state()?;
    let connection = rusqlite::Connection::open(&authority.database)?;
    let (status, stopped) = call(
        &state,
        "POST",
        EMERGENCY_STOP_PATH,
        Some(TOKEN),
        serde_json::json!({"reason": "incident"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    connection.execute_batch("CREATE TABLE stop_test_external_write (value INTEGER);")?;
    let (status, body) = call(&state, "POST", EMERGENCY_RESUME_PATH, Some(TOKEN),
        serde_json::json!({"expected_epoch": {"chain_generation": stopped["head"]["chain_generation"], "epoch": stopped["head"]["epoch"]}})).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        serde_json::json!({"error": "resume_refused", "message": "Resume was refused.", "urn": "urn:chio:error:kernel:resume-refused"})
    );
    assert!(state.stop.control().heads().is_stopped());
    let (status, body) = call(
        &state,
        "POST",
        EMERGENCY_STOP_PATH,
        Some(TOKEN),
        serde_json::json!({"reason": "incident"}),
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
