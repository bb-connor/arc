//! Operator stop routes stop the proxy path and sidecar issuance until resume.

use super::control_auth::{with_authenticated_control_peer, TEST_CONTROL_TOKEN};
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Upstream {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn upstream() -> Upstream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .test_unwrap();
    let address = listener.local_addr().test_unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let app = Router::new().fallback(any(move || {
        let counted = Arc::clone(&counted);
        async move {
            counted.fetch_add(1, Ordering::SeqCst);
            (StatusCode::OK, "[]")
        }
    }));
    let task = tokio::spawn(async move { axum::serve(listener, app).await });
    Upstream {
        address,
        calls,
        task,
    }
}

fn control(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
    with_authenticated_control_peer(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
            .test_unwrap(),
    )
}

fn read_pets() -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap()
}

fn mint() -> Request<Body> {
    control(
        "POST",
        "/v1/capabilities/mint",
        serde_json::json!({
            "subject": Keypair::from_seed(&[7; 32]).public_key().to_hex(),
            "scopes": ["tools:search"],
            "job_uid": "job-uid-1",
        }),
    )
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app.clone().oneshot(request).await.test_unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_denies_the_proxy_and_issuance_until_resume() {
    let upstream = upstream().await;
    let mut state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        format!("http://{}", upstream.address),
    );
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
        Some(TEST_CONTROL_TOKEN.to_owned());
    let app = build_app(Arc::clone(&state));

    assert_eq!(send(&app, read_pets()).await.0, StatusCode::OK);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);

    let (status, stopped) = send(
        &app,
        control(
            "POST",
            "/chio/emergency-stop",
            serde_json::json!({"reason": "incident"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stopped["stopped"], true);
    assert_eq!(stopped["readiness"]["state"], "ready_stopped");
    assert_eq!(stopped["durability"], "process_local");
    assert!(state.evaluator.stop_control().heads().is_stopped());

    let (status, refused) = send(&app, read_pets()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused["error"], "kernel_stopped");
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    let (status, refused) = send(&app, mint()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused["error"], "kernel_stopped");
    let (status, current) = send(
        &app,
        control("GET", "/chio/emergency-status", serde_json::Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current["stopped"], true);

    let (status, resumed) = send(
        &app,
        control(
            "POST",
            "/chio/emergency-resume",
            serde_json::json!({"expected_epoch": {"chain_generation": 1, "epoch": 1}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resumed["stopped"], false);
    assert_eq!(send(&app, read_pets()).await.0, StatusCode::OK);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    assert_eq!(send(&app, mint()).await.0, StatusCode::OK);
}

#[tokio::test]
async fn a_stop_request_is_bounded_and_validated() {
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_owned());
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
        Some(TEST_CONTROL_TOKEN.to_owned());
    let app = build_app(Arc::clone(&state));
    for body in [
        serde_json::json!({"reason": ""}),
        serde_json::json!({"reason": "x".repeat(1025)}),
        serde_json::json!({"reason": "incident", "unexpected": true}),
    ] {
        let (status, _) = send(&app, control("POST", "/chio/emergency-stop", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert!(!state.stop.heads().is_stopped());
}

#[tokio::test]
async fn stop_routes_redact_failed_store_appends() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let database = directory.path().join("authority.db");
    let locks = directory.path().join("locks");
    std::fs::create_dir(&locks)?;
    std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))?;
    chio_store_sqlite::SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &locks,
        Arc::new(chio_security_types::clock::FixedClock::new(1_800_000_000)),
    )?;
    let store = Arc::new(authority.admission_operation_store());
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_owned());
    let inner = Arc::get_mut(&mut state).test_unwrap();
    inner.stop = chio_kernel::stop::StopControl::durable(&store, authority.mutation_fence());
    inner.sidecar_control_token = Some(TEST_CONTROL_TOKEN.to_owned());
    let app = build_app(Arc::clone(&state));
    let connection = rusqlite::Connection::open(&database)?;
    let (status, stopped) = send(
        &app,
        control(
            "POST",
            "/chio/emergency-stop",
            serde_json::json!({"reason": "incident"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    connection.execute_batch("CREATE TABLE stop_test_external_write (value INTEGER);")?;
    let (status, body) = send(&app, control("POST", "/chio/emergency-resume",
        serde_json::json!({"expected_epoch": {"chain_generation": stopped["head"]["chain_generation"], "epoch": stopped["head"]["epoch"]}}))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        serde_json::json!({"error": "resume_refused", "message": "Resume was refused.", "urn": "urn:chio:error:kernel:resume-refused"})
    );
    assert!(state.stop.heads().is_stopped());
    let (status, body) = send(
        &app,
        control(
            "POST",
            "/chio/emergency-stop",
            serde_json::json!({"reason": "incident"}),
        ),
    )
    .await;
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
