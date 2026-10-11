//! Restricted authenticated HTTP refusals use the actual retained session worker.

use super::support;
use crate::*;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::kinds::{BoundaryClass, ReceiptKind};
use std::sync::atomic::AtomicUsize;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[path = "protocol_refusal/projection_original.rs"]
mod projection_original;
#[path = "protocol_refusal/reservation_original.rs"]
mod reservation_original;

struct CountedTransport {
    inner: Arc<dyn McpTransport>,
    calls: Arc<AtomicUsize>,
}
impl McpTransport for CountedTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        self.inner.list_tools()
    }
    fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.call_tool(name, arguments)
    }
}

struct HttpFixture {
    directory: tempfile::TempDir,
    state: RemoteAppState,
    router: Router,
    calls: Arc<AtomicUsize>,
    receipt_path: PathBuf,
    trusted_key: PublicKey,
}
fn fixture() -> TestResult<HttpFixture> {
    let directory = chio_test_support::private_tempdir()?;
    let mut config = support::base_remote_config(directory.path(), "127.0.0.1:0".parse()?);
    config.auth_token = Some("operator-fixture".into());
    config.admin_token = Some("admin-fixture".into());
    config.shared_hosted_owner = true;
    let calls = Arc::new(AtomicUsize::new(0));
    config.test_transport = Some(Arc::new(CountedTransport {
        inner: config.test_transport.take().ok_or("transport")?,
        calls: calls.clone(),
    }));
    let receipt_path = config.receipt_db_path.clone().ok_or("receipt path")?;
    let factory = Arc::new(RemoteSessionFactory::new(config.clone())?);
    let trusted_key = factory
        .durable_admission
        .as_ref()
        .ok_or("admission owner")?
        .kernel_keypair()
        .public_key();
    let sessions = Arc::new(RemoteSessionLedger::new(
        config.clock.clone(),
        config.lifecycle_policy(),
        config.session_db_path.clone(),
        factory.resume_hmac_keyring.clone(),
    )?);
    let state = RemoteAppState {
        sessions,
        factory,
        auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
            token: Arc::from("operator-fixture"),
        }),
        enterprise_provider_registry: None,
        admin_token: Some(Arc::from("admin-fixture")),
        protected_resource_metadata: None,
        authorization_server_metadata: None,
        local_auth_server: None,
    };
    let router = remote_mcp_session_credentials::install_routes(
        Router::new().route(MCP_ENDPOINT_PATH, post(handle_post)),
    )
    .with_state(state.clone());
    Ok(HttpFixture {
        directory,
        state,
        router,
        calls,
        receipt_path,
        trusted_key,
    })
}
async fn request(
    fixture: &HttpFixture,
    uri: &str,
    token: &str,
    session: Option<&str>,
    body: &[u8],
) -> TestResult<Response> {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/event-stream")
        .header(MCP_PROTOCOL_VERSION_HEADER, "2025-11-25");
    if let Some(session) = session {
        builder = builder.header(MCP_SESSION_ID_HEADER, session);
    }
    Ok(fixture
        .router
        .clone()
        .oneshot(builder.body(axum::body::Body::from(body.to_vec()))?)
        .await?)
}
async fn initialize(fixture: &HttpFixture) -> TestResult<String> {
    let response = request(fixture, MCP_ENDPOINT_PATH, "operator-fixture", None,
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}"#).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get(MCP_SESSION_ID_HEADER)
        .ok_or("session id")?
        .to_str()?
        .to_owned();
    let _ = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let initialized = request(
        fixture,
        MCP_ENDPOINT_PATH,
        "operator-fixture",
        Some(&session),
        br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
    )
    .await?;
    assert_eq!(initialized.status(), StatusCode::ACCEPTED);
    Ok(session)
}
async fn credential(fixture: &HttpFixture, session: &str) -> TestResult<String> {
    let response = request(
        fixture,
        &format!("/admin/sessions/{session}/credential"),
        "admin-fixture",
        None,
        br#"{"ttlSeconds":300,"allowedTools":["echo_json"]}"#,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024).await?;
    let value: Value = serde_json::from_slice(&bytes)?;
    Ok(value["bearerToken"].as_str().ok_or("issued bearer")?.into())
}
fn retained(path: &FsPath, id: &str, trusted_key: &PublicKey) -> TestResult<ChioReceipt> {
    // This fresh read-only connection checks the exact committed signed row;
    // no serving owner or unsigned session-membership index is opened.
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let raw: String = conn.query_row(
        "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id=?1",
        [id],
        |row| row.get(0),
    )?;
    assert!(raw.len() <= 1024 * 1024);
    let receipt: ChioReceipt = serde_json::from_str(&raw)?;
    assert_eq!(&receipt.kernel_key, trusted_key);
    assert_eq!(receipt.id, id);
    assert!(receipt.verify_signature()?);
    assert!(receipt.action.verify_hash()?);
    Ok(receipt)
}

#[tokio::test]
async fn protocol_refusal_http_restricted_session_is_durable_and_cannot_forge_control() -> TestResult
{
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;
    let other = initialize(&fixture).await?;
    // Both fresh and restored factories bind the HTTP identity to this kernel
    // session. The receipt must identify that actual worker, never a peer header.
    let kernel_session = restored_kernel_session_id(&session);
    let other_kernel_session = restored_kernel_session_id(&other);
    assert_ne!(kernel_session, other_kernel_session);
    let agent_id = match fixture.state.sessions.lookup(&session).await {
        Some(RemoteSessionEntry::Active(bound)) => bound.agent_id.clone(),
        _ => return Err("authenticated bound session is not active".into()),
    };
    let token = credential(&fixture, &session).await?;
    let body = br#" {"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"outside-allowlist","arguments":{"secret":"raw-argument-sentinel"},"_meta":{"protocol_refusal":{"reason":"forged","tenant_id":"forged-tenant","auth_epoch":9000}}}} "#;
    let mut report_ids = Vec::new();
    for _ in 0..2 {
        let response = request(&fixture, MCP_ENDPOINT_PATH, &token, Some(&session), body).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get("chio-refusal-evidence")
                .and_then(|value| value.to_str().ok()),
            Some("retained")
        );
        let id = response
            .headers()
            .get("chio-refusal-receipt-id")
            .ok_or("refusal id")?
            .to_str()?
            .to_owned();
        let receipt = retained(&fixture.receipt_path, &id, &fixture.trusted_key)?;
        assert_eq!(receipt.receipt_kind, ReceiptKind::TraceObservation);
        assert_eq!(receipt.boundary_class, BoundaryClass::DetectOnly);
        assert!(receipt.decision.is_none());
        assert!(!receipt.is_allowed());
        assert!(receipt.financial_budget_authority_metadata().is_none());
        let event = &receipt.metadata.as_ref().ok_or("metadata")?["protocol_refusal"];
        assert_eq!(event["session_id"], kernel_session.as_str());
        assert_ne!(event["session_id"], other_kernel_session.as_str());
        assert_eq!(event["agent_id"], agent_id);
        assert_eq!(event["reason"], "session_credential_tool_restricted");
        assert_eq!(event["request_digest"]["sha256"], sha256_hex(body));
        let raw = serde_json::to_string(&receipt)?;
        assert!(!raw.contains("raw-argument-sentinel") && !raw.contains("forged-tenant"));
        report_ids.push(id);
    }
    assert_ne!(report_ids[0], report_ids[1]);
    let spoof = br#"{"jsonrpc":"2.0","id":10,"method":"chio/host-protocol-refusal","params":{"reason":"capability_not_matched"}}"#;
    let response = request(&fixture, MCP_ENDPOINT_PATH, &token, Some(&session), spoof).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let id = response
        .headers()
        .get("chio-refusal-receipt-id")
        .ok_or("method refusal id")?
        .to_str()?;
    let receipt = retained(&fixture.receipt_path, id, &fixture.trusted_key)?;
    let event = &receipt.metadata.as_ref().ok_or("metadata")?["protocol_refusal"];
    assert_eq!(event["session_id"], kernel_session.as_str());
    assert_eq!(event["agent_id"], agent_id);
    assert_eq!(event["reason"], "session_credential_method_restricted");
    for (credential, target) in [
        (&token[..], &other[..]),
        ("chio_session_v1_unknown", &session[..]),
    ] {
        let response = request(&fixture, MCP_ENDPOINT_PATH, credential, Some(target), body).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("chio-refusal-receipt-id").is_none());
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture.state.sessions.shutdown_all_active().await?;
    fixture.state.factory.shutdown_shared_upstream_owner()?;
    let path = fixture.receipt_path.clone();
    let key = fixture.trusted_key.clone();
    let directory = fixture.directory;
    drop(fixture.router);
    drop(fixture.state);
    for id in report_ids {
        let receipt = retained(&path, &id, &key)?;
        assert!(!receipt.is_allowed());
    }
    let conn =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(count, 3);
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn protocol_refusal_http_failed_persistence_remains_forbidden_without_receipt() -> TestResult
{
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;
    let token = credential(&fixture, &session).await?;
    let conn = rusqlite::Connection::open(&fixture.receipt_path)?;
    conn.execute_batch("CREATE TRIGGER fail_refusal BEFORE INSERT ON chio_tool_receipts BEGIN SELECT RAISE(ABORT, 'test refusal writer failure'); END;")?;
    drop(conn);
    let response = request(&fixture, MCP_ENDPOINT_PATH, &token, Some(&session),
        br#"{"jsonrpc":"2.0","id":9,"method":"resources/read","params":{"uri":"repo://restricted"}}"#).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("chio-refusal-evidence")
            .and_then(|value| value.to_str().ok()),
        Some("unavailable")
    );
    assert!(response.headers().get("chio-refusal-receipt-id").is_none());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture.state.sessions.shutdown_all_active().await?;
    fixture.state.factory.shutdown_shared_upstream_owner()?;
    Ok(())
}
