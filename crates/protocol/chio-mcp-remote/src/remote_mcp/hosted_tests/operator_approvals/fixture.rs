//! Native MCP sessions using an activated replay source and externally held signer.
use crate::*;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use chio_kernel::admission_operation::AdmissionIdentifier;
use std::sync::atomic::AtomicUsize;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) struct CountingTransport(pub Arc<AtomicUsize>);
impl McpTransport for CountingTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        Ok(vec![serde_json::from_value(json!({
            "name":"echo_json", "title":"Echo JSON", "description":"Return structured JSON",
            "inputSchema":{"type":"object", "properties":{"message":{"type":"string"}}},
            "outputSchema":{"type":"object", "properties":{"echo":{"type":"string"}}},
            "annotations":{"readOnlyHint":true}
        }))
        .map_err(|error| {
            AdapterError::ParseError(error.to_string())
        })?])
    }
    fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        if name != "echo_json" {
            return Err(AdapterError::ToolNotFound(name.into()));
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(chio_mcp_adapter::edge::McpToolResult {
            content: vec![json!({"type":"text","text":"approved native execution"})],
            structured_content: Some(json!({"echo": arguments["message"]})),
            is_error: Some(false),
        })
    }
}

pub(super) fn config(
    directory: &FsPath,
    approver: &Keypair,
    calls: Arc<AtomicUsize>,
) -> TestResult<RemoteServeHttpConfig> {
    let mut config =
        super::super::super::support::base_remote_config(directory, "127.0.0.1:0".parse()?);
    config.auth_token = Some("ap23-test-agent".into());
    config.admin_token = Some("ap23-test-operator".into());
    config.test_transport = Some(Arc::new(CountingTransport(calls)));
    std::fs::write(
        &config.policy_path,
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow: [echo_json]
    require_confirmation: [echo_json]
capabilities:
  default:
    tools:
      - {server: wrapped-http-mock, tool: echo_json, operations: [invoke], ttl: 300}
"#,
    )?;
    let session_db = config
        .session_db_path
        .as_deref()
        .ok_or("session database")?;
    let runtime = DurableAdmissionRuntime::open(&durable_admission_sidecar_path(session_db)?)?;
    let authority = runtime.local_authority_store().ok_or("local authority")?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let replay = directory.join("approval-replay.sqlite3");
    drop(chio_store_sqlite::SqliteGovernedApprovalReplayStore::open_with_capacity(&replay, 128)?);
    let source = chio_store_sqlite::SqliteGovernedApprovalReplaySource::open(&replay)?;
    let authority_id = AdmissionIdentifier::try_new("approval_authority", "mcp-operator")?;
    let source_id = AdmissionIdentifier::try_new("approval_source", "mcp-replay")?;
    let now = config.clock.millis()?;
    let expected = store.expect_governed_approval_replay_source(
        &source_id,
        &authority_id,
        &source,
        &fence,
        now,
    )?;
    let imported = store.import_governed_approval_replay_source(
        &authority_id,
        expected.expectation_id(),
        &source,
        &fence,
        now,
    )?;
    let binding =
        GovernedApprovalAuthorityBindingV1::new(authority_id, imported.expectation_id().clone());
    store.activate_governed_approval_replay_source(&binding, &source, &fence, now)?;
    config.approval = Some(RemoteApprovalConfig {
        tenant_id: "ap23-mcp-tenant".into(),
        approvers: vec![approver.public_key()],
        replay_source_path: replay,
        binding,
    });
    Ok(config)
}

pub(super) async fn open(
    config: RemoteServeHttpConfig,
    resume: Option<&RemoteSessionResumeRecord>,
) -> TestResult<(RemoteAppState, Arc<RemoteSession>)> {
    let factory = Arc::new(RemoteSessionFactory::new(config.clone())?);
    let sessions = Arc::new(RemoteSessionLedger::new(
        config.clock.clone(),
        config.lifecycle_policy(),
        config.session_db_path.clone(),
        factory.resume_hmac_keyring.clone(),
    )?);
    let session = match resume {
        Some(record) => factory
            .restore_session(record)?
            .ok_or("session was not restorable")?,
        None => factory.spawn_session(SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:ap23-agent",
            sha256_hex(b"ap23-test-agent"),
            None,
        ))?,
    };
    if resume.is_none() {
        initialize(&session).await?;
    }
    sessions.insert_active(session.clone()).await;
    let state = RemoteAppState {
        sessions,
        factory,
        auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
            token: "ap23-test-agent".into(),
        }),
        enterprise_provider_registry: None,
        admin_token: Some("ap23-test-operator".into()),
        protected_resource_metadata: None,
        authorization_server_metadata: None,
        local_auth_server: None,
    };
    Ok((state, session))
}

async fn initialize(session: &RemoteSession) -> TestResult {
    let params = json!({"protocolVersion":"2025-11-25", "capabilities":{},
        "clientInfo":{"name":"ap23-native","version":"1"}});
    let result = rpc(
        session,
        json!({"jsonrpc":"2.0", "id":1,
        "method":"initialize", "params":params}),
    )
    .await?;
    assert!(result.get("error").is_none(), "{result}");
    let mut peer = parse_remote_session_peer_capabilities(&params);
    peer.authorization =
        Some(chio_mcp_adapter::edge::authorization::negotiate_authorization_capabilities(&params)?);
    session.mark_ready(Some("2025-11-25".into()), params, peer)?;
    // Match the HTTP owner: commit Ready after a successful initialize response
    // before accepting any subsequent client message.
    session.send(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}))?;
    Ok(())
}

pub(super) async fn rpc(session: &RemoteSession, message: Value) -> TestResult<Value> {
    let id = message.get("id").ok_or("RPC request needs an ID")?.clone();
    let mut events = session.subscribe();
    session.send(message)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await?;
            if event.message.get("id") == Some(&id) {
                return Ok(event.message);
            }
        }
    })
    .await?
}

pub(super) async fn stop(state: RemoteAppState, session: Arc<RemoteSession>) -> TestResult {
    let mut events = session.subscribe();
    state.sessions.remove_active(&session.session_id).await;
    drop(session);
    drop(state);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Err(broadcast::error::RecvError::Closed) => return,
                Err(broadcast::error::RecvError::Lagged(_)) | Ok(_) => {}
            }
        }
    })
    .await?;
    Ok(())
}

pub(super) fn headers() -> TestResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str("Bearer ap23-test-operator")?,
    );
    Ok(headers)
}

pub(super) async fn body(response: Response, status: StatusCode) -> TestResult<Value> {
    let actual = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), MAX_SESSION_JSON_BYTES).await?;
    assert_eq!(actual, status, "{}", String::from_utf8_lossy(&bytes));
    Ok(decode_json(&bytes, MAX_SESSION_JSON_BYTES)?)
}

pub(super) async fn submit(
    state: &RemoteAppState,
    session: &RemoteSession,
    request_id: &str,
) -> TestResult<Value> {
    submit_with_ttl(state, session, request_id, 120).await
}

pub(super) async fn submit_with_ttl(
    state: &RemoteAppState,
    session: &RemoteSession,
    request_id: &str,
    ttl_seconds: u64,
) -> TestResult<Value> {
    let capability = session
        .issued_capabilities
        .first()
        .ok_or("session capability")?;
    let request = serde_json::from_value(json!({
        "session_id":session.session_id, "capability_id":capability.id,
        "request_id":request_id, "tool_name":"echo_json", "arguments":{"message":"exact"},
        "purpose":"operator-approved native test", "ttl_seconds":ttl_seconds,
    }))?;
    body(
        crate::remote_mcp_approvals::submit(State(state.clone()), headers()?, BoundedJson(request))
            .await,
        StatusCode::CREATED,
    )
    .await
}

pub(super) fn token(
    pending: &Value,
    approver: &Keypair,
) -> TestResult<chio_core::capability::governance::GovernedApprovalToken> {
    use chio_core::capability::governance::*;
    let record = &pending["record"];
    let intent: GovernedTransactionIntent = serde_json::from_value(record["intent"].clone())?;
    Ok(GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("{}-decision", record["id"].as_str().ok_or("approval id")?),
            approver: approver.public_key(),
            subject: serde_json::from_value(record["subject"].clone())?,
            governed_intent_hash: intent.binding_hash()?,
            request_id: record["request_id"].as_str().ok_or("request id")?.into(),
            threshold_proposal_hash: None,
            issued_at: record["created_at"].as_u64().ok_or("created_at")?,
            expires_at: record["expires_at"].as_u64().ok_or("expires_at")?,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )?)
}

pub(super) async fn decide(
    state: &RemoteAppState,
    pending: &Value,
    token: &chio_core::capability::governance::GovernedApprovalToken,
) -> TestResult<Response> {
    let id = pending["record"]["id"].as_str().ok_or("approval id")?;
    let request = serde_json::from_value(json!({"token":token}))?;
    Ok(crate::remote_mcp_approvals::decide(
        State(state.clone()),
        AxumPath(id.into()),
        headers()?,
        BoundedJson(request),
    )
    .await)
}

pub(super) async fn call(session: &RemoteSession, params: Value, id: u64) -> TestResult<Value> {
    rpc(
        session,
        json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":params}),
    )
    .await
}
