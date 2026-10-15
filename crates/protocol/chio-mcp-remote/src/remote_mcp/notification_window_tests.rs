use super::*;
use std::io::Write as _;

struct IdleTransport;

impl McpTransport for IdleTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        Ok(Vec::new())
    }

    fn call_tool(
        &self,
        _tool_name: &str,
        _arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        Err(AdapterError::ConnectionFailed("idle".to_string()))
    }
}

/// A ready session whose broadcast holds eight events, far below the window.
fn session() -> (
    Arc<RemoteSession>,
    crate::session_core_writer::BroadcastJsonRpcWriter,
) {
    let (input_tx, _input_rx) = mcp_inbox();
    let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(8);
    let session = Arc::new(
        RemoteSession::new(RemoteSessionInit {
            clock: RemoteClock::new(Arc::new(
                chio_security_types::clock::FixedClock::from_millis(12),
            )),
            session_id: "lag-session".to_string(),
            agent_id: "lag-agent".to_string(),
            capabilities: Vec::new(),
            issued_capabilities: Vec::new(),
            auth_context: SessionAuthContext::streamable_http_static_bearer(
                "lag-agent",
                "lag-token",
                None,
            ),
            auth_mode_fingerprint: "auth".to_string(),
            policy_fingerprint: "policy".to_string(),
            runtime_contract_fingerprint: "runtime".to_string(),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle_policy: SessionLifecyclePolicy {
                idle_expiry_millis: 5_000,
                drain_grace_millis: 1_000,
                reaper_interval_millis: 100,
                tombstone_retention_millis: 10_000,
                request_response_timeout_millis: 10_000,
            },
            protocol_version: None,
            peer_capabilities: None,
            initialize_params: None,
            lifecycle_snapshot: None,
            input_tx,
            event_tx,
            retained_notification_events: Arc::new(StdMutex::new(VecDeque::new())),
            next_event_id: Arc::new(AtomicU64::new(0)),
            resync_catalogs: declared_resync_catalogs(true, false, false),
            session_db_path: None,
            approval_redemption: None,
            session_store_lease: None,
            resume_hmac_keyring: None,
            resume_generation: 0,
            upstream_transport: Arc::new(IdleTransport),
        })
        .expect("session"),
    );
    let writer = crate::session_core_writer::BroadcastJsonRpcWriter::new(
        session.event_tx.clone(),
        session.retained_notification_events.clone(),
        session.next_event_id.clone(),
        session.session_id.clone(),
        session.input_tx.response_context(),
    );
    (session, writer)
}

fn info(index: usize) -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/message",
        "params": {"level": "info", "data": format!("n{index}")}})
}

fn flood(
    writer: &mut crate::session_core_writer::BroadcastJsonRpcWriter,
    range: std::ops::RangeInclusive<usize>,
) {
    for index in range {
        writer
            .write_all(format!("{}\n", info(index)).as_bytes())
            .expect("write notification");
    }
}

async fn take(source: &mut GetNotificationSource, count: usize) -> Vec<Value> {
    let mut delivered = Vec::new();
    for _ in 0..count {
        match source.next().await {
            GetNext::Deliver { message, .. } => delivered.push(message),
            GetNext::ResyncRequired => panic!("unexpected resync-required"),
            GetNext::Ended => panic!("unexpected end"),
        }
    }
    delivered
}

fn retained(seq: u64, message: Value) -> RetainedRemoteSessionEvent {
    RetainedRemoteSessionEvent {
        seq,
        event_id: format!("s-{seq}"),
        message,
    }
}

#[test]
fn a_newer_reread_hint_replaces_older_hints_with_the_same_meaning() {
    let tools = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
    let updated = |uri: &str| json!({"jsonrpc": "2.0", "method": "notifications/resources/updated", "params": {"uri": uri}});
    let mut window = VecDeque::new();
    retain(&mut window, retained(1, tools.clone()));
    retain(&mut window, retained(2, updated("file:///a")));
    retain(&mut window, retained(3, info(1)));
    retain(&mut window, retained(4, updated("file:///b")));
    retain(&mut window, retained(5, tools.clone()));
    retain(&mut window, retained(6, updated("file:///a")));
    retain(&mut window, retained(7, info(1)));
    let kept: Vec<u64> = window.iter().map(|event| event.seq).collect();
    assert_eq!(kept, vec![3, 4, 5, 6, 7]);
}

#[test]
fn the_window_keeps_the_newest_256_notifications() {
    let mut window = VecDeque::new();
    for seq in 1..=300 {
        retain(&mut window, retained(seq, info(seq as usize)));
    }
    assert_eq!(window.len(), 256);
    assert_eq!(window.front().map(|event| event.seq), Some(45));
    assert_eq!(window.back().map(|event| event.seq), Some(300));
}

#[tokio::test]
async fn a_lag_the_window_covers_replays_every_notification_without_resync() {
    let (session, mut writer) = session();
    let mut source =
        GetNotificationSource::new(session.clone(), session.subscribe(), 0, Vec::new());
    flood(&mut writer, 1..=20);

    let delivered = take(&mut source, 20).await;

    assert_eq!(delivered, (1..=20).map(info).collect::<Vec<_>>());
    assert_eq!(
        session.retained_notification_events.lock().unwrap().len(),
        20
    );
}

#[tokio::test]
async fn an_incomplete_lag_appends_one_resync_pass_after_the_retained_window() {
    let (session, mut writer) = session();
    let mut source =
        GetNotificationSource::new(session.clone(), session.subscribe(), 0, Vec::new());
    flood(&mut writer, 1..=300);

    let delivered = take(&mut source, 256).await;

    // The two resync items evict the two oldest of the 256 retained floods.
    assert_eq!(delivered.first(), Some(&info(47)));
    assert_eq!(delivered[253], info(300));
    assert_eq!(
        delivered[254],
        json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
    );
    assert_eq!(
        delivered[255],
        json!({"jsonrpc": "2.0", "method": "notifications/message",
            "params": {"level": "warning", "logger": "chio",
                "data": "notification stream skipped 292 session events; re-read every listed catalog and subscribed resource"}})
    );
}

#[tokio::test]
async fn consecutive_incomplete_lags_end_the_stream_with_resync_required() {
    let (session, mut writer) = session();
    let mut source =
        GetNotificationSource::new(session.clone(), session.subscribe(), 0, Vec::new());
    for round in 0..3 {
        flood(&mut writer, round * 300 + 1..=round * 300 + 300);
        assert_eq!(take(&mut source, 256).await.len(), 256);
    }
    flood(&mut writer, 901..=1200);

    assert!(matches!(source.next().await, GetNext::ResyncRequired));
    assert!(
        !*session.worker_serving_closed.borrow(),
        "resync-required closed the session"
    );
    assert_ne!(
        session.lifecycle_snapshot().state,
        RemoteSessionState::Closed
    );
}

#[tokio::test]
async fn a_closed_session_ends_the_stream() {
    let (session, mut writer) = session();
    let mut source =
        GetNotificationSource::new(session.clone(), session.subscribe(), 0, Vec::new());
    flood(&mut writer, 1..=3);
    session.worker_serving_closed.send_replace(true);

    assert!(matches!(source.next().await, GetNext::Ended));
}
