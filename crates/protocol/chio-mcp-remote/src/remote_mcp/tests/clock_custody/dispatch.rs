//! Session authority is checked again at the queue admission boundary.
use super::*;

fn tool_call() -> Value {
    json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"test", "arguments":{}}})
}

fn ready_session() -> (Arc<TestClock>, Arc<RemoteSession>, McpInboxReceiver) {
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
    let mut init = session_init(RemoteClock::new(source.clone()));
    let (tx, rx) = mcp_inbox();
    init.input_tx = tx;
    let session = Arc::new(RemoteSession::new(init).unwrap());
    session
        .mark_ready(None, json!({}), PeerCapabilities::default())
        .unwrap();
    (source, session, rx)
}

#[test]
fn p0p1_session_send_refuses_terminal_and_draining_handles() {
    for state in [
        RemoteSessionState::Closed,
        RemoteSessionState::Deleted,
        RemoteSessionState::Expired,
        RemoteSessionState::Draining,
    ] {
        let (_, session, rx) = ready_session();
        session.send(tool_call()).unwrap();
        assert_eq!(*rx.try_recv().unwrap().unwrap().value(), tool_call());
        if state == RemoteSessionState::Draining {
            session.begin_draining().unwrap();
        } else {
            session.mark_terminal(state, 1_000);
        }
        assert!(
            matches!(
                session.send(tool_call()),
                Err(CliError::Kernel(
                    chio_kernel::KernelError::GovernedTransactionDenied(_)
                ))
            ),
            "{state:?}"
        );
        assert!(matches!(rx.try_recv(), Ok(None)));
    }
}

#[test]
fn p0p1_session_send_refuses_expired_and_faulted_clocks() {
    for fault in [
        reading(2_000, 1_000_000_000),
        reading(1_000, 1_000_000_000),
        reading(999, 1),
        Err(ClockError::Unavailable),
    ] {
        let (clock, session, rx) = ready_session();
        *clock.0.lock().unwrap() = fault;
        assert!(matches!(session.send(tool_call()), Err(CliError::Clock(_))));
        assert!(matches!(rx.try_recv(), Ok(None)));
    }
}

#[test]
fn p0p1_initializing_session_only_accepts_initialize() {
    let mut init = session_init(RemoteClock::new(Arc::new(TestClock(StdMutex::new(
        reading(1_000, 0),
    )))));
    let (tx, rx) = mcp_inbox();
    init.input_tx = tx;
    let session = RemoteSession::new(init).unwrap();
    assert!(matches!(
        session.send(tool_call()),
        Err(CliError::Kernel(
            chio_kernel::KernelError::GovernedTransactionDenied(_)
        ))
    ));
    assert!(matches!(rx.try_recv(), Ok(None)));
    let initialize = json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}});
    session.send(initialize.clone()).unwrap();
    assert_eq!(*rx.try_recv().unwrap().unwrap().value(), initialize);
}

#[tokio::test]
async fn p0p1_http_request_waiting_for_stream_cannot_send_after_close() {
    use std::{future::Future, task::Poll};
    let directory = tempfile::tempdir().unwrap();
    let mut config = test_remote_config();
    config.policy_path = directory.path().join("policy.yaml");
    std::fs::write(&config.policy_path, "kernel:\n  allow_ephemeral_receipt_log: true\n  allow_ephemeral_revocation_store: true\n  durable_admission_mode: off\n  allow_unsafe_durable_admission_off: true\n").unwrap();
    config.wrapped_args.clear();
    config.test_transport = Some(Arc::new(TestSessionTransport));
    configure_signed_manifest(&mut config, directory.path());
    let factory = Arc::new(RemoteSessionFactory::new(config).unwrap());
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer queue-token"),
    );
    let clock = RemoteClock::new(Arc::new(TestClock(StdMutex::new(reading(1_000, 0)))));
    let mut init = session_init(clock.clone());
    init.auth_context = build_static_bearer_session_auth_context(&headers, "queue-token");
    let (tx, rx) = mcp_inbox();
    init.input_tx = tx;
    let sessions = Arc::new(
        RemoteSessionLedger::new(clock, init.lifecycle_policy.clone(), None, None).unwrap(),
    );
    let session = Arc::new(RemoteSession::new(init).unwrap());
    session
        .mark_ready(None, json!({}), PeerCapabilities::default())
        .unwrap();
    sessions.insert_active(session.clone()).await;
    let state = RemoteAppState {
        sessions: sessions.clone(),
        factory,
        auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
            token: "queue-token".into(),
        }),
        enterprise_provider_registry: None,
        admin_token: None,
        protected_resource_metadata: None,
        authorization_server_metadata: None,
        local_auth_server: None,
    };
    let held_stream = session.active_request_stream.clone().lock_owned().await;
    let request = Request::builder()
        .method("POST")
        .uri(MCP_ENDPOINT_PATH)
        .header(AUTHORIZATION, "Bearer queue-token")
        .header(MCP_SESSION_ID_HEADER, &session.session_id)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(tool_call().to_string()))
        .unwrap();
    let mut response = Box::pin(handle_post(State(state), request));
    std::future::poll_fn(|cx| {
        assert!(response.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // A POST waiting for the stream lock holds no session event subscription.
    assert_eq!(session.event_tx.receiver_count(), 0);
    sessions.mark_closed(&session).await.unwrap();
    drop(held_stream);
    let response = response.await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(matches!(rx.try_recv(), Ok(None)));
}
