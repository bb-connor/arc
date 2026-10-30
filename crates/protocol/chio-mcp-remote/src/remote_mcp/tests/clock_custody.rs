use super::*;
use chio_security_types::clock::{ClockReading, MonotonicInstant};

#[path = "clock_custody/dispatch.rs"]
mod dispatch;

pub(super) struct TestClock(pub(super) StdMutex<Result<ClockReading, ClockError>>);
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().unwrap()
    }
}
pub(super) fn reading(wall: u64, mono: u64) -> Result<ClockReading, ClockError> {
    Ok(ClockReading::new(
        UnixMillis::new(wall),
        MonotonicInstant::from_nanos(mono),
    ))
}
fn token_form(code: &str) -> TokenRequestForm {
    serde_json::from_value(json!({"grant_type":"authorization_code", "code":code,
        "redirect_uri":"https://client.example/callback", "client_id":"client-abc", "code_verifier":"verifier"})).unwrap()
}
fn code(server: &LocalAuthorizationServer) -> String {
    let mut request = test_authorization_request();
    request.code_challenge = Some(pkce_s256("verifier"));
    let form = test_authorization_approval_form(server, &request, "approve");
    authorization_code_from_redirect(server.approve_authorization(form).unwrap())
}
#[test]
fn clock_fault_and_rollback_retain_authorization_code_until_successful_exchange() {
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000_000, 0))));
    let mut server = test_local_authorization_server();
    server.clock = RemoteClock::new(source.clone());
    let code = code(&server);
    for fault in [Err(ClockError::Unavailable), reading(999_000, 1)] {
        *source.0.lock().unwrap() = fault;
        let response = server
            .exchange_authorization_code((&HeaderMap::new()).into(), token_form(&code))
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.extensions().get::<Arc<ClockError>>().is_some());
        assert!(server.codes.lock().unwrap().contains_key(&code));
    }
    *source.0.lock().unwrap() = reading(1_000_000, 1);
    assert!(server
        .exchange_authorization_code((&HeaderMap::new()).into(), token_form(&code))
        .is_ok());
    assert!(!server.codes.lock().unwrap().contains_key(&code));
    assert_eq!(
        server
            .exchange_authorization_code((&HeaderMap::new()).into(), token_form(&code))
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
}
#[test]
fn authorization_code_expires_at_monotonic_deadline_with_frozen_wall_time() {
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000_000, 0))));
    let mut server = test_local_authorization_server();
    server.clock = RemoteClock::new(source.clone());
    let code = code(&server);
    *source.0.lock().unwrap() = reading(1_000_000, server.code_ttl_secs * 1_000_000_000);
    assert_eq!(
        server
            .exchange_authorization_code((&HeaderMap::new()).into(), token_form(&code))
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
}
#[test]
fn concurrent_exchange_consumes_one_grant_once() {
    let server = test_local_authorization_server();
    let code = code(&server);
    let successes = std::thread::scope(|scope| {
        let handles = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    server
                        .exchange_authorization_code((&HeaderMap::new()).into(), token_form(&code))
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(successes, 1);
}
#[test]
fn exhausted_counters_fail_without_wrapping() {
    let counter = AtomicU64::new(u64::MAX);
    assert_eq!(
        crate::clock::next_counter(&counter),
        Err(ClockError::Overflow)
    );
    assert_eq!(counter.load(Ordering::SeqCst), u64::MAX);
}

fn session_init(clock: RemoteClock) -> RemoteSessionInit {
    let (input_tx, _input_rx) = mcp_inbox();
    let (event_tx, _) = broadcast::channel(8);
    RemoteSessionInit {
        clock,
        session_id: "clock-session".into(),
        agent_id: "agent".into(),
        capabilities: vec![],
        issued_capabilities: vec![],
        auth_context: SessionAuthContext::streamable_http_static_bearer("agent", "token", None),
        auth_mode_fingerprint: "auth".into(),
        policy_fingerprint: "policy".into(),
        runtime_contract_fingerprint: "runtime".into(),
        hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
        lifecycle_policy: SessionLifecyclePolicy {
            idle_expiry_millis: 1_000,
            drain_grace_millis: 100,
            reaper_interval_millis: 10,
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
        session_db_path: None,
        approval_redemption: None,
        session_store_lease: None,
        resume_hmac_keyring: None,
        resume_generation: 0,
        upstream_transport: Arc::new(TestSessionTransport),
    }
}

#[test]
fn session_initialization_and_renewal_keep_state_on_clock_faults() {
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
    let session = RemoteSession::new(session_init(RemoteClock::new(source.clone()))).unwrap();
    *source.0.lock().unwrap() = Err(ClockError::Unavailable);
    assert!(matches!(
        session.mark_ready(Some("v1".into()), json!({}), PeerCapabilities::default()),
        Err(CliError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(
        session.lifecycle_snapshot().state,
        RemoteSessionState::Initializing
    );
    assert!(session.protocol_version.lock().unwrap().is_none());
    *source.0.lock().unwrap() = reading(1_000, 0);
    session
        .mark_ready(Some("v1".into()), json!({}), PeerCapabilities::default())
        .unwrap();
    for observation in [Err(ClockError::Unavailable), reading(999, 1)] {
        *source.0.lock().unwrap() = observation;
        assert!(matches!(session.touch(), Err(CliError::Clock(_))));
        assert!(matches!(session.begin_draining(), Err(CliError::Clock(_))));
        assert_eq!(session.lifecycle_snapshot().last_seen_at, 1_000);
        assert_eq!(
            session.lifecycle_snapshot().state,
            RemoteSessionState::Ready
        );
    }
    *source.0.lock().unwrap() = reading(1_000, 1_000_000_000);
    assert!(matches!(
        session.touch(),
        Err(CliError::Clock(ClockError::Expired))
    ));
    assert!(session.deadline_expired().unwrap());
    session.mark_terminal(RemoteSessionState::Expired, 1_000);
    assert!(matches!(
        session.mark_ready(None, json!({}), PeerCapabilities::default()),
        Err(CliError::Chio(_))
    ));
    assert_eq!(
        session.lifecycle_snapshot().state,
        RemoteSessionState::Expired
    );
}

#[test]
fn restored_session_rebuilds_deadline_without_reviving_expired_or_future_state() {
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
    let clock = RemoteClock::new(source.clone());
    let session = RemoteSession::new(session_init(clock.clone())).unwrap();
    session
        .mark_ready(None, json!({}), PeerCapabilities::default())
        .unwrap();
    let saved = session.lifecycle_snapshot();
    for (wall, expected) in [(999, ClockError::NotYetValid), (2_000, ClockError::Expired)] {
        // A restart owns a fresh monotonic origin. Persisted wall bounds remain authoritative.
        let fresh = RemoteClock::new(Arc::new(TestClock(StdMutex::new(reading(wall, 0)))));
        let mut init = session_init(fresh);
        init.lifecycle_snapshot = Some(saved.clone());
        assert!(
            matches!(RemoteSession::new(init), Err(CliError::Clock(error)) if error == expected)
        );
    }
    *source.0.lock().unwrap() = reading(1_500, 0);
    let mut init = session_init(clock);
    init.lifecycle_snapshot = Some(saved);
    let restored = RemoteSession::new(init).unwrap();
    *source.0.lock().unwrap() = reading(1_500, 500_000_000);
    assert!(restored.deadline_expired().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn persistence_counter_exhaustion_cannot_initialize_or_extend_live_authority() {
    let (directory, path) = private_test_session_database("clock-counter");
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
    let mut init = session_init(RemoteClock::new(source.clone()));
    init.session_store_lease = Some(acquire_test_session_store(&path));
    init.session_db_path = Some(path.clone());
    init.resume_hmac_keyring = Some(test_resume_hmac_keyring());
    init.resume_generation = u64::MAX;
    init.lifecycle_policy.idle_expiry_millis = 20_000;
    let session = RemoteSession::new(init).unwrap();
    assert!(matches!(
        session.mark_ready(None, json!({}), PeerCapabilities::default()),
        Err(CliError::Clock(ClockError::Overflow))
    ));
    assert_eq!(
        session.lifecycle_snapshot().state,
        RemoteSessionState::Initializing
    );
    assert!(session.initialize_params.lock().unwrap().is_none());
    session.resume_generation.store(0, Ordering::SeqCst);
    session
        .mark_ready(None, json!({}), PeerCapabilities::default())
        .unwrap();
    let before = session.lifecycle_snapshot();
    session.resume_generation.store(u64::MAX, Ordering::SeqCst);
    *source.0.lock().unwrap() = reading(6_000, 5_000_000_000);
    assert!(matches!(
        session.touch(),
        Err(CliError::Clock(ClockError::Overflow))
    ));
    let after = session.lifecycle_snapshot();
    assert_eq!(after.idle_expires_at, before.idle_expires_at);
    assert_eq!(after.last_seen_at, before.last_seen_at);
    let persisted = load_active_session_records(
        &path,
        session.resume_hmac_keyring.as_deref().unwrap(),
        6_000,
    )
    .unwrap();
    assert_eq!(
        persisted.records[0].lifecycle.idle_expires_at,
        before.idle_expires_at
    );
    drop(session);
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn persisted_transitions_use_one_fenced_observation() {
    struct OnceClock(StdMutex<Option<ClockReading>>);
    impl Clock for OnceClock {
        fn read(&self) -> Result<ClockReading, ClockError> {
            self.0.lock().unwrap().take().ok_or(ClockError::Unavailable)
        }
    }
    let (directory, path) = private_test_session_database("clock-once");
    let source = Arc::new(OnceClock(StdMutex::new(reading(1_000, 0).ok())));
    let mut init = session_init(RemoteClock::new(source.clone()));
    init.session_store_lease = Some(acquire_test_session_store(&path));
    init.session_db_path = Some(path);
    init.resume_hmac_keyring = Some(test_resume_hmac_keyring());
    init.lifecycle_policy.idle_expiry_millis = 20_000;
    let session = RemoteSession::new(init).unwrap();
    *source.0.lock().unwrap() = reading(1_000, 0).ok();
    session
        .mark_ready(None, json!({}), PeerCapabilities::default())
        .unwrap();
    *source.0.lock().unwrap() = reading(6_000, 5_000_000_000).ok();
    session.touch().unwrap();
    assert_eq!(session.lifecycle_snapshot().last_seen_at, 6_000);
    assert!(matches!(
        session.touch(),
        Err(CliError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(session.lifecycle_snapshot().idle_expires_at, 26_000);
    drop(session);
    std::fs::remove_dir_all(directory).unwrap();
}

const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

struct BlockingShutdownTransport {
    entered: std::sync::mpsc::Sender<()>,
    release: StdMutex<std::sync::mpsc::Receiver<()>>,
}

impl McpTransport for BlockingShutdownTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        TestSessionTransport.list_tools()
    }
    fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        TestSessionTransport.call_tool(name, arguments)
    }
    fn shutdown(&self) -> Result<(), AdapterError> {
        let _ = self.entered.send(());
        let _ = self.release.lock().unwrap().recv_timeout(HANG_BOUND);
        Ok(())
    }
}

fn ready_ledger_session(
    init: RemoteSessionInit,
    clock: RemoteClock,
) -> (RemoteSessionLedger, Arc<RemoteSession>) {
    let sessions =
        RemoteSessionLedger::new(clock, init.lifecycle_policy.clone(), None, None).unwrap();
    let session = Arc::new(RemoteSession::new(init).unwrap());
    session
        .mark_ready(None, json!({}), PeerCapabilities::default())
        .unwrap();
    (sessions, session)
}

fn is_terminal_entry(entry: &Option<RemoteSessionEntry>, state: RemoteSessionState) -> bool {
    matches!(entry, Some(RemoteSessionEntry::Terminal(record)) if record.lifecycle.state == state)
}

#[test]
fn terminal_transition_keeps_session_visible_while_upstream_shutdown_runs() {
    let runtime = || {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    };
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
    let clock = RemoteClock::new(source.clone());
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let mut init = session_init(clock.clone());
    init.upstream_transport = Arc::new(BlockingShutdownTransport {
        entered: entered_tx,
        release: StdMutex::new(release_rx),
    });
    let (sessions, session) = ready_ledger_session(init, clock);
    runtime().block_on(sessions.insert_active(session.clone()));
    *source.0.lock().unwrap() = reading(2_000, 1_000_000_000);

    let (entered, during_shutdown, expired) = std::thread::scope(|scope| {
        let expiry = scope.spawn(|| runtime().block_on(sessions.mark_expired(&session)));
        let entered = entered_rx.recv_timeout(HANG_BOUND);
        let entry = entered
            .is_ok()
            .then(|| runtime().block_on(sessions.lookup(&session.session_id)))
            .flatten();
        let _ = release_tx.send(());
        (entered, entry, expiry.join().unwrap())
    });

    assert!(entered.is_ok(), "upstream shutdown never started");
    expired.unwrap();
    assert!(
        is_terminal_entry(&during_shutdown, RemoteSessionState::Expired),
        "session must stay visible as terminal while upstream shutdown runs: {during_shutdown:?}"
    );
    assert!(is_terminal_entry(
        &runtime().block_on(sessions.lookup(&session.session_id)),
        RemoteSessionState::Expired
    ));
}

#[tokio::test]
async fn cancelled_terminal_transition_at_a_contended_map_leaves_session_live() {
    use std::{future::Future, task::Poll};
    for hold_active in [true, false] {
        let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
        let clock = RemoteClock::new(source.clone());
        let (sessions, session) = ready_ledger_session(session_init(clock.clone()), clock);
        sessions.insert_active(session.clone()).await;
        *source.0.lock().unwrap() = reading(2_000, 1_000_000_000);

        let active_guard = if hold_active {
            Some(sessions.active.lock().await)
        } else {
            None
        };
        let terminal_guard = sessions.terminal.lock().await;
        let mut expiry = Box::pin(sessions.mark_expired(&session));
        std::future::poll_fn(|cx| {
            assert!(expiry.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(expiry);
        drop(terminal_guard);
        drop(active_guard);

        assert_eq!(
            session.lifecycle_snapshot().state,
            RemoteSessionState::Ready,
            "hold_active={hold_active}"
        );
        assert!(
            matches!(
                sessions.lookup(&session.session_id).await,
                Some(RemoteSessionEntry::Active(_))
            ),
            "hold_active={hold_active}"
        );
        sessions.mark_expired(&session).await.unwrap();
        assert!(is_terminal_entry(
            &sessions.lookup(&session.session_id).await,
            RemoteSessionState::Expired
        ));
        let (active, terminal) = sessions.snapshot().await;
        assert!(active.is_empty());
        assert_eq!(terminal.len(), 1);
    }
}

#[tokio::test]
async fn cleanup_publishes_closed_sessions_before_leaving_active_lookup() {
    for serving_closed in [false, true] {
        let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
        let clock = RemoteClock::new(source.clone());
        let (sessions, session) = ready_ledger_session(session_init(clock.clone()), clock);
        sessions.insert_active(session.clone()).await;
        session.mark_terminal(RemoteSessionState::Closed, 1_000);
        session.worker_serving_closed.send_replace(serving_closed);

        sessions.cleanup_due_sessions().await.unwrap();
        assert!(
            is_terminal_entry(
                &sessions.lookup(&session.session_id).await,
                RemoteSessionState::Closed
            ),
            "serving_closed={serving_closed}"
        );
        let (active, terminal) = sessions.snapshot().await;
        assert!(active.is_empty(), "serving_closed={serving_closed}");
        assert_eq!(terminal.len(), 1, "serving_closed={serving_closed}");

        *source.0.lock().unwrap() = Err(ClockError::Unavailable);
        assert!(matches!(
            sessions.cleanup_due_sessions().await,
            Err(CliError::Clock(ClockError::Unavailable))
        ));
    }
}

fn fallback_app_state(
    directory: &std::path::Path,
    sessions: Arc<RemoteSessionLedger>,
) -> RemoteAppState {
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(&config.policy_path, "kernel:\n  allow_ephemeral_receipt_log: true\n  allow_ephemeral_revocation_store: true\n  durable_admission_mode: off\n  allow_unsafe_durable_admission_off: true\n").unwrap();
    config.wrapped_args.clear();
    config.test_transport = Some(Arc::new(TestSessionTransport));
    configure_signed_manifest(&mut config, directory);
    RemoteAppState {
        sessions,
        factory: Arc::new(RemoteSessionFactory::new(config).unwrap()),
        auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
            token: "fallback-token".into(),
        }),
        enterprise_provider_registry: None,
        admin_token: None,
        protected_resource_metadata: None,
        authorization_server_metadata: None,
        local_auth_server: None,
    }
}

fn assert_unpersisted_closed_diagnostic(
    entry: Option<RemoteSessionEntry>,
    session: &RemoteSession,
    last_seen_at: u64,
) {
    let Some(RemoteSessionEntry::Terminal(record)) = entry else {
        panic!("terminal fallback left the session invisible or active: {entry:?}");
    };
    assert_eq!(record.lifecycle.state, RemoteSessionState::Closed);
    assert_eq!(record.terminal_at, last_seen_at);
    assert!(matches!(
        session.send(json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"})),
        Err(CliError::Kernel(
            chio_kernel::KernelError::GovernedTransactionDenied(_)
        ))
    ));
}

#[tokio::test]
async fn stopped_worker_clock_fault_fallback_stays_visible_as_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
    let clock = RemoteClock::new(source.clone());
    let (sessions, session) = ready_ledger_session(session_init(clock.clone()), clock);
    let sessions = Arc::new(sessions);
    let state = fallback_app_state(directory.path(), sessions.clone());
    sessions.insert_active(session.clone()).await;
    *source.0.lock().unwrap() = Err(ClockError::Unavailable);
    assert!(matches!(
        sessions.mark_closed(&session).await,
        Err(CliError::Clock(ClockError::Unavailable))
    ));
    assert!(matches!(
        sessions.lookup(&session.session_id).await,
        Some(RemoteSessionEntry::Active(_))
    ));

    session_worker::close(&state, &session).await;

    assert_unpersisted_closed_diagnostic(
        sessions.lookup(&session.session_id).await,
        &session,
        1_000,
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn resume_persistence_fault_fallback_stays_visible_without_durable_claim() {
    let (store_directory, path) = private_test_session_database("terminal-fallback");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
    let clock = RemoteClock::new(source.clone());
    let init = session_init(clock.clone());
    let sessions = Arc::new(
        RemoteSessionLedger::new(
            clock,
            init.lifecycle_policy.clone(),
            Some(path.clone()),
            Some(keyring.clone()),
        )
        .unwrap(),
    );
    let session = Arc::new(RemoteSession::new(init).unwrap());
    session
        .mark_ready(None, json!({}), PeerCapabilities::default())
        .unwrap();
    let state = fallback_app_state(directory.path(), sessions.clone());
    sessions.insert_active(session.clone()).await;
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("CREATE TRIGGER refuse_terminal BEFORE INSERT ON remote_session_terminal_fences BEGIN SELECT RAISE(ABORT, 'injected fence outage'); END;")
        .unwrap();
    let fault = sessions.mark_closed(&session).await.unwrap_err();
    assert!(
        fault.to_string().contains("injected fence outage"),
        "{fault}"
    );
    assert!(matches!(
        sessions.lookup(&session.session_id).await,
        Some(RemoteSessionEntry::Active(_))
    ));

    let response = fail_closed_session_after_persistence_error(
        &state,
        &session,
        CliError::cli_other_error("injected resume persistence failure"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_unpersisted_closed_diagnostic(
        sessions.lookup(&session.session_id).await,
        &session,
        1_000,
    );
    assert!(load_terminal_session_records(&path, &keyring, 1_000)
        .unwrap()
        .is_empty());
    drop(connection);
    drop(lease);
    std::fs::remove_dir_all(store_directory).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn finalized_terminal_record_survives_repeated_retire_cleanup_and_close() {
    let (store_directory, path) = private_test_session_database("terminal-immutable");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000, 0))));
    let clock = RemoteClock::new(source.clone());
    let init = session_init(clock.clone());
    let sessions = Arc::new(
        RemoteSessionLedger::new(
            clock,
            init.lifecycle_policy.clone(),
            Some(path.clone()),
            Some(keyring.clone()),
        )
        .unwrap(),
    );
    let session = Arc::new(RemoteSession::new(init).unwrap());
    session
        .mark_ready(None, json!({}), PeerCapabilities::default())
        .unwrap();
    let state = fallback_app_state(directory.path(), sessions.clone());
    sessions.insert_active(session.clone()).await;
    *source.0.lock().unwrap() = reading(2_000, 1_000_000_000);
    sessions.mark_expired(&session).await.unwrap();

    let terminal_record = || async {
        match sessions.lookup(&session.session_id).await {
            Some(RemoteSessionEntry::Terminal(record)) => record,
            other => panic!("expected a terminal record: {other:?}"),
        }
    };
    let finalized = terminal_record().await;
    let finalized_bytes = serde_json::to_vec(finalized.as_ref()).unwrap();
    let durable = load_terminal_session_records(&path, &keyring, 2_000).unwrap();
    assert_eq!(
        serde_json::to_vec(durable[&session.session_id].as_ref()).unwrap(),
        finalized_bytes
    );

    sessions.retire_terminal(&session).await;
    sessions.mark_closed(&session).await.unwrap();
    session.worker_serving_closed.send_replace(true);
    sessions.cleanup_due_sessions().await.unwrap();
    session_worker::close(&state, &session).await;

    let retained = terminal_record().await;
    assert!(Arc::ptr_eq(&finalized, &retained));
    assert_eq!(
        serde_json::to_vec(retained.as_ref()).unwrap(),
        finalized_bytes
    );
    assert_eq!(retained.lifecycle.state, RemoteSessionState::Expired);
    let (active, terminal) = sessions.snapshot().await;
    assert!(active.is_empty());
    assert_eq!(terminal.len(), 1);
    drop(lease);
    std::fs::remove_dir_all(store_directory).unwrap();
}

fn consent_refusal_detail(
    server: &LocalAuthorizationServer,
    form: AuthorizationApprovalForm,
) -> String {
    let response = server
        .approve_authorization(form)
        .expect_err("consent answer must be refused");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response
        .headers()
        .get(axum::http::header::LOCATION)
        .is_none());
    let cause = response
        .extensions()
        .get::<Arc<OAuthRejection>>()
        .expect("local OAuth cause");
    assert_eq!(cause.kind, OAuthError::InvalidRequest);
    cause.local_detail().to_string()
}
#[test]
fn local_authorization_server_consent_nonce_is_single_use_and_expiring() {
    let source = Arc::new(TestClock(StdMutex::new(reading(1_000_000, 0))));
    let mut server = test_local_authorization_server();
    server.clock = RemoteClock::new(source.clone());
    let request = test_authorization_request();
    let missing = AuthorizationApprovalForm {
        consent_nonce: None,
        decision: "approve".to_string(),
    };
    assert_eq!(
        consent_refusal_detail(&server, missing),
        "missing consent_nonce"
    );
    let forged = AuthorizationApprovalForm {
        consent_nonce: Some("consent-forged".to_string()),
        decision: "approve".to_string(),
    };
    assert_eq!(
        consent_refusal_detail(&server, forged),
        "unknown or answered consent_nonce"
    );

    let denied = test_authorization_approval_form(&server, &request, "deny");
    let replayed = AuthorizationApprovalForm {
        consent_nonce: denied.consent_nonce.clone(),
        decision: "approve".to_string(),
    };
    assert_eq!(
        server
            .approve_authorization(denied)
            .expect_err("denial redirects")
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        consent_refusal_detail(&server, replayed),
        "unknown or answered consent_nonce"
    );

    let approved = test_authorization_approval_form(&server, &request, "approve");
    let replayed = AuthorizationApprovalForm {
        consent_nonce: approved.consent_nonce.clone(),
        decision: "approve".to_string(),
    };
    authorization_code_from_redirect(server.approve_authorization(approved).unwrap());
    assert_eq!(
        consent_refusal_detail(&server, replayed),
        "unknown or answered consent_nonce"
    );

    let late = test_authorization_approval_form(&server, &request, "approve");
    *source.0.lock().unwrap() = reading(1_000_000, server.code_ttl_secs * 1_000_000_000);
    assert_eq!(
        consent_refusal_detail(&server, late),
        "consent_nonce expired"
    );
}
