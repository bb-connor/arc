use super::*;
use chio_security_types::clock::{ClockReading, MonotonicInstant};

struct TestClock(StdMutex<Result<ClockReading, ClockError>>);
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().unwrap()
    }
}
fn reading(wall: u64, mono: u64) -> Result<ClockReading, ClockError> {
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
    let mut form = test_authorization_approval_form();
    form.code_challenge = pkce_s256("verifier");
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
            .exchange_authorization_code(&HeaderMap::new(), token_form(&code))
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.extensions().get::<Arc<ClockError>>().is_some());
        assert!(server.codes.lock().unwrap().contains_key(&code));
    }
    *source.0.lock().unwrap() = reading(1_000_000, 1);
    assert!(server
        .exchange_authorization_code(&HeaderMap::new(), token_form(&code))
        .is_ok());
    assert!(!server.codes.lock().unwrap().contains_key(&code));
    assert_eq!(
        server
            .exchange_authorization_code(&HeaderMap::new(), token_form(&code))
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
            .exchange_authorization_code(&HeaderMap::new(), token_form(&code))
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
                        .exchange_authorization_code(&HeaderMap::new(), token_form(&code))
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
    let (input_tx, _) = mpsc::channel();
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
