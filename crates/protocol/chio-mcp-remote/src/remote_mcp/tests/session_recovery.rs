use super::*;
use chio_security_types::clock::{ClockReading, MonotonicInstant};

struct RecoveryClock(StdMutex<Result<ClockReading, ClockError>>);
impl Clock for RecoveryClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}
fn reading(now: u64) -> Result<ClockReading, ClockError> {
    Ok(ClockReading::new(
        UnixMillis::new(now),
        MonotonicInstant::from_nanos(now),
    ))
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_restoration_preserves_authenticated_session_bytes() {
    let (directory, path) = private_test_session_database("restore-failure");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let record = sample_resume_record_with_keyring(&keyring);
    persist_active_session_record(&path, &record, &keyring, session_now_millis())
        .expect("persist session");
    let sessions = RemoteSessionLedger::new(
        RemoteClock::new(Arc::new(RecoveryClock(StdMutex::new(reading(11))))),
        SessionLifecyclePolicy::from_env(),
        None,
        None,
    )
    .expect("session ledger");
    let error = restore_persisted_sessions(&path, &keyring, &sessions, |_| {
        Err(CliError::cli_other_error(
            "retained hold authority unavailable".to_owned(),
        ))
    })
    .await
    .expect_err("recovery outage must fail startup");
    assert!(error.to_string().contains("authority unavailable"));
    assert!(sessions.lookup(&record.session_id).await.is_none());
    let retained =
        load_active_session_records(&path, &keyring, session_now_millis()).expect("reload session");
    assert!(retained.invalid_session_ids.is_empty());
    assert_eq!(retained.records.len(), 1);
    assert_eq!(
        serde_json::to_vec(&retained.records[0]).expect("retained bytes"),
        serde_json::to_vec(&record).expect("original bytes")
    );

    // An intentional configuration change may leave the session inactive,
    // but it does not authorize deleting authenticated recovery material.
    restore_persisted_sessions(&path, &keyring, &sessions, |_| Ok(None))
        .await
        .expect("incompatible session remains inactive");
    assert!(sessions.lookup(&record.session_id).await.is_none());
    assert_eq!(
        load_active_session_records(&path, &keyring, session_now_millis())
            .expect("reload inactive session")
            .records
            .len(),
        1
    );
    drop(lease);
    std::fs::remove_dir_all(directory).expect("remove test session directory");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn expired_ready_recovery_is_durable_before_any_upstream_launch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, path) = private_test_session_database("expired-recovery");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let record = sample_resume_record_with_keyring(&keyring);
    persist_active_session_record(&path, &record, &keyring, 12)?;
    let sessions = RemoteSessionLedger::new(
        RemoteClock::new(Arc::new(RecoveryClock(StdMutex::new(reading(12))))),
        SessionLifecyclePolicy::from_env(),
        None,
        None,
    )?;
    let mut launched = 0;
    for _ in 0..2 {
        restore_persisted_sessions(&path, &keyring, &sessions, |_| {
            launched += 1;
            Err(ClockError::Expired.into())
        })
        .await?;
    }
    assert_eq!(launched, 0);
    assert!(load_active_session_records(&path, &keyring, 12)?
        .records
        .is_empty());
    let terminal = load_terminal_session_records(&path, &keyring, 12)?;
    assert_eq!(
        terminal
            .get(&record.session_id)
            .ok_or("missing tombstone")?
            .lifecycle
            .state,
        RemoteSessionState::Expired
    );
    assert!(persist_active_session_record(&path, &record, &keyring, 12).is_err());
    drop(lease);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recovery_clock_fault_or_future_record_preserves_active_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, path) = private_test_session_database("future-recovery");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let record = sample_resume_record_with_keyring(&keyring);
    persist_active_session_record(&path, &record, &keyring, 11)?;
    for time in [Err(ClockError::Unavailable), reading(10)] {
        let sessions = RemoteSessionLedger::new(
            RemoteClock::new(Arc::new(RecoveryClock(StdMutex::new(time)))),
            SessionLifecyclePolicy::from_env(),
            None,
            None,
        )?;
        let mut launched = false;
        assert!(restore_persisted_sessions(&path, &keyring, &sessions, |_| {
            launched = true;
            Ok(None)
        })
        .await
        .is_err());
        assert!(!launched);
        assert_eq!(
            load_active_session_records(&path, &keyring, 11)?
                .records
                .len(),
            1
        );
        assert!(load_terminal_session_records(&path, &keyring, 11)?.is_empty());
    }
    drop(lease);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn expiry_during_recovery_is_terminal_but_unrelated_expiry_is_retained(
) -> Result<(), Box<dyn std::error::Error>> {
    for session_expires in [false, true] {
        let (directory, path) = private_test_session_database("recovery-race");
        let lease = acquire_test_session_store(&path);
        let keyring = test_resume_hmac_keyring();
        let record = sample_resume_record_with_keyring(&keyring);
        persist_active_session_record(&path, &record, &keyring, 11)?;
        let source = Arc::new(RecoveryClock(StdMutex::new(reading(11))));
        let sessions = RemoteSessionLedger::new(
            RemoteClock::new(source.clone()),
            SessionLifecyclePolicy::from_env(),
            None,
            None,
        )?;
        let outcome = restore_persisted_sessions(&path, &keyring, &sessions, |_| {
            if session_expires {
                // A frozen wall clock must not extend the original restore lease.
                *source.0.lock().unwrap() = Ok(ClockReading::new(
                    UnixMillis::new(11),
                    MonotonicInstant::from_nanos(1_000_011),
                ));
            }
            Err(ClockError::Expired.into())
        })
        .await;
        assert_eq!(outcome.is_ok(), session_expires);
        assert_eq!(
            load_active_session_records(&path, &keyring, 11)?
                .records
                .is_empty(),
            session_expires
        );
        assert_eq!(
            load_terminal_session_records(&path, &keyring, 11)?.contains_key(&record.session_id),
            session_expires
        );
        drop(lease);
        std::fs::remove_dir_all(directory)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_expiry_fence_preserves_recovery_material() -> Result<(), Box<dyn std::error::Error>>
{
    let (directory, path) = private_test_session_database("recovery-fence-fault");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let record = sample_resume_record_with_keyring(&keyring);
    persist_active_session_record(&path, &record, &keyring, 12)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("CREATE TRIGGER refuse_expiry BEFORE INSERT ON remote_session_terminal_fences BEGIN SELECT RAISE(ABORT, 'injected fence outage'); END;")?;
    let sessions = RemoteSessionLedger::new(
        RemoteClock::new(Arc::new(RecoveryClock(StdMutex::new(reading(12))))),
        SessionLifecyclePolicy::from_env(),
        None,
        None,
    )?;
    let mut launched = false;
    assert!(restore_persisted_sessions(&path, &keyring, &sessions, |_| {
        launched = true;
        Ok(None)
    })
    .await
    .is_err());
    assert!(!launched);
    assert_eq!(
        load_active_session_records(&path, &keyring, 12)?
            .records
            .len(),
        1
    );
    assert!(load_terminal_session_records(&path, &keyring, 12)?.is_empty());
    drop(connection);
    drop(lease);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[derive(Debug, Default)]
struct RecoveryTransport(AtomicU64);
impl McpTransport for RecoveryTransport {
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
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn restored_transport_obeys_original_deadline_and_stops_even_if_fencing_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    for (elapsed_ns, persistence_fails) in [(500_000, false), (1_000_000, false), (1_000_000, true)]
    {
        let (directory, path) = private_test_session_database("restored-transport");
        let lease = acquire_test_session_store(&path);
        let keyring = test_resume_hmac_keyring();
        let record = sample_resume_record_with_keyring(&keyring);
        persist_active_session_record(&path, &record, &keyring, 11)?;
        if persistence_fails {
            rusqlite::Connection::open(&path)?.execute_batch("CREATE TRIGGER refuse_expiry BEFORE INSERT ON remote_session_terminal_fences BEGIN SELECT RAISE(ABORT, 'injected fence outage'); END;")?;
        }
        let source = Arc::new(RecoveryClock(StdMutex::new(reading(11))));
        let clock = RemoteClock::new(source.clone());
        let sessions = RemoteSessionLedger::new(
            clock.clone(),
            SessionLifecyclePolicy::from_env(),
            None,
            None,
        )?;
        let transport = Arc::new(RecoveryTransport::default());
        let result = restore_persisted_sessions(&path, &keyring, &sessions, |record| {
            *source.0.lock().unwrap() = Ok(ClockReading::new(
                UnixMillis::new(11),
                MonotonicInstant::from_nanos(11 + elapsed_ns),
            ));
            // Construction sees a fresh local instant after upstream setup.
            // Startup recovery must restore the earlier deadline before use.
            let (input_tx, _input_rx) = mpsc::channel();
            let (event_tx, _) = broadcast::channel(8);
            let session = RemoteSession::new(RemoteSessionInit {
                clock: clock.clone(),
                session_id: record.session_id.clone(),
                agent_id: record.agent_id.clone(),
                capabilities: Vec::new(),
                issued_capabilities: record.issued_capabilities.clone(),
                auth_context: record.auth_context.clone(),
                auth_mode_fingerprint: record.auth_mode_fingerprint.clone().unwrap_or_default(),
                policy_fingerprint: record.policy_fingerprint.clone().unwrap_or_default(),
                runtime_contract_fingerprint: record.runtime_contract_fingerprint.clone(),
                hosted_isolation: record.hosted_isolation,
                lifecycle_policy: SessionLifecyclePolicy::from_env(),
                protocol_version: record.protocol_version.clone(),
                peer_capabilities: Some(record.peer_capabilities.clone()),
                initialize_params: Some(record.initialize_params.clone()),
                lifecycle_snapshot: Some(record.lifecycle.clone()),
                input_tx,
                event_tx,
                retained_notification_events: Arc::new(StdMutex::new(VecDeque::new())),
                next_event_id: Arc::new(AtomicU64::new(0)),
                session_db_path: Some(path.clone()),
                approval_redemption: None,
                session_store_lease: Some(lease.clone()),
                resume_hmac_keyring: Some(keyring.clone()),
                resume_generation: record.resume_generation,
                upstream_transport: transport.clone(),
            })?;
            Ok(Some(Arc::new(session)))
        })
        .await;
        assert_eq!(result.is_err(), persistence_fails);
        if elapsed_ns < 1_000_000 {
            let Some(RemoteSessionEntry::Active(session)) =
                sessions.lookup(&record.session_id).await
            else {
                return Err("unexpired session not restored".into());
            };
            let deadline = session
                .lifecycle
                .lock()
                .unwrap()
                .deadline
                .ok_or("missing deadline")?;
            let mut deadline = deadline;
            assert_eq!(
                deadline.remaining(ClockReading::new(
                    UnixMillis::new(11),
                    MonotonicInstant::from_nanos(1_000_011)
                )),
                Err(ClockError::Expired)
            );
            assert_eq!(transport.0.load(Ordering::SeqCst), 0);
        } else {
            assert!(!matches!(
                sessions.lookup(&record.session_id).await,
                Some(RemoteSessionEntry::Active(_))
            ));
            assert!(
                transport.0.load(Ordering::SeqCst) >= 1,
                "expired restored transport must stop even when durable fencing fails"
            );
            assert_eq!(
                load_active_session_records(&path, &keyring, 11)?
                    .records
                    .len(),
                usize::from(persistence_fails)
            );
        }
        drop(sessions);
        drop(lease);
        std::fs::remove_dir_all(directory)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn committed_expiry_fence_survives_failed_tombstone_finalization_and_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, path) = private_test_session_database("expiry-finalize-failure");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let record = sample_resume_record_with_keyring(&keyring);
    persist_active_session_record(&path, &record, &keyring, 12)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("CREATE TRIGGER refuse_finalization BEFORE INSERT ON remote_session_tombstones BEGIN SELECT RAISE(ABORT, 'injected tombstone outage'); END;")?;
    let clock = RemoteClock::new(Arc::new(RecoveryClock(StdMutex::new(reading(12)))));
    let sessions = RemoteSessionLedger::new(
        clock.clone(),
        SessionLifecyclePolicy::from_env(),
        Some(path.clone()),
        Some(keyring.clone()),
    )?;
    let mut launched = false;
    assert!(restore_persisted_sessions(&path, &keyring, &sessions, |_| {
        launched = true;
        Ok(None)
    })
    .await
    .is_err());
    assert!(!launched);
    assert!(load_active_session_records(&path, &keyring, 12)?
        .records
        .is_empty());
    assert!(load_terminal_session_records(&path, &keyring, 12)?.is_empty());
    let fences: i64 = connection.query_row(
        "SELECT COUNT(*) FROM remote_session_terminal_fences",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(fences, 1);
    connection.execute_batch("DROP TRIGGER refuse_finalization")?;
    drop(sessions);
    let restarted = RemoteSessionLedger::new(
        clock,
        SessionLifecyclePolicy::from_env(),
        Some(path.clone()),
        Some(keyring.clone()),
    )?;
    restore_persisted_sessions(&path, &keyring, &restarted, |_| {
        launched = true;
        Ok(None)
    })
    .await?;
    assert!(!launched);
    assert!(persist_active_session_record(&path, &record, &keyring, 12).is_err());
    drop(restarted);
    drop(connection);
    drop(lease);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
