//! Restored incarnations seed event ids above every earlier incarnation.
use super::*;

#[derive(Debug)]
pub(super) struct ReadOnlyTransport;

impl McpTransport for ReadOnlyTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        Ok(vec![chio_mcp_adapter::edge::McpToolInfo {
            name: "read".into(),
            title: None,
            description: Some("Read".into()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            annotations: Some(json!({"readOnlyHint": true, "destructiveHint": false})),
            execution: None,
        }])
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        TestSessionTransport.call_tool(tool_name, arguments)
    }
}

pub(super) async fn ready_factory_session(
    session: &RemoteSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let params = json!({"protocolVersion":"2025-11-25", "capabilities":{},
        "clientInfo":{"name":"cursor-seed","version":"1"}});
    let mut events = session.subscribe();
    session.send(json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":params}))?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if events.recv().await?.message.get("id") == Some(&json!(1)) {
                return Ok::<_, broadcast::error::RecvError>(());
            }
        }
    })
    .await??;
    let mut peer = parse_remote_session_peer_capabilities(&params);
    peer.authorization =
        Some(chio_mcp_adapter::edge::authorization::negotiate_authorization_capabilities(&params)?);
    session.mark_ready(Some("2025-11-25".into()), params, peer)?;
    Ok(())
}

/// Publishes `count` notifications through the session's own output writer
/// and returns the id of the last one.
fn publish_notifications(
    session: &RemoteSession,
    count: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut writer = BroadcastJsonRpcWriter::new(
        session.event_tx.clone(),
        session.retained_notification_events.clone(),
        session.next_event_id.clone(),
        session.session_id.clone(),
        session.input_tx.response_context(),
    );
    for sequence in 0..count {
        let mut line = serde_json::to_vec(&json!({"jsonrpc":"2.0",
            "method":"notifications/message","params":{"level":"info","data":sequence}}))?;
        line.push(b'\n');
        writer.write_all(&line)?;
    }
    let retained = session
        .retained_notification_events
        .lock()
        .map_err(|_| "retained notifications poisoned")?;
    Ok(retained
        .back()
        .ok_or("no retained notification")?
        .event_id
        .clone())
}

async fn restore_with_factory(
    path: &FsPath,
    factory: &RemoteSessionFactory,
    session_id: &str,
) -> Result<Option<Arc<RemoteSession>>, Box<dyn std::error::Error>> {
    let keyring = factory
        .resume_hmac_keyring
        .clone()
        .ok_or("resume keyring")?;
    let sessions = RemoteSessionLedger::new(
        factory.config.clock.clone(),
        factory.config.lifecycle_policy(),
        None,
        None,
    )?;
    restore_persisted_sessions(path, &keyring, &sessions, |record| {
        factory.restore_session(record)
    })
    .await?;
    Ok(match sessions.lookup(session_id).await {
        Some(RemoteSessionEntry::Active(session)) => Some(session),
        _ => None,
    })
}

fn persisted_generation(
    path: &FsPath,
    factory: &RemoteSessionFactory,
) -> Result<u64, Box<dyn std::error::Error>> {
    let keyring = factory
        .resume_hmac_keyring
        .clone()
        .ok_or("resume keyring")?;
    let loaded = load_active_session_records(path, &keyring, factory.config.clock.millis()?)?;
    Ok(loaded
        .records
        .first()
        .ok_or("no active record")?
        .resume_generation)
}

fn assert_cursor_refused(session: &RemoteSession, cursor: &str) {
    match session.replay_notifications_after(Some(cursor)) {
        Err(response) => assert_eq!(response.status(), StatusCode::CONFLICT),
        Ok((after, replay)) => panic!(
            "cursor {cursor} from an earlier incarnation aliased into replay after {after} ({} events)",
            replay.len()
        ),
    }
}

#[tokio::test]
async fn restored_incarnations_refuse_cursors_from_earlier_incarnations(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, path) = private_test_session_database("cursor-seed");
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(
        &config.policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )?;
    config.test_transport = Some(Arc::new(ReadOnlyTransport));
    config.session_db_path = Some(path.clone());
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
    configure_signed_manifest(&mut config, &directory);
    let factory = RemoteSessionFactory::new(config)?;

    let fresh = factory.spawn_session(SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:cursor-seed",
        sha256_hex(b"cursor-seed-agent"),
        None,
    ))?;
    ready_factory_session(&fresh).await?;
    let session_id = fresh.session_id.clone();
    let fresh_cursor = publish_notifications(&fresh, 4)?;
    let fresh_generation = persisted_generation(&path, &factory)?;

    let first = restore_with_factory(&path, &factory, &session_id)
        .await?
        .ok_or("first restore was not served")?;
    // Enough later notifications that an unseeded incarnation reaches the
    // stale cursor's sequence inside its replay window.
    let published = parse_session_event_id(&fresh_cursor, &session_id)? + 2;
    let first_cursor = publish_notifications(&first, published)?;
    assert_cursor_refused(&first, &fresh_cursor);
    assert_eq!(persisted_generation(&path, &factory)?, fresh_generation + 1);

    // No session write separates the two restores.
    let second = restore_with_factory(&path, &factory, &session_id)
        .await?
        .ok_or("second restore was not served")?;
    publish_notifications(&second, published)?;
    assert_cursor_refused(&second, &first_cursor);
    assert_cursor_refused(&second, &fresh_cursor);
    assert_eq!(persisted_generation(&path, &factory)?, fresh_generation + 2);

    // A failed generation persist leaves the session unserved and startup running.
    rusqlite::Connection::open(&path)?.execute_batch(
        "CREATE TRIGGER refuse_active_update BEFORE UPDATE ON remote_active_sessions \
         BEGIN SELECT RAISE(ABORT, 'injected generation persist outage'); END; \
         CREATE TRIGGER refuse_active_insert BEFORE INSERT ON remote_active_sessions \
         BEGIN SELECT RAISE(ABORT, 'injected generation persist outage'); END;",
    )?;
    assert!(restore_with_factory(&path, &factory, &session_id)
        .await?
        .is_none());
    assert_eq!(persisted_generation(&path, &factory)?, fresh_generation + 2);

    drop((fresh, first, second, factory));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[tokio::test]
async fn restore_retains_records_it_cannot_serve() -> Result<(), Box<dyn std::error::Error>> {
    let (directory, path) = private_test_session_database("cursor-seed-bound");
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(
        &config.policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )?;
    config.test_transport = Some(Arc::new(ReadOnlyTransport));
    config.session_db_path = Some(path.clone());
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
    configure_signed_manifest(&mut config, &directory);
    let factory = RemoteSessionFactory::new(config)?;
    let keyring = factory
        .resume_hmac_keyring
        .clone()
        .ok_or("resume keyring")?;
    let fresh = factory.spawn_session(SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:cursor-seed",
        sha256_hex(b"cursor-seed-agent"),
        None,
    ))?;
    ready_factory_session(&fresh).await?;
    let mut record = fresh.resume_record()?.ok_or("fresh record")?;

    record.resume_generation = u64::from(u32::MAX) - 1;
    let last = factory
        .restore_session(&sign_test_resume_record(record.clone(), &keyring))?
        .ok_or("the last seedable generation was not restorable")?;
    let first_id = publish_notifications(&last, 1)?;
    assert_eq!(
        parse_session_event_id(&first_id, &last.session_id)?,
        (u64::from(u32::MAX) << 32) + 1
    );

    record.resume_generation = u64::from(u32::MAX);
    assert!(factory
        .restore_session(&sign_test_resume_record(record, &keyring))?
        .is_none());

    let mut subscribed = fresh.resume_record()?.ok_or("fresh record")?;
    assert_eq!(
        subscribed.resume_integrity.envelope,
        RemoteSessionEnvelope::V3
    );
    subscribed.subscriptions = vec![PersistedSubscription::Standard {
        uri: "file:///workspace/notes.txt".into(),
        capability_id: "capability-subscribe".into(),
    }];
    subscribed.resume_integrity.tag =
        compute_resume_record_integrity_tag(&keyring.current, &subscribed)?;
    assert!(factory.restore_session(&subscribed)?.is_none());

    drop((fresh, last, factory));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
