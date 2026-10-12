//! Restore re-authorizes every persisted subscription or never serves the session.
use super::cursor_seed::{ready_factory_session, restore_with_factory};
use super::*;
use chio_core::session::ResourceDefinition;

const URI: &str = "repo://docs/roadmap";

type RecordEdit = fn(&mut RemoteSessionResumeRecord);

/// Upstream state a test changes after the session is built.
#[derive(Debug, Default)]
struct Upstream {
    resource_absent: AtomicBool,
    notifications: StdMutex<Vec<Value>>,
}

#[derive(Debug)]
struct ResourceTransport(Arc<Upstream>);

impl McpTransport for ResourceTransport {
    fn capabilities(&self) -> chio_mcp_adapter::edge::McpServerCapabilities {
        chio_mcp_adapter::edge::McpServerCapabilities {
            resources_supported: true,
            resources_subscribe: true,
            ..Default::default()
        }
    }

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

    fn drain_notifications(&self) -> Vec<Value> {
        std::mem::take(&mut *self.0.notifications.lock().unwrap())
    }

    fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        if self.0.resource_absent.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }
        Ok(vec![ResourceDefinition {
            uri: URI.into(),
            name: "roadmap".into(),
            title: None,
            description: None,
            mime_type: None,
            size: None,
            annotations: None,
            icons: None,
        }])
    }
}

async fn rpc(session: &RemoteSession, message: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let id = message.get("id").ok_or("request id")?.clone();
    let mut events = session.subscribe();
    session.send(message)?;
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await?;
            if event.message.get("id") == Some(&id) {
                return Ok::<_, broadcast::error::RecvError>(event.message);
            }
        }
    })
    .await??)
}

fn stored(
    path: &FsPath,
    factory: &RemoteSessionFactory,
) -> Result<RemoteSessionResumeRecord, Box<dyn std::error::Error>> {
    let keyring = factory
        .resume_hmac_keyring
        .clone()
        .ok_or("resume keyring")?;
    let mut loaded = load_active_session_records(path, &keyring, factory.config.clock.millis()?)?;
    Ok(loaded.records.pop().ok_or("no active record")?)
}

struct Hosted {
    directory: PathBuf,
    path: PathBuf,
    factory: RemoteSessionFactory,
    upstream: Arc<Upstream>,
}

/// How far the clock cases move past the 300 second capability TTL.
const PAST_CAPABILITY_TTL_MILLIS: u64 = 301_000;

/// The default clock moved forward by a test-controlled offset.
struct OffsetClock {
    base: RemoteClock,
    offset_millis: AtomicU64,
}

impl Clock for OffsetClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let base = self.base.read()?;
        let offset = self.offset_millis.load(Ordering::SeqCst);
        Ok(ClockReading::new(
            base.unix_millis().checked_add(offset)?,
            base.monotonic().checked_add_millis(offset)?,
        ))
    }
}

impl Hosted {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_clock(label, None)
    }

    fn with_clock(
        label: &str,
        clock: Option<RemoteClock>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (directory, path) = private_test_session_database(label);
        let mut config = test_remote_config();
        if let Some(clock) = clock {
            config.clock = clock;
        }
        config.policy_path = directory.join("policy.yaml");
        std::fs::write(
            &config.policy_path,
            "capabilities:\n  default:\n    resources:\n      - uri: \"repo://docs/*\"\n        operations: [read, subscribe]\n        ttl: 300\n",
        )?;
        let upstream = Arc::new(Upstream::default());
        config.test_transport = Some(Arc::new(ResourceTransport(upstream.clone())));
        config.session_db_path = Some(path.clone());
        config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
        configure_signed_manifest(&mut config, &directory);
        let factory = RemoteSessionFactory::new(config)?;
        Ok(Self {
            directory,
            path,
            factory,
            upstream,
        })
    }

    fn ledger(&self) -> Result<RemoteSessionLedger, Box<dyn std::error::Error>> {
        Ok(RemoteSessionLedger::new(
            self.factory.config.clock.clone(),
            self.factory.config.lifecycle_policy(),
            Some(self.path.clone()),
            self.factory.resume_hmac_keyring.clone(),
        )?)
    }

    fn terminal(
        &self,
        session_id: &str,
    ) -> Result<Arc<RemoteSessionDiagnosticRecord>, Box<dyn std::error::Error>> {
        let keyring = self
            .factory
            .resume_hmac_keyring
            .clone()
            .ok_or("resume keyring")?;
        let now = self.factory.config.clock.millis()?;
        Ok(load_terminal_session_records(&self.path, &keyring, now)?
            .get(session_id)
            .cloned()
            .ok_or("no terminal record")?)
    }

    async fn subscribed_session(&self) -> Result<Arc<RemoteSession>, Box<dyn std::error::Error>> {
        let session =
            self.factory
                .spawn_session(SessionAuthContext::streamable_http_static_bearer(
                    "static-bearer:subscription-restore",
                    sha256_hex(b"subscription-restore-agent"),
                    None,
                ))?;
        ready_factory_session(&session).await?;
        session.send(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}))?;
        let response = rpc(
            &session,
            json!({"jsonrpc":"2.0", "id":2, "method":"resources/subscribe", "params":{"uri":URI}}),
        )
        .await?;
        assert_eq!(response["result"], json!({}), "{response}");
        Ok(session)
    }

    /// Re-signs the stored record one generation later with `edit` applied.
    fn rewrite(
        &self,
        edit: impl FnOnce(&mut RemoteSessionResumeRecord),
    ) -> Result<(), Box<dyn std::error::Error>> {
        let keyring = self
            .factory
            .resume_hmac_keyring
            .clone()
            .ok_or("resume keyring")?;
        let mut record = stored(&self.path, &self.factory)?;
        edit(&mut record);
        record.resume_generation += 1;
        record.resume_integrity.tag =
            compute_resume_record_integrity_tag(&keyring.current, &record)?;
        persist_active_session_record(
            &self.path,
            &record,
            &keyring,
            self.factory.config.clock.millis()?,
        )?;
        Ok(())
    }

    fn remove(self) -> Result<(), Box<dyn std::error::Error>> {
        drop(self.factory);
        std::fs::remove_dir_all(self.directory)?;
        Ok(())
    }
}

#[tokio::test]
async fn a_subscription_survives_restore_and_is_caught_up() -> Result<(), Box<dyn std::error::Error>>
{
    let hosted = Hosted::new("subscription-restore")?;
    let fresh = hosted.subscribed_session().await?;
    let record = stored(&hosted.path, &hosted.factory)?;
    assert_eq!(record.subscriptions.len(), 1);

    let restored = restore_with_factory(&hosted.path, &hosted.factory, &fresh.session_id)
        .await?
        .ok_or("the subscribed session was not served after restore")?;
    let persisted = stored(&hosted.path, &hosted.factory)?;
    assert_eq!(persisted.resume_generation, record.resume_generation + 1);
    assert_eq!(persisted.subscriptions, record.subscriptions);
    assert_eq!(restored.persisted_subscriptions()?, record.subscriptions);

    let caught_up = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (_, retained) = restored
                .replay_notifications_after(None)
                .map_err(|_| "retained notifications unavailable")?;
            if retained.iter().any(|event| {
                event.message["method"] == "notifications/resources/updated"
                    && event.message["params"]["uri"] == URI
            }) {
                return Ok::<_, &str>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        matches!(caught_up, Ok(Ok(()))),
        "no catch-up resources/updated after restore"
    );

    let response = rpc(
        &restored,
        json!({"jsonrpc":"2.0", "id":3, "method":"resources/unsubscribe", "params":{"uri":URI}}),
    )
    .await?;
    assert_eq!(response["result"], json!({}), "{response}");
    assert!(stored(&hosted.path, &hosted.factory)?
        .subscriptions
        .is_empty());

    drop((fresh, restored));
    hosted.remove()
}

#[tokio::test]
async fn a_subscription_that_fails_re_authorization_terminates_the_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let cases: [(&str, RecordEdit); 2] = [
        ("subscription-capability-gone", |record| {
            record.subscriptions = vec![PersistedSubscription::Standard {
                uri: URI.into(),
                capability_id: "capability-no-longer-held".into(),
            }];
        }),
        ("subscription-out-of-scope", |record| {
            let PersistedSubscription::Standard { capability_id, .. } = &record.subscriptions[0];
            record.subscriptions = vec![PersistedSubscription::Standard {
                uri: "repo://secret/plans".into(),
                capability_id: capability_id.clone(),
            }];
        }),
    ];
    for (label, edit) in cases {
        let hosted = Hosted::new(label)?;
        let fresh = hosted.subscribed_session().await?;
        hosted.rewrite(edit)?;
        let stored_generation = stored(&hosted.path, &hosted.factory)?.resume_generation;
        let keyring = hosted
            .factory
            .resume_hmac_keyring
            .clone()
            .ok_or("resume keyring")?;

        assert!(
            restore_with_factory(&hosted.path, &hosted.factory, &fresh.session_id)
                .await?
                .is_none()
        );
        let now = hosted.factory.config.clock.millis()?;
        assert!(load_active_session_records(&hosted.path, &keyring, now)?
            .records
            .is_empty());
        let terminal = load_terminal_session_records(&hosted.path, &keyring, now)?;
        let tombstone = terminal
            .get(&fresh.session_id)
            .ok_or("the failed restore left no terminal record")?;
        assert_eq!(tombstone.lifecycle.state, RemoteSessionState::Closed);
        assert_eq!(
            tombstone.terminal_reason,
            Some(TerminalReason::SubscriptionNotRestored)
        );
        let fence_epoch: i64 = rusqlite::Connection::open(&hosted.path)?.query_row(
            "SELECT terminal_epoch FROM remote_session_terminal_fences",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(fence_epoch as u64, stored_generation + 1);

        drop(fresh);
        hosted.remove()?;
    }
    Ok(())
}

fn controlled_clock() -> (Arc<OffsetClock>, RemoteClock) {
    let source = Arc::new(OffsetClock {
        base: RemoteClock::default(),
        offset_millis: AtomicU64::new(0),
    });
    let clock = RemoteClock::new(source.clone());
    (source, clock)
}

#[tokio::test]
async fn a_subject_absent_at_restore_and_recreated_stays_terminal(
) -> Result<(), Box<dyn std::error::Error>> {
    let hosted = Hosted::new("subscription-subject-absent")?;
    let fresh = hosted.subscribed_session().await?;
    hosted
        .upstream
        .resource_absent
        .store(true, Ordering::SeqCst);
    assert!(
        restore_with_factory(&hosted.path, &hosted.factory, &fresh.session_id)
            .await?
            .is_none()
    );
    hosted
        .upstream
        .resource_absent
        .store(false, Ordering::SeqCst);

    let terminal = hosted.terminal(&fresh.session_id)?;
    assert_eq!(
        terminal.terminal_reason,
        Some(TerminalReason::SubscriptionNotRestored)
    );
    let restarted = hosted.ledger()?;
    assert!(matches!(
        restarted.lookup(&fresh.session_id).await,
        Some(RemoteSessionEntry::Terminal(_))
    ));
    let renewed = hosted.subscribed_session().await?;
    assert_ne!(renewed.session_id, fresh.session_id);

    drop((fresh, renewed, restarted));
    hosted.remove()
}

#[tokio::test]
async fn an_update_without_authority_terminates_the_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let hosted = Hosted::new("subscription-authority-emission")?;
    let ledger = hosted.ledger()?;
    let session = hosted.subscribed_session().await?;
    ledger.insert_active(session.clone()).await;
    let mut serving_closed = session.worker_serving_closed.subscribe();

    hosted
        .upstream
        .resource_absent
        .store(true, Ordering::SeqCst);
    hosted.upstream.notifications.lock().unwrap().push(json!({
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": {"uri": URI},
    }));
    tokio::time::timeout(
        Duration::from_secs(10),
        serving_closed.wait_for(|closed| *closed),
    )
    .await??;
    let (_, retained) = session
        .replay_notifications_after(None)
        .map_err(|_| "retained notifications unavailable")?;
    assert!(!retained
        .iter()
        .any(|event| event.message["method"] == "notifications/resources/updated"));

    ledger.cleanup_due_sessions().await?;
    assert_eq!(
        hosted.terminal(&session.session_id)?.terminal_reason,
        Some(TerminalReason::SubscriptionAuthorityLost)
    );
    drop((session, ledger));
    hosted.remove()
}

#[tokio::test]
async fn a_quiet_subscription_ends_when_its_capability_expires(
) -> Result<(), Box<dyn std::error::Error>> {
    let (source, clock) = controlled_clock();
    let hosted = Hosted::with_clock("subscription-quiet-expiry", Some(clock))?;
    let ledger = hosted.ledger()?;
    let session = hosted.subscribed_session().await?;
    ledger.insert_active(session.clone()).await;

    ledger.cleanup_due_sessions().await?;
    assert!(matches!(
        ledger.lookup(&session.session_id).await,
        Some(RemoteSessionEntry::Active(_))
    ));

    source
        .offset_millis
        .store(PAST_CAPABILITY_TTL_MILLIS, Ordering::SeqCst);
    ledger.cleanup_due_sessions().await?;
    assert_eq!(
        hosted.terminal(&session.session_id)?.terminal_reason,
        Some(TerminalReason::SubscriptionAuthorityLost)
    );
    drop((session, ledger));
    hosted.remove()
}

#[tokio::test]
async fn authority_that_lapses_during_the_restore_persist_is_never_served(
) -> Result<(), Box<dyn std::error::Error>> {
    let (source, clock) = controlled_clock();
    let hosted = Hosted::with_clock("subscription-restore-lapse", Some(clock))?;
    let fresh = hosted.subscribed_session().await?;
    let stored_generation = stored(&hosted.path, &hosted.factory)?.resume_generation;
    let keyring = hosted
        .factory
        .resume_hmac_keyring
        .clone()
        .ok_or("resume keyring")?;
    let ledger = hosted.ledger()?;

    restore_persisted_sessions(&hosted.path, &keyring, &ledger, |record| {
        let restored = hosted.factory.restore_session(record);
        source
            .offset_millis
            .store(PAST_CAPABILITY_TTL_MILLIS, Ordering::SeqCst);
        restored
    })
    .await?;
    assert!(!matches!(
        ledger.lookup(&fresh.session_id).await,
        Some(RemoteSessionEntry::Active(_))
    ));
    assert_eq!(
        hosted.terminal(&fresh.session_id)?.terminal_reason,
        Some(TerminalReason::SubscriptionNotRestored)
    );
    let fence_epoch: i64 = rusqlite::Connection::open(&hosted.path)?.query_row(
        "SELECT terminal_epoch FROM remote_session_terminal_fences",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(fence_epoch as u64, stored_generation + 2);

    drop((fresh, ledger));
    hosted.remove()
}
