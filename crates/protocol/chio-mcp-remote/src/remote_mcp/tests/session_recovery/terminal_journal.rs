//! Startup finishes, clears or refuses each journaled terminal tombstone.
use super::*;

struct Store {
    directory: PathBuf,
    path: PathBuf,
    lease: Arc<RemoteSessionStoreLifecycleLease>,
    keyring: Arc<RemoteSessionHmacKeyring>,
    session_id: String,
}

impl Store {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let (directory, path) = private_test_session_database(label);
        let lease = acquire_test_session_store(&path);
        let keyring = test_resume_hmac_keyring();
        let record = sample_resume_record_with_keyring(&keyring);
        persist_active_session_record(&path, &record, &keyring, 12)?;
        Ok(Self {
            directory,
            path,
            lease,
            keyring,
            session_id: record.session_id,
        })
    }

    fn sign(
        &self,
        terminal_at: u64,
    ) -> Result<(RemoteSessionTombstoneRecord, RemoteSessionTerminalFence), CliError> {
        let active = sample_resume_record_with_keyring(&self.keyring);
        let mut lifecycle = active.lifecycle.clone();
        lifecycle.state = RemoteSessionState::Closed;
        let record = RemoteSessionDiagnosticRecord {
            session_id: active.session_id,
            auth_context: active.auth_context,
            capabilities: Vec::new(),
            lifecycle,
            protocol_version: active.protocol_version,
            ownership: RemoteSessionOwnershipSnapshot::default(),
            terminal_at,
            terminal_reason: None,
        };
        sign_terminal_session_records(
            &self.keyring,
            record,
            TerminalReason::SubscriptionAuthorityLost,
            2,
            2,
        )
    }

    fn boot(&self) -> Result<RemoteSessionLedger, CliError> {
        RemoteSessionLedger::new(
            RemoteClock::new(Arc::new(RecoveryClock(StdMutex::new(reading(13))))),
            SessionLifecyclePolicy::from_env(),
            Some(self.path.clone()),
            Some(self.keyring.clone()),
        )
    }

    fn pending(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open(&self.path)?;
        let mut statement =
            connection.prepare("SELECT record_json FROM remote_session_pending_terminals")?;
        let rows = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    fn set_pending(&self, record_json: &str) -> Result<(), Box<dyn std::error::Error>> {
        rusqlite::Connection::open(&self.path)?.execute(
            "INSERT INTO remote_session_pending_terminals (session_id, record_json)
             VALUES (?1, ?2)
             ON CONFLICT(session_id) DO UPDATE SET record_json = excluded.record_json",
            [self.session_id.as_str(), record_json],
        )?;
        Ok(())
    }

    fn finalized(&self) -> Result<Option<Arc<RemoteSessionDiagnosticRecord>>, CliError> {
        Ok(
            load_terminal_session_records(&self.path, &self.keyring, 13)?
                .get(&self.session_id)
                .cloned(),
        )
    }

    fn remove(self) -> Result<(), Box<dyn std::error::Error>> {
        drop(self.lease);
        std::fs::remove_dir_all(self.directory)?;
        Ok(())
    }
}

#[tokio::test]
async fn crash_after_the_prepare_transaction_finishes_at_startup(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::new("journal-after-prepare")?;
    let (tombstone, fence) = store.sign(13)?;
    prepare_terminal_session_transition(&store.path, &fence, &tombstone, &store.keyring, 13)?;
    assert_eq!(store.pending()?.len(), 1);
    assert!(store.finalized()?.is_none());

    let ledger = store.boot()?;
    let finished = store
        .finalized()?
        .ok_or("startup left the tombstone pending")?;
    assert_eq!(
        finished.terminal_reason,
        Some(TerminalReason::SubscriptionAuthorityLost)
    );
    assert!(store.pending()?.is_empty());
    assert!(matches!(
        ledger.lookup(&store.session_id).await,
        Some(RemoteSessionEntry::Terminal(_))
    ));
    assert!(
        load_active_session_records(&store.path, &store.keyring, 13)?
            .records
            .is_empty()
    );
    drop(ledger);
    store.remove()
}

#[test]
fn crash_after_the_finalize_transaction_needs_no_replay() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Store::new("journal-after-finalize")?;
    let (tombstone, fence) = store.sign(13)?;
    prepare_terminal_session_transition(&store.path, &fence, &tombstone, &store.keyring, 13)?;
    finalize_terminal_session_transition(&store.path, &tombstone, &store.keyring, 13)?;
    assert!(store.pending()?.is_empty());
    let before = store
        .finalized()?
        .ok_or("finalize published no tombstone")?;

    drop(store.boot()?);
    drop(store.boot()?);
    let after = store
        .finalized()?
        .ok_or("startup lost the finalized tombstone")?;
    assert_eq!(
        serde_json::to_value(&*before)?,
        serde_json::to_value(&*after)?
    );
    assert!(store.pending()?.is_empty());
    store.remove()
}

#[test]
fn identical_pending_tombstone_over_a_finalized_one_is_cleared(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::new("journal-identical")?;
    let (tombstone, fence) = store.sign(13)?;
    prepare_terminal_session_transition(&store.path, &fence, &tombstone, &store.keyring, 13)?;
    finalize_terminal_session_transition(&store.path, &tombstone, &store.keyring, 13)?;
    store.set_pending(&serde_json::to_string(&tombstone)?)?;

    drop(store.boot()?);
    assert!(store.pending()?.is_empty());
    assert!(store.finalized()?.is_some());
    store.remove()
}

#[test]
fn pending_tombstone_with_different_bytes_keeps_the_store_unserved(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::new("journal-different")?;
    let (tombstone, fence) = store.sign(13)?;
    prepare_terminal_session_transition(&store.path, &fence, &tombstone, &store.keyring, 13)?;
    let (other, _) = store.sign(14)?;
    validate_terminal_tombstone_integrity(&store.keyring, &other, 13)?;
    store.set_pending(&serde_json::to_string(&other)?)?;

    assert!(store.boot().is_err());
    assert!(store.finalized()?.is_none());
    assert_eq!(store.pending()?.len(), 1);

    finalize_terminal_session_transition(&store.path, &tombstone, &store.keyring, 13)?;
    store.set_pending(&serde_json::to_string(&other)?)?;
    assert!(store.boot().is_err());
    store.remove()
}
