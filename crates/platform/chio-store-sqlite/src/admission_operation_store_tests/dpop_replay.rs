use super::*;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chio_kernel::dpop::replay_source::{
    DpopReplaySourceBinding, DpopReplaySourcePort, DpopReplaySourceSnapshot,
};
use chio_kernel::dpop::DpopNonceStore;
use chio_kernel::KernelError;

#[path = "dpop_replay/activation.rs"]
mod activation;
#[path = "dpop_replay/claims.rs"]
mod claims;
#[path = "dpop_replay/concurrency.rs"]
mod concurrency;
#[path = "dpop_replay/failures.rs"]
mod failures;
#[path = "dpop_replay/integrity.rs"]
mod integrity;
#[path = "dpop_replay/lifecycle.rs"]
mod lifecycle;
#[path = "dpop_replay/migration.rs"]
mod migration;

const AUTHORITY_ID: &str = "dpop-authority";
const TABLES: [&str; 3] = [
    "dpop_replay_legacy_tombstones",
    "dpop_replay_migration_events",
    "dpop_replay_migration_expectations",
];

#[derive(Default)]
struct SourceState {
    calls: Vec<&'static str>,
    panic_on: Option<&'static str>,
    lose_seal_ack_once: bool,
    unavailable: bool,
}

/// Instrument the real process-local cache, never reconstruct it from a blob.
struct Source {
    raw: Arc<DpopNonceStore>,
    instance: AdmissionIdentifier,
    destination: Arc<Mutex<Connection>>,
    state: Mutex<SourceState>,
}

impl Source {
    fn new(fixture: &Fixture, empty: bool) -> AnchoredTestResult<Self> {
        let raw = Arc::new(DpopNonceStore::new(8, Duration::from_secs(3600)));
        if !empty {
            assert!(raw.check_and_insert("local", "capability")?);
            assert!(raw.check_and_insert_through(
                "signed",
                "capability",
                now_ms() / 1000 + 3600
            )?);
            assert!(raw.check_and_insert_through("overflow", "capability", u64::MAX)?);
        }
        let snapshot = raw.preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: identifier("authority", AUTHORITY_ID),
            destination_authority_id: identifier("destination", &fixture.fence.store_uuid),
        })?;
        Ok(Self::attach(
            raw,
            identifier("instance", snapshot.instance_id()),
            &fixture.store,
        ))
    }

    fn attach(
        raw: Arc<DpopNonceStore>,
        instance: AdmissionIdentifier,
        store: &SqliteAdmissionOperationStore,
    ) -> Self {
        Self {
            raw,
            instance,
            destination: Arc::clone(&store.connection),
            state: Mutex::default(),
        }
    }

    fn observe(&self, call: &'static str) -> Result<(), KernelError> {
        let connection = self
            .destination
            .try_lock()
            .expect("callback outside destination mutex");
        assert!(
            connection.is_autocommit(),
            "callback outside destination transaction"
        );
        drop(connection);
        let (panic, unavailable) = {
            let mut state = self.state.lock().expect("state");
            state.calls.push(call);
            (state.panic_on == Some(call), state.unavailable)
        };
        assert!(!panic, "injected source callback panic");
        if unavailable {
            return Err(source_error());
        }
        Ok(())
    }

    fn calls(&self) -> Vec<&'static str> {
        self.state.lock().expect("state").calls.clone()
    }
}

fn source_error() -> KernelError {
    KernelError::DpopVerificationFailed("private source failure detail".into())
}

impl DpopReplaySourcePort for Source {
    fn preview_unsealed(
        &self,
        binding: &DpopReplaySourceBinding,
    ) -> Result<DpopReplaySourceSnapshot, KernelError> {
        self.observe("preview")?;
        self.raw.preview_unsealed(binding)
    }

    fn seal_exact(&self, expected: &DpopReplaySourceSnapshot) -> Result<(), KernelError> {
        self.observe("seal")?;
        self.raw.seal_exact(expected)?;
        if std::mem::take(&mut self.state.lock().expect("state").lose_seal_ack_once) {
            return Err(source_error());
        }
        Ok(())
    }

    fn verify_exact(&self, expected: &DpopReplaySourceSnapshot) -> Result<(), KernelError> {
        self.observe("verify")?;
        self.raw.verify_exact(expected)
    }
}

fn pin(
    fixture: &Fixture,
    source: &Source,
) -> Result<DpopReplayMigrationRecordV1, AdmissionOperationStoreError> {
    fixture.store.expect_dpop_replay_source(
        &source.instance,
        &identifier("authority", AUTHORITY_ID),
        source,
        &fixture.fence,
        now_ms(),
    )
}

fn import(
    fixture: &Fixture,
    source: &dyn DpopReplaySourcePort,
    expected: &DpopReplayMigrationRecordV1,
) -> Result<DpopReplayMigrationRecordV1, AdmissionOperationStoreError> {
    fixture.store.import_dpop_replay_source(
        &identifier("authority", AUTHORITY_ID),
        expected.expectation_id(),
        source,
        &fixture.fence,
        now_ms(),
    )
}

fn load(
    fixture: &Fixture,
) -> Result<Option<DpopReplayMigrationRecordV1>, AdmissionOperationStoreError> {
    fixture.store.load_dpop_replay_migration(
        &identifier("authority", AUTHORITY_ID),
        &fixture.fence,
        now_ms(),
    )
}

fn counts(fixture: &Fixture) -> [i64; 3] {
    let connection = fixture.store.connection().expect("connection");
    TABLES.map(|table| {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count")
    })
}

fn global_count(fixture: &Fixture) -> i64 {
    fixture
        .store
        .connection()
        .expect("connection")
        .query_row("SELECT COUNT(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })
        .expect("global count")
}

/// Fixture shaping only. Never discard populated security history to downgrade.
pub(super) fn remove_empty_v24_tables(connection: &Connection) -> rusqlite::Result<()> {
    activation::remove_empty_v25_activation(connection)?;
    for table in TABLES {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        if !exists {
            continue;
        }
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 0, "predecessor fixture cannot discard DPoP history");
        connection.execute_batch(&format!("DROP TABLE {table}"))?;
    }
    Ok(())
}
