use super::*;

use std::sync::{Arc, Mutex};

use crate::{SqliteGovernedApprovalReplaySource, SqliteGovernedApprovalReplayStore};
use chio_kernel::admission_operation::governed_approval_replay::{
    GovernedApprovalReplaySourceBinding, GovernedApprovalReplaySourcePort,
    GovernedApprovalReplaySourceSnapshot, LEGACY_UNSCOPED_GOVERNED_APPROVAL_SUBJECT,
};

#[path = "governed_approval_replay/bounds.rs"]
mod bounds;
#[path = "governed_approval_replay/claims.rs"]
mod claims;
#[path = "governed_approval_replay/concurrency.rs"]
mod concurrency;
#[path = "governed_approval_replay/cutpoints.rs"]
mod cutpoints;
#[path = "governed_approval_replay/integrity.rs"]
mod integrity;
#[path = "governed_approval_replay/lifecycle.rs"]
mod lifecycle;
#[path = "governed_approval_replay/migration.rs"]
mod migration;

const SOURCE_ID: &str = "approval-source";
const AUTHORITY_ID: &str = "approval-authority";
const TABLES: [&str; 3] = [
    "governed_approval_replay_legacy_tombstones",
    "governed_approval_replay_migration_events",
    "governed_approval_replay_migration_expectations",
];

#[derive(Default)]
struct SourceState {
    calls: Vec<&'static str>,
    panic_on: Option<&'static str>,
    lose_seal_ack_once: bool,
}

/// The callbacks use the real SQLite migration handle, including persistent
/// barriers and physical identity. The wrapper instruments destination locking
/// and failures at the source/destination boundary.
struct Source {
    raw: SqliteGovernedApprovalReplaySource,
    path: PathBuf,
    destination: Arc<Mutex<Connection>>,
    state: Mutex<SourceState>,
}

impl Source {
    fn new(fixture: &Fixture, empty: bool) -> AnchoredTestResult<Self> {
        let path = fixture._temp.path().join("approval-source.db");
        drop(SqliteGovernedApprovalReplayStore::open_with_capacity(
            &path, 8,
        )?);
        let connection = Connection::open(&path)?;
        // Deliberately historical clock and expired retained rows. Migration
        // must preserve them, not use legacy startup pruning as a shortcut.
        connection.execute_batch(
            "UPDATE chio_governed_approval_replay_clock
            SET wall_clock_high_water = 100, pruned_through = 50;",
        )?;
        if !empty {
            for (subject, request, expiry, owner) in [
                (
                    LEGACY_UNSCOPED_GOVERNED_APPROVAL_SUBJECT,
                    "wildcard",
                    1,
                    Some("historical-owner"),
                ),
                ("subject", "committed", 90, None),
                ("subject", "reserved", 200, Some("private-owner")),
            ] {
                connection.execute("INSERT INTO chio_governed_approval_replay_entries VALUES (?1, ?2, 'intent', ?3, ?4)",
                    params![subject, request, expiry, owner])?;
            }
        }
        drop(connection);
        Self::reopen(path, &fixture.store)
    }

    fn reopen(path: PathBuf, store: &SqliteAdmissionOperationStore) -> AnchoredTestResult<Self> {
        Ok(Self {
            raw: SqliteGovernedApprovalReplaySource::open(&path)?,
            path,
            destination: Arc::clone(&store.connection),
            state: Mutex::default(),
        })
    }

    fn observe(&self, call: &'static str) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.destination.try_lock().map_err(|_| {
            AdmissionOperationStoreError::Invariant("source callback held destination lock".into())
        })?;
        assert!(connection.is_autocommit());
        drop(connection);
        let panic = {
            let mut state = self.state.lock().expect("state");
            state.calls.push(call);
            state.panic_on == Some(call)
        };
        assert!(!panic, "injected source callback panic");
        Ok(())
    }

    fn calls(&self) -> Vec<&'static str> {
        self.state.lock().expect("state").calls.clone()
    }
}

impl GovernedApprovalReplaySourcePort for Source {
    fn preview_unsealed(
        &self,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
        self.observe("preview")?;
        self.raw.preview_unsealed(binding)
    }

    fn seal_exact(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.observe("seal")?;
        self.raw.seal_exact(expected)?;
        if std::mem::take(&mut self.state.lock().expect("state").lose_seal_ack_once) {
            return Err(AdmissionOperationStoreError::OutcomeUnknown(
                "seal acknowledgement lost".into(),
            ));
        }
        Ok(())
    }

    fn verify_exact(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.observe("verify")?;
        self.raw.verify_exact(expected)
    }
}

fn pin(
    fixture: &Fixture,
    source: &dyn GovernedApprovalReplaySourcePort,
) -> Result<GovernedApprovalReplayMigrationRecordV1, AdmissionOperationStoreError> {
    fixture.store.expect_governed_approval_replay_source(
        &identifier("source", SOURCE_ID),
        &identifier("authority", AUTHORITY_ID),
        source,
        &fixture.fence,
        now_ms(),
    )
}

fn import(
    fixture: &Fixture,
    source: &dyn GovernedApprovalReplaySourcePort,
    expected: &GovernedApprovalReplayMigrationRecordV1,
) -> Result<GovernedApprovalReplayMigrationRecordV1, AdmissionOperationStoreError> {
    fixture.store.import_governed_approval_replay_source(
        &identifier("authority", AUTHORITY_ID),
        expected.expectation_id(),
        source,
        &fixture.fence,
        now_ms(),
    )
}

fn load(
    fixture: &Fixture,
) -> Result<Option<GovernedApprovalReplayMigrationRecordV1>, AdmissionOperationStoreError> {
    fixture.store.load_governed_approval_replay_migration(
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

/// Fixture shaping only. Never erase populated security history to downgrade.
pub(super) fn remove_empty_v22_approval_tables(connection: &Connection) -> rusqlite::Result<()> {
    remove_empty_v23_claim_tables(connection)?;
    for table in TABLES {
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        assert_eq!(
            count, 0,
            "historical fixture must contain no approval history"
        );
        connection.execute_batch(&format!("DROP TABLE {table};"))?;
    }
    Ok(())
}

/// Build a real predecessor catalog while preserving all admission history.
/// Already shaped older catalogs are left intact, never upgraded by a fixture.
fn remove_empty_v23_claim_tables(connection: &Connection) -> rusqlite::Result<()> {
    super::dpop_replay::remove_empty_v24_tables(connection)?;
    connection.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA legacy_alter_table = ON")?;
    for table in [
        "governed_approval_replay_claim_releases",
        "governed_approval_replay_claim_resources",
        "governed_approval_replay_claim_episodes",
    ] {
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
        assert_eq!(
            count, 0,
            "predecessor fixture cannot discard approval ownership"
        );
        connection.execute_batch(&format!("DROP TABLE {table}"))?;
    }
    let sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'admission_operation_commits'",
        [],
        |row| row.get(0),
    )?;
    if sql.contains("'governed_approval_claim'") {
        let count: i64 = connection.query_row("SELECT COUNT(*) FROM admission_operation_commits WHERE mutation_kind IN ('governed_approval_claim', 'governed_approval_release')", [], |row| row.get(0))?;
        assert_eq!(
            count, 0,
            "predecessor fixture cannot discard approval commits"
        );
        connection.execute_batch(
            "DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits RENAME TO admission_commits_v23_fixture;",
        )?;
        let ddl = crate::admission_operation_store::schema::pre_approval_claim_schema_fixture();
        connection.execute_batch(&ddl)?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;
            INSERT INTO admission_operation_commits SELECT * FROM admission_commits_v23_fixture ORDER BY commit_sequence;
            DROP TABLE admission_commits_v23_fixture;")?;
        connection.execute_batch(&ddl)?;
    }
    Ok(())
}
