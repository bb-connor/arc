//! SQLite-backed [`ApprovalReplayStore`].
//!
//! Durable single-use enforcement for governed-approval witnesses so the
//! same approval cannot settle twice across settlement workers or process
//! restarts. The in-memory store in `chio-settle` is process-local; any
//! deployment with more than one worker, or that can restart between an
//! approval's issuance and expiry, must share one instance of this store
//! across every settlement lane.
//!
//! The contract mirrors [`chio_settle::InMemoryApprovalReplayStore`]:
//!
//! - `record_if_fresh` is the only mutating entry point and is atomic:
//!   the insert races through a `UNIQUE (request_id, intent_hash)` key, so
//!   two concurrent presentations of the same approval cannot both observe
//!   [`ApprovalReplayOutcome::Fresh`].
//! - Any present row, even past its retention bound, is a replay. The
//!   record path never prunes; [`ApprovalReplayStore::gc_expired`] is the
//!   only entry point that drops rows, so replay decisions stay decoupled
//!   from the wall clock.
//! - Every SQLite failure maps to a deny-shaped
//!   [`SettlementError::InvalidBinding`]; an infrastructure fault can never
//!   surface as a silent `Fresh`.
//!
//! The schema is:
//!
//! ```sql
//! CREATE TABLE chio_approval_replays (
//!     request_id   TEXT NOT NULL,
//!     intent_hash  TEXT NOT NULL,
//!     retain_until INTEGER NOT NULL,
//!     PRIMARY KEY (request_id, intent_hash)
//! );
//! CREATE INDEX idx_chio_approval_replays_retain_until
//!     ON chio_approval_replays(retain_until);
//! ```

use std::fs;
use std::path::Path;

use chio_settle::{ApprovalReplayOutcome, ApprovalReplayStore, SettlementError};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, TransactionBehavior};

/// Durable SQLite-backed single-use replay store for verified governed
/// approvals.
///
/// Share ONE instance (or several handles opened on the SAME database file)
/// across all settlement workers; single-use only holds within the set of
/// lanes that consult the same underlying database.
pub struct SqliteApprovalReplayStore {
    pool: Pool<SqliteConnectionManager>,
    max_entries: usize,
}

impl SqliteApprovalReplayStore {
    /// Open the store at the given path with the default hard capacity.
    /// Creates the parent directory if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SettlementError> {
        Self::open_with_max_entries(path, chio_settle::DEFAULT_MAX_APPROVAL_REPLAY_ENTRIES)
    }

    /// Open the store at the given path with a custom hard capacity.
    pub fn open_with_max_entries(
        path: impl AsRef<Path>,
        max_entries: usize,
    ) -> Result<Self, SettlementError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(store_error)?;
            }
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(store_error)?;
        let store = Self { pool, max_entries };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, SettlementError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(store_error)?;
        let store = Self {
            pool,
            max_entries: chio_settle::DEFAULT_MAX_APPROVAL_REPLAY_ENTRIES,
        };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), SettlementError> {
        let conn = self.pool.get().map_err(store_error)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_approval_replays (
                request_id   TEXT NOT NULL,
                intent_hash  TEXT NOT NULL,
                retain_until INTEGER NOT NULL,
                PRIMARY KEY (request_id, intent_hash)
            );

            CREATE INDEX IF NOT EXISTS idx_chio_approval_replays_retain_until
                ON chio_approval_replays(retain_until);
            "#,
        )
        .map_err(store_error)?;
        Ok(())
    }
}

/// Map any infrastructure failure to a deny-shaped settlement error, the
/// same variant the in-memory store uses for its own infrastructure faults.
fn store_error(error: impl std::fmt::Display) -> SettlementError {
    SettlementError::InvalidBinding(format!("sqlite approval replay store: {error}"))
}

/// Clamp a u64 Unix-seconds bound into SQLite's signed INTEGER domain.
/// Saturation only lengthens retention, which is the fail-closed direction.
fn clamp_seconds(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl ApprovalReplayStore for SqliteApprovalReplayStore {
    fn record_if_fresh(
        &self,
        request_id: &str,
        intent_hash: &str,
        retain_until_unix_seconds: u64,
    ) -> Result<ApprovalReplayOutcome, SettlementError> {
        let mut conn = self.pool.get().map_err(store_error)?;

        // BEGIN IMMEDIATE takes the write lock up front so the insert and
        // the capacity count observe one consistent snapshot; the UNIQUE
        // primary key is what makes two racing presentations of the same
        // approval resolve to exactly one Fresh.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        let inserted = tx
            .execute(
                r#"
                INSERT INTO chio_approval_replays (request_id, intent_hash, retain_until)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(request_id, intent_hash) DO NOTHING
                "#,
                params![
                    request_id,
                    intent_hash,
                    clamp_seconds(retain_until_unix_seconds)
                ],
            )
            .map_err(store_error)?;
        if inserted == 0 {
            tx.commit().map_err(store_error)?;
            return Ok(ApprovalReplayOutcome::Replayed);
        }

        // Hard capacity, mirroring the in-memory store: fail closed once
        // the retained set is full and rely on `gc_expired` to reopen
        // capacity. Rolling back keeps the over-capacity row unrecorded,
        // so the caller's denial does not burn the slot.
        let retained: i64 = tx
            .query_row("SELECT COUNT(*) FROM chio_approval_replays", [], |row| {
                row.get(0)
            })
            .map_err(store_error)?;
        let retained = usize::try_from(retained).map_err(store_error)?;
        if retained > self.max_entries {
            tx.rollback().map_err(store_error)?;
            return Err(SettlementError::InvalidBinding(format!(
                "approval replay store capacity exceeded: {} retained entries (max {})",
                retained - 1,
                self.max_entries
            )));
        }

        tx.commit().map_err(store_error)?;
        Ok(ApprovalReplayOutcome::Fresh)
    }

    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, SettlementError> {
        let conn = self.pool.get().map_err(store_error)?;
        conn.execute(
            "DELETE FROM chio_approval_replays WHERE retain_until < ?1",
            params![clamp_seconds(now_unix_seconds)],
        )
        .map_err(store_error)
    }

    fn len(&self) -> Result<usize, SettlementError> {
        let conn = self.pool.get().map_err(store_error)?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM chio_approval_replays", [], |row| {
                row.get(0)
            })
            .map_err(store_error)?;
        usize::try_from(count).map_err(store_error)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn single_use_holds_across_two_handles_on_the_same_file() {
        let path = unique_db_path("chio-approval-replay-shared");
        let first_handle = SqliteApprovalReplayStore::open(&path).unwrap();
        let second_handle = SqliteApprovalReplayStore::open(&path).unwrap();

        assert_eq!(
            first_handle
                .record_if_fresh("req-1", "hash-1", 1_000)
                .unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        assert_eq!(
            second_handle
                .record_if_fresh("req-1", "hash-1", 1_000)
                .unwrap(),
            ApprovalReplayOutcome::Replayed,
            "a second worker sharing the same database must see the consumed slot"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn replay_still_denied_after_drop_and_reopen() {
        let path = unique_db_path("chio-approval-replay-restart");
        {
            let store = SqliteApprovalReplayStore::open(&path).unwrap();
            assert_eq!(
                store.record_if_fresh("req-1", "hash-1", 1_000).unwrap(),
                ApprovalReplayOutcome::Fresh
            );
        }
        let reopened = SqliteApprovalReplayStore::open(&path).unwrap();
        assert_eq!(
            reopened.record_if_fresh("req-1", "hash-1", 1_000).unwrap(),
            ApprovalReplayOutcome::Replayed,
            "a restart must not reopen a consumed approval slot"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn distinct_pairs_are_independent() {
        let store = SqliteApprovalReplayStore::open_in_memory().unwrap();
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 0).unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        assert_eq!(
            store.record_if_fresh("req-2", "hash-1", 0).unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        assert_eq!(
            store.record_if_fresh("req-1", "hash-2", 0).unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        assert_eq!(store.len().unwrap(), 3);
    }

    #[test]
    fn gc_prunes_expired_rows_and_slot_stays_burned_before_expiry() {
        let store = SqliteApprovalReplayStore::open_in_memory().unwrap();
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 10).unwrap(),
            ApprovalReplayOutcome::Fresh
        );

        // Before expiry: GC keeps the row and the slot is NOT reusable.
        assert_eq!(store.gc_expired(10).unwrap(), 0);
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 10).unwrap(),
            ApprovalReplayOutcome::Replayed,
            "GC before the retention bound must not reopen the slot"
        );

        // The record path never prunes: even past the retention bound the
        // present row is still a replay until gc_expired runs.
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 20).unwrap(),
            ApprovalReplayOutcome::Replayed
        );

        // After expiry: GC drops the row and a fresh presentation records.
        assert_eq!(store.gc_expired(11).unwrap(), 1);
        assert!(store.is_empty().unwrap());
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 20).unwrap(),
            ApprovalReplayOutcome::Fresh
        );
    }

    #[test]
    fn fails_closed_at_capacity() {
        let path = unique_db_path("chio-approval-replay-cap");
        let store = SqliteApprovalReplayStore::open_with_max_entries(&path, 1).unwrap();
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 0).unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        let error = store.record_if_fresh("req-2", "hash-2", 0).unwrap_err();
        assert!(
            error.to_string().contains("capacity exceeded"),
            "got: {error}"
        );
        assert_eq!(
            store.len().unwrap(),
            1,
            "the over-capacity row must be rolled back, not retained"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn broken_backing_store_yields_err_not_fresh() {
        let path = unique_db_path("chio-approval-replay-broken");
        let store = SqliteApprovalReplayStore::open(&path).unwrap();
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 0).unwrap(),
            ApprovalReplayOutcome::Fresh
        );

        // Break the schema behind the store's back: every later call must
        // surface Err, never a silent Fresh.
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch("DROP TABLE chio_approval_replays;")
            .unwrap();
        drop(raw);

        let error = store.record_if_fresh("req-2", "hash-2", 0).unwrap_err();
        assert!(
            error.to_string().contains("sqlite approval replay store"),
            "got: {error}"
        );
        assert!(store.len().is_err());
        assert!(store.gc_expired(0).is_err());
        let _ = fs::remove_file(path);
    }
}
