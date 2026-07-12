//! SQLite-backed `ExecutionNonceStore`.
//!
//! Durable replay-prevention for execution nonces so a kernel that
//! crashes and restarts cannot be tricked into accepting a nonce that was
//! already consumed by the previous process. Expiry is enforced by
//! storing the nonce's `expires_at` alongside the consumed marker;
//! `reserve` refuses to recycle a slot until the nonce is past its
//! expiry.
//!
//! The schema is:
//!
//! ```sql
//! CREATE TABLE chio_execution_nonces (
//!     nonce_id    TEXT PRIMARY KEY,
//!     consumed_at INTEGER NOT NULL,
//!     expires_at  INTEGER NOT NULL
//! );
//! CREATE INDEX idx_chio_execution_nonces_expires_at
//!     ON chio_execution_nonces(expires_at);
//! ```

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{
    ExecutionNonceReservation, ExecutionNonceReservationError, ExecutionNonceStore, KernelError,
    ReplayReservationState,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

/// Default number of seconds a consumed-marker persists after its
/// `expires_at` before the garbage collector reclaims the row. Keeps the
/// table bounded without letting a replay slip through immediately after
/// the nonce would have expired anyway.
const RETENTION_GRACE_SECS: i64 = 60;
const MAX_OPERATION_NONCE_ID_BYTES: usize = 512;

/// Opaque error type returned by the SQLite nonce store.
#[derive(Debug)]
pub struct SqliteExecutionNonceStoreError(String);

impl std::fmt::Display for SqliteExecutionNonceStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sqlite execution nonce store error: {}", self.0)
    }
}

impl std::error::Error for SqliteExecutionNonceStoreError {}

impl From<rusqlite::Error> for SqliteExecutionNonceStoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<std::io::Error> for SqliteExecutionNonceStoreError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<r2d2::Error> for SqliteExecutionNonceStoreError {
    fn from(e: r2d2::Error) -> Self {
        Self(e.to_string())
    }
}

/// SQLite-backed replay-prevention store for execution nonces.
pub struct SqliteExecutionNonceStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteExecutionNonceStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteExecutionNonceStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, SqliteExecutionNonceStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager)?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), SqliteExecutionNonceStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteExecutionNonceStoreError(format!("pool acquire: {e}")))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_execution_nonces (
                nonce_id    TEXT PRIMARY KEY,
                consumed_at INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_execution_nonces_expires_at
                ON chio_execution_nonces(expires_at);

            CREATE TABLE IF NOT EXISTS chio_execution_nonce_reservations (
                operation_id TEXT PRIMARY KEY
                    CHECK (length(operation_id) = 64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
                nonce_id TEXT NOT NULL UNIQUE
                    CHECK (
                        length(CAST(nonce_id AS BLOB)) BETWEEN 1 AND 512
                        AND instr(nonce_id, char(0)) = 0
                    ),
                signed_expires_at INTEGER NOT NULL CHECK (signed_expires_at > 0),
                state TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'cancelled'))
            );

            CREATE TRIGGER IF NOT EXISTS chio_execution_nonce_legacy_operation_exclusion
            BEFORE INSERT ON chio_execution_nonces
            WHEN EXISTS (
                SELECT 1 FROM chio_execution_nonce_reservations
                WHERE nonce_id = NEW.nonce_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'execution nonce is operation-owned');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_execution_nonce_operation_legacy_exclusion
            BEFORE INSERT ON chio_execution_nonce_reservations
            WHEN EXISTS (
                SELECT 1 FROM chio_execution_nonces
                WHERE nonce_id = NEW.nonce_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'execution nonce was consumed by the legacy registry');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_execution_nonce_reservation_identity_immutable
            BEFORE UPDATE OF operation_id, nonce_id, signed_expires_at
            ON chio_execution_nonce_reservations
            BEGIN
                SELECT RAISE(ABORT, 'immutable execution nonce reservation ownership');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_execution_nonce_reservation_delete_forbidden
            BEFORE DELETE ON chio_execution_nonce_reservations
            BEGIN
                SELECT RAISE(ABORT, 'execution nonce reservation tombstones cannot be deleted');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_execution_nonce_reservation_transition_guard
            BEFORE UPDATE OF state ON chio_execution_nonce_reservations
            WHEN NOT (
                OLD.state = 'reserved'
                AND NEW.state IN ('committed', 'cancelled')
            )
            BEGIN
                SELECT RAISE(ABORT, 'invalid execution nonce reservation transition');
            END;
            "#,
        )?;
        let dual_owner = conn
            .query_row(
                r#"
                SELECT 1
                FROM chio_execution_nonces AS legacy
                INNER JOIN chio_execution_nonce_reservations AS operation
                    ON operation.nonce_id = legacy.nonce_id
                LIMIT 1
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if dual_owner.is_some() {
            return Err(SqliteExecutionNonceStoreError(
                "migration audit: execution nonce has legacy and operation ownership".to_string(),
            ));
        }
        Ok(())
    }

    /// Reserve a nonce id. Shared code path for the trait impl and
    /// tests -- takes an explicit `expires_at` for caller-controlled
    /// retention (the trait method uses `now + RETENTION_GRACE_SECS`).
    pub fn try_reserve(
        &self,
        nonce_id: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<bool, SqliteExecutionNonceStoreError> {
        if nonce_id.trim().is_empty()
            || nonce_id.trim() != nonce_id
            || nonce_id.len() > MAX_OPERATION_NONCE_ID_BYTES
            || nonce_id.bytes().any(|byte| byte == 0)
        {
            return Err(SqliteExecutionNonceStoreError(
                "nonce_id must be non-empty, unpadded, NUL-free, and at most 512 bytes".to_string(),
            ));
        }
        let mut conn = self
            .pool
            .get()
            .map_err(|e| SqliteExecutionNonceStoreError(format!("pool acquire: {e}")))?;

        configure_nonce_connection(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // First, prune any rows that are past their `expires_at` so a
        // long-lived kernel doesn't accumulate garbage. Keeping the
        // prune here (rather than a background job) is safe because the
        // query is indexed on expires_at.
        tx.execute(
            "DELETE FROM chio_execution_nonces WHERE expires_at <= ?1",
            params![now],
        )?;

        let operation_owned = tx
            .query_row(
                "SELECT 1 FROM chio_execution_nonce_reservations WHERE nonce_id = ?1",
                params![nonce_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if operation_owned {
            tx.rollback()?;
            return Ok(false);
        }

        // Then attempt the reservation. A conflicting row means the
        // nonce was already consumed and is still within the retention
        // window; return `false`.
        let rows = tx.execute(
            r#"
            INSERT INTO chio_execution_nonces (nonce_id, consumed_at, expires_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(nonce_id) DO NOTHING
            "#,
            params![nonce_id, now, expires_at],
        )?;
        tx.commit()?;
        Ok(rows > 0)
    }

    fn transition_nonce_reservation(
        &self,
        operation_id: &str,
        target: ReplayReservationState,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        validate_operation_id(operation_id)?;
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ExecutionNonceReservationError::Store(format!("pool acquire: {e}")))?;
        configure_nonce_connection(&conn).map_err(|e| {
            ExecutionNonceReservationError::Store(format!("configure database: {e}"))
        })?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| {
                ExecutionNonceReservationError::Store(format!("begin reservation tx: {e}"))
            })?;
        let current = load_nonce_reservation(&tx, operation_id)?
            .ok_or_else(|| ExecutionNonceReservationError::NotFound(operation_id.to_string()))?;
        if current.state() == target {
            tx.rollback().map_err(|e| {
                ExecutionNonceReservationError::Store(format!("rollback reservation read: {e}"))
            })?;
            return Ok(current);
        }
        if current.state() != ReplayReservationState::Reserved
            || target == ReplayReservationState::Reserved
        {
            return Err(ExecutionNonceReservationError::Conflict(format!(
                "operation `{operation_id}` nonce reservation cannot transition from {} to {}",
                current.state().as_str(),
                target.as_str()
            )));
        }
        let updated = tx
            .execute(
                r#"
                UPDATE chio_execution_nonce_reservations
                SET state = ?2
                WHERE operation_id = ?1 AND state = 'reserved'
                "#,
                params![operation_id, target.as_str()],
            )
            .map_err(|e| {
                ExecutionNonceReservationError::Store(format!("transition nonce reservation: {e}"))
            })?;
        if updated != 1 {
            return Err(ExecutionNonceReservationError::Conflict(format!(
                "operation `{operation_id}` nonce reservation changed concurrently"
            )));
        }
        let transitioned = ExecutionNonceReservation::from_persisted_parts(
            current.operation_id().to_string(),
            current.nonce_id().to_string(),
            current.signed_expires_at(),
            target,
        )?;
        tx.commit().map_err(|e| {
            ExecutionNonceReservationError::Store(format!(
                "commit nonce reservation transition: {e}"
            ))
        })?;
        Ok(transitioned)
    }
}

fn configure_nonce_connection(
    connection: &Connection,
) -> Result<(), SqliteExecutionNonceStoreError> {
    connection.execute_batch(
        r#"
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
        "#,
    )?;
    Ok(())
}

fn validate_operation_id(operation_id: &str) -> Result<(), ExecutionNonceReservationError> {
    ExecutionNonceReservation::new(operation_id.to_string(), "validation-nonce".to_string(), 1)
        .map(|_| ())
}

fn load_nonce_reservation(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<ExecutionNonceReservation>, ExecutionNonceReservationError> {
    let row = connection
        .query_row(
            r#"
            SELECT nonce_id, signed_expires_at, state
            FROM chio_execution_nonce_reservations
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|e| {
            ExecutionNonceReservationError::Store(format!("load nonce reservation: {e}"))
        })?;
    let Some((nonce_id, signed_expires_at, state)) = row else {
        return Ok(None);
    };
    let state = ReplayReservationState::parse(&state).ok_or_else(|| {
        ExecutionNonceReservationError::Store(
            "persisted nonce reservation state is unknown".to_string(),
        )
    })?;
    Ok(Some(ExecutionNonceReservation::from_persisted_parts(
        operation_id.to_string(),
        nonce_id,
        signed_expires_at,
        state,
    )?))
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(i64::MAX)
}

impl ExecutionNonceStore for SqliteExecutionNonceStore {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        // Back-compat path: callers that do not know the nonce's signed
        // expiry estimate the kernel default TTL and delegate to
        // `reserve_until` so the consumed marker survives the full
        // cryptographic validity window.
        let now = now_secs();
        let estimated_nonce_expiry = now.saturating_add(
            i64::try_from(chio_kernel::DEFAULT_EXECUTION_NONCE_TTL_SECS).unwrap_or(0),
        );
        self.reserve_until(nonce_id, estimated_nonce_expiry)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        // Retain the consumed marker for the full signed validity window
        // plus a small grace, so a pruner cannot reclaim the row while
        // the nonce is still cryptographically valid. Take the max of
        // `nonce_expires_at + RETENTION_GRACE_SECS` and
        // `now + RETENTION_GRACE_SECS`, preserving the original grace
        // for clock-skew safety.
        let now = now_secs();
        let retention = nonce_expires_at.saturating_add(RETENTION_GRACE_SECS);
        let baseline = now.saturating_add(RETENTION_GRACE_SECS);
        let expires_at = retention.max(baseline);
        self.try_reserve(nonce_id, now, expires_at)
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))
    }

    fn reserve_nonce_for_operation(
        &self,
        operation_id: &str,
        nonce_id: &str,
        signed_expires_at: i64,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        let requested = ExecutionNonceReservation::new(
            operation_id.to_string(),
            nonce_id.to_string(),
            signed_expires_at,
        )?;
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ExecutionNonceReservationError::Store(format!("pool acquire: {e}")))?;
        configure_nonce_connection(&conn).map_err(|e| {
            ExecutionNonceReservationError::Store(format!("configure database: {e}"))
        })?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| {
                ExecutionNonceReservationError::Store(format!("begin reservation tx: {e}"))
            })?;

        if let Some(existing) = load_nonce_reservation(&tx, operation_id)? {
            if existing.nonce_id() == requested.nonce_id()
                && existing.signed_expires_at() == requested.signed_expires_at()
            {
                tx.rollback().map_err(|e| {
                    ExecutionNonceReservationError::Store(format!(
                        "rollback reservation retry: {e}"
                    ))
                })?;
                return Ok(existing);
            }
            return Err(ExecutionNonceReservationError::Conflict(format!(
                "operation `{operation_id}` is already bound to a different nonce"
            )));
        }

        let owner = tx
            .query_row(
                "SELECT operation_id FROM chio_execution_nonce_reservations WHERE nonce_id = ?1",
                params![nonce_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| {
                ExecutionNonceReservationError::Store(format!("query nonce owner: {e}"))
            })?;
        if let Some(owner) = owner {
            return Err(ExecutionNonceReservationError::Conflict(format!(
                "nonce `{nonce_id}` is already owned by operation `{owner}`"
            )));
        }

        tx.execute(
            "DELETE FROM chio_execution_nonces WHERE expires_at <= ?1",
            params![now_secs()],
        )
        .map_err(|e| {
            ExecutionNonceReservationError::Store(format!("prune legacy nonce markers: {e}"))
        })?;
        let legacy_consumed = tx
            .query_row(
                "SELECT 1 FROM chio_execution_nonces WHERE nonce_id = ?1",
                params![nonce_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| {
                ExecutionNonceReservationError::Store(format!("query legacy nonce marker: {e}"))
            })?
            .is_some();
        if legacy_consumed {
            return Err(ExecutionNonceReservationError::Conflict(format!(
                "nonce `{nonce_id}` was already consumed"
            )));
        }

        tx.execute(
            r#"
            INSERT INTO chio_execution_nonce_reservations (
                operation_id, nonce_id, signed_expires_at, state
            ) VALUES (?1, ?2, ?3, 'reserved')
            "#,
            params![operation_id, nonce_id, signed_expires_at],
        )
        .map_err(|e| {
            ExecutionNonceReservationError::Store(format!("insert nonce reservation: {e}"))
        })?;
        tx.commit().map_err(|e| {
            ExecutionNonceReservationError::Store(format!("commit nonce reservation: {e}"))
        })?;
        Ok(requested)
    }

    fn commit_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.transition_nonce_reservation(operation_id, ReplayReservationState::Committed)
    }

    fn cancel_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.transition_nonce_reservation(operation_id, ReplayReservationState::Cancelled)
    }

    fn get_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ExecutionNonceReservation>, ExecutionNonceReservationError> {
        validate_operation_id(operation_id)?;
        let conn = self
            .pool
            .get()
            .map_err(|e| ExecutionNonceReservationError::Store(format!("pool acquire: {e}")))?;
        configure_nonce_connection(&conn).map_err(|e| {
            ExecutionNonceReservationError::Store(format!("configure database: {e}"))
        })?;
        load_nonce_reservation(&conn, operation_id)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn operation_id(hex_pair: &str) -> String {
        hex_pair.repeat(32)
    }

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn fresh_nonce_is_reserved() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        assert!(<SqliteExecutionNonceStore as ExecutionNonceStore>::reserve(&store, "a").unwrap());
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        assert!(store.try_reserve("a", 1_000, 1_100).unwrap());
        assert!(!store.try_reserve("a", 1_001, 1_100).unwrap());
    }

    #[test]
    fn padded_nonce_id_is_rejected() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let error = store.try_reserve(" nonce", 1_000, 1_100).unwrap_err();

        assert!(
            error.to_string().contains("nonce_id"),
            "expected nonce_id validation error, got {error}"
        );
    }

    #[test]
    fn expired_row_is_pruned_and_slot_reusable() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        assert!(store.try_reserve("a", 1_000, 1_030).unwrap());
        // "Now" after expiry + retention: prune removes the row and the
        // same id can be re-reserved (this is benign because verify_
        // execution_nonce also checks the signed expires_at).
        assert!(store.try_reserve("a", 2_000, 2_030).unwrap());
    }

    #[test]
    fn persists_across_reopen() {
        let path = unique_db_path("chio-exec-nonce");
        {
            let store = SqliteExecutionNonceStore::open(&path).unwrap();
            assert!(store
                .try_reserve("persistent-nonce", 1_000, 1_000_000_000)
                .unwrap());
        }
        let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
        assert!(!reopened
            .try_reserve("persistent-nonce", 1_001, 1_000_000_000)
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn operation_reservation_schema_bounds_nonce_identifiers() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let connection = store.pool.get().unwrap();
        assert!(connection
            .execute(
                r#"
                INSERT INTO chio_execution_nonce_reservations (
                    operation_id, nonce_id, signed_expires_at, state
                ) VALUES (?1, ?2, ?3, 'reserved')
                "#,
                params![operation_id("20"), "x".repeat(513), 10_000],
            )
            .is_err());
    }

    #[test]
    fn operation_nonce_cancellation_survives_restart_and_blocks_reuse() {
        let path = unique_db_path("chio-exec-nonce-reservation");
        let cancelled = {
            let store = SqliteExecutionNonceStore::open(&path).unwrap();
            store
                .reserve_nonce_for_operation(operation_id("01").as_str(), "nonce-owned", 10_000)
                .and_then(|_| store.cancel_nonce_reservation(operation_id("01").as_str()))
                .unwrap()
        };
        assert_eq!(cancelled.state(), ReplayReservationState::Cancelled);
        let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .get_nonce_reservation(operation_id("01").as_str())
                .unwrap(),
            Some(cancelled.clone())
        );
        assert_eq!(
            reopened
                .cancel_nonce_reservation(operation_id("01").as_str())
                .unwrap(),
            cancelled
        );
        assert!(matches!(
            reopened.reserve_nonce_for_operation(
                operation_id("02").as_str(),
                "nonce-owned",
                10_000
            ),
            Err(ExecutionNonceReservationError::Conflict(_))
        ));
        assert!(!reopened.try_reserve("nonce-owned", 1_000, 10_000).unwrap());
        let legacy_expiry = now_secs().saturating_add(1_000);
        assert!(reopened
            .try_reserve("legacy-owned", now_secs(), legacy_expiry)
            .unwrap());
        assert!(matches!(
            reopened.reserve_nonce_for_operation(
                operation_id("03").as_str(),
                "legacy-owned",
                legacy_expiry
            ),
            Err(ExecutionNonceReservationError::Conflict(_))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn concurrent_nonce_reservations_have_one_operation_owner() {
        let path = unique_db_path("chio-exec-nonce-reservation-race");
        let first = std::sync::Arc::new(SqliteExecutionNonceStore::open(&path).unwrap());
        let second = std::sync::Arc::new(SqliteExecutionNonceStore::open(&path).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let spawn = |store: std::sync::Arc<SqliteExecutionNonceStore>, operation_id: String| {
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.reserve_nonce_for_operation(&operation_id, "nonce-race", 10_000)
            })
        };
        let first_thread = spawn(std::sync::Arc::clone(&first), operation_id("04"));
        let second_thread = spawn(std::sync::Arc::clone(&second), operation_id("05"));
        barrier.wait();
        let results = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(result, Err(ExecutionNonceReservationError::Conflict(_)))
                })
                .count(),
            1
        );
        let _ = fs::remove_file(path);
    }
}
