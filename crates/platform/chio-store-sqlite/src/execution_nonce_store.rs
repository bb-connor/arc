//! SQLite-backed `ExecutionNonceStore`.
//!
//! Durable replay-prevention for execution nonces so a kernel that
//! crashes and restarts cannot be tricked into accepting a nonce that was
//! already consumed by the previous process. Consumed identifiers are
//! permanent tombstones. The signed `expires_at` is retained as audit
//! metadata, but wall-clock movement never authorizes deletion or reuse.
//!
//! The schema is:
//!
//! ```sql
//! CREATE TABLE chio_execution_nonces (
//!     nonce_id    TEXT PRIMARY KEY,
//!     consumed_at INTEGER NOT NULL,
//!     expires_at  INTEGER NOT NULL
//! );
//! ```

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{
    ExecutionNonceReservation, ExecutionNonceReservationError, ExecutionNonceStore,
    ExecutionNonceStoreProfile, KernelError, ReplayReservationState,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

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
    authority_profile: ExecutionNonceStoreProfile,
    database_identity_file: Option<Arc<crate::durable_sqlite::DurableSqliteFile>>,
}

/// Execution-nonce-store schema revision. Bump on every schema-affecting change.
const EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const EXECUTION_NONCE_STORE_SCHEMA_KEY: &str = "execution_nonce";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// execution-nonce database rather than reject it as foreign.
const EXECUTION_NONCE_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["chio_execution_nonces"];

impl SqliteExecutionNonceStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteExecutionNonceStoreError> {
        let path = path.as_ref();
        reject_volatile_database_path(path)?;
        // Resolve any `file:` URI to its on-disk parent before creating it, so a
        // URI-configured store creates the real backing directory rather than a
        // bogus scheme-prefixed one.
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(parent)?;
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self {
            pool,
            authority_profile: ExecutionNonceStoreProfile::SingleNodeDurable,
            database_identity_file: None,
        };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open a durable nonce authority through one retained trusted parent
    /// shared with its sibling authorities.
    pub fn open_hardened(
        path: impl AsRef<Path>,
        directory: Arc<crate::durable_sqlite::TrustedSqliteDirectory>,
    ) -> Result<Self, SqliteExecutionNonceStoreError> {
        let database_identity_file = directory
            .open_database(path, true)
            .map_err(|error| SqliteExecutionNonceStoreError(error.to_string()))?;
        let manager_identity = Arc::clone(&database_identity_file);
        let manager = SqliteConnectionManager::file(database_identity_file.path())
            .with_flags(
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .with_init(move |connection| {
                manager_identity
                    .validate_live_connection(connection)
                    .map_err(|error| rusqlite::Error::InvalidParameterName(error.to_string()))
            });
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self {
            pool,
            authority_profile: ExecutionNonceStoreProfile::SingleNodeDurable,
            database_identity_file: Some(database_identity_file),
        };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, SqliteExecutionNonceStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager)?;
        let store = Self {
            pool,
            authority_profile: ExecutionNonceStoreProfile::EphemeralLocal,
            database_identity_file: None,
        };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), SqliteExecutionNonceStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| SqliteExecutionNonceStoreError(format!("pool acquire: {e}")))?;
        self.validate_connection(&conn)?;
        crate::check_schema_version(
            &conn,
            EXECUTION_NONCE_STORE_SCHEMA_KEY,
            EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION,
            EXECUTION_NONCE_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| SqliteExecutionNonceStoreError(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            "#,
        )?;
        self.validate_connection(&conn)?;
        conn.execute_batch(
            r#"

            CREATE TABLE IF NOT EXISTS chio_execution_nonces (
                nonce_id    TEXT PRIMARY KEY,
                consumed_at INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_execution_nonces_expires_at
                ON chio_execution_nonces(expires_at);

            CREATE TRIGGER IF NOT EXISTS chio_execution_nonce_delete_forbidden
            BEFORE DELETE ON chio_execution_nonces
            BEGIN
                SELECT RAISE(ABORT, 'execution nonce tombstones cannot be deleted');
            END;

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
        audit_permanent_nonce_tombstone_trigger(&mut conn)?;
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
        crate::stamp_schema_version(
            &conn,
            EXECUTION_NONCE_STORE_SCHEMA_KEY,
            EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| SqliteExecutionNonceStoreError(error.to_string()))?;
        self.validate_connection(&conn)?;
        Ok(())
    }

    fn validate_connection(
        &self,
        connection: &Connection,
    ) -> Result<(), SqliteExecutionNonceStoreError> {
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file
                .validate_live_connection(connection)
                .map_err(|error| SqliteExecutionNonceStoreError(error.to_string()))?;
        }
        Ok(())
    }

    /// Reserve a nonce id. Shared code path for the trait impl and tests.
    /// `now` and `expires_at` are persisted only as audit metadata and never
    /// control tombstone deletion.
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
        self.validate_connection(&conn)?;

        configure_nonce_connection(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

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

        // A conflicting row is a permanent replay tombstone.
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
        self.validate_connection(&conn).map_err(|error| {
            ExecutionNonceReservationError::Store(format!("database identity: {error}"))
        })?;
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

fn audit_permanent_nonce_tombstone_trigger(
    connection: &mut Connection,
) -> Result<(), SqliteExecutionNonceStoreError> {
    const AUDIT_NONCE_ID: &str = "chio-execution-nonce-permanent-tombstone-audit";
    const EXPECTED_TRIGGER_SQL: &str = r#"
        CREATE TRIGGER chio_execution_nonce_delete_forbidden
        BEFORE DELETE ON chio_execution_nonces
        BEGIN
            SELECT RAISE(ABORT, 'execution nonce tombstones cannot be deleted');
        END
    "#;
    let stored_trigger_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'chio_execution_nonce_delete_forbidden'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let normalize = |sql: &str| sql.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
    if stored_trigger_sql
        .as_deref()
        .is_none_or(|sql| normalize(sql) != normalize(EXPECTED_TRIGGER_SQL))
    {
        return Err(SqliteExecutionNonceStoreError(
            "permanent execution nonce tombstone trigger has an unexpected definition".to_string(),
        ));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        r#"
        INSERT INTO chio_execution_nonces (nonce_id, consumed_at, expires_at)
        VALUES (?1, 1, 1)
        ON CONFLICT(nonce_id) DO NOTHING
        "#,
        params![AUDIT_NONCE_ID],
    )?;
    let deletion_blocked = transaction
        .execute(
            "DELETE FROM chio_execution_nonces WHERE nonce_id = ?1",
            params![AUDIT_NONCE_ID],
        )
        .is_err();
    let tombstone_retained = transaction
        .query_row(
            "SELECT 1 FROM chio_execution_nonces WHERE nonce_id = ?1",
            params![AUDIT_NONCE_ID],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    transaction.rollback()?;
    if !deletion_blocked || !tombstone_retained {
        return Err(SqliteExecutionNonceStoreError(
            "permanent execution nonce tombstone deletion guard is unavailable".to_string(),
        ));
    }
    Ok(())
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
    fn authority_profile(&self) -> ExecutionNonceStoreProfile {
        self.authority_profile
    }

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
        let now = now_secs();
        self.try_reserve(nonce_id, now, nonce_expires_at)
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
        self.validate_connection(&conn).map_err(|error| {
            ExecutionNonceReservationError::Store(format!("database identity: {error}"))
        })?;
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
        self.validate_connection(&conn).map_err(|error| {
            ExecutionNonceReservationError::Store(format!("database identity: {error}"))
        })?;
        configure_nonce_connection(&conn).map_err(|e| {
            ExecutionNonceReservationError::Store(format!("configure database: {e}"))
        })?;
        load_nonce_reservation(&conn, operation_id)
    }
}

fn reject_volatile_database_path(path: &Path) -> Result<(), SqliteExecutionNonceStoreError> {
    let path = path.to_string_lossy();
    let lower = path.to_ascii_lowercase();
    let memory_uri = lower.starts_with("file:")
        && (lower.contains("?mode=memory") || lower.contains("&mode=memory"));
    if path.is_empty() || path == ":memory:" || memory_uri || lower.starts_with("file::memory:") {
        return Err(SqliteExecutionNonceStoreError(
            "volatile SQLite execution-nonce paths are not durable; use open_in_memory for an explicitly ephemeral store"
                .to_string(),
        ));
    }
    Ok(())
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
    fn forward_clock_jump_then_rollback_cannot_reuse_nonce_tombstone() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        assert!(store.try_reserve("a", 1_000, 1_030).unwrap());
        assert!(!store.try_reserve("a", 2_000, 2_030).unwrap());
        assert!(!store.try_reserve("a", 1_001, 1_030).unwrap());
        assert!(matches!(
            store.reserve_nonce_for_operation(operation_id("09").as_str(), "a", 2_030),
            Err(ExecutionNonceReservationError::Conflict(_))
        ));
    }

    #[test]
    fn existing_database_migration_installs_idempotent_permanent_tombstone_guard() {
        let path = unique_db_path("chio-exec-nonce-tombstone-migration");
        let legacy = Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                r#"
                CREATE TABLE chio_execution_nonces (
                    nonce_id TEXT PRIMARY KEY,
                    consumed_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                INSERT INTO chio_execution_nonces (nonce_id, consumed_at, expires_at)
                VALUES ('legacy-consumed', 1000, 1030);
                "#,
            )
            .unwrap();
        drop(legacy);

        let store = SqliteExecutionNonceStore::open(&path).unwrap();
        assert!(!store.try_reserve("legacy-consumed", 2_000, 2_030).unwrap());
        assert!(!store.try_reserve("legacy-consumed", 1_001, 1_030).unwrap());
        let connection = store.pool.get().unwrap();
        assert!(connection
            .execute(
                "DELETE FROM chio_execution_nonces WHERE nonce_id = ?1",
                params!["legacy-consumed"],
            )
            .is_err());
        drop(connection);
        drop(store);

        let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
        assert!(!reopened
            .try_reserve("legacy-consumed", 1_002, 1_030)
            .unwrap());
        drop(reopened);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn migration_rejects_conflicting_nonce_delete_trigger_contract() {
        let path = unique_db_path("chio-exec-nonce-conflicting-trigger");
        let legacy = Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                r#"
                CREATE TABLE chio_execution_nonces (
                    nonce_id TEXT PRIMARY KEY,
                    consumed_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TRIGGER chio_execution_nonce_delete_forbidden
                BEFORE UPDATE ON chio_execution_nonces
                BEGIN
                    SELECT 1;
                END;
                "#,
            )
            .unwrap();
        drop(legacy);

        assert!(SqliteExecutionNonceStore::open(&path).is_err());
        let _ = fs::remove_file(path);
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
