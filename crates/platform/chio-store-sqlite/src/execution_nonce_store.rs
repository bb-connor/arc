//! SQLite-backed `ExecutionNonceStore`.
//!
//! Durable replay-prevention for execution nonces so a kernel that
//! crashes and restarts cannot be tricked into accepting a nonce that was
//! already consumed by the previous process. Expiry is enforced by storing a
//! retention boundary derived from the nonce's signed `expires_at` alongside
//! the consumed marker; signed reservations refuse to recycle the slot before
//! that boundary.
//!
//! The schema is:
//!
//! ```sql
//! CREATE TABLE chio_execution_nonces (
//!     nonce_id    TEXT PRIMARY KEY,
//!     consumed_at INTEGER NOT NULL,
//!     expires_at  INTEGER NOT NULL,
//!     dispatch_reservation_id TEXT
//! );
//! CREATE INDEX idx_chio_execution_nonces_expires_at
//!     ON chio_execution_nonces(expires_at);
//! CREATE TABLE chio_execution_nonce_clock (
//!     singleton             INTEGER PRIMARY KEY,
//!     wall_clock_high_water INTEGER NOT NULL,
//!     pruned_through        INTEGER NOT NULL
//! );
//! CREATE TABLE chio_execution_nonce_limits (
//!     singleton INTEGER PRIMARY KEY,
//!     capacity  INTEGER NOT NULL
//! );
//! ```

use chio_security_types::clock::{Clock, ClockError, SystemClock};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use chio_kernel::{
    ExecutionNonceStore, KernelError, ReplayClockDirection, DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, TransactionBehavior};

use crate::replay_clock::{ReplayClockValidationError, StableReplayClock};

/// Default number of seconds a consumed marker persists after the signed
/// artifact's `expires_at` before the garbage collector reclaims the row. Keeps the
/// table bounded without letting a replay slip through immediately after
/// the nonce would have expired anyway.
const RETENTION_GRACE_SECS: i64 = 60;

/// Maximum unexplained wall-clock skew accepted before nonce reservation
/// fails with a typed clock anomaly and leaves durable replay state unchanged.
#[allow(
    clippy::as_conversions,
    reason = "The constant u32 clock skew widens into u64 without loss."
)]
pub const MAX_EXECUTION_NONCE_CLOCK_SKEW_SECS: u64 =
    chio_security_types::clock::MAX_REPLAY_WALL_SKEW_SECS as u64;

#[allow(
    clippy::as_conversions,
    reason = "The constant u32 clock skew widens into i64 without loss."
)]
const MAX_EXECUTION_NONCE_CLOCK_SKEW_I64: i64 =
    chio_security_types::clock::MAX_REPLAY_WALL_SKEW_SECS as i64;

fn configure_pooled_connection(connection: &mut Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA busy_timeout = 5000;")
}

/// Error returned by the SQLite nonce store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqliteExecutionNonceStoreError {
    /// SQLite, pool, filesystem, configuration, or invariant failure.
    Storage(String),
    /// Failure of the injected trusted clock or checked time arithmetic.
    Clock(ClockError),
    Capacity,
    /// Wall-clock movement that cannot safely advance replay retention.
    ClockAnomaly {
        direction: ReplayClockDirection,
        observed_unix_secs: i64,
        high_water_unix_secs: i64,
        max_tolerated_skew_secs: u64,
    },
}

impl SqliteExecutionNonceStoreError {
    fn storage(message: impl Into<String>) -> Self {
        Self::Storage(message.into())
    }

    fn clock_anomaly(
        direction: ReplayClockDirection,
        observed_unix_secs: i64,
        high_water_unix_secs: i64,
    ) -> Self {
        Self::ClockAnomaly {
            direction,
            observed_unix_secs,
            high_water_unix_secs,
            max_tolerated_skew_secs: MAX_EXECUTION_NONCE_CLOCK_SKEW_SECS,
        }
    }
}

impl std::fmt::Display for SqliteExecutionNonceStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(message) => {
                write!(f, "sqlite execution nonce store error: {message}")
            }
            Self::Capacity => f.write_str("execution nonce store capacity exhausted"),
            Self::Clock(error) => write!(f, "trusted time rejected: {error}"),
            Self::ClockAnomaly {
                direction,
                observed_unix_secs,
                high_water_unix_secs,
                max_tolerated_skew_secs,
            } => write!(
                f,
                "sqlite execution nonce replay clock {direction}: observed {observed_unix_secs}, high-water {high_water_unix_secs}, maximum tolerated skew {max_tolerated_skew_secs}s"
            ),
        }
    }
}

impl std::error::Error for SqliteExecutionNonceStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            _ => None,
        }
    }
}
impl From<ClockError> for SqliteExecutionNonceStoreError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<rusqlite::Error> for SqliteExecutionNonceStoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<std::io::Error> for SqliteExecutionNonceStoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<r2d2::Error> for SqliteExecutionNonceStoreError {
    fn from(e: r2d2::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

fn map_replay_clock_error(error: ReplayClockValidationError) -> SqliteExecutionNonceStoreError {
    match error {
        ReplayClockValidationError::Clock(error) => SqliteExecutionNonceStoreError::Clock(error),
        ReplayClockValidationError::Anomaly {
            direction,
            observed,
            high_water,
        } => SqliteExecutionNonceStoreError::clock_anomaly(direction, observed, high_water),
    }
}

/// SQLite-backed replay-prevention store for execution nonces.
pub struct SqliteExecutionNonceStore {
    pool: Pool<SqliteConnectionManager>,
    capacity: usize,
    clock: StableReplayClock,
}

/// Execution-nonce-store schema revision. Bump on every schema-affecting change.
const EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 1;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const EXECUTION_NONCE_STORE_SCHEMA_KEY: &str = "execution_nonce";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// execution-nonce database rather than reject it as foreign.
const EXECUTION_NONCE_STORE_ANCHOR_TABLES: &[&str] = &["chio_execution_nonces"];

impl SqliteExecutionNonceStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteExecutionNonceStoreError> {
        Self::open_with_capacity(path, DEFAULT_EXECUTION_NONCE_STORE_CAPACITY)
    }

    /// Open the store with a hard store-wide retained-row capacity.
    ///
    /// Expired rows are pruned before the limit is checked. Live replay
    /// markers are never evicted to make room for a new reservation.
    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, SqliteExecutionNonceStoreError> {
        Self::open_with_clock(path, capacity, Arc::new(SystemClock))
    }

    pub fn open_with_clock(
        path: impl AsRef<Path>,
        capacity: usize,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, SqliteExecutionNonceStoreError> {
        let clock = StableReplayClock::new(clock, MAX_EXECUTION_NONCE_CLOCK_SKEW_I64)?;
        Self::validate_capacity(capacity)?;
        let path = path.as_ref();
        // Resolve any `file:` URI to its on-disk parent before creating it, so a
        // URI-configured store creates the real backing directory rather than a
        // bogus scheme-prefixed one.
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(&parent)?;
        }
        let manager = SqliteConnectionManager::file(path).with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self {
            pool,
            capacity,
            clock,
        };
        store.run_migrations()?;
        store.validate_retained_row_capacity()?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, SqliteExecutionNonceStoreError> {
        Self::open_in_memory_with_capacity(DEFAULT_EXECUTION_NONCE_STORE_CAPACITY)
    }

    /// Open an in-memory store with a hard retained-row capacity.
    pub fn open_in_memory_with_capacity(
        capacity: usize,
    ) -> Result<Self, SqliteExecutionNonceStoreError> {
        Self::open_in_memory_with_clock(capacity, Arc::new(SystemClock))
    }

    pub fn open_in_memory_with_clock(
        capacity: usize,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, SqliteExecutionNonceStoreError> {
        let clock = StableReplayClock::new(clock, MAX_EXECUTION_NONCE_CLOCK_SKEW_I64)?;
        Self::validate_capacity(capacity)?;
        let manager = SqliteConnectionManager::memory().with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(1).build(manager)?;
        let store = Self {
            pool,
            capacity,
            clock,
        };
        store.run_migrations()?;
        store.validate_retained_row_capacity()?;
        Ok(store)
    }

    fn validate_capacity(capacity: usize) -> Result<(), SqliteExecutionNonceStoreError> {
        if capacity == 0 {
            return Err(SqliteExecutionNonceStoreError::storage(
                "execution nonce store capacity must be greater than zero",
            ));
        }
        Ok(())
    }

    fn run_migrations(&self) -> Result<(), SqliteExecutionNonceStoreError> {
        let mut conn = self.pool.get().map_err(|error| {
            SqliteExecutionNonceStoreError::storage(format!("pool acquire: {error}"))
        })?;
        let existing: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chio_execution_nonces')", [], |row| row.get(0),
        )?;
        if existing {
            let version: i32 = conn.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
                [EXECUTION_NONCE_STORE_SCHEMA_KEY],
                |row| row.get(0),
            )?;
            if version != EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION {
                return Err(SqliteExecutionNonceStoreError::storage(
                    "unsupported execution nonce schema",
                ));
            }
            // Existing stores must already carry the full owned-custody schema.
            // Never synthesize a clock or ownership column from older rows.
            conn.prepare("SELECT dispatch_reservation_id FROM chio_execution_nonces LIMIT 0")?;
            conn.query_row(
                "SELECT pruned_through FROM chio_execution_nonce_clock WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            conn.query_row(
                "SELECT capacity FROM chio_execution_nonce_limits WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?;
        }
        crate::check_schema_version(
            &conn,
            EXECUTION_NONCE_STORE_SCHEMA_KEY,
            EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION,
            EXECUTION_NONCE_STORE_ANCHOR_TABLES,
        )
        .map_err(|error| SqliteExecutionNonceStoreError::storage(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            "#,
        )?;

        let tx = conn.transaction()?;
        tx.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chio_execution_nonces (
                nonce_id    TEXT PRIMARY KEY,
                consumed_at INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                dispatch_reservation_id TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_chio_execution_nonces_expires_at
                ON chio_execution_nonces(expires_at);

            CREATE TABLE IF NOT EXISTS chio_execution_nonce_clock (
                singleton             INTEGER PRIMARY KEY CHECK (singleton = 1),
                wall_clock_high_water INTEGER NOT NULL,
                pruned_through        INTEGER NOT NULL DEFAULT -9223372036854775808
            );

            CREATE TABLE IF NOT EXISTS chio_execution_nonce_limits (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                capacity  INTEGER NOT NULL CHECK (capacity > 0)
            );
            "#,
        )?;

        let capacity = i64::try_from(self.capacity).map_err(|_| {
            SqliteExecutionNonceStoreError::storage(
                "execution nonce store capacity exceeds SQLite integer range",
            )
        })?;
        tx.execute(
            "INSERT INTO chio_execution_nonce_limits (singleton, capacity) VALUES (1, ?1) ON CONFLICT(singleton) DO NOTHING",
            params![capacity],
        )?;

        let migration_now = self
            .clock
            .expected_wall_now()
            .map_err(map_replay_clock_error)?;
        tx.execute(
            "INSERT INTO chio_execution_nonce_clock (singleton, wall_clock_high_water) VALUES (1, ?1) ON CONFLICT(singleton) DO NOTHING",
            params![migration_now],
        )?;
        tx.execute(
            "UPDATE chio_execution_nonce_clock SET wall_clock_high_water = MAX(wall_clock_high_water, ?1) WHERE singleton = 1",
            params![migration_now],
        )?;

        tx.commit()?;

        crate::stamp_schema_version(
            &conn,
            EXECUTION_NONCE_STORE_SCHEMA_KEY,
            EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| SqliteExecutionNonceStoreError::storage(error.to_string()))?;
        Ok(())
    }

    fn validate_retained_row_capacity(&self) -> Result<(), SqliteExecutionNonceStoreError> {
        let mut conn = self.pool.get().map_err(|error| {
            SqliteExecutionNonceStoreError::storage(format!("pool acquire: {error}"))
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let wall_clock_high_water = tx.query_row(
            "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        self.validate_persisted_clock(wall_clock_high_water)?;
        record_execution_nonce_prune(&tx, wall_clock_high_water)?;

        let retained_rows =
            tx.query_row("SELECT COUNT(*) FROM chio_execution_nonces", [], |row| {
                row.get::<_, i64>(0)
            })?;
        let retained_rows = usize::try_from(retained_rows).map_err(|_| {
            SqliteExecutionNonceStoreError::storage(
                "retained execution nonce row count cannot be represented as usize",
            )
        })?;
        let persisted_capacity = tx.query_row(
            "SELECT capacity FROM chio_execution_nonce_limits WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let requested_capacity = i64::try_from(self.capacity).map_err(|_| {
            SqliteExecutionNonceStoreError::storage(
                "execution nonce store capacity exceeds SQLite integer range",
            )
        })?;

        if requested_capacity < persisted_capacity {
            return Err(SqliteExecutionNonceStoreError::storage(format!(
                "execution nonce capacity cannot shrink from {persisted_capacity} to {requested_capacity}"
            )));
        }
        if retained_rows > self.capacity {
            return Err(SqliteExecutionNonceStoreError::storage(format!(
                "configured capacity {} is below the {retained_rows} retained execution nonce rows",
                self.capacity
            )));
        }
        if requested_capacity > persisted_capacity {
            let changed = tx.execute(
                "UPDATE chio_execution_nonce_limits SET capacity = ?1 WHERE singleton = 1 AND capacity = ?2",
                params![requested_capacity, persisted_capacity],
            )?;
            if changed != 1 {
                return Err(SqliteExecutionNonceStoreError::storage(
                    "execution nonce capacity changed during serialized reconfiguration",
                ));
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn validate_persisted_clock(
        &self,
        wall_clock_high_water: i64,
    ) -> Result<(), SqliteExecutionNonceStoreError> {
        self.clock
            .validate_persisted(wall_clock_high_water)
            .map_err(map_replay_clock_error)
    }

    fn validate_observed_clock(
        &self,
        observed: i64,
        wall_clock_high_water: i64,
    ) -> Result<(), SqliteExecutionNonceStoreError> {
        self.clock
            .validate_observed(observed, wall_clock_high_water)
            .map_err(map_replay_clock_error)
    }

    /// Deliberately lower a latched clock high-water after the host clock has
    /// been corrected. The exact old value is a compare-and-swap guard, and
    /// recovery never deletes retained nonce rows.
    pub fn recover_clock_high_water(
        path: impl AsRef<Path>,
        expected_high_water: i64,
        corrected_high_water: i64,
    ) -> Result<(), SqliteExecutionNonceStoreError> {
        Self::recover_clock_high_water_with_clock(
            path,
            expected_high_water,
            corrected_high_water,
            &SystemClock,
        )
    }

    pub fn recover_clock_high_water_with_clock(
        path: impl AsRef<Path>,
        expected_high_water: i64,
        corrected_high_water: i64,
        clock: &dyn Clock,
    ) -> Result<(), SqliteExecutionNonceStoreError> {
        let path = path.as_ref();
        let filesystem_path = path
            .to_str()
            .map(crate::sqlite_filesystem_path)
            .unwrap_or_else(|| path.to_path_buf());
        if !filesystem_path.is_file() {
            return Err(SqliteExecutionNonceStoreError::storage(format!(
                "execution nonce database does not exist: {}",
                filesystem_path.display()
            )));
        }

        let observed_now =
            i64::try_from(clock.unix_millis()?.as_secs()).map_err(|_| ClockError::Overflow)?;
        let minimum_corrected = observed_now
            .checked_sub(MAX_EXECUTION_NONCE_CLOCK_SKEW_I64)
            .ok_or(ClockError::Overflow)?;
        let maximum_corrected = observed_now
            .checked_add(MAX_EXECUTION_NONCE_CLOCK_SKEW_I64)
            .ok_or(ClockError::Overflow)?;
        if corrected_high_water < minimum_corrected || corrected_high_water > maximum_corrected {
            return Err(SqliteExecutionNonceStoreError::storage(format!(
                "corrected high-water {corrected_high_water} is not within the tolerated skew of current wall time {observed_now}"
            )));
        }
        if corrected_high_water >= expected_high_water {
            return Err(SqliteExecutionNonceStoreError::storage(
                "clock recovery must lower the expected high-water",
            ));
        }

        let mut connection = Connection::open(path)?;
        configure_pooled_connection(&mut connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual_high_water = transaction.query_row(
            "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let pruned_through = transaction.query_row(
            "SELECT pruned_through FROM chio_execution_nonce_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if actual_high_water != expected_high_water {
            return Err(SqliteExecutionNonceStoreError::storage(format!(
                "clock recovery compare-and-swap failed: expected {expected_high_water}, found {actual_high_water}"
            )));
        }
        if corrected_high_water < pruned_through {
            return Err(SqliteExecutionNonceStoreError::storage(format!(
                "clock recovery cannot lower the high-water below pruned-through {pruned_through}; retained replay markers may already have been deleted"
            )));
        }
        let changed = transaction.execute(
            "UPDATE chio_execution_nonce_clock SET wall_clock_high_water = ?1 WHERE singleton = 1 AND wall_clock_high_water = ?2",
            params![corrected_high_water, expected_high_water],
        )?;
        if changed != 1 {
            return Err(SqliteExecutionNonceStoreError::storage(
                "clock recovery compare-and-swap did not update the high-water",
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn try_reserve(
        &self,
        nonce_id: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<bool, SqliteExecutionNonceStoreError> {
        self.try_reserve_signed_entry(nonce_id, now, expires_at, expires_at, None)
    }

    fn try_reserve_signed_entry(
        &self,
        nonce_id: &str,
        now: i64,
        signed_expires_at: i64,
        retention_expires_at: i64,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, SqliteExecutionNonceStoreError> {
        self.try_reserve_entry_with_clock_policy(
            nonce_id,
            now,
            retention_expires_at.max(signed_expires_at),
            signed_expires_at,
            dispatch_reservation_id,
        )
    }

    fn try_reserve_entry_with_clock_policy(
        &self,
        nonce_id: &str,
        now: i64,
        expires_at: i64,
        signed_expires_at: i64,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, SqliteExecutionNonceStoreError> {
        if dispatch_reservation_id.is_some_and(|owner| owner.is_empty() || owner.trim() != owner) {
            return Err(SqliteExecutionNonceStoreError::storage(
                "reservation owner must be non-empty and unpadded",
            ));
        }
        if nonce_id.trim().is_empty() || nonce_id.trim() != nonce_id {
            return Err(SqliteExecutionNonceStoreError::storage(
                "nonce_id must be non-empty and unpadded",
            ));
        }
        let mut conn = self.pool.get().map_err(|error| {
            SqliteExecutionNonceStoreError::storage(format!("pool acquire: {error}"))
        })?;

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let wall_clock_high_water = tx.query_row(
            "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        self.validate_observed_clock(now, wall_clock_high_water)?;
        let admission_now = self.clock.now_secs()?;
        self.validate_observed_clock(admission_now, wall_clock_high_water)?;
        // `now` is sampled before this serialized transaction begins. A
        // concurrent request may therefore have committed a slightly newer
        // second while this request waited for the writer lock. Keep the
        // durable clock monotonic and accept that bounded stale observation.
        let updated_high_water = wall_clock_high_water.max(now).max(admission_now);
        if updated_high_water != wall_clock_high_water {
            tx.execute(
                "UPDATE chio_execution_nonce_clock SET wall_clock_high_water = ?1 WHERE singleton = 1",
                params![updated_high_water],
            )?;
        }

        if signed_expires_at <= updated_high_water {
            return Err(ClockError::Expired.into());
        }
        // Both reservation and reclamation use the durable clock. A queued
        // observation can never move pruning backwards or authorize an expired nonce.
        record_execution_nonce_prune(&tx, updated_high_water)?;

        let already_reserved = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_execution_nonces WHERE nonce_id = ?1)",
            params![nonce_id],
            |row| row.get::<_, bool>(0),
        )?;
        if already_reserved {
            tx.commit()?;
            return Ok(false);
        }

        let retained_rows =
            tx.query_row("SELECT COUNT(*) FROM chio_execution_nonces", [], |row| {
                row.get::<_, i64>(0)
            })?;
        let capacity = tx.query_row(
            "SELECT capacity FROM chio_execution_nonce_limits WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if retained_rows >= capacity {
            return Err(SqliteExecutionNonceStoreError::Capacity);
        }

        // The immediate transaction serializes the prune/count/insert sequence
        // across pooled connections, so concurrent writers cannot exceed the
        // configured live-row bound.
        let rows = tx.execute(
            r#"
            INSERT INTO chio_execution_nonces (
                nonce_id,
                consumed_at,
                expires_at,
                dispatch_reservation_id
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(nonce_id) DO NOTHING
            "#,
            params![nonce_id, now, expires_at, dispatch_reservation_id],
        )?;
        tx.commit()?;
        Ok(rows > 0)
    }
}

fn record_execution_nonce_prune(
    transaction: &rusqlite::Transaction<'_>,
    horizon: i64,
) -> Result<(), rusqlite::Error> {
    transaction.execute(
        "DELETE FROM chio_execution_nonces WHERE expires_at <= ?1",
        params![horizon],
    )?;
    transaction.execute(
        "UPDATE chio_execution_nonce_clock SET pruned_through = MAX(pruned_through, ?1) WHERE singleton = 1",
        params![horizon],
    )?;
    Ok(())
}

fn kernel_store_error(error: SqliteExecutionNonceStoreError) -> KernelError {
    match error {
        SqliteExecutionNonceStoreError::Capacity => KernelError::ExecutionNonceCapacity,
        SqliteExecutionNonceStoreError::Clock(error) => KernelError::Clock(error),
        SqliteExecutionNonceStoreError::ClockAnomaly {
            direction,
            observed_unix_secs,
            high_water_unix_secs,
            max_tolerated_skew_secs,
        } => KernelError::ReplayClockAnomaly {
            store: "sqlite_execution_nonce_store",
            direction,
            observed_unix_secs,
            high_water_unix_secs,
            max_tolerated_skew_secs,
        },
        SqliteExecutionNonceStoreError::Storage(message) => {
            KernelError::Internal(format!("sqlite execution nonce store: {message}"))
        }
    }
}

impl ExecutionNonceStore for SqliteExecutionNonceStore {
    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        // Retain the consumed marker for the full signed validity window
        // plus a small grace, so a pruner cannot reclaim the row while
        // the nonce is still cryptographically valid. Take the max of
        // `nonce_expires_at + RETENTION_GRACE_SECS` and
        // `now + RETENTION_GRACE_SECS`, preserving the original grace
        // for clock-skew safety.
        let now = self.clock.now_secs()?;
        if nonce_expires_at < 0 {
            return Err(ClockError::BeforeEpoch.into());
        }
        if nonce_expires_at <= now {
            return Err(ClockError::Expired.into());
        }
        let retention = nonce_expires_at
            .checked_add(RETENTION_GRACE_SECS)
            .ok_or(ClockError::Overflow)?;
        let baseline = now
            .checked_add(RETENTION_GRACE_SECS)
            .ok_or(ClockError::Overflow)?;
        let expires_at = retention.max(baseline);
        self.try_reserve_signed_entry(nonce_id, now, nonce_expires_at, expires_at, None)
            .map_err(kernel_store_error)
    }

    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let now = self.clock.now_secs()?;
        if nonce_expires_at < 0 {
            return Err(ClockError::BeforeEpoch.into());
        }
        if nonce_expires_at <= now {
            return Err(ClockError::Expired.into());
        }
        let retention = nonce_expires_at
            .checked_add(RETENTION_GRACE_SECS)
            .ok_or(ClockError::Overflow)?;
        let baseline = now
            .checked_add(RETENTION_GRACE_SECS)
            .ok_or(ClockError::Overflow)?;
        self.try_reserve_signed_entry(
            nonce_id,
            now,
            nonce_expires_at,
            retention.max(baseline),
            Some(reservation_id),
        )
        .map_err(kernel_store_error)
    }

    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))?;
        let rows = tx
            .execute(
                "DELETE FROM chio_execution_nonces WHERE nonce_id = ?1 AND dispatch_reservation_id = ?2",
                params![nonce_id, reservation_id],
            )
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))?;
        tx.commit()
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))?;
        Ok(rows > 0)
    }

    fn is_consumed(&self, nonce_id: &str) -> Result<bool, KernelError> {
        let now = self.clock.now_secs()?;
        let conn = self.pool.get().map_err(|error| {
            KernelError::Internal(format!(
                "sqlite execution nonce store pool acquire: {error}"
            ))
        })?;
        let high_water = conn
            .query_row(
                "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(SqliteExecutionNonceStoreError::from)
            .map_err(kernel_store_error)?;
        self.validate_observed_clock(now, high_water)
            .map_err(kernel_store_error)?;
        conn.query_row(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM chio_execution_nonces
                WHERE nonce_id = ?1 AND expires_at > ?2
            )
            "#,
            params![nonce_id, now],
            |row| row.get(0),
        )
        .map_err(|error| {
            KernelError::Internal(format!(
                "sqlite execution nonce store consumed lookup: {error}"
            ))
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
fn now_secs() -> i64 {
    use chio_security_types::clock::Clock;
    i64::try_from(SystemClock.unix_millis().unwrap().as_secs()).unwrap()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
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
    fn fresh_nonce_is_reserved() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        assert!(
            <SqliteExecutionNonceStore as ExecutionNonceStore>::reserve_until(
                &store,
                "a",
                now_secs() + 30
            )
            .unwrap()
        );
    }

    #[test]
    fn zero_capacity_is_rejected() {
        let error = match SqliteExecutionNonceStore::open_in_memory_with_capacity(0) {
            Ok(_) => panic!("zero-capacity store must not open"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("greater than zero"));
    }

    #[test]
    fn live_capacity_pressure_fails_closed_without_evicting_markers() {
        let store = SqliteExecutionNonceStore::open_in_memory_with_capacity(2).unwrap();
        let now = now_secs();
        let expires_at = now.saturating_add(100);
        assert!(store.try_reserve("capacity-a", now, expires_at).unwrap());
        assert!(store.try_reserve("capacity-b", now, expires_at).unwrap());
        assert!(!store.try_reserve("capacity-a", now, expires_at).unwrap());

        let error = store
            .try_reserve("capacity-c", now, expires_at)
            .unwrap_err();
        assert!(matches!(error, SqliteExecutionNonceStoreError::Capacity));
        assert!(!store.try_reserve("capacity-a", now, expires_at).unwrap());
        assert!(!store.try_reserve("capacity-b", now, expires_at).unwrap());

        assert!(store
            .try_reserve(
                "capacity-c",
                now.saturating_add(200),
                now.saturating_add(300),
            )
            .unwrap());
    }

    #[test]
    fn concurrent_writers_cannot_exceed_capacity() {
        let path = unique_db_path("chio-exec-nonce-capacity-concurrent");
        let store =
            std::sync::Arc::new(SqliteExecutionNonceStore::open_with_capacity(&path, 1).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let now = now_secs();
        let mut writers = Vec::new();

        for nonce_id in ["concurrent-a", "concurrent-b"] {
            let store = std::sync::Arc::clone(&store);
            let barrier = std::sync::Arc::clone(&barrier);
            writers.push(std::thread::spawn(move || {
                barrier.wait();
                store.try_reserve(nonce_id, now, now.saturating_add(300))
            }));
        }

        barrier.wait();
        let outcomes: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(true)))
                .count(),
            1
        );
        let errors: Vec<_> = outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            errors[0],
            SqliteExecutionNonceStoreError::Capacity
        ));

        let conn = store.pool.get().unwrap();
        let retained_rows = conn
            .query_row("SELECT COUNT(*) FROM chio_execution_nonces", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(retained_rows, 1);
        drop(conn);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn every_pooled_connection_has_busy_timeout() {
        let path = unique_db_path("chio-exec-nonce-busy-timeout");
        let store = SqliteExecutionNonceStore::open(&path).unwrap();
        let first = store.pool.get().unwrap();
        let second = store.pool.get().unwrap();

        for connection in [&first, &second] {
            let busy_timeout = connection
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap();
            assert!(busy_timeout >= 5_000);
        }

        drop(second);
        drop(first);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn owned_rollback_frees_capacity() {
        let store = SqliteExecutionNonceStore::open_in_memory_with_capacity(1).unwrap();
        let expires_at = now_secs().saturating_add(300);
        assert!(store
            .reserve_for_dispatch("rollback-a", expires_at, "owner-a")
            .unwrap());
        assert!(store
            .reserve_for_dispatch("rollback-b", expires_at, "owner-b")
            .is_err());
        assert!(!store
            .rollback_dispatch_reservation("rollback-a", "owner-b")
            .unwrap());
        assert!(store
            .reserve_for_dispatch("rollback-b", expires_at, "owner-b")
            .is_err());
        assert!(store
            .rollback_dispatch_reservation("rollback-a", "owner-a")
            .unwrap());
        assert!(store
            .reserve_for_dispatch("rollback-b", expires_at, "owner-b")
            .unwrap());
    }

    #[test]
    fn retention_expiry_reclaims_crash_owned_reservation_and_capacity() {
        let store = SqliteExecutionNonceStore::open_in_memory_with_capacity(1).unwrap();
        let base = now_secs();

        assert!(store
            .try_reserve_signed_entry(
                "crashed-owned",
                base,
                base.saturating_add(1),
                base.saturating_add(1),
                Some("abandoned-owner"),
            )
            .unwrap());
        assert!(store
            .try_reserve_signed_entry(
                "next",
                base,
                base.saturating_add(100),
                base.saturating_add(160),
                Some("next-owner"),
            )
            .is_err());

        assert!(store
            .try_reserve_signed_entry(
                "next",
                base.saturating_add(1),
                base.saturating_add(100),
                base.saturating_add(160),
                Some("next-owner"),
            )
            .unwrap());
        assert!(!store
            .rollback_dispatch_reservation("crashed-owned", "abandoned-owner")
            .unwrap());
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        assert!(store
            .try_reserve("a", now, now.saturating_add(100))
            .unwrap());
        assert!(!store
            .try_reserve("a", now.saturating_add(1), now.saturating_add(100))
            .unwrap());
    }

    #[test]
    fn bounded_stale_observation_keeps_high_water_monotonic() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let base = now_secs();
        assert!(store
            .try_reserve("newer", base.saturating_add(1), base.saturating_add(100))
            .unwrap());
        assert!(store
            .try_reserve("lagged", base, base.saturating_add(100))
            .unwrap());

        let high_water = store
            .pool
            .get()
            .unwrap()
            .query_row(
                "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(high_water, base.saturating_add(1));
    }

    #[test]
    fn dispatch_reservation_rolls_back_only_for_its_owner() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        assert!(store
            .reserve_for_dispatch("dispatch-owned", now.saturating_add(100), "owner-a")
            .unwrap());
        assert!(!store
            .rollback_dispatch_reservation("dispatch-owned", "owner-b")
            .unwrap());
        assert!(!store.reserve_until("dispatch-owned", now + 100).unwrap());
        assert!(store
            .rollback_dispatch_reservation("dispatch-owned", "owner-a")
            .unwrap());
        assert!(store.reserve_until("dispatch-owned", now + 100).unwrap());
    }

    #[test]
    fn padded_nonce_id_is_rejected() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        let error = store
            .try_reserve(" nonce", now, now.saturating_add(100))
            .unwrap_err();

        assert!(
            error.to_string().contains("nonce_id"),
            "expected nonce_id validation error, got {error}"
        );
    }

    #[test]
    fn expired_row_is_pruned_and_slot_reusable() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        assert!(store.try_reserve("a", now, now.saturating_add(30)).unwrap());
        // The explicit local API preserves caller-controlled prune and reuse.
        assert!(store
            .try_reserve("a", now.saturating_add(60), now.saturating_add(90))
            .unwrap());
    }

    #[test]
    fn forward_jump_is_typed_and_latched_clock_is_recoverable() {
        let path = unique_db_path("chio-exec-nonce-high-water");
        let base_time = now_secs();
        let high_water_before;
        {
            let store = SqliteExecutionNonceStore::open(&path).unwrap();
            assert!(store
                .try_reserve_signed_entry(
                    "used",
                    base_time,
                    base_time.saturating_add(10_000),
                    base_time.saturating_add(10_060),
                    None,
                )
                .unwrap());
            high_water_before = store
                .pool
                .get()
                .unwrap()
                .query_row(
                    "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            let error = store
                .try_reserve(
                    "forward-local",
                    base_time.saturating_add(MAX_EXECUTION_NONCE_CLOCK_SKEW_I64 + 1),
                    base_time.saturating_add(20_000),
                )
                .unwrap_err();
            assert!(matches!(
                error,
                SqliteExecutionNonceStoreError::ClockAnomaly {
                    direction: ReplayClockDirection::ForwardJump,
                    ..
                }
            ));
            let conn = store.pool.get().unwrap();
            let high_water_after = conn
                .query_row(
                    "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            assert_eq!(high_water_after, high_water_before);
        }

        let latched_high_water = base_time.saturating_add(1_000);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE chio_execution_nonce_clock SET wall_clock_high_water = ?1 WHERE singleton = 1",
                params![latched_high_water],
            )
            .unwrap();
        drop(connection);

        let error = match SqliteExecutionNonceStore::open(&path) {
            Ok(_) => panic!("a latched future high-water must require recovery"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SqliteExecutionNonceStoreError::ClockAnomaly {
                direction: ReplayClockDirection::Rollback,
                high_water_unix_secs,
                ..
            } if high_water_unix_secs == latched_high_water
        ));

        let corrected_high_water = now_secs();
        SqliteExecutionNonceStore::recover_clock_high_water(
            &path,
            latched_high_water,
            corrected_high_water,
        )
        .unwrap();
        let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
        assert!(!reopened
            .try_reserve("used", now_secs(), base_time.saturating_add(10_060),)
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn obsolete_schema_is_refused_without_rewriting_retained_rows() {
        let path = unique_db_path("chio-exec-nonce-legacy-high-water");
        let now = now_secs();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE chio_execution_nonces (
                    nonce_id   TEXT PRIMARY KEY,
                    consumed_at INTEGER NOT NULL,
                    expires_at  INTEGER NOT NULL
                );
                "#,
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chio_execution_nonces (nonce_id, consumed_at, expires_at) VALUES (?1, ?2, ?3)",
                params![
                    "legacy-used",
                    now.saturating_add(1_000),
                    now.saturating_add(2_000),
                ],
            )
            .unwrap();
        }

        assert!(matches!(
            SqliteExecutionNonceStore::open(&path),
            Err(SqliteExecutionNonceStoreError::Storage(_))
        ));
        let connection = Connection::open(&path).unwrap();
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(chio_execution_nonces)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(columns, ["nonce_id", "consumed_at", "expires_at"]);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM chio_execution_nonces", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            1
        );
        drop(connection);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn recovery_refuses_to_cross_a_pruned_high_water() {
        let path = unique_db_path("chio-exec-nonce-pruned-through");
        let base = now_secs();
        {
            let store = SqliteExecutionNonceStore::open(&path).unwrap();
            assert!(store
                .try_reserve_signed_entry(
                    "used",
                    base,
                    base.saturating_add(100),
                    base.saturating_add(160),
                    None,
                )
                .unwrap());
        }

        let jumped = base.saturating_add(1_000);
        let manager = SqliteConnectionManager::file(&path).with_init(configure_pooled_connection);
        let advanced = SqliteExecutionNonceStore {
            pool: Pool::builder().max_size(1).build(manager).unwrap(),
            capacity: DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
            clock: StableReplayClock::new(
                Arc::new(chio_security_types::clock::FixedClock::new(jumped as u64)),
                MAX_EXECUTION_NONCE_CLOCK_SKEW_I64,
            )
            .unwrap(),
        };
        advanced.run_migrations().unwrap();
        advanced.validate_retained_row_capacity().unwrap();
        drop(advanced);

        let error = SqliteExecutionNonceStore::recover_clock_high_water(&path, jumped, now_secs())
            .unwrap_err();
        assert!(error.to_string().contains("below pruned-through"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn typed_store_clock_anomaly_maps_to_typed_kernel_error() {
        let error =
            SqliteExecutionNonceStoreError::clock_anomaly(ReplayClockDirection::Rollback, 10, 20);
        assert!(matches!(
            kernel_store_error(error),
            KernelError::ReplayClockAnomaly {
                store: "sqlite_execution_nonce_store",
                direction: ReplayClockDirection::Rollback,
                observed_unix_secs: 10,
                high_water_unix_secs: 20,
                max_tolerated_skew_secs: MAX_EXECUTION_NONCE_CLOCK_SKEW_SECS,
            }
        ));
    }

    #[test]
    fn persists_across_reopen() {
        let path = unique_db_path("chio-exec-nonce");
        let now = now_secs();
        let expires_at = now.saturating_add(120);
        {
            let store = SqliteExecutionNonceStore::open(&path).unwrap();
            let now = now_secs();
            assert!(store
                .try_reserve("persistent-nonce", now, expires_at)
                .unwrap());
            assert!(store.is_consumed("persistent-nonce").unwrap());
        }
        let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
        assert!(reopened.is_consumed("persistent-nonce").unwrap());
        assert!(!reopened
            .try_reserve("persistent-nonce", now, expires_at)
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn consumed_lookup_ignores_expired_rows() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        store
            .pool
            .get()
            .unwrap()
            .execute(
                "INSERT INTO chio_execution_nonces (nonce_id, consumed_at, expires_at) VALUES (?1, ?2, ?3)",
                params![
                    "expired-nonce",
                    now.saturating_sub(2),
                    now.saturating_sub(1),
                ],
            )
            .unwrap();
        assert!(!store.is_consumed("expired-nonce").unwrap());
    }
}

#[cfg(test)]
mod clock_tests;
