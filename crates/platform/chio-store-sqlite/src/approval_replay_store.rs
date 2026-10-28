use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use chio_security_types::clock::ClockError;
use chio_settle::{ApprovalReplayOutcome, ApprovalReplayStore, SettlementError};
use chio_sqlite_file_identity::{main_database_file_identity, SqliteFileIdentity};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::{SchemaTransaction, SchemaVersionError};

mod path;
mod schema;

use schema::{validate_state, SCHEMA, SCHEMA_KEY};

const MAX_CAPACITY: usize = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum SqliteApprovalReplayStoreError {
    #[error("settlement replay requires an owned, unaliased durable file")]
    InvalidPath,
    #[error("settlement replay file identity changed")]
    FileIdentityChanged,
    #[error("settlement replay capacity invalid")]
    InvalidCapacity,
    #[error("settlement replay capacity differs from the retained limit")]
    CapacityMismatch,
    #[error("settlement replay capacity exhausted")]
    CapacityExhausted,
    #[error("settlement replay identity malformed")]
    InvalidIdentity,
    #[error("settlement replay state invalid")]
    InvalidState,
    #[error("settlement replay store unavailable")]
    Unavailable,
    #[error("settlement replay schema refused: {0}")]
    Schema(#[from] SchemaVersionError),
    #[error("settlement replay SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("settlement replay filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("settlement replay clock failed: {0}")]
    Clock(#[from] ClockError),
}

pub struct SqliteApprovalReplayStore {
    connection: Mutex<Connection>,
    path: PathBuf,
    identity: SqliteFileIdentity,
    capacity: usize,
}

impl SqliteApprovalReplayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteApprovalReplayStoreError> {
        Self::open_with_capacity(path, MAX_CAPACITY)
    }

    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, SqliteApprovalReplayStoreError> {
        if capacity == 0 || capacity > MAX_CAPACITY {
            return Err(SqliteApprovalReplayStoreError::InvalidCapacity);
        }
        let path = path::prepare(path.as_ref())?;
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let identity = main_database_file_identity(&connection)
            .map_err(|_| SqliteApprovalReplayStoreError::InvalidPath)?;
        path::verify(&path, identity)?;
        let schema = SchemaTransaction::begin(&mut connection, &[SCHEMA_KEY])?;
        if schema.is_fresh() {
            schema.connection().execute_batch(SCHEMA)?;
            schema.connection().execute(
                "INSERT INTO settlement_approval_replay_state (singleton, capacity, high_water_unix_ms) VALUES (1, ?1, 0)",
                [i64::try_from(capacity).map_err(|_| SqliteApprovalReplayStoreError::InvalidCapacity)?],
            )?;
            schema.stamp(SCHEMA_KEY)?;
        }
        schema.validate_catalog(SCHEMA)?;
        validate_state(schema.connection(), capacity)?;
        schema.commit()?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        path::verify(&path, identity)?;
        Ok(Self {
            connection: Mutex::new(connection),
            path,
            identity,
            capacity,
        })
    }

    fn record(
        &self,
        request_id: &str,
        intent_hash: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<ApprovalReplayOutcome, SqliteApprovalReplayStoreError> {
        if request_id.is_empty()
            || request_id.len() > 256
            || request_id.trim() != request_id
            || request_id.chars().any(char::is_control)
            || intent_hash.len() != 64
            || !intent_hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(SqliteApprovalReplayStoreError::InvalidIdentity);
        }
        if expires_at_unix_ms <= now_unix_ms {
            return Err(ClockError::Expired.into());
        }
        let expires_at = i64::try_from(expires_at_unix_ms).map_err(|_| ClockError::Overflow)?;
        let now = i64::try_from(now_unix_ms).map_err(|_| ClockError::Overflow)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SqliteApprovalReplayStoreError::Unavailable)?;
        let opened = main_database_file_identity(&connection)
            .map_err(|_| SqliteApprovalReplayStoreError::FileIdentityChanged)?;
        if opened != self.identity {
            return Err(SqliteApprovalReplayStoreError::FileIdentityChanged);
        }
        path::verify(&self.path, self.identity)?;
        let schema = SchemaTransaction::begin(&mut connection, &[SCHEMA_KEY])?;
        if schema.is_fresh() {
            return Err(SqliteApprovalReplayStoreError::InvalidState);
        }
        schema.validate_catalog(SCHEMA)?;
        let high_water = validate_state(schema.connection(), self.capacity)?;
        if now < high_water {
            return Err(ClockError::WallClockRegression.into());
        }
        let transaction = schema.connection();
        transaction.execute(
            "DELETE FROM settlement_approval_replays WHERE expires_at_unix_ms <= ?1",
            [now],
        )?;
        transaction.execute(
            "UPDATE settlement_approval_replay_state SET high_water_unix_ms = ?1 WHERE singleton = 1",
            [now],
        )?;
        let present = transaction
            .query_row(
                "SELECT 1 FROM settlement_approval_replays WHERE request_id = ?1 AND intent_hash = ?2",
                params![request_id, intent_hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let outcome = if present {
            ApprovalReplayOutcome::Replayed
        } else {
            let count: i64 = transaction.query_row(
                "SELECT count(*) FROM settlement_approval_replays",
                [],
                |row| row.get(0),
            )?;
            if usize::try_from(count).map_err(|_| SqliteApprovalReplayStoreError::InvalidState)?
                >= self.capacity
            {
                return Err(SqliteApprovalReplayStoreError::CapacityExhausted);
            }
            transaction.execute(
                "INSERT INTO settlement_approval_replays (request_id, intent_hash, expires_at_unix_ms) VALUES (?1, ?2, ?3)",
                params![request_id, intent_hash, expires_at],
            )?;
            ApprovalReplayOutcome::Fresh
        };
        path::verify(&self.path, self.identity)?;
        schema.commit()?;
        Ok(outcome)
    }
}

impl ApprovalReplayStore for SqliteApprovalReplayStore {
    fn record_if_fresh(
        &self,
        request_id: &str,
        intent_hash: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<ApprovalReplayOutcome, SettlementError> {
        self.record(request_id, intent_hash, expires_at_unix_ms, now_unix_ms)
            .map_err(|error| {
                let reason = match error {
                    SqliteApprovalReplayStoreError::Clock(clock) => clock.code().to_string(),
                    SqliteApprovalReplayStoreError::Schema(_) => {
                        "settlement replay schema refused".to_string()
                    }
                    other => other.to_string(),
                };
                SettlementError::Verification(reason)
            })
    }
}
