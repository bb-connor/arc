//! The receiver's durable state: a replay table keyed by request identifier and
//! a signed decision log.
//!
//! SQLite in WAL with `synchronous = FULL`, the same durability the Chio
//! receipt store runs under, so a per-call latency or per-call byte figure
//! taken here is comparable with the one taken there.

use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Sqlite(error) => write!(f, "sqlite: {error}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        StoreError::Sqlite(error)
    }
}

/// Outcome of claiming a request identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceClaim {
    /// This call created the row: the identifier had not been seen.
    Fresh,
    /// A row already existed: the identifier is a replay.
    Seen,
}

pub struct BaselineStore {
    connection: Connection,
}

impl BaselineStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS replay_table (
                 request_id TEXT PRIMARY KEY,
                 caller TEXT NOT NULL,
                 claimed_at_unix_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS decision_log (
                 decision_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 request_id TEXT NOT NULL,
                 record_json TEXT NOT NULL,
                 record_sig TEXT NOT NULL
             );",
        )?;
        Ok(Self { connection })
    }

    /// Claim a request identifier. A single-row insert on a primary key:
    /// exactly one of any set of concurrent claims creates the row.
    pub fn claim_request_id(
        &self,
        request_id: &str,
        caller: &str,
        now_unix_ms: u64,
    ) -> Result<NonceClaim, StoreError> {
        let created = self.connection.execute(
            "INSERT OR IGNORE INTO replay_table (request_id, caller, claimed_at_unix_ms)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![request_id, caller, now_unix_ms as i64],
        )?;
        if created == 1 {
            Ok(NonceClaim::Fresh)
        } else {
            Ok(NonceClaim::Seen)
        }
    }

    /// Append one signed decision record. Durable on return.
    pub fn append_decision(
        &self,
        request_id: &str,
        record_json: &str,
        record_sig: &str,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO decision_log (request_id, record_json, record_sig) VALUES (?1, ?2, ?3)",
            rusqlite::params![request_id, record_json, record_sig],
        )?;
        Ok(())
    }

    pub fn decision_count(&self) -> Result<u64, StoreError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM decision_log", [], |row| row.get(0))?;
        Ok(count.max(0) as u64)
    }

    pub fn seen_request_id(&self, request_id: &str) -> Result<bool, StoreError> {
        let found: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM replay_table WHERE request_id = ?1",
                rusqlite::params![request_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Flush the write-ahead log into the main database so a file-size reading
    /// counts every byte the run made durable.
    pub fn checkpoint(&self) -> Result<(), StoreError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }
}
