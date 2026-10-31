//! The `chio_federation::verifier_ledger` ports over one SQLite file.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, Transaction, TransactionBehavior};

use chio_federation::verifier_ledger::LedgerFieldError;

use crate::integer::IntegerRangeError;
use crate::store_connection::StoreConnection;
use crate::{SchemaTransaction, SchemaVersionError};

mod challenges;
mod oid4vp_requests;

const SCHEMA_KEY: &str = "passport_verifier";

#[derive(Debug, thiserror::Error)]
pub enum PassportVerifierStoreError {
    #[error("passport verifier store requires a durable file path")]
    InvalidPath,
    #[error("passport verifier store schema refused: {0}")]
    Schema(#[from] SchemaVersionError),
    #[error("passport verifier store sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("passport verifier store filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("passport verifier store is unavailable: {0}")]
    Unavailable(String),
    #[error("passport verifier store value is out of range: {0}")]
    IntegerRange(#[from] IntegerRangeError),
    #[error("passport verifier store already holds `{0}`")]
    Duplicate(String),
    #[error("passport verifier store holds an invalid row")]
    InvalidRow,
    #[error("passport verifier store holds an invalid field: {0}")]
    InvalidField(#[from] LedgerFieldError),
}

type Result<T> = std::result::Result<T, PassportVerifierStoreError>;

/// One SQLite file holding a verifier's challenge and OID4VP ledgers.
#[derive(Debug)]
pub struct SqlitePassportVerifierStore {
    connection: StoreConnection,
}

impl SqlitePassportVerifierStore {
    /// Refuses an in-memory, foreign or other-schema database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = path.to_string_lossy();
        if text.is_empty() || text.eq_ignore_ascii_case(":memory:") || text.starts_with("file:") {
            return Err(PassportVerifierStoreError::InvalidPath);
        }
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let catalog = format!("{}\n{}", challenges::SCHEMA, oid4vp_requests::SCHEMA);
        let schema = SchemaTransaction::begin(&mut connection, &[SCHEMA_KEY])?;
        if schema.is_fresh() {
            schema.connection().execute_batch(&catalog)?;
            schema.stamp(SCHEMA_KEY)?;
        }
        schema.validate_catalog(&catalog)?;
        schema.commit()?;
        connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        Ok(Self {
            connection: StoreConnection::transaction_only("passport_verifier", connection),
        })
    }

    /// Runs `operation` as one single-statement read outside a transaction.
    fn read<T>(&self, operation: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        operation(&*self.lock()?)
    }

    fn transact<T>(&self, operation: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = operation(&transaction)?;
        transaction.commit()?;
        Ok(value)
    }

    fn lock(&self) -> Result<crate::store_connection::StoreGuard<'_>> {
        self.connection
            .lock()
            .map_err(|fenced| PassportVerifierStoreError::Unavailable(fenced.to_string()))
    }
}

fn duplicate_or(error: rusqlite::Error, id: &str) -> PassportVerifierStoreError {
    match &error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY =>
        {
            PassportVerifierStoreError::Duplicate(id.to_owned())
        }
        _ => error.into(),
    }
}

fn stored_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| PassportVerifierStoreError::InvalidRow)
}

#[cfg(test)]
#[path = "passport_verifier_store_tests.rs"]
mod tests;
