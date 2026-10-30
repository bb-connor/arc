//! SQLite storage for the enterprise identity index.
//!
//! One immediate transaction covers each index operation: it reads every row, and the rows the
//! operation returns replace them before commit. A refused operation rolls back.

use std::path::Path;
use std::time::Duration;

use chio_core::enterprise_identity::{
    EnterpriseIdentityId, EnterpriseIdentityIndexError, EnterpriseIdentityRow,
    EnterpriseIdentityRows, EnterpriseIdentityStore, EnterpriseIdentityTransaction,
    EnterpriseSubjectHistoryRow, ENTERPRISE_IDENTITY_MAX_IDENTITIES,
};
use chio_core::enterprise_subject::EnterpriseSubjectKey;
use rusqlite::{params, Connection, TransactionBehavior};

use crate::store_connection::StoreConnection;
use crate::{SchemaTransaction, SchemaVersionError};

const SCHEMA_KEY: &str = "enterprise_identity";
const SCHEMA: &str = include_str!("enterprise_identity_store.sql");

#[derive(Debug, thiserror::Error)]
pub enum SqliteEnterpriseIdentityStoreError {
    #[error("enterprise identity store requires a durable file path")]
    InvalidPath,
    #[error("enterprise identity store schema refused: {0}")]
    Schema(#[from] SchemaVersionError),
    #[error("enterprise identity store sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("enterprise identity store filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

/// One SQLite file holding one enterprise identity index.
#[derive(Debug)]
pub struct SqliteEnterpriseIdentityStore {
    connection: StoreConnection,
}

impl SqliteEnterpriseIdentityStore {
    /// Open or create the store at `path`. An in-memory database, a foreign database or a
    /// database of another schema refuses.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteEnterpriseIdentityStoreError> {
        let path = path.as_ref();
        let text = path.to_string_lossy();
        if text.is_empty() || text.eq_ignore_ascii_case(":memory:") || text.starts_with("file:") {
            return Err(SqliteEnterpriseIdentityStoreError::InvalidPath);
        }
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let schema = SchemaTransaction::begin(&mut connection, &[SCHEMA_KEY])?;
        if schema.is_fresh() {
            schema.connection().execute_batch(SCHEMA)?;
            schema.stamp(SCHEMA_KEY)?;
        }
        schema.validate_catalog(SCHEMA)?;
        schema.commit()?;
        connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        Ok(Self {
            connection: StoreConnection::transaction_only("enterprise_identity", connection),
        })
    }
}

impl EnterpriseIdentityStore for SqliteEnterpriseIdentityStore {
    fn transact<R>(
        &self,
        transaction: impl FnOnce(EnterpriseIdentityRows) -> EnterpriseIdentityTransaction<R>,
    ) -> Result<R, EnterpriseIdentityIndexError> {
        let mut connection = self.connection.lock().map_err(|_| unavailable())?;
        let write = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let (outcome, replaced) = transaction(read_rows(&write)?)?;
        if let Some(rows) = replaced {
            replace_rows(&write, &rows).map_err(|_| unavailable())?;
        }
        write.commit().map_err(|_| unavailable())?;
        Ok(outcome)
    }
}

fn unavailable() -> EnterpriseIdentityIndexError {
    EnterpriseIdentityIndexError::StoreUnavailable
}

fn malformed() -> EnterpriseIdentityIndexError {
    EnterpriseIdentityIndexError::MalformedRow
}

/// Every stored row. The identity count is bounded before any row is read.
fn read_rows(
    connection: &Connection,
) -> Result<EnterpriseIdentityRows, EnterpriseIdentityIndexError> {
    let identities: i64 = connection
        .query_row("SELECT count(*) FROM enterprise_identities", [], |row| {
            row.get(0)
        })
        .map_err(|_| unavailable())?;
    if !usize::try_from(identities).is_ok_and(|count| count <= ENTERPRISE_IDENTITY_MAX_IDENTITIES) {
        return Err(EnterpriseIdentityIndexError::CapacityExhausted);
    }
    let mut rows = EnterpriseIdentityRows::default();
    let mut statement = connection
        .prepare(
            "SELECT identity_id, provider_scope, principal, subject, deactivated_at \
             FROM enterprise_identities ORDER BY identity_id",
        )
        .map_err(|_| unavailable())?;
    let mut stored = statement.query([]).map_err(|_| unavailable())?;
    while let Some(row) = stored.next().map_err(|_| unavailable())? {
        let deactivated_at: Option<i64> = row.get(4).map_err(|_| malformed())?;
        rows.identities.push(EnterpriseIdentityRow {
            identity_id: identity_id(row.get(0).map_err(|_| malformed())?)?,
            provider_scope: row.get(1).map_err(|_| malformed())?,
            principal: row.get(2).map_err(|_| malformed())?,
            subject: subject(&row.get::<_, String>(3).map_err(|_| malformed())?)?,
            deactivated_at: deactivated_at.map(|at| u64::from_be_bytes(at.to_be_bytes())),
        });
    }
    let mut statement = connection
        .prepare(
            "SELECT identity_id, subject FROM enterprise_identity_history \
             ORDER BY identity_id, subject",
        )
        .map_err(|_| unavailable())?;
    let mut stored = statement.query([]).map_err(|_| unavailable())?;
    while let Some(row) = stored.next().map_err(|_| unavailable())? {
        rows.history.push(EnterpriseSubjectHistoryRow {
            identity_id: identity_id(row.get(0).map_err(|_| malformed())?)?,
            subject: subject(&row.get::<_, String>(1).map_err(|_| malformed())?)?,
        });
    }
    Ok(rows)
}

/// Replaces every stored row. A deactivation time is stored as the two's-complement `i64`
/// bit pattern of its `u64` value.
fn replace_rows(
    connection: &Connection,
    rows: &EnterpriseIdentityRows,
) -> Result<(), rusqlite::Error> {
    connection.execute_batch(
        "DELETE FROM enterprise_identity_history; DELETE FROM enterprise_identities;",
    )?;
    let mut insert = connection.prepare(
        "INSERT INTO enterprise_identities \
         (identity_id, provider_scope, principal, subject, deactivated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for row in &rows.identities {
        insert.execute(params![
            row.identity_id.as_str(),
            row.provider_scope,
            row.principal,
            row.subject.to_string(),
            row.deactivated_at
                .map(|at| i64::from_be_bytes(at.to_be_bytes())),
        ])?;
    }
    let mut insert = connection.prepare(
        "INSERT INTO enterprise_identity_history (subject, identity_id) VALUES (?1, ?2)",
    )?;
    for row in &rows.history {
        insert.execute(params![row.subject.to_string(), row.identity_id.as_str()])?;
    }
    Ok(())
}

fn identity_id(text: String) -> Result<EnterpriseIdentityId, EnterpriseIdentityIndexError> {
    EnterpriseIdentityId::try_from(text).map_err(|_| malformed())
}

fn subject(text: &str) -> Result<EnterpriseSubjectKey, EnterpriseIdentityIndexError> {
    EnterpriseSubjectKey::parse(text).map_err(|_| malformed())
}

#[cfg(test)]
#[path = "enterprise_identity_store_tests.rs"]
mod tests;
