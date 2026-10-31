//! SQLite storage for the enterprise identity index.
//!
//! One immediate transaction covers each index operation: it reads every row, applies the
//! changes the operation returns, and commits. A refused or read-only operation rolls back.

use std::path::Path;
use std::time::Duration;

use chio_core::enterprise_identity::{
    EnterpriseIdentityChanges, EnterpriseIdentityId, EnterpriseIdentityIndexError as IndexError,
    EnterpriseIdentityRow, EnterpriseIdentityRows, EnterpriseIdentityStore,
    EnterpriseIdentityTransaction, EnterpriseSubjectHistoryRow, StoreFault,
    ENTERPRISE_IDENTITY_MAX_HISTORY, ENTERPRISE_IDENTITY_MAX_IDENTITIES,
    ENTERPRISE_PRINCIPAL_MAX_BYTES,
};
use chio_core::enterprise_subject::EnterpriseSubjectKey;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, ErrorCode, Row, TransactionBehavior};

use crate::store_connection::StoreConnection;
use crate::{SchemaTransaction, SchemaVersionError};

const SCHEMA_KEY: &str = "enterprise_identity";
const SCHEMA: &str = include_str!("enterprise_identity_store.sql");

const _: () = assert!(ENTERPRISE_PRINCIPAL_MAX_BYTES == 4096);
const IDENTITY_ID_BYTES: usize = 32;
const SUBJECT_MAX_BYTES: usize = 256;

const COUNT_IDENTITIES: &str = "SELECT count(*) FROM enterprise_identities";
const COUNT_HISTORY: &str = "SELECT count(*) FROM enterprise_identity_history";
const SELECT_IDENTITIES: &str = "SELECT \
    CASE WHEN typeof(identity_id) = 'text' AND octet_length(identity_id) = 32 \
        THEN identity_id END, \
    CASE WHEN typeof(provider_scope) = 'text' AND octet_length(provider_scope) <= 4096 \
        THEN provider_scope END, \
    CASE WHEN typeof(principal) = 'text' AND octet_length(principal) <= 4096 \
        THEN principal END, \
    CASE WHEN typeof(subject) = 'text' AND octet_length(subject) <= 256 THEN subject END, \
    deactivated_at \
    FROM enterprise_identities ORDER BY identity_id";
const SELECT_HISTORY: &str = "SELECT \
    CASE WHEN typeof(identity_id) = 'text' AND octet_length(identity_id) = 32 \
        THEN identity_id END, \
    CASE WHEN typeof(subject) = 'text' AND octet_length(subject) <= 256 THEN subject END \
    FROM enterprise_identity_history ORDER BY identity_id, subject";
const DELETE_HISTORY: &str = "DELETE FROM enterprise_identity_history WHERE subject = ?1";
const INSERT_IDENTITY: &str = "INSERT INTO enterprise_identities \
    (identity_id, provider_scope, principal, subject, deactivated_at) VALUES (?1, ?2, ?3, ?4, ?5)";
const REKEY_IDENTITY: &str = "UPDATE enterprise_identities SET subject = ?2 WHERE identity_id = ?1";
const INSERT_HISTORY: &str =
    "INSERT INTO enterprise_identity_history (subject, identity_id) VALUES (?1, ?2)";
const DEACTIVATE_IDENTITY: &str = "UPDATE enterprise_identities SET deactivated_at = ?2 \
    WHERE identity_id = ?1 AND deactivated_at IS NULL";

const MALFORMED: IndexError = IndexError::MalformedRow;

/// Why an enterprise identity store could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum SqliteEnterpriseIdentityStoreError {
    /// The path names no durable file.
    #[error("enterprise identity store requires a durable file path")]
    InvalidPath,
    /// The database holds a foreign or mismatched schema.
    #[error("enterprise identity store schema refused: {0}")]
    Schema(#[from] SchemaVersionError),
    /// SQLite refused an open-time statement.
    #[error("enterprise identity store sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The parent directory could not be created.
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
        connection.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;",
        )?;
        Ok(Self {
            connection: StoreConnection::transaction_only("enterprise_identity", connection),
        })
    }
}

impl EnterpriseIdentityStore for SqliteEnterpriseIdentityStore {
    fn transact(
        &self,
        transaction: &mut EnterpriseIdentityTransaction<'_>,
    ) -> Result<(), IndexError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_fenced| IndexError::StoreUnavailable(StoreFault::Io))?;
        let write = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(fault)?;
        if let Some(changes) = transaction(read_rows(&write)?)? {
            apply(&write, &changes).map_err(fault)?;
            write.commit().map_err(fault)?;
        }
        Ok(())
    }
}

/// The backend-free class of a SQLite error.
fn fault(error: rusqlite::Error) -> IndexError {
    IndexError::StoreUnavailable(match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => StoreFault::Busy,
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => StoreFault::Corrupt,
        Some(ErrorCode::ConstraintViolation) => StoreFault::Constraint,
        _ => StoreFault::Io,
    })
}

/// Every stored row.
fn read_rows(connection: &Connection) -> Result<EnterpriseIdentityRows, IndexError> {
    let identities = (
        COUNT_IDENTITIES,
        SELECT_IDENTITIES,
        ENTERPRISE_IDENTITY_MAX_IDENTITIES,
    );
    let history = (
        COUNT_HISTORY,
        SELECT_HISTORY,
        ENTERPRISE_IDENTITY_MAX_HISTORY,
    );
    Ok(EnterpriseIdentityRows {
        identities: read_table(connection, identities, |row| {
            let deactivated_at = match row.get_ref(4).map_err(fault)? {
                ValueRef::Null => None,
                ValueRef::Integer(at) => Some(u64::try_from(at).or(Err(MALFORMED))?),
                _ => return Err(MALFORMED),
            };
            Ok(EnterpriseIdentityRow {
                identity_id: identity_id(row, 0)?,
                provider_scope: text(row, 1, ENTERPRISE_PRINCIPAL_MAX_BYTES)?,
                principal: text(row, 2, ENTERPRISE_PRINCIPAL_MAX_BYTES)?,
                subject: subject(row, 3)?,
                deactivated_at,
            })
        })?,
        history: read_table(connection, history, |row| {
            Ok(EnterpriseSubjectHistoryRow {
                identity_id: identity_id(row, 0)?,
                subject: subject(row, 1)?,
            })
        })?,
    })
}

/// Every row `select` returns, decoded. A table whose `count` exceeds `max` is refused as
/// tampered before any row is read.
fn read_table<T>(
    connection: &Connection,
    (count, select, max): (&str, &str, usize),
    decode: impl Fn(&Row<'_>) -> Result<T, IndexError>,
) -> Result<Vec<T>, IndexError> {
    let rows: i64 = connection
        .query_row(count, [], |row| row.get(0))
        .map_err(fault)?;
    if !usize::try_from(rows).is_ok_and(|rows| rows <= max) {
        return Err(MALFORMED);
    }
    let mut statement = connection.prepare(select).map_err(fault)?;
    let mut stored = statement.query([]).map_err(fault)?;
    let mut decoded = Vec::new();
    while let Some(row) = stored.next().map_err(fault)? {
        decoded.push(decode(row)?);
    }
    Ok(decoded)
}

/// Column `index` as UTF-8 text of at most `max` bytes, borrowed until it is in bounds. The
/// select guards each text column's type and stored size, so an oversized value reads as NULL.
fn text(row: &Row<'_>, index: usize, max: usize) -> Result<String, IndexError> {
    let ValueRef::Text(bytes) = row.get_ref(index).map_err(fault)? else {
        return Err(MALFORMED);
    };
    let text = std::str::from_utf8(bytes)
        .ok()
        .filter(|text| text.len() <= max);
    text.map(str::to_owned).ok_or(MALFORMED)
}

fn identity_id(row: &Row<'_>, index: usize) -> Result<EnterpriseIdentityId, IndexError> {
    EnterpriseIdentityId::try_from(text(row, index, IDENTITY_ID_BYTES)?).or(Err(MALFORMED))
}

fn subject(row: &Row<'_>, index: usize) -> Result<EnterpriseSubjectKey, IndexError> {
    EnterpriseSubjectKey::parse(&text(row, index, SUBJECT_MAX_BYTES)?).or(Err(MALFORMED))
}

/// Applies `changes` in field order, so each history row lands after the identity it names.
fn apply(connection: &Connection, changes: &EnterpriseIdentityChanges) -> rusqlite::Result<()> {
    for subject in &changes.restored {
        connection.execute(DELETE_HISTORY, [subject.to_string()])?;
    }
    for row in &changes.inserted {
        let (id, subject) = (row.identity_id.as_str(), row.subject.to_string());
        let (scope, principal, at) = (&row.provider_scope, &row.principal, row.deactivated_at);
        connection.execute(INSERT_IDENTITY, (id, scope, principal, subject, at))?;
    }
    for (identity_id, subject) in &changes.rekeyed {
        connection.execute(REKEY_IDENTITY, (identity_id.as_str(), subject.to_string()))?;
    }
    for row in &changes.history {
        let history = (row.subject.to_string(), row.identity_id.as_str());
        connection.execute(INSERT_HISTORY, history)?;
    }
    for (identity_id, at) in &changes.deactivated {
        connection.execute(DEACTIVATE_IDENTITY, (identity_id.as_str(), *at))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "enterprise_identity_store_tests.rs"]
mod tests;
