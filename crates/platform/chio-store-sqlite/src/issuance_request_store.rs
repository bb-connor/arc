//! SQLite [`IssuanceRequestRepository`] for federated-issuance requests
//! awaiting an operator decision.

use std::path::Path;
use std::time::Duration;

use chio_federation::issuance_requests::{
    IssuanceClaim, IssuanceClaimToken, IssuanceDecision, IssuanceListQuery, IssuanceRequestPage,
    IssuanceRequestRecord, IssuanceRequestRepository, IssuanceRequestStatus,
    IssuanceRequestSummary, IssuanceStoreError, EXPIRED_REASON, MAX_PENDING_ISSUANCE_REQUESTS,
};
use rusqlite::{params, Connection, ErrorCode, OptionalExtension, Row, TransactionBehavior};

use crate::store_connection::{StoreConnection, StoreGuard};
use crate::{SchemaTransaction, SchemaVersionError};

mod sql;

const SCHEMA_KEY: &str = "federation_issuance_requests";

#[derive(Debug, thiserror::Error)]
pub enum IssuanceRequestStoreOpenError {
    #[error("issuance request store requires a durable file path")]
    InvalidPath,
    #[error("issuance request store schema refused: {0}")]
    Schema(#[from] SchemaVersionError),
    #[error("issuance request store sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("issuance request store filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

/// One SQLite file holding every federated-issuance request. Each repository
/// method runs in one `IMMEDIATE` transaction with the expiry sweep it
/// depends on.
pub struct SqliteIssuanceRequestStore {
    connection: StoreConnection,
    pending_cap: usize,
}

impl std::fmt::Debug for SqliteIssuanceRequestStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteIssuanceRequestStore")
            .field("pending_cap", &self.pending_cap)
            .finish_non_exhaustive()
    }
}

/// Busy and locked databases are `Busy`; a corrupt file, a foreign file or a
/// row that does not decode is `Integrity`; every other failure is
/// `Unavailable`.
fn classify(error: rusqlite::Error) -> IssuanceStoreError {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => IssuanceStoreError::Busy,
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => IssuanceStoreError::Integrity,
        _ => match error {
            rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
            | rusqlite::Error::InvalidColumnType(..) => IssuanceStoreError::Integrity,
            _ => IssuanceStoreError::Unavailable,
        },
    }
}

fn to_i64(value: u64) -> Result<i64, IssuanceStoreError> {
    i64::try_from(value).map_err(|_| IssuanceStoreError::InvalidTimestamp)
}

fn column_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn column_optional_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    match row.get::<_, Option<i64>>(index)? {
        None => Ok(None),
        Some(_) => column_u64(row, index).map(Some),
    }
}

fn column_status(row: &Row<'_>, index: usize) -> rusqlite::Result<IssuanceRequestStatus> {
    let value: String = row.get(index)?;
    IssuanceRequestStatus::parse(&value).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            format!("unknown issuance request status {value}").into(),
        )
    })
}

fn record_row(row: &Row<'_>) -> rusqlite::Result<IssuanceRequestRecord> {
    Ok(IssuanceRequestRecord {
        challenge_id: row.get(0)?,
        subject: row.get(1)?,
        verifier: row.get(2)?,
        presentation_json: row.get(3)?,
        challenge_json: row.get(4)?,
        submitted_at: column_u64(row, 5)?,
        expires_at: column_u64(row, 6)?,
        status: column_status(row, 7)?,
        decided_at: column_optional_u64(row, 8)?,
        capability_id: row.get(9)?,
        decision_reason: row.get(10)?,
    })
}

fn summary_row(row: &Row<'_>) -> rusqlite::Result<IssuanceRequestSummary> {
    Ok(IssuanceRequestSummary {
        challenge_id: row.get(0)?,
        subject: row.get(1)?,
        verifier: row.get(2)?,
        submitted_at: column_u64(row, 3)?,
        expires_at: column_u64(row, 4)?,
        status: column_status(row, 5)?,
        decided_at: column_optional_u64(row, 6)?,
        capability_id: row.get(7)?,
        decision_reason: row.get(8)?,
    })
}

fn get_with(
    connection: &Connection,
    challenge_id: &str,
) -> Result<Option<IssuanceRequestRecord>, IssuanceStoreError> {
    connection
        .query_row(sql::GET, params![challenge_id], record_row)
        .optional()
        .map_err(classify)
}

fn expire_stale(connection: &Connection, now: u64) -> Result<(), IssuanceStoreError> {
    connection
        .execute(sql::EXPIRE_STALE, params![to_i64(now)?, EXPIRED_REASON])
        .map_err(classify)?;
    Ok(())
}

impl SqliteIssuanceRequestStore {
    /// Open or create the store at `path`. An in-memory database, a foreign
    /// database or a database of another schema refuses.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IssuanceRequestStoreOpenError> {
        let path = path.as_ref();
        let text = path.to_string_lossy();
        if text.is_empty() || text.eq_ignore_ascii_case(":memory:") || text.starts_with("file:") {
            return Err(IssuanceRequestStoreOpenError::InvalidPath);
        }
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let schema = SchemaTransaction::begin(&mut connection, &[SCHEMA_KEY])?;
        if schema.is_fresh() {
            schema.connection().execute_batch(sql::SCHEMA)?;
            schema.stamp(SCHEMA_KEY)?;
        }
        schema.validate_catalog(sql::SCHEMA)?;
        schema.commit()?;
        connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        Ok(Self {
            connection: StoreConnection::transaction_only(SCHEMA_KEY, connection),
            pending_cap: MAX_PENDING_ISSUANCE_REQUESTS,
        })
    }

    #[cfg(test)]
    fn with_pending_cap(mut self, pending_cap: usize) -> Self {
        self.pending_cap = pending_cap;
        self
    }

    fn lock(&self) -> Result<StoreGuard<'_>, IssuanceStoreError> {
        self.connection
            .lock()
            .map_err(|_| IssuanceStoreError::Unavailable)
    }
}

impl IssuanceRequestRepository for SqliteIssuanceRequestStore {
    fn submit(&self, record: &IssuanceRequestRecord, now: u64) -> Result<(), IssuanceStoreError> {
        if record.expires_at <= now {
            return Err(IssuanceStoreError::Expired(record.challenge_id.clone()));
        }
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify)?;
        expire_stale(&tx, now)?;
        let exists = tx
            .query_row(sql::EXISTS, params![record.challenge_id], |_| Ok(()))
            .optional()
            .map_err(classify)?;
        if exists.is_some() {
            return Err(IssuanceStoreError::AlreadySubmitted(
                record.challenge_id.clone(),
            ));
        }
        let open: i64 = tx
            .query_row(sql::COUNT_OPEN, [], |row| row.get(0))
            .map_err(classify)?;
        if usize::try_from(open).map_err(|_| IssuanceStoreError::Integrity)? >= self.pending_cap {
            return Err(IssuanceStoreError::Full);
        }
        tx.execute(
            sql::INSERT_PENDING,
            params![
                record.challenge_id,
                record.subject,
                record.verifier,
                record.presentation_json,
                record.challenge_json,
                to_i64(record.submitted_at)?,
                to_i64(record.expires_at)?,
            ],
        )
        .map_err(classify)?;
        tx.commit().map_err(classify)
    }

    fn get(&self, challenge_id: &str) -> Result<Option<IssuanceRequestRecord>, IssuanceStoreError> {
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(classify)?;
        let record = get_with(&tx, challenge_id)?;
        tx.commit().map_err(classify)?;
        Ok(record)
    }

    fn list(
        &self,
        query: IssuanceListQuery<'_>,
        now: u64,
    ) -> Result<IssuanceRequestPage, IssuanceStoreError> {
        let limit = query.limit.get();
        let fetch = i64::try_from(limit + 1).map_err(|_| IssuanceStoreError::Unavailable)?;
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify)?;
        expire_stale(&tx, now)?;
        let cursor = match query.after {
            None => None,
            Some(id) => {
                let submitted_at: Option<i64> = tx
                    .query_row(sql::SUBMITTED_AT, params![id], |row| row.get(0))
                    .optional()
                    .map_err(classify)?;
                Some((
                    submitted_at.ok_or_else(|| IssuanceStoreError::NotFound(id.to_string()))?,
                    id,
                ))
            }
        };
        let mut requests = {
            let status = query.status.map(IssuanceRequestStatus::as_str);
            let mut values: Vec<&dyn rusqlite::ToSql> = Vec::new();
            if let Some(status) = &status {
                values.push(status);
            }
            if let Some((at, id)) = &cursor {
                values.push(at);
                values.push(id);
            }
            values.push(&fetch);
            let statement = match (status.is_some(), cursor.is_some()) {
                (false, false) => sql::LIST_ALL,
                (false, true) => sql::LIST_ALL_AFTER,
                (true, false) => sql::LIST_STATUS,
                (true, true) => sql::LIST_STATUS_AFTER,
            };
            let mut statement = tx.prepare(statement).map_err(classify)?;
            let summaries = statement
                .query_map(values.as_slice(), summary_row)
                .map_err(classify)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(classify)?;
            summaries
        };
        tx.commit().map_err(classify)?;
        let next_after = if requests.len() > limit {
            requests.truncate(limit);
            requests.last().map(|request| request.challenge_id.clone())
        } else {
            None
        };
        Ok(IssuanceRequestPage {
            requests,
            next_after,
        })
    }

    fn claim(&self, challenge_id: &str, now: u64) -> Result<IssuanceClaim, IssuanceStoreError> {
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify)?;
        expire_stale(&tx, now)?;
        let epoch: Option<i64> = tx
            .query_row(sql::CLAIM, params![challenge_id], |row| row.get(0))
            .optional()
            .map_err(classify)?;
        let record = get_with(&tx, challenge_id)?;
        tx.commit().map_err(classify)?;
        match (epoch, record) {
            (Some(epoch), Some(record)) => Ok(IssuanceClaim {
                token: IssuanceClaimToken::new(
                    challenge_id,
                    u64::try_from(epoch).map_err(|_| IssuanceStoreError::Integrity)?,
                ),
                record,
            }),
            (_, Some(_)) => Err(IssuanceStoreError::NotPending(challenge_id.to_string())),
            (_, None) => Err(IssuanceStoreError::NotFound(challenge_id.to_string())),
        }
    }

    fn finish(
        &self,
        token: &IssuanceClaimToken,
        decision: &IssuanceDecision,
        now: u64,
        reason: Option<&str>,
    ) -> Result<(), IssuanceStoreError> {
        let challenge_id = token.challenge_id();
        let not_claimed = || IssuanceStoreError::NotClaimed(challenge_id.to_string());
        let epoch = i64::try_from(token.epoch()).map_err(|_| not_claimed())?;
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify)?;
        let changed = tx
            .execute(
                sql::FINISH,
                params![
                    challenge_id,
                    decision.status().as_str(),
                    to_i64(now)?,
                    decision.capability_id(),
                    reason,
                    epoch
                ],
            )
            .map_err(classify)?;
        if changed == 0 {
            return Err(not_claimed());
        }
        tx.commit().map_err(classify)
    }

    fn release(&self, token: &IssuanceClaimToken) -> Result<(), IssuanceStoreError> {
        let challenge_id = token.challenge_id();
        let not_claimed = || IssuanceStoreError::NotClaimed(challenge_id.to_string());
        let epoch = i64::try_from(token.epoch()).map_err(|_| not_claimed())?;
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify)?;
        let changed = tx
            .execute(sql::RELEASE, params![challenge_id, epoch])
            .map_err(classify)?;
        if changed == 0 {
            return Err(not_claimed());
        }
        tx.commit().map_err(classify)
    }
}

#[cfg(test)]
#[path = "issuance_request_store_tests.rs"]
mod tests;
