use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use chio_core::canonical::{canonical_json_bytes, UntrustedJsonText};
use chio_security_types::ports::{
    AlertBackendOutcome, AlertDeliveryStatus, Digest32, DueSecurityAlert, PortError, PortErrorKind,
    PortResult, RecordId, SecurityAlert, SecurityAlertOutboxBacklog, SecurityAlertOutboxStore,
    SECURITY_ALERT_MAX_CANONICAL_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::store_connection::{StoreConnection, StoreGuard};
use crate::{SchemaTransaction, SchemaVersionError};

mod sql;

use sql::{
    INSERT_BACKEND_OUTCOME, INSERT_PENDING, RECORD_DELIVERY, RECORD_FAILURE, RECORD_PARKED,
    SELECT_BACKEND_RECORDS, SELECT_BACKLOG, SELECT_DUE, SELECT_PENDING_ATTEMPTS, SELECT_STATUS,
    UPDATE_BACKEND_OUTCOME,
};

const SCHEMA_KEY: &str = "security_alert_outbox";
const SCHEMA: &str = include_str!("security_alert_outbox_store.sql");
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COMMAND_JSON_BYTES: usize = 16 * 1024;
const _: () = assert!(SECURITY_ALERT_MAX_CANONICAL_BYTES <= MAX_COMMAND_JSON_BYTES);

/// SQLite paging outbox: one row per paged alert and one outcome row per
/// backend that was dispatched to.
#[derive(Debug)]
pub struct SqliteSecurityAlertOutboxStore {
    connection: StoreConnection,
}

impl SqliteSecurityAlertOutboxStore {
    /// Open or create the outbox at `path`. An in-memory database, a foreign
    /// database or a catalog that differs from the declared schema refuses
    /// before any schema change.
    pub fn open(path: impl AsRef<Path>) -> PortResult<Self> {
        let path = path.as_ref();
        let text = path.to_string_lossy();
        if text.is_empty() || text.eq_ignore_ascii_case(":memory:") || text.starts_with("file:") {
            return Err(PortError::invalid_data());
        }
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            std::fs::create_dir_all(parent).map_err(|_| PortError::unavailable())?;
        }
        let mut connection = Connection::open(path).map_err(sqlite_fault)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(sqlite_fault)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(sqlite_fault)?;
        let quick_check: String = connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(sqlite_fault)?;
        if quick_check != "ok" {
            return Err(PortError::integrity_failure());
        }
        let schema =
            SchemaTransaction::begin(&mut connection, &[SCHEMA_KEY]).map_err(schema_error)?;
        if schema.is_fresh() {
            schema
                .connection()
                .execute_batch(SCHEMA)
                .map_err(sqlite_fault)?;
            schema.stamp(SCHEMA_KEY).map_err(schema_error)?;
        }
        schema.validate_catalog(SCHEMA).map_err(schema_error)?;
        schema.commit().map_err(schema_error)?;
        connection
            .execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")
            .map_err(sqlite_fault)?;
        Ok(Self {
            connection: StoreConnection::transaction_only("security_alert_outbox", connection),
        })
    }

    fn connection(&self) -> PortResult<StoreGuard<'_>> {
        self.connection.lock().map_err(|_| PortError::unavailable())
    }

    /// Runs one compare-and-set write; a write that changes no row refuses.
    fn cas(&self, sql: &str, params: impl rusqlite::Params) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_fault)?;
        if transaction.execute(sql, params).map_err(sqlite_fault)? != 1 {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_fault)
    }
}

impl SecurityAlertOutboxStore for SqliteSecurityAlertOutboxStore {
    fn ensure_ready(&self) -> PortResult<()> {
        let connection = self.connection()?;
        crate::schema_version::validate_catalog(&connection, SCHEMA).map_err(schema_error)
    }

    fn admit(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
        let canonical = canonical_json_bytes(alert).map_err(|_| PortError::invalid_data())?;
        if canonical.len() > MAX_COMMAND_JSON_BYTES {
            return Err(PortError::invalid_data());
        }
        let command_hash = chio_core::sha256(&canonical);
        let occurred_at = sqlite_time(alert.occurred_at_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_fault)?;
        let key = alert.idempotency_key.as_str();
        let status = match load_status(&transaction, key, &canonical, command_hash.as_bytes())? {
            Some(status) => status,
            None => {
                transaction
                    .execute(
                        INSERT_PENDING,
                        params![
                            key,
                            canonical.as_slice(),
                            command_hash.as_bytes().as_slice(),
                            occurred_at
                        ],
                    )
                    .map_err(sqlite_fault)?;
                AlertDeliveryStatus::Pending {
                    attempts: 0,
                    next_attempt_at_unix_ms: alert.occurred_at_unix_ms,
                }
            }
        };
        transaction.commit().map_err(sqlite_fault)?;
        Ok(status)
    }

    fn load_status(&self, alert: &SecurityAlert) -> PortResult<Option<AlertDeliveryStatus>> {
        let canonical = canonical_json_bytes(alert).map_err(|_| PortError::invalid_data())?;
        let command_hash = chio_core::sha256(&canonical);
        let connection = self.connection()?;
        load_status(
            &connection,
            alert.idempotency_key.as_str(),
            &canonical,
            command_hash.as_bytes(),
        )
    }

    fn load_command(
        &self,
        idempotency_key: &RecordId,
    ) -> PortResult<Option<(SecurityAlert, AlertDeliveryStatus)>> {
        let connection = self.connection()?;
        let Some(row) = query_status(&connection, idempotency_key.as_str())? else {
            return Ok(None);
        };
        let alert = decode_command(&row.command_json, &row.command_hash)?;
        if &alert.idempotency_key != idempotency_key {
            return Err(PortError::integrity_failure());
        }
        let status = row.status()?;
        Ok(Some((alert, status)))
    }

    fn load_backend_deliveries(
        &self,
        alert: &SecurityAlert,
    ) -> PortResult<Option<BTreeMap<String, AlertDeliveryStatus>>> {
        let canonical = canonical_json_bytes(alert).map_err(|_| PortError::invalid_data())?;
        let command_hash = chio_core::sha256(&canonical);
        let key = alert.idempotency_key.as_str();
        let connection = self.connection()?;
        let Some(status) = load_status(&connection, key, &canonical, command_hash.as_bytes())?
        else {
            return Ok(None);
        };
        let retry_at = match status {
            AlertDeliveryStatus::Pending {
                next_attempt_at_unix_ms,
                ..
            } => Some(next_attempt_at_unix_ms),
            AlertDeliveryStatus::Delivered { .. } | AlertDeliveryStatus::Parked { .. } => None,
        };
        let records = load_backend_records(&connection, key, command_hash.as_bytes())?;
        Ok(Some(
            records
                .into_iter()
                .map(|(backend, record)| {
                    let attempts = record.attempts;
                    let status = match (record.delivered_at_unix_ms, retry_at) {
                        (Some(delivered_at_unix_ms), _) => AlertDeliveryStatus::Delivered {
                            attempts,
                            delivered_at_unix_ms,
                        },
                        (None, Some(next_attempt_at_unix_ms)) => AlertDeliveryStatus::Pending {
                            attempts,
                            next_attempt_at_unix_ms,
                        },
                        (None, None) => AlertDeliveryStatus::Parked { attempts },
                    };
                    (backend, status)
                })
                .collect(),
        ))
    }

    fn backlog(&self) -> PortResult<SecurityAlertOutboxBacklog> {
        let connection = self.connection()?;
        let (pending, parked): (i64, i64) = connection
            .query_row(SELECT_BACKLOG, [], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(sqlite_fault)?;
        Ok(SecurityAlertOutboxBacklog {
            pending: u64::try_from(pending).map_err(|_| PortError::integrity_failure())?,
            parked: u64::try_from(parked).map_err(|_| PortError::integrity_failure())?,
        })
    }

    fn load_due(&self, now_unix_ms: u64, limit: usize) -> PortResult<Vec<DueSecurityAlert>> {
        let now = sqlite_time(now_unix_ms)?;
        let limit = i64::try_from(limit).map_err(|_| PortError::invalid_data())?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(SELECT_DUE).map_err(sqlite_fault)?;
        let mut rows = statement.query(params![now, limit]).map_err(sqlite_fault)?;
        let mut due = Vec::new();
        while let Some(row) = rows.next().map_err(sqlite_fault)? {
            let command_json: Vec<u8> = stored(row, 0)?;
            let command_hash: Vec<u8> = stored(row, 1)?;
            let attempts: i64 = stored(row, 2)?;
            let alert = decode_command(&command_json, &command_hash)?;
            due.push(DueSecurityAlert {
                alert,
                command_hash: <[u8; 32]>::try_from(command_hash.as_slice())
                    .map(Digest32::new)
                    .map_err(|_| PortError::integrity_failure())?,
                attempts: u32::try_from(attempts).map_err(|_| PortError::integrity_failure())?,
            });
        }
        Ok(due)
    }

    fn confirmed_backends(&self, row: &DueSecurityAlert) -> PortResult<BTreeSet<String>> {
        let connection = self.connection()?;
        let records = load_backend_records(
            &connection,
            row.alert.idempotency_key.as_str(),
            row.command_hash.as_bytes(),
        )?;
        Ok(records
            .into_iter()
            .filter_map(|(backend, record)| record.delivered_at_unix_ms.map(|_| backend))
            .collect())
    }

    fn record_backend_outcome(
        &self,
        row: &DueSecurityAlert,
        backend: &str,
        outcome: AlertBackendOutcome,
        now_unix_ms: u64,
    ) -> PortResult<()> {
        let (status, delivered_at) = match outcome {
            AlertBackendOutcome::Confirmed => ("delivered", Some(sqlite_time(now_unix_ms)?)),
            AlertBackendOutcome::Refused => ("pending", None),
        };
        let key = row.alert.idempotency_key.as_str();
        let command_hash = row.command_hash.as_bytes().as_slice();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_fault)?;
        let row_attempts: Option<i64> = transaction
            .query_row(
                SELECT_PENDING_ATTEMPTS,
                params![key, command_hash],
                |stored| stored.get(0),
            )
            .optional()
            .map_err(sqlite_fault)?;
        if row_attempts != Some(i64::from(row.attempts)) {
            return Err(PortError::integrity_failure());
        }
        let records = load_backend_records(&transaction, key, command_hash)?;
        let changed = match records.get(backend) {
            None => transaction
                .execute(
                    INSERT_BACKEND_OUTCOME,
                    params![key, backend, command_hash, status, delivered_at],
                )
                .map_err(sqlite_fault)?,
            Some(previous) if previous.delivered_at_unix_ms.is_none() => {
                let attempts = previous
                    .attempts
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
                transaction
                    .execute(
                        UPDATE_BACKEND_OUTCOME,
                        params![
                            status,
                            i64::from(attempts),
                            delivered_at,
                            key,
                            backend,
                            command_hash,
                            i64::from(previous.attempts)
                        ],
                    )
                    .map_err(sqlite_fault)?
            }
            Some(_) => return Err(PortError::integrity_failure()),
        };
        if changed != 1 {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_fault)
    }

    fn record_failure(
        &self,
        row: &DueSecurityAlert,
        next_attempt_at_unix_ms: u64,
    ) -> PortResult<()> {
        let attempts = row
            .attempts
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        self.cas(
            RECORD_FAILURE,
            params![
                i64::from(attempts),
                sqlite_time(next_attempt_at_unix_ms)?,
                row.alert.idempotency_key.as_str(),
                row.command_hash.as_bytes().as_slice(),
                i64::from(row.attempts)
            ],
        )
    }

    fn record_delivery(
        &self,
        row: &DueSecurityAlert,
        backends: &[&str],
        now_unix_ms: u64,
    ) -> PortResult<()> {
        let attempts = row
            .attempts
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        let key = row.alert.idempotency_key.as_str();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_fault)?;
        let records = load_backend_records(&transaction, key, row.command_hash.as_bytes())?;
        let unconfirmed = backends.iter().any(|backend| {
            records
                .get(*backend)
                .is_none_or(|record| record.delivered_at_unix_ms.is_none())
        });
        if unconfirmed {
            return Err(PortError::integrity_failure());
        }
        let changed = transaction
            .execute(
                RECORD_DELIVERY,
                params![
                    i64::from(attempts),
                    sqlite_time(now_unix_ms)?,
                    key,
                    row.command_hash.as_bytes().as_slice(),
                    i64::from(row.attempts)
                ],
            )
            .map_err(sqlite_fault)?;
        if changed != 1 {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_fault)
    }

    fn record_parked(&self, row: &DueSecurityAlert, attempts: u32) -> PortResult<()> {
        if attempts != row.attempts && Some(attempts) != row.attempts.checked_add(1) {
            return Err(PortError::invalid_data());
        }
        self.cas(
            RECORD_PARKED,
            params![
                i64::from(attempts),
                row.alert.idempotency_key.as_str(),
                row.command_hash.as_bytes().as_slice(),
                i64::from(row.attempts)
            ],
        )
    }
}

struct StatusRow {
    command_json: Vec<u8>,
    command_hash: Vec<u8>,
    status: String,
    attempts: i64,
    next_attempt_at_unix_ms: i64,
    delivered_at_unix_ms: Option<i64>,
}

impl StatusRow {
    fn status(&self) -> PortResult<AlertDeliveryStatus> {
        let attempts = u32::try_from(self.attempts).map_err(|_| PortError::integrity_failure())?;
        match (self.status.as_str(), self.delivered_at_unix_ms) {
            ("pending", None) => Ok(AlertDeliveryStatus::Pending {
                attempts,
                next_attempt_at_unix_ms: u64::try_from(self.next_attempt_at_unix_ms)
                    .map_err(|_| PortError::integrity_failure())?,
            }),
            ("delivered", Some(delivered_at)) => Ok(AlertDeliveryStatus::Delivered {
                attempts,
                delivered_at_unix_ms: u64::try_from(delivered_at)
                    .map_err(|_| PortError::integrity_failure())?,
            }),
            ("parked", None) => Ok(AlertDeliveryStatus::Parked { attempts }),
            _ => Err(PortError::integrity_failure()),
        }
    }
}

struct BackendRecord {
    attempts: u32,
    delivered_at_unix_ms: Option<u64>,
}

fn query_status(connection: &Connection, idempotency_key: &str) -> PortResult<Option<StatusRow>> {
    let mut statement = connection.prepare(SELECT_STATUS).map_err(sqlite_fault)?;
    let mut rows = statement.query([idempotency_key]).map_err(sqlite_fault)?;
    let Some(row) = rows.next().map_err(sqlite_fault)? else {
        return Ok(None);
    };
    Ok(Some(StatusRow {
        command_json: stored(row, 0)?,
        command_hash: stored(row, 1)?,
        status: stored(row, 2)?,
        attempts: stored(row, 3)?,
        next_attempt_at_unix_ms: stored(row, 4)?,
        delivered_at_unix_ms: stored(row, 5)?,
    }))
}

/// A stored column of the wrong type or range is an integrity failure.
fn stored<T: rusqlite::types::FromSql>(row: &rusqlite::Row<'_>, index: usize) -> PortResult<T> {
    row.get(index).map_err(|_| PortError::integrity_failure())
}

fn load_status(
    connection: &Connection,
    idempotency_key: &str,
    expected_json: &[u8],
    expected_hash: &[u8],
) -> PortResult<Option<AlertDeliveryStatus>> {
    let Some(row) = query_status(connection, idempotency_key)? else {
        return Ok(None);
    };
    if row.command_json != expected_json || row.command_hash != expected_hash {
        return Err(PortError::conflict());
    }
    row.status().map(Some)
}

/// Decodes a stored command and returns it only when its canonical bytes and
/// their digest equal the stored values.
fn decode_command(command_json: &[u8], command_hash: &[u8]) -> PortResult<SecurityAlert> {
    let alert: SecurityAlert = UntrustedJsonText::from_wire(command_json, MAX_COMMAND_JSON_BYTES)
        .and_then(|input| input.decode_signed())
        .map_err(|error| {
            PortError::with_source(PortErrorKind::IntegrityFailure, error.code(), error)
        })?;
    let canonical = canonical_json_bytes(&alert).map_err(|_| PortError::integrity_failure())?;
    let actual_hash = chio_core::sha256(&canonical);
    if canonical != command_json || actual_hash.as_bytes().as_slice() != command_hash {
        return Err(PortError::integrity_failure());
    }
    Ok(alert)
}

fn load_backend_records(
    connection: &Connection,
    idempotency_key: &str,
    command_hash: &[u8],
) -> PortResult<BTreeMap<String, BackendRecord>> {
    let mut statement = connection
        .prepare(SELECT_BACKEND_RECORDS)
        .map_err(sqlite_fault)?;
    let mut rows = statement.query([idempotency_key]).map_err(sqlite_fault)?;
    let mut records = BTreeMap::new();
    while let Some(row) = rows.next().map_err(sqlite_fault)? {
        let backend: String = stored(row, 0)?;
        let stored_hash: Vec<u8> = stored(row, 1)?;
        let status: String = stored(row, 2)?;
        let attempts: i64 = stored(row, 3)?;
        let delivered_at: Option<i64> = stored(row, 4)?;
        if stored_hash != command_hash {
            return Err(PortError::integrity_failure());
        }
        let attempts = u32::try_from(attempts)
            .ok()
            .filter(|attempts| *attempts > 0)
            .ok_or_else(PortError::integrity_failure)?;
        let delivered_at_unix_ms = match (status.as_str(), delivered_at) {
            ("pending", None) => None,
            ("delivered", Some(delivered_at)) => {
                Some(u64::try_from(delivered_at).map_err(|_| PortError::integrity_failure())?)
            }
            _ => return Err(PortError::integrity_failure()),
        };
        if records
            .insert(
                backend,
                BackendRecord {
                    attempts,
                    delivered_at_unix_ms,
                },
            )
            .is_some()
        {
            return Err(PortError::integrity_failure());
        }
    }
    Ok(records)
}

fn sqlite_time(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

/// Corruption is an integrity failure; every other SQLite error is an outage.
fn sqlite_fault(error: rusqlite::Error) -> PortError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            PortError::integrity_failure()
        }
        _ => PortError::unavailable(),
    }
}

fn schema_error(error: SchemaVersionError) -> PortError {
    match error {
        SchemaVersionError::Sqlite(error) => sqlite_fault(error),
        SchemaVersionError::Io(_) => PortError::unavailable(),
        SchemaVersionError::InvalidCreationPlan
        | SchemaVersionError::MissingSchema { .. }
        | SchemaVersionError::CreationNotAllowed
        | SchemaVersionError::MalformedMetadata
        | SchemaVersionError::UnexpectedNamespaces
        | SchemaVersionError::CatalogMismatch
        | SchemaVersionError::ForeignDatabase { .. }
        | SchemaVersionError::StaleSchema { .. } => PortError::integrity_failure(),
    }
}

#[cfg(test)]
#[path = "security_alert_outbox_store_tests.rs"]
mod tests;
