//! SQLite-backed persistence for [`DeadLetterRecord`] rows.
//!
//! The `settle_dead_letters` table is keyed by `receipt_id` so a
//! finalized receipt can have at most one dead-letter row at any time.
//! Re-inserting the same record is idempotent: a byte-identical row
//! returns `Ok(false)`; a different row returns
//! [`DeadLetterStoreError::Conflict`].
//!
//! Fail-closed: once a row is persisted the kernel observer slot
//! MUST NOT replay the failed settlement until an operator clears
//! the row via [`SqliteDeadLetterStore::clear`]. There is no
//! auto-retry past the documented bound.
//!
//! The migration is `CREATE TABLE IF NOT EXISTS` plus
//! `CREATE INDEX IF NOT EXISTS`, so it can run repeatedly against a
//! receipt-store database that already holds other tables.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use chio_settle::{
    DeadLetterRecord, DEAD_LETTER_MAX_ATTEMPTS, DEAD_LETTER_PIPELINE_ERROR_MAX_BYTES,
    DEAD_LETTER_REASON_MAX_BYTES, DEAD_LETTER_RECEIPT_ID_MAX_BYTES,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use thiserror::Error;

pub(crate) trait SqliteConnectionLease {
    fn connection(&self) -> &rusqlite::Connection;

    fn connection_mut(&mut self) -> &mut rusqlite::Connection;
}

struct PooledSqliteConnection<C>(C);

impl<C> SqliteConnectionLease for PooledSqliteConnection<C>
where
    C: Deref<Target = rusqlite::Connection> + DerefMut,
{
    fn connection(&self) -> &rusqlite::Connection {
        &self.0
    }

    fn connection_mut(&mut self) -> &mut rusqlite::Connection {
        &mut self.0
    }
}

pub(crate) type SqliteConnectionCheckout =
    Arc<dyn Fn() -> Result<Box<dyn SqliteConnectionLease>, String> + Send + Sync>;

pub(crate) fn sqlite_connection_checkout(
    pool: Pool<SqliteConnectionManager>,
) -> SqliteConnectionCheckout {
    Arc::new(move || -> Result<Box<dyn SqliteConnectionLease>, String> {
        let connection = pool.get().map_err(|error| error.to_string())?;
        Ok(Box::new(PooledSqliteConnection(connection)))
    })
}

pub(crate) fn receipt_connection_checkout(
    store: &crate::SqliteReceiptStore,
) -> SqliteConnectionCheckout {
    let pool = store.pool.clone();
    Arc::new(move || -> Result<Box<dyn SqliteConnectionLease>, String> {
        let connection = pool.get().map_err(|error| error.to_string())?;
        Ok(Box::new(PooledSqliteConnection(connection)))
    })
}

/// SQL migration applied by [`SqliteDeadLetterStore::open_with_pool`]
/// to create the `settle_dead_letters` table.
pub const SETTLE_DEAD_LETTERS_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS settle_dead_letters (
    receipt_id TEXT PRIMARY KEY
        CHECK (
            typeof(receipt_id) = 'text'
            AND length(trim(receipt_id)) > 0
            AND length(CAST(receipt_id AS BLOB)) <= 512
        ),
    finalized_at INTEGER NOT NULL
        CHECK (typeof(finalized_at) = 'integer' AND finalized_at >= 0),
    attempts INTEGER NOT NULL
        CHECK (typeof(attempts) = 'integer' AND attempts BETWEEN 1 AND 33),
    reason TEXT NOT NULL
        CHECK (
            typeof(reason) = 'text'
            AND length(CAST(reason AS BLOB)) <= 2048
            AND length(reason) = length('settlement_failure:sha256:') + 64
            AND substr(reason, 1, length('settlement_failure:sha256:')) = 'settlement_failure:sha256:'
            AND substr(reason, length('settlement_failure:sha256:') + 1) NOT GLOB '*[^0-9a-f]*'
        ),
    pipeline_error TEXT
        CHECK (
            pipeline_error IS NULL
            OR (
                typeof(pipeline_error) = 'text'
                AND length(CAST(pipeline_error AS BLOB)) <= 2048
                AND length(pipeline_error) = length('settlement_pipeline_error:sha256:') + 64
                AND substr(pipeline_error, 1, length('settlement_pipeline_error:sha256:')) = 'settlement_pipeline_error:sha256:'
                AND substr(pipeline_error, length('settlement_pipeline_error:sha256:') + 1) NOT GLOB '*[^0-9a-f]*'
            )
        ),
    canonical_json TEXT NOT NULL
        CHECK (
            typeof(canonical_json) = 'text'
            AND length(CAST(canonical_json AS BLOB)) <= 16384
            AND json_valid(canonical_json)
        ),
    recorded_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        CHECK (typeof(recorded_at) = 'integer' AND recorded_at >= 0)
);
CREATE INDEX IF NOT EXISTS idx_settle_dead_letters_finalized_at
    ON settle_dead_letters(finalized_at, receipt_id);
CREATE TRIGGER IF NOT EXISTS settle_dead_letters_reject_update
BEFORE UPDATE ON settle_dead_letters
BEGIN
    SELECT RAISE(ABORT, 'settlement dead-letter rows are immutable');
END;
"#;

const SETTLE_DEAD_LETTER_CANONICAL_JSON_MAX_BYTES: usize = 16_384;

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
        .replace(" if not exists", "")
        .trim_end_matches(';')
        .to_string()
}

fn validate_dead_letter_record(record: &DeadLetterRecord) -> Result<(), DeadLetterStoreError> {
    record.validate().map_err(|error| {
        DeadLetterStoreError::Conflict(format!("invalid settlement dead-letter record: {error}"))
    })
}

fn validate_dead_letter_receipt_id(receipt_id: &str) -> Result<(), DeadLetterStoreError> {
    if receipt_id.trim().is_empty() || receipt_id.len() > DEAD_LETTER_RECEIPT_ID_MAX_BYTES {
        return Err(DeadLetterStoreError::Conflict(
            "dead-letter receipt id must be nonempty and at most 512 bytes".to_string(),
        ));
    }
    Ok(())
}

/// Errors surfaced from the SQLite-backed dead-letter store.
#[derive(Debug, Error)]
pub enum DeadLetterStoreError {
    /// Backend (connection pool, SQLite, JSON) error.
    #[error("dead letter backend error: {0}")]
    Backend(String),
    /// A different dead-letter row already exists for this receipt.
    /// Operators should clear the row explicitly before replacing it.
    #[error("dead letter conflict: {0}")]
    Conflict(String),
}

fn encode_dead_letter_record(record: &DeadLetterRecord) -> Result<String, DeadLetterStoreError> {
    let bytes = chio_core::canonical::canonical_json_bytes(record)
        .map_err(|_| DeadLetterStoreError::Conflict("dead-letter encoding failed".to_string()))?;
    if bytes.len() > SETTLE_DEAD_LETTER_CANONICAL_JSON_MAX_BYTES {
        return Err(DeadLetterStoreError::Conflict(
            "dead-letter canonical JSON exceeds 16384 bytes".to_string(),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        DeadLetterStoreError::Conflict("dead-letter canonical JSON is not UTF-8".to_string())
    })
}

fn validate_dead_letter_schema(
    connection: &rusqlite::Connection,
) -> Result<(), DeadLetterStoreError> {
    let columns = connection
        .prepare("PRAGMA table_info(settle_dead_letters)")
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    let expected_columns = vec![
        ("receipt_id".to_string(), "TEXT".to_string(), 0, None, 1),
        (
            "finalized_at".to_string(),
            "INTEGER".to_string(),
            1,
            None,
            0,
        ),
        ("attempts".to_string(), "INTEGER".to_string(), 1, None, 0),
        ("reason".to_string(), "TEXT".to_string(), 1, None, 0),
        ("pipeline_error".to_string(), "TEXT".to_string(), 0, None, 0),
        ("canonical_json".to_string(), "TEXT".to_string(), 1, None, 0),
        (
            "recorded_at".to_string(),
            "INTEGER".to_string(),
            1,
            Some("strftime('%s','now')".to_string()),
            0,
        ),
    ];
    if columns != expected_columns {
        return Err(DeadLetterStoreError::Conflict(
            "settlement dead-letter columns or primary key are invalid".to_string(),
        ));
    }

    let table_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'settle_dead_letters'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?
        .ok_or_else(|| {
            DeadLetterStoreError::Conflict("settlement dead-letter table is missing".to_string())
        })?;
    let expected_table_sql = normalize_schema_sql(
        r#"
        CREATE TABLE settle_dead_letters (
            receipt_id TEXT PRIMARY KEY
                CHECK (
                    typeof(receipt_id) = 'text'
                    AND length(trim(receipt_id)) > 0
                    AND length(CAST(receipt_id AS BLOB)) <= 512
                ),
            finalized_at INTEGER NOT NULL
                CHECK (typeof(finalized_at) = 'integer' AND finalized_at >= 0),
            attempts INTEGER NOT NULL
                CHECK (typeof(attempts) = 'integer' AND attempts BETWEEN 1 AND 33),
            reason TEXT NOT NULL
                CHECK (
                    typeof(reason) = 'text'
                    AND length(CAST(reason AS BLOB)) <= 2048
                    AND length(reason) = length('settlement_failure:sha256:') + 64
                    AND substr(reason, 1, length('settlement_failure:sha256:')) = 'settlement_failure:sha256:'
                    AND substr(reason, length('settlement_failure:sha256:') + 1) NOT GLOB '*[^0-9a-f]*'
                ),
            pipeline_error TEXT
                CHECK (
                    pipeline_error IS NULL
                    OR (
                        typeof(pipeline_error) = 'text'
                        AND length(CAST(pipeline_error AS BLOB)) <= 2048
                        AND length(pipeline_error) = length('settlement_pipeline_error:sha256:') + 64
                        AND substr(pipeline_error, 1, length('settlement_pipeline_error:sha256:')) = 'settlement_pipeline_error:sha256:'
                        AND substr(pipeline_error, length('settlement_pipeline_error:sha256:') + 1) NOT GLOB '*[^0-9a-f]*'
                    )
                ),
            canonical_json TEXT NOT NULL
                CHECK (
                    typeof(canonical_json) = 'text'
                    AND length(CAST(canonical_json AS BLOB)) <= 16384
                    AND json_valid(canonical_json)
                ),
            recorded_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
                CHECK (typeof(recorded_at) = 'integer' AND recorded_at >= 0)
        )
        "#,
    );
    if normalize_schema_sql(&table_sql) != expected_table_sql {
        return Err(DeadLetterStoreError::Conflict(
            "settlement dead-letter table constraints are invalid".to_string(),
        ));
    }

    let index_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_settle_dead_letters_finalized_at'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?
        .ok_or_else(|| {
            DeadLetterStoreError::Conflict("settlement dead-letter index is missing".to_string())
        })?;
    let expected_index_sql = normalize_schema_sql(
        "CREATE INDEX idx_settle_dead_letters_finalized_at ON settle_dead_letters(finalized_at, receipt_id)",
    );
    if normalize_schema_sql(&index_sql) != expected_index_sql {
        return Err(DeadLetterStoreError::Conflict(
            "settlement dead-letter index is invalid".to_string(),
        ));
    }

    let triggers = connection
        .prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'settle_dead_letters' ORDER BY name",
        )
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                normalize_schema_sql(&row.get::<_, String>(1)?),
            ))
        })
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    let expected_trigger_sql = normalize_schema_sql(
        r#"
        CREATE TRIGGER settle_dead_letters_reject_update
        BEFORE UPDATE ON settle_dead_letters
        BEGIN
            SELECT RAISE(ABORT, 'settlement dead-letter rows are immutable');
        END
        "#,
    );
    if triggers
        != vec![(
            "settle_dead_letters_reject_update".to_string(),
            expected_trigger_sql,
        )]
    {
        return Err(DeadLetterStoreError::Conflict(
            "settlement dead-letter integrity trigger is invalid".to_string(),
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json, recorded_at FROM settle_dead_letters ORDER BY receipt_id",
        )
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    for row in rows {
        let (
            receipt_id,
            finalized_at,
            attempts,
            reason,
            pipeline_error,
            canonical_json,
            recorded_at,
        ) = row.map_err(|_| {
            DeadLetterStoreError::Conflict(
                "settlement dead-letter row has invalid SQLite types".to_string(),
            )
        })?;
        if receipt_id.len() > DEAD_LETTER_RECEIPT_ID_MAX_BYTES
            || reason.len() > DEAD_LETTER_REASON_MAX_BYTES
            || pipeline_error
                .as_deref()
                .is_some_and(|value| value.len() > DEAD_LETTER_PIPELINE_ERROR_MAX_BYTES)
            || canonical_json.len() > SETTLE_DEAD_LETTER_CANONICAL_JSON_MAX_BYTES
            || recorded_at < 0
        {
            return Err(DeadLetterStoreError::Conflict(
                "settlement dead-letter row exceeds a storage bound".to_string(),
            ));
        }
        let finalized_at = u64::try_from(finalized_at).map_err(|_| {
            DeadLetterStoreError::Conflict(
                "settlement dead-letter finalized_at is invalid".to_string(),
            )
        })?;
        let attempts = u32::try_from(attempts).map_err(|_| {
            DeadLetterStoreError::Conflict(
                "settlement dead-letter attempts are invalid".to_string(),
            )
        })?;
        if attempts > DEAD_LETTER_MAX_ATTEMPTS {
            return Err(DeadLetterStoreError::Conflict(
                "settlement dead-letter attempts exceed the retry envelope".to_string(),
            ));
        }
        let record: DeadLetterRecord = serde_json::from_str(&canonical_json).map_err(|_| {
            DeadLetterStoreError::Conflict(
                "settlement dead-letter canonical JSON is invalid".to_string(),
            )
        })?;
        validate_dead_letter_record(&record)?;
        if record.receipt_id != receipt_id
            || record.finalized_at != finalized_at
            || record.attempts != attempts
            || record.reason != reason
            || record.pipeline_error != pipeline_error
            || encode_dead_letter_record(&record)? != canonical_json
        {
            return Err(DeadLetterStoreError::Conflict(
                "settlement dead-letter projections diverge from canonical JSON".to_string(),
            ));
        }
    }
    Ok(())
}

fn initialize_dead_letter_schema(
    connection: &mut rusqlite::Connection,
) -> Result<(), DeadLetterStoreError> {
    let transaction = connection
        .transaction()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    transaction
        .execute_batch(SETTLE_DEAD_LETTERS_MIGRATION)
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    validate_dead_letter_schema(&transaction)?;
    transaction
        .commit()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))
}

fn dead_letter_error_to_receipt(error: DeadLetterStoreError) -> chio_kernel::ReceiptStoreError {
    match error {
        DeadLetterStoreError::Conflict(message) => {
            chio_kernel::ReceiptStoreError::Conflict(message)
        }
        DeadLetterStoreError::Backend(message) => {
            chio_kernel::ReceiptStoreError::Canonical(message)
        }
    }
}

fn receipt_error_to_dead_letter(error: chio_kernel::ReceiptStoreError) -> DeadLetterStoreError {
    match error {
        chio_kernel::ReceiptStoreError::Conflict(message) => {
            DeadLetterStoreError::Conflict(message)
        }
        chio_kernel::ReceiptStoreError::Canonical(message) => {
            DeadLetterStoreError::Backend(message)
        }
        other => DeadLetterStoreError::Backend(other.to_string()),
    }
}

fn insert_dead_letter_on_connection(
    connection: &mut rusqlite::Connection,
    record: &DeadLetterRecord,
    canonical_str: &str,
    finalized_at: i64,
    attempts: i64,
) -> Result<bool, DeadLetterStoreError> {
    let transaction = connection
        .transaction()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    let existing = transaction
        .query_row(
            "SELECT canonical_json FROM settle_dead_letters WHERE receipt_id = ?1",
            params![record.receipt_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    if let Some(existing_canonical) = existing {
        let existing_record: DeadLetterRecord =
            serde_json::from_str(&existing_canonical).map_err(|_| {
                DeadLetterStoreError::Conflict(
                    "existing settlement dead-letter canonical JSON is invalid".to_string(),
                )
            })?;
        validate_dead_letter_record(&existing_record)?;
        if encode_dead_letter_record(&existing_record)? != existing_canonical {
            return Err(DeadLetterStoreError::Conflict(
                "existing settlement dead-letter bytes are not canonical".to_string(),
            ));
        }
        if existing_canonical == canonical_str {
            return Ok(false);
        }
        return Err(DeadLetterStoreError::Conflict(format!(
            "settle_dead_letters row for receipt_id={} already exists with different bytes",
            record.receipt_id
        )));
    }

    transaction
        .execute(
            "INSERT INTO settle_dead_letters \
                (receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.receipt_id.as_str(),
                finalized_at,
                attempts,
                record.reason.as_str(),
                record.pipeline_error.as_deref(),
                canonical_str,
            ],
        )
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    transaction
        .commit()
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    Ok(true)
}

fn clear_dead_letter_on_connection(
    connection: &rusqlite::Connection,
    receipt_id: &str,
) -> Result<bool, DeadLetterStoreError> {
    let affected = connection
        .execute(
            "DELETE FROM settle_dead_letters WHERE receipt_id = ?1",
            params![receipt_id],
        )
        .map_err(|error| DeadLetterStoreError::Backend(error.to_string()))?;
    Ok(affected == 1)
}

/// SQLite-backed dead-letter store. Wraps an existing connection pool
/// from [`crate::SqliteReceiptStore`] so dead-letter writes share the
/// same SQLite database and journal mode.
pub struct SqliteDeadLetterStore {
    connection_checkout: SqliteConnectionCheckout,
    writer: Option<crate::receipt_store::WriterHandle>,
}

impl SqliteDeadLetterStore {
    /// Open a store backed by the same pool as a sibling receipt
    /// store. Runs the additive migration if the table is absent.
    pub fn open_with_pool(
        pool: Pool<SqliteConnectionManager>,
    ) -> Result<Self, DeadLetterStoreError> {
        let connection_checkout = sqlite_connection_checkout(pool);
        let mut connection = connection_checkout().map_err(DeadLetterStoreError::Backend)?;
        initialize_dead_letter_schema(connection.connection_mut())?;
        Ok(Self {
            connection_checkout,
            writer: None,
        })
    }

    /// Construct the store sharing the connection pool of an existing
    /// [`crate::SqliteReceiptStore`].
    pub fn open_alongside(store: &crate::SqliteReceiptStore) -> Result<Self, DeadLetterStoreError> {
        let writer = store.writer_handle();
        writer
            .run_write(|connection| {
                initialize_dead_letter_schema(connection).map_err(dead_letter_error_to_receipt)
            })
            .map_err(receipt_error_to_dead_letter)?;
        let connection_checkout = receipt_connection_checkout(store);
        Ok(Self {
            connection_checkout,
            writer: Some(writer),
        })
    }

    /// Persist a dead-letter record. Idempotent on byte-identical
    /// re-inserts; returns [`DeadLetterStoreError::Conflict`] if a
    /// different record already exists for the same receipt.
    pub fn insert(&self, record: &DeadLetterRecord) -> Result<bool, DeadLetterStoreError> {
        validate_dead_letter_record(record)?;
        let canonical_str = encode_dead_letter_record(record)?;
        let attempts: i64 = i64::from(record.attempts);
        let finalized_at = i64::try_from(record.finalized_at).map_err(|_| {
            DeadLetterStoreError::Conflict(
                "dead-letter finalized_at exceeds the signed SQLite integer range".to_string(),
            )
        })?;

        match &self.writer {
            Some(writer) => {
                let record = record.clone();
                writer
                    .run_write(move |connection| {
                        insert_dead_letter_on_connection(
                            connection,
                            &record,
                            &canonical_str,
                            finalized_at,
                            attempts,
                        )
                        .map_err(dead_letter_error_to_receipt)
                    })
                    .map_err(receipt_error_to_dead_letter)
            }
            None => {
                let mut connection =
                    (self.connection_checkout)().map_err(DeadLetterStoreError::Backend)?;
                insert_dead_letter_on_connection(
                    connection.connection_mut(),
                    record,
                    &canonical_str,
                    finalized_at,
                    attempts,
                )
            }
        }
    }

    /// Look up a single dead-letter record by `receipt_id`.
    pub fn get(&self, receipt_id: &str) -> Result<Option<DeadLetterRecord>, DeadLetterStoreError> {
        validate_dead_letter_receipt_id(receipt_id)?;
        let connection = (self.connection_checkout)().map_err(DeadLetterStoreError::Backend)?;
        let canonical = connection
            .connection()
            .query_row(
                "SELECT canonical_json FROM settle_dead_letters WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        match canonical {
            Some(json) => {
                let record: DeadLetterRecord = serde_json::from_str(&json).map_err(|_| {
                    DeadLetterStoreError::Conflict(
                        "settlement dead-letter canonical JSON is invalid".to_string(),
                    )
                })?;
                validate_dead_letter_record(&record)?;
                if record.receipt_id != receipt_id || encode_dead_letter_record(&record)? != json {
                    return Err(DeadLetterStoreError::Conflict(
                        "settlement dead-letter lookup diverges from canonical JSON".to_string(),
                    ));
                }
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// List all dead-letter records sorted by finalization time then
    /// receipt id (matching the deterministic settlement ordering).
    pub fn list(&self) -> Result<Vec<DeadLetterRecord>, DeadLetterStoreError> {
        let connection = (self.connection_checkout)().map_err(DeadLetterStoreError::Backend)?;
        let mut stmt = connection
            .connection()
            .prepare(
                "SELECT canonical_json FROM settle_dead_letters \
                 ORDER BY finalized_at ASC, receipt_id ASC",
            )
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let canonical = row.map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
            let record: DeadLetterRecord = serde_json::from_str(&canonical).map_err(|_| {
                DeadLetterStoreError::Conflict(
                    "settlement dead-letter canonical JSON is invalid".to_string(),
                )
            })?;
            validate_dead_letter_record(&record)?;
            if encode_dead_letter_record(&record)? != canonical {
                return Err(DeadLetterStoreError::Conflict(
                    "settlement dead-letter bytes are not canonical".to_string(),
                ));
            }
            out.push(record);
        }
        Ok(out)
    }

    /// Remove a dead-letter row. Returns `true` if a row was deleted.
    pub fn clear(&self, receipt_id: &str) -> Result<bool, DeadLetterStoreError> {
        validate_dead_letter_receipt_id(receipt_id)?;
        match &self.writer {
            Some(writer) => {
                let receipt_id = receipt_id.to_string();
                writer
                    .run_write(move |connection| {
                        clear_dead_letter_on_connection(connection, &receipt_id)
                            .map_err(dead_letter_error_to_receipt)
                    })
                    .map_err(receipt_error_to_dead_letter)
            }
            None => {
                let connection =
                    (self.connection_checkout)().map_err(DeadLetterStoreError::Backend)?;
                clear_dead_letter_on_connection(connection.connection(), receipt_id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_settle::{
        DeadLetterRecord, SettlementError, DEAD_LETTER_REASON_DIGEST_PREFIX,
        DEAD_LETTER_RECEIPT_ID_MAX_BYTES,
    };
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    use chio_test_support::prelude::*;

    fn pool() -> Pool<SqliteConnectionManager> {
        let manager = SqliteConnectionManager::memory();
        Pool::builder()
            .max_size(2)
            .build(manager)
            .test_expect("test pool builds")
    }

    fn sample_record(receipt_id: &str, attempts: u32) -> DeadLetterRecord {
        DeadLetterRecord::new(receipt_id, 100, attempts, "rpc failure")
            .with_pipeline_error(&SettlementError::Rpc("connection refused".to_string()))
    }

    #[test]
    fn migration_is_idempotent() {
        let pool = pool();
        SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("first open");
        SqliteDeadLetterStore::open_with_pool(pool).test_expect("second open");
    }

    #[test]
    fn insert_persists_and_get_round_trips() {
        let pool = pool();
        let store = SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("store opens");
        let secret = "credential-é-SEED-9d3f";
        let record = DeadLetterRecord::new("rcpt-1", 100, 4, format!("rpc failure {secret}"))
            .with_pipeline_error(&SettlementError::Rpc(format!(
                "connection refused {secret}"
            )));
        assert!(store.insert(&record).test_expect("insert ok"));
        let loaded = store
            .get("rcpt-1")
            .test_expect("get ok")
            .test_expect("row present");
        assert_eq!(loaded, record);
        let connection = pool.get().test_expect("connection");
        let (reason, pipeline_error, canonical_json): (String, String, String) = connection
            .query_row(
                "SELECT reason, pipeline_error, canonical_json FROM settle_dead_letters WHERE receipt_id = 'rcpt-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .test_expect("persisted row");
        assert!(reason.starts_with(DEAD_LETTER_REASON_DIGEST_PREFIX));
        assert!(!reason.contains(secret));
        assert!(!pipeline_error.contains(secret));
        assert!(!canonical_json.contains(secret));
    }

    #[test]
    fn insert_is_idempotent_on_byte_identical_replays() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let record = sample_record("rcpt-2", 3);
        assert!(store
            .insert(&record)
            .test_expect("first insert returns true"));
        assert!(!store
            .insert(&record)
            .test_expect("second insert returns false"));
    }

    #[test]
    fn insert_with_different_bytes_returns_conflict() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let record = sample_record("rcpt-3", 2);
        store.insert(&record).test_expect("first insert");
        let conflicting = DeadLetterRecord::new("rcpt-3", 100, 2, "different reason")
            .with_pipeline_error(&SettlementError::Rpc("connection refused".to_string()));
        let err = store
            .insert(&conflicting)
            .test_expect_err("byte-different second insert errors");
        match err {
            DeadLetterStoreError::Conflict(message) => {
                assert!(message.contains("rcpt-3"));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn list_orders_by_finalization_time_then_receipt_id() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let mut a = sample_record("rcpt-b", 1);
        a.finalized_at = 5;
        let mut b = sample_record("rcpt-a", 1);
        b.finalized_at = 5;
        let mut c = sample_record("rcpt-c", 1);
        c.finalized_at = 10;
        store.insert(&a).test_expect("insert a");
        store.insert(&b).test_expect("insert b");
        store.insert(&c).test_expect("insert c");
        let listed = store.list().test_expect("list ok");
        assert_eq!(
            listed
                .iter()
                .map(|r| r.receipt_id.as_str())
                .collect::<Vec<_>>(),
            vec!["rcpt-a", "rcpt-b", "rcpt-c"]
        );
    }

    #[test]
    fn clear_removes_existing_row() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let record = sample_record("rcpt-4", 1);
        store.insert(&record).test_expect("insert");
        assert!(store.clear("rcpt-4").test_expect("clear ok"));
        assert!(store.get("rcpt-4").test_expect("get ok").is_none());
        assert!(!store.clear("rcpt-4").test_expect("idempotent clear ok"));
    }

    #[test]
    fn insert_rejects_invalid_record_boundaries() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");

        let mut record = sample_record("rcpt-invalid", 1);
        record.schema = "chio.settle.dead-letter.v0".to_string();
        assert!(matches!(
            store.insert(&record),
            Err(DeadLetterStoreError::Conflict(_))
        ));

        let mut record = sample_record("rcpt-invalid", 1);
        record.receipt_id = "r".repeat(DEAD_LETTER_RECEIPT_ID_MAX_BYTES + 1);
        assert!(matches!(
            store.insert(&record),
            Err(DeadLetterStoreError::Conflict(_))
        ));

        let mut record = sample_record("rcpt-invalid", 1);
        record.attempts = 0;
        assert!(matches!(
            store.insert(&record),
            Err(DeadLetterStoreError::Conflict(_))
        ));

        let mut record = sample_record("rcpt-invalid", 1);
        record.finalized_at = u64::MAX;
        assert!(matches!(
            store.insert(&record),
            Err(DeadLetterStoreError::Conflict(_))
        ));

        let mut record = sample_record("rcpt-invalid", 1);
        record.reason = "raw secret".to_string();
        assert!(matches!(
            store.insert(&record),
            Err(DeadLetterStoreError::Conflict(_))
        ));
    }

    #[test]
    fn open_rejects_same_name_trigger_tamper_and_corrupt_rows() {
        let directory = tempfile::tempdir().test_expect("temporary directory");
        let schema_path = directory.path().join("dead-letter-schema.sqlite3");
        let schema_pool = Pool::builder()
            .max_size(2)
            .build(SqliteConnectionManager::file(&schema_path))
            .test_expect("schema pool");
        drop(
            SqliteDeadLetterStore::open_with_pool(schema_pool.clone())
                .test_expect("initial schema"),
        );
        {
            let connection = schema_pool.get().test_expect("schema connection");
            connection
                .execute_batch(
                    r#"
                    DROP TRIGGER settle_dead_letters_reject_update;
                    CREATE TRIGGER settle_dead_letters_reject_update
                    BEFORE UPDATE ON settle_dead_letters
                    BEGIN
                        SELECT 1;
                    END;
                    "#,
                )
                .test_expect("tamper trigger");
        }
        assert!(matches!(
            SqliteDeadLetterStore::open_with_pool(schema_pool),
            Err(DeadLetterStoreError::Conflict(message))
                if message.contains("integrity trigger")
        ));

        let row_path = directory.path().join("dead-letter-row.sqlite3");
        let row_pool = Pool::builder()
            .max_size(2)
            .build(SqliteConnectionManager::file(&row_path))
            .test_expect("row pool");
        let store = SqliteDeadLetterStore::open_with_pool(row_pool.clone())
            .test_expect("initial row schema");
        let record = sample_record("rcpt-corrupt", 1);
        store.insert(&record).test_expect("seed row");
        drop(store);
        {
            let connection = row_pool.get().test_expect("row connection");
            connection
                .execute_batch(
                    r#"
                    PRAGMA ignore_check_constraints = ON;
                    DROP TRIGGER settle_dead_letters_reject_update;
                    UPDATE settle_dead_letters
                    SET reason = 'credential-SEED-corrupt';
                    "#,
                )
                .test_expect("corrupt row");
        }
        assert!(matches!(
            SqliteDeadLetterStore::open_with_pool(row_pool),
            Err(DeadLetterStoreError::Conflict(_))
        ));
    }

    #[test]
    fn colocated_writes_bypass_query_only_reader_pool() {
        let directory =
            chio_test_support::private_fs::private_tempdir("receipt-colocated-dead-letter")
                .test_expect("temporary directory");
        let path = directory.path().join("receipt.sqlite3");
        let receipt_store = crate::SqliteReceiptStore::open(&path).test_expect("receipt store");
        {
            let mut held = Vec::new();
            for _ in 0..crate::DEFAULT_READER_POOL_MAX_SIZE {
                held.push(receipt_store.connection().test_expect("reader connection"));
            }
            for connection in &held {
                connection
                    .execute_batch("PRAGMA query_only = ON;")
                    .test_expect("query-only reader");
            }
        }
        let reader = receipt_store.connection().test_expect("reader control");
        assert!(reader
            .execute("CREATE TABLE forbidden_reader_write (id INTEGER)", [])
            .is_err());
        drop(reader);

        let store = SqliteDeadLetterStore::open_alongside(&receipt_store)
            .test_expect("co-located dead-letter store");
        let record = sample_record("rcpt-writer", 1);
        assert!(store.insert(&record).test_expect("writer insert"));
        assert_eq!(
            store
                .get("rcpt-writer")
                .test_expect("reader lookup")
                .test_expect("record"),
            record
        );
        assert!(store.clear("rcpt-writer").test_expect("writer clear"));
    }
}
