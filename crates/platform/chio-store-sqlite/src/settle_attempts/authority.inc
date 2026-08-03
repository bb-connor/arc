use chio_kernel::settlement_retry::{
    SettleAttemptLease, SettleAttemptRecord, SettlementRetryError, SettlementRetryStore,
};
use rusqlite::{OptionalExtension, TransactionBehavior};

use crate::dead_letters::{
    receipt_connection_checkout, DeadLetterStoreError, SqliteConnectionCheckout,
    SqliteDeadLetterStore,
};

pub(crate) const MAX_SETTLEMENT_RETRY_BATCH: usize = 4_096;
const MAX_SETTLEMENT_RETRY_ATTEMPTS: u32 = 32;
const _: () = assert!(MAX_SETTLEMENT_RETRY_ATTEMPTS == 32);

const SETTLE_ATTEMPTS_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS settle_attempts (
    receipt_id      TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(receipt_id) = 'text'
        AND length(trim(receipt_id)) > 0
        AND length(CAST(receipt_id AS BLOB)) <= 512
    ),
    finalized_at    INTEGER NOT NULL CHECK (
        typeof(finalized_at) = 'integer' AND finalized_at >= 0
    ),
    attempts        INTEGER NOT NULL CHECK (
        typeof(attempts) = 'integer' AND attempts > 0 AND attempts <= 32
    ),
    next_visible_at INTEGER NOT NULL CHECK (
        typeof(next_visible_at) = 'integer' AND next_visible_at >= 0
    ),
    last_reason     TEXT CHECK (
        last_reason IS NULL OR (
            typeof(last_reason) = 'text'
            AND length(trim(last_reason)) > 0
            AND length(CAST(last_reason AS BLOB)) <= 2048
        )
    ),
    updated_at      INTEGER NOT NULL CHECK (
        typeof(updated_at) = 'integer' AND updated_at >= 0
    ),
    state           TEXT NOT NULL DEFAULT 'pending'
        CHECK (typeof(state) = 'text' AND state IN ('pending', 'claimed')),
    claim_token     TEXT CHECK (
        claim_token IS NULL OR (
            typeof(claim_token) = 'text'
            AND length(trim(claim_token)) > 0
            AND length(CAST(claim_token AS BLOB)) <= 512
        )
    ),
    claim_deadline_unix_secs INTEGER CHECK (
        claim_deadline_unix_secs IS NULL OR (
            typeof(claim_deadline_unix_secs) = 'integer'
            AND claim_deadline_unix_secs >= 0
        )
    ),
    version         INTEGER NOT NULL DEFAULT 0 CHECK (
        typeof(version) = 'integer' AND version >= 0
    ),
    CHECK (
        (state = 'claimed' AND claim_token IS NOT NULL AND claim_deadline_unix_secs IS NOT NULL)
        OR (state = 'pending' AND claim_token IS NULL AND claim_deadline_unix_secs IS NULL)
    )
);
"#;

const SETTLE_ATTEMPTS_DUE_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_settle_attempts_due
    ON settle_attempts(state, next_visible_at, finalized_at, receipt_id);
"#;

const SETTLE_ATTEMPTS_INSERT_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS settle_attempts_validate_insert
BEFORE INSERT ON settle_attempts
WHEN typeof(NEW.receipt_id) != 'text'
  OR length(trim(NEW.receipt_id)) = 0
  OR length(CAST(NEW.receipt_id AS BLOB)) > 512
  OR typeof(NEW.finalized_at) != 'integer' OR NEW.finalized_at < 0
  OR typeof(NEW.attempts) != 'integer' OR NEW.attempts <= 0 OR NEW.attempts > 32
  OR typeof(NEW.next_visible_at) != 'integer' OR NEW.next_visible_at < 0
  OR typeof(NEW.updated_at) != 'integer' OR NEW.updated_at < 0
  OR typeof(NEW.state) != 'text' OR NEW.state NOT IN ('pending', 'claimed')
  OR (NEW.last_reason IS NOT NULL AND (
      typeof(NEW.last_reason) != 'text'
      OR length(trim(NEW.last_reason)) = 0
      OR length(CAST(NEW.last_reason AS BLOB)) > 2048
  ))
  OR (NEW.claim_token IS NOT NULL AND (
      typeof(NEW.claim_token) != 'text'
      OR length(trim(NEW.claim_token)) = 0
      OR length(CAST(NEW.claim_token AS BLOB)) > 512
  ))
  OR (NEW.claim_deadline_unix_secs IS NOT NULL AND (
      typeof(NEW.claim_deadline_unix_secs) != 'integer'
      OR NEW.claim_deadline_unix_secs < 0
  ))
  OR typeof(NEW.version) != 'integer' OR NEW.version < 0
  OR (NEW.state = 'claimed' AND (NEW.claim_token IS NULL OR NEW.claim_deadline_unix_secs IS NULL))
  OR (NEW.state = 'pending' AND (NEW.claim_token IS NOT NULL OR NEW.claim_deadline_unix_secs IS NOT NULL))
BEGIN
    SELECT RAISE(ABORT, 'invalid settlement retry row');
END;
"#;

const SETTLE_ATTEMPTS_UPDATE_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS settle_attempts_validate_update
BEFORE UPDATE ON settle_attempts
WHEN NEW.receipt_id != OLD.receipt_id
  OR NEW.finalized_at != OLD.finalized_at
  OR NEW.version != OLD.version + 1
  OR typeof(NEW.receipt_id) != 'text'
  OR length(trim(NEW.receipt_id)) = 0
  OR length(CAST(NEW.receipt_id AS BLOB)) > 512
  OR typeof(NEW.finalized_at) != 'integer' OR NEW.finalized_at < 0
  OR typeof(NEW.attempts) != 'integer' OR NEW.attempts <= 0 OR NEW.attempts > 32
  OR typeof(NEW.next_visible_at) != 'integer' OR NEW.next_visible_at < 0
  OR typeof(NEW.updated_at) != 'integer' OR NEW.updated_at < 0
  OR typeof(NEW.state) != 'text' OR NEW.state NOT IN ('pending', 'claimed')
  OR (NEW.last_reason IS NOT NULL AND (
      typeof(NEW.last_reason) != 'text'
      OR length(trim(NEW.last_reason)) = 0
      OR length(CAST(NEW.last_reason AS BLOB)) > 2048
  ))
  OR (NEW.claim_token IS NOT NULL AND (
      typeof(NEW.claim_token) != 'text'
      OR length(trim(NEW.claim_token)) = 0
      OR length(CAST(NEW.claim_token AS BLOB)) > 512
  ))
  OR (NEW.claim_deadline_unix_secs IS NOT NULL AND (
      typeof(NEW.claim_deadline_unix_secs) != 'integer'
      OR NEW.claim_deadline_unix_secs < 0
  ))
  OR typeof(NEW.version) != 'integer' OR NEW.version < 0
  OR (NEW.state = 'claimed' AND (NEW.claim_token IS NULL OR NEW.claim_deadline_unix_secs IS NULL))
  OR (NEW.state = 'pending' AND (NEW.claim_token IS NOT NULL OR NEW.claim_deadline_unix_secs IS NOT NULL))
  OR NOT (
      (OLD.state = 'pending' AND NEW.state = 'pending'
       AND NEW.attempts = OLD.attempts + 1)
      OR (OLD.state = 'pending' AND NEW.state = 'claimed'
          AND NEW.attempts = OLD.attempts
          AND NEW.next_visible_at = OLD.next_visible_at
          AND NEW.last_reason IS OLD.last_reason)
      OR (OLD.state = 'claimed' AND NEW.state = 'claimed'
          AND NEW.attempts = OLD.attempts
          AND NEW.next_visible_at = OLD.next_visible_at
          AND NEW.last_reason IS OLD.last_reason)
      OR (OLD.state = 'claimed' AND NEW.state = 'pending'
          AND NEW.attempts = OLD.attempts + 1)
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid settlement retry transition');
END;
"#;

const SETTLE_ATTEMPTS_LIVE_RECEIPT_INSERT_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS settle_attempts_require_live_receipt_insert
BEFORE INSERT ON settle_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM chio_tool_receipts AS receipt
    WHERE receipt.receipt_id = NEW.receipt_id
      AND receipt.timestamp = NEW.finalized_at
)
BEGIN
    SELECT RAISE(ABORT, 'settlement retry requires exact authoritative live receipt');
END;
"#;

const SETTLE_ATTEMPTS_LIVE_RECEIPT_UPDATE_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS settle_attempts_require_live_receipt_update
BEFORE UPDATE ON settle_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM chio_tool_receipts AS receipt
    WHERE receipt.receipt_id = NEW.receipt_id
      AND receipt.timestamp = NEW.finalized_at
)
BEGIN
    SELECT RAISE(ABORT, 'settlement retry requires exact authoritative live receipt');
END;
"#;

/// Settlement retry sink: `settle_attempts` plus the dead-letter store, both
/// on the receipt store's connection pool.
pub struct SqliteSettlementRetryStore {
    connection_checkout: SqliteConnectionCheckout,
    dead_letters: SqliteDeadLetterStore,
    writer: crate::receipt_store::WriterHandle,
    storage_identity: chio_core::Hash,
    clock: std::sync::Arc<dyn SettlementClock + Send + Sync>,
}

trait SettlementClock {
    fn now_unix_secs(&self) -> Result<u64, SettlementRetryError>;
}

#[derive(Debug)]
struct SystemSettlementClock;

impl SettlementClock for SystemSettlementClock {
    fn now_unix_secs(&self) -> Result<u64, SettlementRetryError> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(backend_err)
    }
}

impl SqliteSettlementRetryStore {
    /// Open the retry sink in the same database as `store` (mirrors
    /// [`SqliteDeadLetterStore::open_alongside`]).
    pub fn open_alongside(store: &crate::SqliteReceiptStore) -> Result<Self, SettlementRetryError> {
        Self::open_alongside_with_clock(store, std::sync::Arc::new(SystemSettlementClock))
    }

    fn open_alongside_with_clock(
        store: &crate::SqliteReceiptStore,
        clock: std::sync::Arc<dyn SettlementClock + Send + Sync>,
    ) -> Result<Self, SettlementRetryError> {
        let dead_letters = SqliteDeadLetterStore::open_alongside(store).map_err(map_dl_err)?;
        let connection_checkout = receipt_connection_checkout(store);
        let writer = store.writer_handle();
        let storage_identity = chio_kernel::ReceiptStore::durable_storage_identity(store)
            .map_err(backend_err)?
            .ok_or_else(|| {
                SettlementRetryError::Backend(
                    "SQLite receipt store omitted its durable storage identity".to_string(),
                )
            })?;
        writer
            .run_write(|connection| {
                let iou_transaction =
                    connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                iou_transaction.execute_batch(crate::iou_store::IOU_ENVELOPE_MIGRATION)?;
                crate::iou_store::ensure_alongside_receipt_ownership_schema(&iou_transaction)
                    .map_err(iou_to_retry_error)
                    .map_err(retry_to_receipt_error)?;
                ensure_settle_attempt_lease_schema_on_connection(&iou_transaction)
                    .map_err(retry_to_receipt_error)?;
                iou_transaction
                    .commit()
                    .map_err(chio_kernel::ReceiptStoreError::from)
            })
            .map_err(receipt_to_retry_error)?;
        Ok(Self {
            connection_checkout,
            dead_letters,
            writer,
            storage_identity,
            clock,
        })
    }

    fn now_unix_secs(&self) -> Result<u64, SettlementRetryError> {
        self.clock.now_unix_secs()
    }

    fn run_write<T, F>(&self, job: F) -> Result<T, SettlementRetryError>
    where
        F: FnOnce(
                &mut crate::receipt_store::SqliteStoreConnection,
            ) -> Result<T, SettlementRetryError>
            + Send
            + 'static,
        T: Send + 'static,
    {
        self.writer
            .run_write(move |connection| job(connection).map_err(retry_to_receipt_error))
            .map_err(receipt_to_retry_error)
    }
}

fn ensure_settle_attempt_lease_schema_on_connection(
    connection: &rusqlite::Connection,
) -> Result<(), SettlementRetryError> {
    let mut statement = connection
        .prepare("PRAGMA table_info(settle_attempts)")
        .map_err(backend_err)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(backend_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(backend_err)?;
    drop(statement);
    let legacy_columns = [
        "receipt_id",
        "finalized_at",
        "attempts",
        "next_visible_at",
        "last_reason",
        "updated_at",
    ];
    let previous_columns = [
        "receipt_id",
        "finalized_at",
        "work_kind",
        "attempts",
        "next_visible_at_ms",
        "row_version",
        "lease_owner",
        "lease_token",
        "lease_until_ms",
        "reason_code",
        "reason_detail_sha256",
        "updated_at_ms",
    ];
    let current_columns = [
        "receipt_id",
        "finalized_at",
        "attempts",
        "next_visible_at",
        "last_reason",
        "updated_at",
        "state",
        "claim_token",
        "claim_deadline_unix_secs",
        "version",
    ];
    if columns.is_empty() {
        connection
            .execute_batch(SETTLE_ATTEMPTS_MIGRATION)
            .map_err(backend_err)?;
    } else if columns.iter().map(String::as_str).eq(legacy_columns) {
        let orphaned_legacy = connection
            .query_row(
                "SELECT attempt.receipt_id FROM settle_attempts AS attempt \
                 WHERE NOT EXISTS ( \
                     SELECT 1 FROM chio_tool_receipts AS receipt \
                     WHERE receipt.receipt_id = attempt.receipt_id \
                       AND receipt.timestamp = attempt.finalized_at \
                 ) LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(backend_err)?;
        if orphaned_legacy.is_some() {
            return Err(SettlementRetryError::Conflict(
                "legacy settle_attempts contains a row without its exact authoritative live receipt"
                    .to_string(),
            ));
        }
        connection
            .execute_batch(
                "DROP TRIGGER IF EXISTS settle_attempts_require_live_receipt_insert; \
                 DROP TRIGGER IF EXISTS settle_attempts_require_live_receipt_update;",
            )
            .map_err(backend_err)?;
        connection
            .execute_batch("ALTER TABLE settle_attempts RENAME TO settle_attempts_legacy;")
            .map_err(backend_err)?;
        connection
            .execute_batch(SETTLE_ATTEMPTS_MIGRATION)
            .map_err(backend_err)?;
        connection
            .execute_batch(SETTLE_ATTEMPTS_LIVE_RECEIPT_INSERT_TRIGGER)
            .map_err(backend_err)?;
        connection
            .execute_batch(SETTLE_ATTEMPTS_LIVE_RECEIPT_UPDATE_TRIGGER)
            .map_err(backend_err)?;
        connection
            .execute(
                "INSERT INTO settle_attempts \
                     (receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at) \
                 SELECT receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at \
                 FROM settle_attempts_legacy",
                [],
            )
            .map_err(backend_err)?;
        connection
            .execute_batch("DROP TABLE settle_attempts_legacy;")
            .map_err(backend_err)?;
    } else if columns
        .iter()
        .map(String::as_str)
        .eq(previous_columns)
    {
        let orphaned_previous = connection
            .query_row(
                "SELECT attempt.receipt_id FROM settle_attempts AS attempt \
                 WHERE NOT EXISTS ( \
                     SELECT 1 FROM chio_tool_receipts AS receipt \
                     WHERE receipt.receipt_id = attempt.receipt_id \
                       AND receipt.timestamp = attempt.finalized_at \
                 ) LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(backend_err)?;
        if orphaned_previous.is_some() {
            return Err(SettlementRetryError::Conflict(
                "previous settle_attempts contains a row without its exact authoritative live receipt"
                    .to_string(),
            ));
        }
        connection
            .execute_batch(
                "DROP INDEX IF EXISTS idx_settle_attempts_visible; \
                 DROP TRIGGER IF EXISTS trg_settle_attempts_reject_terminal_insert; \
                 DROP TRIGGER IF EXISTS trg_settle_attempts_reject_terminal_update; \
                 DROP TRIGGER IF EXISTS trg_settle_dead_letters_reject_attempt_insert; \
                 DROP TRIGGER IF EXISTS trg_settle_dead_letters_reject_attempt_update;",
            )
            .map_err(backend_err)?;
        connection
            .execute_batch("ALTER TABLE settle_attempts RENAME TO settle_attempts_previous;")
            .map_err(backend_err)?;
        connection
            .execute_batch(SETTLE_ATTEMPTS_MIGRATION)
            .map_err(backend_err)?;
        connection
            .execute_batch(SETTLE_ATTEMPTS_LIVE_RECEIPT_INSERT_TRIGGER)
            .map_err(backend_err)?;
        connection
            .execute_batch(SETTLE_ATTEMPTS_LIVE_RECEIPT_UPDATE_TRIGGER)
            .map_err(backend_err)?;
        connection
            .execute(
                "INSERT INTO settle_attempts \
                     (receipt_id, finalized_at, attempts, next_visible_at, last_reason, \
                      updated_at, state, claim_token, claim_deadline_unix_secs, version) \
                 SELECT receipt_id, finalized_at, \
                        CASE WHEN attempts = 0 THEN 1 ELSE attempts END, \
                        (next_visible_at_ms / 1000) + \
                            CASE WHEN (next_visible_at_ms % 1000) = 0 THEN 0 ELSE 1 END, \
                        CASE WHEN work_kind = 'pending_observation' \
                             THEN 'migrated pending observation' ELSE reason_code END, \
                        (updated_at_ms / 1000) + \
                            CASE WHEN (updated_at_ms % 1000) = 0 THEN 0 ELSE 1 END, \
                        CASE WHEN lease_token IS NULL THEN 'pending' ELSE 'claimed' END, \
                        lease_token, \
                        CASE WHEN lease_until_ms IS NULL THEN NULL \
                             ELSE (lease_until_ms / 1000) + \
                                  CASE WHEN (lease_until_ms % 1000) = 0 THEN 0 ELSE 1 END \
                        END, \
                        row_version \
                 FROM settle_attempts_previous",
                [],
            )
            .map_err(backend_err)?;
        connection
            .execute_batch("DROP TABLE settle_attempts_previous;")
            .map_err(backend_err)?;
    } else if !columns.iter().map(String::as_str).eq(current_columns) {
        return Err(SettlementRetryError::Conflict(
            "settle_attempts columns are neither a supported prior nor current schema".to_string(),
        ));
    }
    for schema_object in [
        SETTLE_ATTEMPTS_DUE_INDEX,
        SETTLE_ATTEMPTS_LIVE_RECEIPT_INSERT_TRIGGER,
        SETTLE_ATTEMPTS_LIVE_RECEIPT_UPDATE_TRIGGER,
        SETTLE_ATTEMPTS_INSERT_TRIGGER,
        SETTLE_ATTEMPTS_UPDATE_TRIGGER,
    ] {
        connection
            .execute_batch(schema_object)
            .map_err(backend_err)?;
    }
    validate_settle_attempt_lease_schema(connection)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_string()
}

fn normalize_expected_schema_sql(sql: &str) -> String {
    normalize_schema_sql(&sql.replacen(" IF NOT EXISTS", "", 1))
}

fn validate_settle_attempt_lease_schema(
    connection: &rusqlite::Connection,
) -> Result<(), SettlementRetryError> {
    let mut statement = connection
        .prepare("PRAGMA table_info(settle_attempts)")
        .map_err(backend_err)?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(backend_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(backend_err)?;
    let expected_columns = vec![
        ("receipt_id".to_string(), "TEXT".to_string(), 1, None, 1),
        (
            "finalized_at".to_string(),
            "INTEGER".to_string(),
            1,
            None,
            0,
        ),
        ("attempts".to_string(), "INTEGER".to_string(), 1, None, 0),
        (
            "next_visible_at".to_string(),
            "INTEGER".to_string(),
            1,
            None,
            0,
        ),
        ("last_reason".to_string(), "TEXT".to_string(), 0, None, 0),
        ("updated_at".to_string(), "INTEGER".to_string(), 1, None, 0),
        (
            "state".to_string(),
            "TEXT".to_string(),
            1,
            Some("'pending'".to_string()),
            0,
        ),
        ("claim_token".to_string(), "TEXT".to_string(), 0, None, 0),
        (
            "claim_deadline_unix_secs".to_string(),
            "INTEGER".to_string(),
            0,
            None,
            0,
        ),
        (
            "version".to_string(),
            "INTEGER".to_string(),
            1,
            Some("0".to_string()),
            0,
        ),
    ];
    if columns != expected_columns {
        return Err(SettlementRetryError::Conflict(
            "settle_attempts columns, defaults, nullability, or primary key are invalid"
                .to_string(),
        ));
    }

    let table_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(backend_err)?
        .ok_or_else(|| {
            SettlementRetryError::Conflict("settle_attempts table is missing".to_string())
        })?;
    let expected_table_sql =
        SETTLE_ATTEMPTS_MIGRATION.replacen("CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1);
    if normalize_schema_sql(&table_sql) != normalize_schema_sql(&expected_table_sql) {
        return Err(SettlementRetryError::Conflict(
            "settle_attempts table constraints are invalid".to_string(),
        ));
    }

    let indexes = connection
        .prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'index' \
             AND tbl_name = 'settle_attempts' AND sql IS NOT NULL ORDER BY name",
        )
        .map_err(backend_err)?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(backend_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(backend_err)?;
    if indexes.len() != 1
        || indexes[0].0 != "idx_settle_attempts_due"
        || normalize_schema_sql(&indexes[0].1)
            != normalize_expected_schema_sql(SETTLE_ATTEMPTS_DUE_INDEX)
    {
        return Err(SettlementRetryError::Conflict(
            "settle_attempts due index is missing or invalid".to_string(),
        ));
    }

    let triggers = connection
        .prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' \
             AND tbl_name = 'settle_attempts' ORDER BY name",
        )
        .map_err(backend_err)?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(backend_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(backend_err)?;
    let expected_triggers = [
        (
            "settle_attempts_require_live_receipt_insert",
            SETTLE_ATTEMPTS_LIVE_RECEIPT_INSERT_TRIGGER,
        ),
        (
            "settle_attempts_require_live_receipt_update",
            SETTLE_ATTEMPTS_LIVE_RECEIPT_UPDATE_TRIGGER,
        ),
        (
            "settle_attempts_validate_insert",
            SETTLE_ATTEMPTS_INSERT_TRIGGER,
        ),
        (
            "settle_attempts_validate_update",
            SETTLE_ATTEMPTS_UPDATE_TRIGGER,
        ),
    ];
    if triggers.len() != expected_triggers.len()
        || triggers.iter().zip(expected_triggers.iter()).any(
            |((actual_name, actual_sql), (expected_name, expected_sql))| {
                actual_name != expected_name
                    || normalize_schema_sql(actual_sql)
                        != normalize_expected_schema_sql(expected_sql)
            },
        )
    {
        return Err(SettlementRetryError::Conflict(
            "settle_attempts integrity triggers are missing or invalid".to_string(),
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT receipt_id, finalized_at, attempts, next_visible_at, last_reason, \
                    state, claim_token, claim_deadline_unix_secs, version, updated_at \
             FROM settle_attempts",
        )
        .map_err(backend_err)?;
    let rows = statement
        .query_map([], row_to_stored_attempt)
        .map_err(backend_err)?;
    for row in rows {
        row.map_err(|error| {
            SettlementRetryError::Conflict(format!(
                "settle_attempts contains an invalid persisted row: {error}"
            ))
        })?;
    }
    drop(statement);
    let orphaned = connection
        .query_row(
            "SELECT attempt.receipt_id FROM settle_attempts AS attempt \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM chio_tool_receipts AS receipt \
                 WHERE receipt.receipt_id = attempt.receipt_id \
                   AND receipt.timestamp = attempt.finalized_at \
             ) LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(backend_err)?;
    if orphaned.is_some() {
        return Err(SettlementRetryError::Conflict(
            "settle_attempts contains a row without its exact authoritative live receipt"
                .to_string(),
        ));
    }
    Ok(())
}

fn sqlite_i64(value: u64, field: &str) -> Result<i64, SettlementRetryError> {
    i64::try_from(value)
        .map_err(|_| SettlementRetryError::Backend(format!("{field} exceeds SQLite INTEGER range")))
}

fn sqlite_limit(value: usize) -> Result<i64, SettlementRetryError> {
    i64::try_from(value).map_err(|_| {
        SettlementRetryError::Backend(
            "settlement retry limit exceeds SQLite INTEGER range".to_string(),
        )
    })
}

fn backend_err(error: impl std::fmt::Display) -> SettlementRetryError {
    SettlementRetryError::Backend(error.to_string())
}

fn retry_to_receipt_error(error: SettlementRetryError) -> chio_kernel::ReceiptStoreError {
    match error {
        SettlementRetryError::Conflict(message) => {
            chio_kernel::ReceiptStoreError::Conflict(message)
        }
        SettlementRetryError::Backend(message) => {
            chio_kernel::ReceiptStoreError::Canonical(message)
        }
    }
}

fn receipt_to_retry_error(error: chio_kernel::ReceiptStoreError) -> SettlementRetryError {
    match error {
        chio_kernel::ReceiptStoreError::Conflict(message) => {
            SettlementRetryError::Conflict(message)
        }
        chio_kernel::ReceiptStoreError::Canonical(message) => {
            SettlementRetryError::Backend(message)
        }
        other => SettlementRetryError::Backend(other.to_string()),
    }
}

fn iou_to_retry_error(error: chio_credit::IouEnvelopeStoreError) -> SettlementRetryError {
    match error {
        chio_credit::IouEnvelopeStoreError::Conflict(message) => {
            SettlementRetryError::Conflict(message)
        }
        chio_credit::IouEnvelopeStoreError::Backend(message) => {
            SettlementRetryError::Backend(message)
        }
    }
}

fn validate_authoritative_settlement_obligation_on_connection(
    connection: &rusqlite::Connection,
    lease: &SettleAttemptLease,
    envelope: &chio_credit::IouEnvelope,
    trusted_kernel_keys: &[chio_core::PublicKey],
) -> Result<(), SettlementRetryError> {
    const MAX_SETTLEMENT_RECEIPT_BYTES: i64 = 1_048_576;

    let raw_size = connection
        .query_row(
            "SELECT length(CAST(raw_json AS BLOB)) FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![lease.record.receipt_id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(backend_err)?
        .ok_or_else(|| {
            SettlementRetryError::Conflict(
                "settlement receipt is absent from authoritative live storage".to_string(),
            )
        })?;
    if raw_size <= 0 || raw_size > MAX_SETTLEMENT_RECEIPT_BYTES {
        return Err(SettlementRetryError::Conflict(format!(
            "authoritative settlement receipt must be between 1 and {MAX_SETTLEMENT_RECEIPT_BYTES} bytes"
        )));
    }

    let (timestamp, capability_id, tool_server, tool_name, tenant_id, raw_json) = connection
        .query_row(
            "SELECT timestamp, capability_id, tool_server, tool_name, tenant_id, raw_json \
             FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![lease.record.receipt_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .map_err(backend_err)?;
    let expected_timestamp = sqlite_i64(
        lease.record.finalized_at,
        "authoritative settlement receipt timestamp",
    )?;
    if timestamp != expected_timestamp {
        return Err(SettlementRetryError::Conflict(
            "settlement lease timestamp diverges from the authoritative receipt".to_string(),
        ));
    }

    let receipt: chio_core::receipt::body::ChioReceipt =
        serde_json::from_str(&raw_json).map_err(|error| {
            SettlementRetryError::Conflict(format!(
                "authoritative settlement receipt is invalid JSON: {error}"
            ))
        })?;
    if receipt.id != lease.record.receipt_id
        || receipt.timestamp != lease.record.finalized_at
        || receipt.capability_id != capability_id
        || receipt.tool_server != tool_server
        || receipt.tool_name != tool_name
        || receipt.tenant_id != tenant_id
    {
        return Err(SettlementRetryError::Conflict(
            "authoritative settlement receipt projections diverge from its signed bytes"
                .to_string(),
        ));
    }
    if !receipt.verify_signature().map_err(|error| {
        SettlementRetryError::Conflict(format!(
            "authoritative settlement receipt signature validation failed: {error}"
        ))
    })? {
        return Err(SettlementRetryError::Conflict(
            "authoritative settlement receipt signature is invalid".to_string(),
        ));
    }
    let expected_receipt_id =
        chio_core::receipt::body::chio_receipt_id(&receipt.body()).map_err(|error| {
            SettlementRetryError::Conflict(format!(
                "authoritative settlement receipt id validation failed: {error}"
            ))
        })?;
    if expected_receipt_id != receipt.id {
        return Err(SettlementRetryError::Conflict(
            "authoritative settlement receipt id is invalid".to_string(),
        ));
    }
    if !receipt.action.verify_hash().map_err(|error| {
        SettlementRetryError::Conflict(format!(
            "authoritative settlement receipt action validation failed: {error}"
        ))
    })? {
        return Err(SettlementRetryError::Conflict(
            "authoritative settlement receipt action hash is invalid".to_string(),
        ));
    }
    if !trusted_kernel_keys.contains(&receipt.kernel_key) {
        return Err(SettlementRetryError::Conflict(
            "authoritative settlement receipt signer is not trusted".to_string(),
        ));
    }
    if !receipt.is_allowed() {
        return Err(SettlementRetryError::Conflict(
            "authoritative settlement receipt is not eligible to mint an IOU".to_string(),
        ));
    }
    let financial = receipt.financial_metadata().ok_or_else(|| {
        SettlementRetryError::Conflict(
            "authoritative settlement receipt has no financial obligation".to_string(),
        )
    })?;
    if financial.cost_charged == 0 {
        return Err(SettlementRetryError::Conflict(
            "authoritative settlement receipt has no positive financial obligation".to_string(),
        ));
    }
    if envelope.body.iou_id != chio_credit::local_account::derive_iou_id(&receipt.id)
        || envelope.body.receipt_id != receipt.id
        || envelope.body.receipt_timestamp != receipt.timestamp
        || envelope.body.tenant_id != receipt.tenant_id
        || envelope.body.tool_server != receipt.tool_server
        || envelope.body.tool_name != receipt.tool_name
        || envelope.body.capability_id != receipt.capability_id
        || envelope.body.amount_units != financial.cost_charged
        || envelope.body.currency != financial.currency
    {
        return Err(SettlementRetryError::Conflict(
            "settlement IOU diverges from the authoritative receipt obligation".to_string(),
        ));
    }
    Ok(())
}

fn map_dl_err(error: DeadLetterStoreError) -> SettlementRetryError {
    match error {
        DeadLetterStoreError::Conflict(message) => SettlementRetryError::Conflict(message),
        other => SettlementRetryError::Backend(other.to_string()),
    }
}

fn invalid_row(
    index: usize,
    value_type: rusqlite::types::Type,
    message: impl Into<String>,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        value_type,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message.into(),
        )),
    )
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize, field: &str) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    u64::try_from(value).map_err(|_| {
        invalid_row(
            index,
            rusqlite::types::Type::Integer,
            format!("{field} is negative"),
        )
    })
}

fn row_u32(row: &rusqlite::Row<'_>, index: usize, field: &str) -> rusqlite::Result<u32> {
    let value = row.get::<_, i64>(index)?;
    let value = u32::try_from(value).map_err(|_| {
        invalid_row(
            index,
            rusqlite::types::Type::Integer,
            format!("{field} is outside u32 range"),
        )
    })?;
    if value == 0 {
        return Err(invalid_row(
            index,
            rusqlite::types::Type::Integer,
            format!("{field} must be positive"),
        ));
    }
    Ok(value)
}

fn row_optional_u64(
    row: &rusqlite::Row<'_>,
    index: usize,
    field: &str,
) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                invalid_row(
                    index,
                    rusqlite::types::Type::Integer,
                    format!("{field} is negative"),
                )
            })
        })
        .transpose()
}

fn validate_receipt_id(receipt_id: &str) -> Result<(), SettlementRetryError> {
    if receipt_id.trim().is_empty() || receipt_id.len() > 512 {
        return Err(SettlementRetryError::Conflict(
            "settlement retry receipt id must be nonblank and at most 512 bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_attempt_record(record: &SettleAttemptRecord) -> Result<(), SettlementRetryError> {
    validate_receipt_id(&record.receipt_id)?;
    if record.attempts == 0 || record.attempts > MAX_SETTLEMENT_RETRY_ATTEMPTS {
        return Err(SettlementRetryError::Conflict(format!(
            "settlement retry attempt count must be in 1..={MAX_SETTLEMENT_RETRY_ATTEMPTS}"
        )));
    }
    if record
        .last_reason
        .as_ref()
        .is_some_and(|reason| reason.trim().is_empty() || reason.len() > 2_048)
    {
        return Err(SettlementRetryError::Conflict(
            "settlement retry reason must be absent, nonblank, and at most 2048 bytes".to_string(),
        ));
    }
    let _ = sqlite_i64(record.finalized_at, "settlement finalized_at")?;
    let _ = sqlite_i64(record.next_visible_at, "settlement next_visible_at")?;
    Ok(())
}

fn require_authoritative_live_receipt(
    connection: &rusqlite::Connection,
    receipt_id: &str,
    finalized_at: i64,
) -> Result<(), SettlementRetryError> {
    let live_timestamp = connection
        .query_row(
            "SELECT timestamp FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![receipt_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(backend_err)?;
    match live_timestamp {
        Some(timestamp) if timestamp == finalized_at => Ok(()),
        Some(_) => Err(SettlementRetryError::Conflict(
            "settlement retry timestamp diverges from the authoritative live receipt".to_string(),
        )),
        None => Err(SettlementRetryError::Conflict(
            "settlement retry receipt is absent from authoritative live storage".to_string(),
        )),
    }
}

fn validate_claim_token(claim_token: &str) -> Result<(), SettlementRetryError> {
    if claim_token.trim().is_empty() || claim_token.len() > 512 {
        return Err(SettlementRetryError::Conflict(
            "settlement retry claim token must be nonblank and at most 512 bytes".to_string(),
        ));
    }
    Ok(())
}

fn row_to_attempt(row: &rusqlite::Row<'_>) -> rusqlite::Result<SettleAttemptRecord> {
    let receipt_id = row.get::<_, String>(0)?;
    if receipt_id.trim().is_empty() || receipt_id.len() > 512 {
        return Err(invalid_row(
            0,
            rusqlite::types::Type::Text,
            "settlement retry receipt id has invalid length",
        ));
    }
    let last_reason = row.get::<_, Option<String>>(4)?;
    if last_reason
        .as_ref()
        .is_some_and(|reason| reason.trim().is_empty() || reason.len() > 2_048)
    {
        return Err(invalid_row(
            4,
            rusqlite::types::Type::Text,
            "settlement retry reason has invalid length",
        ));
    }
    let attempts = row_u32(row, 2, "settlement attempts")?;
    if attempts > MAX_SETTLEMENT_RETRY_ATTEMPTS {
        return Err(invalid_row(
            2,
            rusqlite::types::Type::Integer,
            format!("settlement attempts exceeds {MAX_SETTLEMENT_RETRY_ATTEMPTS}"),
        ));
    }
    Ok(SettleAttemptRecord {
        receipt_id,
        finalized_at: row_u64(row, 1, "settlement finalized_at")?,
        attempts,
        next_visible_at: row_u64(row, 3, "settlement next_visible_at")?,
        last_reason,
    })
}

struct StoredAttemptRow {
    record: SettleAttemptRecord,
    state: String,
    version: u64,
}

fn row_to_stored_attempt(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAttemptRow> {
    let record = row_to_attempt(row)?;
    let state = row.get::<_, String>(5)?;
    let claim_token = row.get::<_, Option<String>>(6)?;
    if claim_token
        .as_ref()
        .is_some_and(|token| token.trim().is_empty() || token.len() > 512)
    {
        return Err(invalid_row(
            6,
            rusqlite::types::Type::Text,
            "settlement retry claim token has invalid length",
        ));
    }
    let claim_deadline_unix_secs = row_optional_u64(row, 7, "settlement claim deadline")?;
    let version = row_u64(row, 8, "settlement retry version")?;
    let _updated_at = row_u64(row, 9, "settlement updated_at")?;
    let claim_shape_is_valid = match state.as_str() {
        "pending" => claim_token.is_none() && claim_deadline_unix_secs.is_none(),
        "claimed" => claim_token.is_some() && claim_deadline_unix_secs.is_some(),
        _ => false,
    };
    if !claim_shape_is_valid {
        return Err(invalid_row(
            5,
            rusqlite::types::Type::Text,
            "settlement retry state and claim fields are inconsistent",
        ));
    }
    Ok(StoredAttemptRow {
        record,
        state,
        version,
    })
}

impl SqliteSettlementRetryStore {
    /// Commit the IOU, exact reconciliation, and lease deletion in one fenced
    /// transaction. A stale or expired lease returns `Ok(false)` without
    /// writing evidence.
    pub fn commit_claimed_settlement_exact(
        &self,
        lease: &SettleAttemptLease,
        envelope: &chio_credit::IouEnvelope,
        trusted_iou_issuers: &[chio_core::PublicKey],
        trusted_kernel_keys: &[chio_core::PublicKey],
        note: Option<&str>,
    ) -> Result<bool, SettlementRetryError> {
        validate_attempt_record(&lease.record)?;
        validate_claim_token(&lease.claim_token)?;
        crate::iou_store::validate_settlement_envelope(
            envelope,
            trusted_iou_issuers,
            trusted_kernel_keys,
        )
        .map_err(iou_to_retry_error)?;
        crate::SqliteReceiptStore::validate_exact_settlement_reconciliation(
            lease.record.receipt_id.as_str(),
            note,
        )
        .map_err(receipt_to_retry_error)?;
        if envelope.body.receipt_id != lease.record.receipt_id
            || envelope.body.receipt_timestamp != lease.record.finalized_at
        {
            return Err(SettlementRetryError::Conflict(
                "settlement IOU changed its claimed receipt binding".to_string(),
            ));
        }

        let lease = lease.clone();
        let envelope = envelope.clone();
        let trusted_iou_issuers = trusted_iou_issuers.to_vec();
        let trusted_kernel_keys = trusted_kernel_keys.to_vec();
        let note = note.map(ToString::to_string);
        let finalized_at = sqlite_i64(lease.record.finalized_at, "settlement finalized_at")?;
        let lease_attempts = i64::from(lease.record.attempts);
        let lease_next_visible_at =
            sqlite_i64(lease.record.next_visible_at, "settlement next_visible_at")?;
        let lease_claim_deadline =
            sqlite_i64(lease.claim_deadline_unix_secs, "settlement claim deadline")?;
        let version = sqlite_i64(lease.version, "settlement lease version")?;
        let clock = std::sync::Arc::clone(&self.clock);
        self.run_write(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;
            let now = sqlite_i64(clock.now_unix_secs()?, "settlement terminal time")?;
            let owns_lease = transaction
                .query_row(
                    "SELECT 1 FROM settle_attempts \
                     WHERE receipt_id = ?1 AND finalized_at = ?2 AND state = 'claimed' \
                       AND claim_token = ?3 AND version = ?4 AND attempts = ?5 \
                       AND next_visible_at = ?6 AND last_reason IS ?7 \
                       AND claim_deadline_unix_secs = ?8 \
                       AND claim_deadline_unix_secs > ?9",
                    rusqlite::params![
                        lease.record.receipt_id.as_str(),
                        finalized_at,
                        lease.claim_token.as_str(),
                        version,
                        lease_attempts,
                        lease_next_visible_at,
                        lease.record.last_reason.as_deref(),
                        lease_claim_deadline,
                        now,
                    ],
                    |_| Ok(()),
                )
                .optional()
                .map_err(backend_err)?
                .is_some();
            if !owns_lease {
                transaction.rollback().map_err(backend_err)?;
                return Ok(false);
            }

            validate_authoritative_settlement_obligation_on_connection(
                &transaction,
                &lease,
                &envelope,
                &trusted_kernel_keys,
            )?;

            crate::iou_store::insert_or_validate_settlement_envelope_on_connection(
                &transaction,
                &envelope,
                &trusted_iou_issuers,
                &trusted_kernel_keys,
            )
            .map_err(iou_to_retry_error)?;
            crate::SqliteReceiptStore::complete_settlement_reconciliation_exact_on_connection(
                &transaction,
                lease.record.receipt_id.as_str(),
                note.as_deref(),
            )
            .map_err(receipt_to_retry_error)?;
            let deleted = transaction
                .execute(
                    "DELETE FROM settle_attempts \
                     WHERE receipt_id = ?1 AND finalized_at = ?2 AND state = 'claimed' \
                       AND claim_token = ?3 AND version = ?4 AND attempts = ?5 \
                       AND next_visible_at = ?6 AND last_reason IS ?7 \
                       AND claim_deadline_unix_secs = ?8 \
                       AND claim_deadline_unix_secs > ?9",
                    rusqlite::params![
                        lease.record.receipt_id.as_str(),
                        finalized_at,
                        lease.claim_token.as_str(),
                        version,
                        lease_attempts,
                        lease_next_visible_at,
                        lease.record.last_reason.as_deref(),
                        lease_claim_deadline,
                        now,
                    ],
                )
                .map_err(backend_err)?;
            if deleted != 1 {
                return Err(SettlementRetryError::Conflict(
                    "settlement evidence commit lost its claimed lease fence".to_string(),
                ));
            }
            transaction.commit().map_err(backend_err)?;
            Ok(true)
        })
    }
}

impl SettlementRetryStore for SqliteSettlementRetryStore {
    fn supports_durable_settlement_retry(&self) -> bool {
        true
    }

    fn durable_storage_identity(&self) -> Result<Option<chio_core::Hash>, SettlementRetryError> {
        Ok(Some(self.storage_identity))
    }

    fn load_attempt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<SettleAttemptRecord>, SettlementRetryError> {
        validate_receipt_id(receipt_id)?;
        let connection = (self.connection_checkout)().map_err(backend_err)?;
        connection
            .connection()
            .query_row(
                "SELECT receipt_id, finalized_at, attempts, next_visible_at, last_reason, \
                        state, claim_token, claim_deadline_unix_secs, version, updated_at \
                 FROM settle_attempts WHERE receipt_id = ?1",
                rusqlite::params![receipt_id],
                |row| row_to_stored_attempt(row).map(|stored| stored.record),
            )
            .optional()
            .map_err(backend_err)
    }

    fn upsert_attempt(&self, record: &SettleAttemptRecord) -> Result<(), SettlementRetryError> {
        validate_attempt_record(record)?;
        let record = record.clone();
        let finalized_at = sqlite_i64(record.finalized_at, "settlement finalized_at")?;
        let next_visible_at = sqlite_i64(record.next_visible_at, "settlement next_visible_at")?;
        let updated_at = sqlite_i64(self.now_unix_secs()?, "settlement updated_at")?;
        self.run_write(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;
            require_authoritative_live_receipt(
                &transaction,
                record.receipt_id.as_str(),
                finalized_at,
            )?;
            let existing = transaction
                .query_row(
                    "SELECT receipt_id, finalized_at, attempts, next_visible_at, last_reason, \
                            state, claim_token, claim_deadline_unix_secs, version, updated_at \
                     FROM settle_attempts WHERE receipt_id = ?1",
                    rusqlite::params![record.receipt_id.as_str()],
                    row_to_stored_attempt,
                )
                .optional()
                .map_err(backend_err)?;
            let Some(StoredAttemptRow {
                record: current,
                state,
                version,
            }) = existing
            else {
                transaction
                    .execute(
                        "INSERT INTO settle_attempts \
                         (receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            record.receipt_id.as_str(),
                            finalized_at,
                            i64::from(record.attempts),
                            next_visible_at,
                            record.last_reason.as_deref(),
                            updated_at,
                        ],
                    )
                    .map_err(backend_err)?;
                transaction.commit().map_err(backend_err)?;
                return Ok(());
            };
            if current == record {
                transaction.commit().map_err(backend_err)?;
                return Ok(());
            }
            if state != "pending"
                || current.finalized_at != record.finalized_at
                || current
                    .attempts
                    .checked_add(1)
                    .is_none_or(|next| next != record.attempts)
            {
                return Err(SettlementRetryError::Conflict(format!(
                    "settlement retry upsert for `{}` is stale, divergent, or not pending",
                    record.receipt_id
                )));
            }
            let changed = transaction
                .execute(
                    "UPDATE settle_attempts \
                     SET attempts = ?1, next_visible_at = ?2, last_reason = ?3, \
                         updated_at = ?4, version = version + 1 \
                     WHERE receipt_id = ?5 AND state = 'pending' AND version = ?6",
                    rusqlite::params![
                        i64::from(record.attempts),
                        next_visible_at,
                        record.last_reason.as_deref(),
                        updated_at,
                        record.receipt_id.as_str(),
                        sqlite_i64(version, "settlement retry version")?,
                    ],
                )
                .map_err(backend_err)?;
            if changed != 1 {
                return Err(SettlementRetryError::Conflict(
                    "settlement retry upsert lost its immediate transaction fence".to_string(),
                ));
            }
            transaction.commit().map_err(backend_err)?;
            Ok(())
        })
    }

    fn insert_observer_attempt_if_absent(
        &self,
        record: &SettleAttemptRecord,
    ) -> Result<bool, SettlementRetryError> {
        validate_attempt_record(record)?;
        let record = record.clone();
        let finalized_at = sqlite_i64(record.finalized_at, "settlement finalized_at")?;
        let next_visible_at = sqlite_i64(record.next_visible_at, "settlement next_visible_at")?;
        let updated_at = sqlite_i64(self.now_unix_secs()?, "settlement updated_at")?;
        self.run_write(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;
            require_authoritative_live_receipt(
                &transaction,
                record.receipt_id.as_str(),
                finalized_at,
            )?;
            let changed = transaction
                .execute(
                    "INSERT INTO settle_attempts \
                     (receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at, \
                      state, claim_token, claim_deadline_unix_secs, version) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, NULL, 0) \
                     ON CONFLICT(receipt_id) DO NOTHING",
                    rusqlite::params![
                        record.receipt_id.as_str(),
                        finalized_at,
                        i64::from(record.attempts),
                        next_visible_at,
                        record.last_reason.as_deref(),
                        updated_at,
                    ],
                )
                .map_err(backend_err)?;
            if changed == 1 {
                transaction.commit().map_err(backend_err)?;
                return Ok(true);
            }
            let existing = transaction
                .query_row(
                    "SELECT receipt_id, finalized_at, attempts, next_visible_at, last_reason, \
                            state, claim_token, claim_deadline_unix_secs, version, updated_at \
                     FROM settle_attempts WHERE receipt_id = ?1",
                    rusqlite::params![record.receipt_id.as_str()],
                    row_to_stored_attempt,
                )
                .optional()
                .map_err(backend_err)?
                .ok_or_else(|| {
                    SettlementRetryError::Backend(
                        "settlement observer attempt conflicted but disappeared".to_string(),
                    )
                })?;
            if existing.record.finalized_at != record.finalized_at {
                return Err(SettlementRetryError::Conflict(format!(
                    "settlement attempt `{}` has finalized_at {} instead of {}",
                    record.receipt_id, existing.record.finalized_at, record.finalized_at
                )));
            }
            transaction.commit().map_err(backend_err)?;
            Ok(false)
        })
    }

    fn clear_attempt(&self, receipt_id: &str) -> Result<(), SettlementRetryError> {
        validate_receipt_id(receipt_id)?;
        let receipt_id = receipt_id.to_string();
        self.run_write(move |connection| {
            let changed = connection
                .execute(
                    "DELETE FROM settle_attempts WHERE receipt_id = ?1 AND state = 'pending'",
                    rusqlite::params![receipt_id.as_str()],
                )
                .map_err(backend_err)?;
            if changed == 1 {
                return Ok(());
            }
            let state = connection
                .query_row(
                    "SELECT state FROM settle_attempts WHERE receipt_id = ?1",
                    rusqlite::params![receipt_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(backend_err)?;
            match state.as_deref() {
                None => Ok(()),
                Some("claimed") => Err(SettlementRetryError::Conflict(format!(
                    "settlement retry row `{receipt_id}` is claimed"
                ))),
                Some(other) => Err(SettlementRetryError::Conflict(format!(
                    "settlement retry row `{receipt_id}` has invalid state `{other}`"
                ))),
            }
        })
    }

    fn insert_dead_letter(
        &self,
        record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, SettlementRetryError> {
        self.dead_letters.insert(record).map_err(map_dl_err)
    }

    fn claim_due_attempts(
        &self,
        now_unix_secs: u64,
        claim_deadline_unix_secs: u64,
        claim_token: &str,
        limit: usize,
    ) -> Result<Vec<SettleAttemptLease>, SettlementRetryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        if limit > MAX_SETTLEMENT_RETRY_BATCH {
            return Err(SettlementRetryError::Conflict(format!(
                "settlement retry claim limit must not exceed {MAX_SETTLEMENT_RETRY_BATCH}"
            )));
        }
        validate_claim_token(claim_token)?;
        if claim_deadline_unix_secs <= now_unix_secs {
            return Err(SettlementRetryError::Conflict(
                "settlement retry claim requires a future deadline".to_string(),
            ));
        }
        let now = sqlite_i64(now_unix_secs, "settlement claim time")?;
        let deadline = sqlite_i64(claim_deadline_unix_secs, "settlement claim deadline")?;
        let claim_token = claim_token.to_string();
        self.run_write(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;
            let candidate = transaction
                .query_row(
                    "SELECT candidate.receipt_id, candidate.finalized_at, candidate.attempts, \
                        candidate.next_visible_at, candidate.last_reason, candidate.version \
                 FROM settle_attempts AS candidate \
                 WHERE candidate.next_visible_at <= ?1 \
                   AND (candidate.state = 'pending' \
                        OR (candidate.state = 'claimed' \
                            AND candidate.claim_deadline_unix_secs <= ?1)) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM settle_attempts AS earlier \
                       WHERE earlier.finalized_at < candidate.finalized_at \
                              OR (earlier.finalized_at = candidate.finalized_at \
                                  AND earlier.receipt_id < candidate.receipt_id) \
                   ) \
                 ORDER BY candidate.finalized_at ASC, candidate.receipt_id ASC \
                 LIMIT 1",
                    rusqlite::params![now],
                    |row| {
                        Ok((
                            row_to_attempt(row)?,
                            row_u64(row, 5, "settlement retry version")?,
                        ))
                    },
                )
                .optional()
                .map_err(backend_err)?;
            let Some((record, prior_version)) = candidate else {
                transaction.commit().map_err(backend_err)?;
                return Ok(Vec::new());
            };
            let version = prior_version.checked_add(1).ok_or_else(|| {
                SettlementRetryError::Backend("settlement retry version overflowed u64".to_string())
            })?;
            let version_sqlite = sqlite_i64(version, "settlement retry version")?;
            let changed = transaction
                .execute(
                    "UPDATE settle_attempts \
                 SET state = 'claimed', claim_token = ?2, \
                     claim_deadline_unix_secs = ?3, version = ?4, updated_at = ?1 \
                 WHERE receipt_id = ?5 AND version = ?6 \
                   AND next_visible_at <= ?1 \
                   AND (state = 'pending' \
                        OR (state = 'claimed' AND claim_deadline_unix_secs <= ?1))",
                    rusqlite::params![
                        now,
                        claim_token.as_str(),
                        deadline,
                        version_sqlite,
                        record.receipt_id.as_str(),
                        sqlite_i64(prior_version, "settlement prior version")?,
                    ],
                )
                .map_err(backend_err)?;
            if changed != 1 {
                return Err(SettlementRetryError::Conflict(
                    "settlement retry claim lost its immediate transaction fence".to_string(),
                ));
            }
            transaction.commit().map_err(backend_err)?;
            Ok(vec![SettleAttemptLease {
                record,
                claim_token,
                claim_deadline_unix_secs,
                version,
            }])
        })
    }

    fn reschedule_claimed_attempt(
        &self,
        lease: &SettleAttemptLease,
        next: &SettleAttemptRecord,
    ) -> Result<bool, SettlementRetryError> {
        validate_attempt_record(&lease.record)?;
        validate_attempt_record(next)?;
        validate_claim_token(&lease.claim_token)?;
        let expected_attempts = lease.record.attempts.checked_add(1).ok_or_else(|| {
            SettlementRetryError::Conflict("settlement attempt count overflowed u32".to_string())
        })?;
        if next.receipt_id != lease.record.receipt_id
            || next.finalized_at != lease.record.finalized_at
            || next.attempts != expected_attempts
        {
            return Err(SettlementRetryError::Conflict(
                "rescheduled settlement attempt changed its immutable binding or monotonic count"
                    .to_string(),
            ));
        }
        let next = next.clone();
        let claim_token = lease.claim_token.clone();
        let lease_version = sqlite_i64(lease.version, "settlement lease version")?;
        let lease_attempts = i64::from(lease.record.attempts);
        let lease_next_visible_at = sqlite_i64(
            lease.record.next_visible_at,
            "settlement lease next_visible_at",
        )?;
        let lease_last_reason = lease.record.last_reason.clone();
        let lease_claim_deadline = sqlite_i64(
            lease.claim_deadline_unix_secs,
            "settlement lease claim deadline",
        )?;
        let finalized_at = sqlite_i64(next.finalized_at, "settlement finalized_at")?;
        let next_visible_at = sqlite_i64(next.next_visible_at, "settlement next_visible_at")?;
        let clock = std::sync::Arc::clone(&self.clock);
        self.run_write(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;
            let updated_at = sqlite_i64(clock.now_unix_secs()?, "settlement updated_at")?;
            let changed = transaction
                .execute(
                    "UPDATE settle_attempts \
                 SET attempts = ?1, next_visible_at = ?2, last_reason = ?3, \
                     updated_at = ?4, state = 'pending', claim_token = NULL, \
                     claim_deadline_unix_secs = NULL, version = version + 1 \
                 WHERE receipt_id = ?5 AND finalized_at = ?6 AND state = 'claimed' \
                   AND claim_token = ?7 AND version = ?8 AND attempts = ?9 \
                   AND next_visible_at = ?10 AND last_reason IS ?11 \
                   AND claim_deadline_unix_secs = ?12 \
                   AND claim_deadline_unix_secs > ?13",
                    rusqlite::params![
                        i64::from(next.attempts),
                        next_visible_at,
                        next.last_reason.as_deref(),
                        updated_at,
                        next.receipt_id.as_str(),
                        finalized_at,
                        claim_token.as_str(),
                        lease_version,
                        lease_attempts,
                        lease_next_visible_at,
                        lease_last_reason.as_deref(),
                        lease_claim_deadline,
                        updated_at,
                    ],
                )
                .map_err(backend_err)?;
            transaction.commit().map_err(backend_err)?;
            Ok(changed == 1)
        })
    }

    fn complete_claimed_attempt(
        &self,
        lease: &SettleAttemptLease,
    ) -> Result<bool, SettlementRetryError> {
        validate_attempt_record(&lease.record)?;
        validate_claim_token(&lease.claim_token)?;
        let receipt_id = lease.record.receipt_id.clone();
        let finalized_at = sqlite_i64(lease.record.finalized_at, "settlement finalized_at")?;
        let attempts = i64::from(lease.record.attempts);
        let next_visible_at =
            sqlite_i64(lease.record.next_visible_at, "settlement next_visible_at")?;
        let last_reason = lease.record.last_reason.clone();
        let claim_token = lease.claim_token.clone();
        let claim_deadline =
            sqlite_i64(lease.claim_deadline_unix_secs, "settlement claim deadline")?;
        let version = sqlite_i64(lease.version, "settlement lease version")?;
        let clock = std::sync::Arc::clone(&self.clock);
        self.run_write(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;
            let now = sqlite_i64(clock.now_unix_secs()?, "settlement terminal time")?;
            let changed = transaction
                .execute(
                    "DELETE FROM settle_attempts \
                 WHERE receipt_id = ?1 AND finalized_at = ?2 AND state = 'claimed' \
                   AND claim_token = ?3 AND version = ?4 AND attempts = ?5 \
                   AND next_visible_at = ?6 AND last_reason IS ?7 \
                   AND claim_deadline_unix_secs = ?8 \
                   AND claim_deadline_unix_secs > ?9",
                    rusqlite::params![
                        receipt_id.as_str(),
                        finalized_at,
                        claim_token.as_str(),
                        version,
                        attempts,
                        next_visible_at,
                        last_reason.as_deref(),
                        claim_deadline,
                        now,
                    ],
                )
                .map_err(backend_err)?;
            transaction.commit().map_err(backend_err)?;
            Ok(changed == 1)
        })
    }

    fn dead_letter_claimed_attempt(
        &self,
        lease: &SettleAttemptLease,
        record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, SettlementRetryError> {
        validate_attempt_record(&lease.record)?;
        validate_claim_token(&lease.claim_token)?;
        crate::dead_letters::validate_dead_letter_record(record)
            .map_err(|error| SettlementRetryError::Conflict(error.to_string()))?;
        let expected_attempts = lease.record.attempts.checked_add(1).ok_or_else(|| {
            SettlementRetryError::Conflict("settlement attempt count overflowed u32".to_string())
        })?;
        if record.receipt_id != lease.record.receipt_id
            || record.finalized_at != lease.record.finalized_at
            || record.attempts != expected_attempts
        {
            return Err(SettlementRetryError::Conflict(
                "dead letter changed its claimed settlement binding".to_string(),
            ));
        }
        let canonical_json =
            chio_core::canonical::canonical_json_bytes(record).map_err(backend_err)?;
        let canonical_json = String::from_utf8(canonical_json).map_err(backend_err)?;
        let reason_projection = crate::dead_letters::dead_letter_reason_projection(record)
            .map_err(|error| SettlementRetryError::Conflict(error.to_string()))?;
        let lease = lease.clone();
        let record = record.clone();
        let finalized_at = sqlite_i64(lease.record.finalized_at, "settlement finalized_at")?;
        let lease_attempts = i64::from(lease.record.attempts);
        let lease_next_visible_at =
            sqlite_i64(lease.record.next_visible_at, "settlement next_visible_at")?;
        let lease_claim_deadline =
            sqlite_i64(lease.claim_deadline_unix_secs, "settlement claim deadline")?;
        let lease_version = sqlite_i64(lease.version, "settlement lease version")?;
        let dead_letter_finalized_at = sqlite_i64(record.finalized_at, "dead-letter finalized_at")?;
        let clock = std::sync::Arc::clone(&self.clock);
        self.run_write(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;
            let now = sqlite_i64(clock.now_unix_secs()?, "settlement terminal time")?;
            let owned = transaction
                .query_row(
                    "SELECT 1 FROM settle_attempts \
                     WHERE receipt_id = ?1 AND finalized_at = ?2 AND state = 'claimed' \
                       AND claim_token = ?3 AND version = ?4 AND attempts = ?5 \
                       AND next_visible_at = ?6 AND last_reason IS ?7 \
                       AND claim_deadline_unix_secs = ?8 \
                       AND claim_deadline_unix_secs > ?9",
                    rusqlite::params![
                        lease.record.receipt_id.as_str(),
                        finalized_at,
                        lease.claim_token.as_str(),
                        lease_version,
                        lease_attempts,
                        lease_next_visible_at,
                        lease.record.last_reason.as_deref(),
                        lease_claim_deadline,
                        now,
                    ],
                |_| Ok(()),
            )
                .optional()
                .map_err(backend_err)?
                .is_some();
            if !owned {
                transaction.rollback().map_err(backend_err)?;
                return Ok(false);
            }
            let existing = transaction
                .query_row(
                "SELECT canonical_json FROM settle_dead_letters WHERE receipt_id = ?1",
                rusqlite::params![record.receipt_id.as_str()],
                |row| row.get::<_, String>(0),
            )
                .optional()
                .map_err(backend_err)?;
            match existing {
                Some(existing) if existing != canonical_json => {
                    return Err(SettlementRetryError::Conflict(format!(
                        "settle_dead_letters row for receipt_id={} has different bytes",
                        record.receipt_id
                    )))
                }
                Some(_) => {}
                None => {
                    transaction
                        .execute(
                            "INSERT INTO settle_dead_letters \
                             (receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            rusqlite::params![
                                record.receipt_id.as_str(),
                                dead_letter_finalized_at,
                                i64::from(record.attempts),
                                reason_projection.as_str(),
                                Option::<&str>::None,
                                canonical_json.as_str(),
                            ],
                        )
                        .map_err(backend_err)?;
                }
            }
            let deleted = transaction
                .execute(
                    "DELETE FROM settle_attempts \
                     WHERE receipt_id = ?1 AND finalized_at = ?2 AND state = 'claimed' \
                       AND claim_token = ?3 AND version = ?4 AND attempts = ?5 \
                       AND next_visible_at = ?6 AND last_reason IS ?7 \
                       AND claim_deadline_unix_secs = ?8 \
                       AND claim_deadline_unix_secs > ?9",
                    rusqlite::params![
                        lease.record.receipt_id.as_str(),
                        finalized_at,
                        lease.claim_token.as_str(),
                        lease_version,
                        lease_attempts,
                        lease_next_visible_at,
                        lease.record.last_reason.as_deref(),
                        lease_claim_deadline,
                        now,
                    ],
                )
                .map_err(backend_err)?;
            if deleted != 1 {
                return Err(SettlementRetryError::Conflict(
                    "dead-letter insertion lost its claimed settlement fence".to_string(),
                ));
            }
            transaction.commit().map_err(backend_err)?;
            Ok(true)
        })
    }

    fn due_attempts(
        &self,
        now_unix_secs: u64,
        limit: usize,
    ) -> Result<Vec<SettleAttemptRecord>, SettlementRetryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        if limit > MAX_SETTLEMENT_RETRY_BATCH {
            return Err(SettlementRetryError::Conflict(format!(
                "settlement retry due limit must not exceed {MAX_SETTLEMENT_RETRY_BATCH}"
            )));
        }
        let now = sqlite_i64(now_unix_secs, "settlement due time")?;
        let limit = sqlite_limit(limit)?;
        let connection = (self.connection_checkout)().map_err(backend_err)?;
        let mut statement = connection
            .connection()
            .prepare(
                "SELECT receipt_id, finalized_at, attempts, next_visible_at, last_reason \
                 FROM settle_attempts \
                 WHERE next_visible_at <= ?1 \
                   AND (state = 'pending' \
                        OR (state = 'claimed' AND claim_deadline_unix_secs <= ?1)) \
                 ORDER BY finalized_at ASC, receipt_id ASC LIMIT ?2",
            )
            .map_err(backend_err)?;
        let rows = statement
            .query_map(rusqlite::params![now, limit], row_to_attempt)
            .map_err(backend_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(backend_err)?);
        }
        Ok(out)
    }
}
