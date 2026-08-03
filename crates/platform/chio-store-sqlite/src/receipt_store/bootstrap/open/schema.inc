use super::*;

/// Receipt-store schema revision. Bump on every schema-affecting change so an
/// older binary refuses to open a database it cannot fully interpret.
///
/// Revision history:
/// - 0: initial stamped schema.
/// - 1: adds the `chio_dispatch_intents` journal table. An older binary must
///   refuse a database that may carry open intent rows, because it would
///   serve without reconciling them or surfacing them in health.
/// - 2: adds the durable settlement-observer outbox. An older binary must
///   refuse a database whose pending deliveries it cannot drain.
/// - 3: enforces exact SQLite types, byte bounds, and nonnegative observer
///   lease deadlines.
/// - 4: adds the lossless currency and full-width cost projection used by
///   indexed receipt queries.
///
/// Tables that identify a database this receipt store may open, all of them the
/// store's own: `chio_tool_receipts` is the current anchor (also the table the
/// store shipped before schema stamping existed) and `http_receipts` /
/// `tool_receipts` are legacy names it may still encounter on disk. A populated
/// database carrying none of these is refused rather than adopted, so a path
/// mistargeted at another store's file (an approval, revocation, budget, or
/// authority database) never has receipt tables written into it.
///
/// `chio api protect` co-locates the receipt and approval stores in one SQLite
/// file and opens the receipt store first, so this store owns the shared file's
/// provenance anchor. The approval store, opened second, adopts the
/// receipt-anchored file through its own co-located open; the receipt store never
/// needs to recognize a neighbor's table to bootstrap the shared file, so a
/// standalone approval database is refused here.
const RECEIPT_STORE_LEGACY_ANCHOR_TABLES: &[&str] =
    &["chio_tool_receipts", "http_receipts", "tool_receipts"];

/// The subset of legacy anchors whose names are generic enough that an unrelated
/// SQLite database could carry them by coincidence. Adopting an unstamped
/// database on one of these names alone would let a mistargeted path capture a
/// foreign file, so each must also carry a receipt payload column before it is
/// accepted. The Chio-specific `chio_tool_receipts` anchor needs no such check.
const RECEIPT_STORE_GENERIC_LEGACY_ANCHOR_TABLES: &[&str] = &["http_receipts", "tool_receipts"];

/// Non-audit operational journal: one durable row per in-flight
/// side-effecting or monetary dispatch, written before the effect and
/// consumed in the same transaction as the receipt append. Never signed,
/// never entered into chio_tool_receipts, and never counted by checkpoints
/// or retention. Shared by the create path and the `open_existing` additive
/// migration from schema revision 0, so both produce identical DDL.
///
/// `owner_token` names the store instance that journaled the row (one fresh
/// token per open, never reused across restarts). Reconciliation skips rows
/// carrying the reconciling instance's own token, which is what makes the
/// pass safe to re-run while serving: liveness comes from the sidecar
/// writer mark, identity from the token, and neither involves a clock (a
/// paused-but-live writer keeps both).
///
/// A row's identity is (tenant, request id): request ids are caller-supplied
/// and only unique within a tenant, so tenant-scoped uniqueness keeps one
/// tenant's open or dead-letter intent from blocking an unrelated tenant's
/// request that reuses the id. The unique index folds a NULL tenant to ''
/// (a nullable column in a plain UNIQUE constraint would admit duplicate
/// NULLs), so tenantless rows still conflict with each other.
const DISPATCH_INTENT_JOURNAL_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS chio_dispatch_intents (
        request_id            TEXT NOT NULL,
        capability_id         TEXT NOT NULL,
        tool_server           TEXT NOT NULL,
        tool_name             TEXT NOT NULL,
        parameter_hash        TEXT NOT NULL,
        side_effect_class     TEXT NOT NULL,
        monetary              INTEGER NOT NULL,
        rail                  TEXT,
        rail_authorization_id TEXT,
        tenant_id             TEXT,
        created_at_unix_ms    INTEGER NOT NULL,
        state                 TEXT NOT NULL DEFAULT 'open',
        resolution_detail     TEXT,
        owner_token           TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_chio_dispatch_intents_tenant_request
        ON chio_dispatch_intents(COALESCE(tenant_id, ''), request_id);
    CREATE INDEX IF NOT EXISTS idx_chio_dispatch_intents_state
        ON chio_dispatch_intents(state);
"#;

const SETTLEMENT_OBSERVER_OUTBOX_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS chio_settlement_observer_outbox (
        receipt_id              TEXT NOT NULL PRIMARY KEY
            CHECK (
                typeof(receipt_id) = 'text'
                AND length(trim(receipt_id)) > 0
                AND length(CAST(receipt_id AS BLOB)) <= 512
            ),
        finalized_at            INTEGER NOT NULL
            CHECK (typeof(finalized_at) = 'integer' AND finalized_at >= 0),
        state                   TEXT NOT NULL DEFAULT 'pending'
            CHECK (
                typeof(state) = 'text'
                AND state IN ('pending', 'claimed', 'routing', 'completed')
            ),
        claim_token             TEXT
            CHECK (
                claim_token IS NULL
                OR (
                    typeof(claim_token) = 'text'
                    AND length(trim(claim_token)) > 0
                    AND length(CAST(claim_token AS BLOB)) <= 512
                )
            ),
        claim_deadline_unix_ms  INTEGER
            CHECK (
                claim_deadline_unix_ms IS NULL
                OR (
                    typeof(claim_deadline_unix_ms) = 'integer'
                    AND claim_deadline_unix_ms >= 0
                )
            ),
        version                 INTEGER NOT NULL DEFAULT 0
            CHECK (typeof(version) = 'integer' AND version >= 0),
        staged_status_json      TEXT
            CHECK (
                staged_status_json IS NULL
                OR (
                    typeof(staged_status_json) = 'text'
                    AND length(trim(staged_status_json)) > 0
                    AND length(CAST(staged_status_json AS BLOB)) <= 65536
                )
            ),
        last_error              TEXT
            CHECK (
                last_error IS NULL
                OR (
                    typeof(last_error) = 'text'
                    AND length(CAST(last_error AS BLOB)) <= 2048
                )
            ),
        CHECK (
            (state IN ('claimed', 'routing') AND claim_token IS NOT NULL AND claim_deadline_unix_ms IS NOT NULL)
            OR (state NOT IN ('claimed', 'routing') AND claim_token IS NULL AND claim_deadline_unix_ms IS NULL)
        ),
        CHECK (
            (state = 'routing' AND staged_status_json IS NOT NULL)
            OR (state != 'routing' AND staged_status_json IS NULL)
        )
    );
    CREATE INDEX IF NOT EXISTS idx_chio_settlement_observer_outbox_pending
        ON chio_settlement_observer_outbox(state, finalized_at, receipt_id);

    CREATE TRIGGER IF NOT EXISTS chio_settlement_observer_outbox_validate_update
    BEFORE UPDATE ON chio_settlement_observer_outbox
    WHEN NEW.receipt_id != OLD.receipt_id
      OR NEW.finalized_at != OLD.finalized_at
      OR OLD.state = 'completed'
      OR NEW.version != OLD.version + 1
      OR (OLD.state = 'pending' AND NEW.state != 'claimed')
      OR (OLD.state = 'claimed' AND NEW.state NOT IN ('pending', 'claimed', 'routing'))
      OR (OLD.state = 'routing' AND NEW.state NOT IN ('routing', 'completed'))
      OR (
          OLD.state = 'routing'
          AND NEW.state = 'routing'
          AND NEW.staged_status_json IS NOT OLD.staged_status_json
      )
    BEGIN
        SELECT RAISE(ABORT, 'invalid settlement-observer outbox transition');
    END;

    CREATE TRIGGER IF NOT EXISTS chio_settlement_observer_outbox_reject_unfinished_delete
    BEFORE DELETE ON chio_settlement_observer_outbox
    WHEN OLD.state != 'completed'
    BEGIN
        SELECT RAISE(ABORT, 'unfinished settlement-observer outbox rows are durable');
    END;
"#;

pub(crate) const SETTLEMENT_OBSERVER_OUTBOX_V2_TABLE_SQL: &str = r#"
    CREATE TABLE chio_settlement_observer_outbox (
        receipt_id TEXT NOT NULL PRIMARY KEY,
        finalized_at INTEGER NOT NULL CHECK (finalized_at >= 0),
        state TEXT NOT NULL DEFAULT 'pending'
            CHECK (state IN ('pending', 'claimed', 'routing', 'completed')),
        claim_token TEXT,
        claim_deadline_unix_ms INTEGER,
        version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
        staged_status_json TEXT,
        last_error TEXT,
        CHECK (
            (state IN ('claimed', 'routing') AND claim_token IS NOT NULL AND claim_deadline_unix_ms IS NOT NULL)
            OR (state NOT IN ('claimed', 'routing') AND claim_token IS NULL AND claim_deadline_unix_ms IS NULL)
        ),
        CHECK (
            (state = 'routing' AND staged_status_json IS NOT NULL)
            OR (state != 'routing' AND staged_status_json IS NULL)
        )
    )
"#;

const SETTLEMENT_OBSERVER_OUTBOX_V3_TABLE_SQL: &str = r#"
    CREATE TABLE chio_settlement_observer_outbox (
        receipt_id TEXT NOT NULL PRIMARY KEY
            CHECK (
                typeof(receipt_id) = 'text'
                AND length(trim(receipt_id)) > 0
                AND length(CAST(receipt_id AS BLOB)) <= 512
            ),
        finalized_at INTEGER NOT NULL
            CHECK (typeof(finalized_at) = 'integer' AND finalized_at >= 0),
        state TEXT NOT NULL DEFAULT 'pending'
            CHECK (
                typeof(state) = 'text'
                AND state IN ('pending', 'claimed', 'routing', 'completed')
            ),
        claim_token TEXT
            CHECK (
                claim_token IS NULL
                OR (
                    typeof(claim_token) = 'text'
                    AND length(trim(claim_token)) > 0
                    AND length(CAST(claim_token AS BLOB)) <= 512
                )
            ),
        claim_deadline_unix_ms INTEGER
            CHECK (
                claim_deadline_unix_ms IS NULL
                OR (
                    typeof(claim_deadline_unix_ms) = 'integer'
                    AND claim_deadline_unix_ms >= 0
                )
            ),
        version INTEGER NOT NULL DEFAULT 0
            CHECK (typeof(version) = 'integer' AND version >= 0),
        staged_status_json TEXT
            CHECK (
                staged_status_json IS NULL
                OR (
                    typeof(staged_status_json) = 'text'
                    AND length(trim(staged_status_json)) > 0
                    AND length(CAST(staged_status_json AS BLOB)) <= 65536
                )
            ),
        last_error TEXT
            CHECK (
                last_error IS NULL
                OR (
                    typeof(last_error) = 'text'
                    AND length(CAST(last_error AS BLOB)) <= 2048
                )
            ),
        CHECK (
            (state IN ('claimed', 'routing') AND claim_token IS NOT NULL AND claim_deadline_unix_ms IS NOT NULL)
            OR (state NOT IN ('claimed', 'routing') AND claim_token IS NULL AND claim_deadline_unix_ms IS NULL)
        ),
        CHECK (
            (state = 'routing' AND staged_status_json IS NOT NULL)
            OR (state != 'routing' AND staged_status_json IS NULL)
        )
    )
"#;

pub(in crate::receipt_store) fn validate_settlement_observer_outbox_schema(
    connection: &Connection,
    expect_v2_table: bool,
) -> Result<(), ReceiptStoreError> {
    let columns = connection
        .prepare("PRAGMA table_info(chio_settlement_observer_outbox)")?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_columns = vec![
        ("receipt_id".to_string(), "TEXT".to_string(), 1, None, 1),
        (
            "finalized_at".to_string(),
            "INTEGER".to_string(),
            1,
            None,
            0,
        ),
        (
            "state".to_string(),
            "TEXT".to_string(),
            1,
            Some("'pending'".to_string()),
            0,
        ),
        ("claim_token".to_string(), "TEXT".to_string(), 0, None, 0),
        (
            "claim_deadline_unix_ms".to_string(),
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
        (
            "staged_status_json".to_string(),
            "TEXT".to_string(),
            0,
            None,
            0,
        ),
        ("last_error".to_string(), "TEXT".to_string(), 0, None, 0),
    ];
    if columns != expected_columns {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox columns, defaults, nullability, or primary key are invalid"
                .to_string(),
        ));
    }

    let table_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'chio_settlement_observer_outbox'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "settlement-observer outbox table is missing".to_string(),
            )
        })?;
    let expected_table = if expect_v2_table {
        normalize_index_schema_sql(SETTLEMENT_OBSERVER_OUTBOX_V2_TABLE_SQL)
    } else {
        let expected_table = normalize_index_schema_sql(
            r#"
        CREATE TABLE chio_settlement_observer_outbox (
            receipt_id TEXT NOT NULL PRIMARY KEY
                CHECK (
                    typeof(receipt_id) = 'text'
                    AND length(trim(receipt_id)) > 0
                    AND length(CAST(receipt_id AS BLOB)) <= 512
                ),
            finalized_at INTEGER NOT NULL
                CHECK (typeof(finalized_at) = 'integer' AND finalized_at >= 0),
            state TEXT NOT NULL DEFAULT 'pending'
                CHECK (
                    typeof(state) = 'text'
                    AND state IN ('pending', 'claimed', 'routing', 'completed')
                ),
            claim_token TEXT
                CHECK (
                    claim_token IS NULL
                    OR (
                        typeof(claim_token) = 'text'
                        AND length(trim(claim_token)) > 0
                        AND length(CAST(claim_token AS BLOB)) <= 512
                    )
                ),
            claim_deadline_unix_ms INTEGER
                CHECK (
                    claim_deadline_unix_ms IS NULL
                    OR (
                        typeof(claim_deadline_unix_ms) = 'integer'
                        AND claim_deadline_unix_ms >= 0
                    )
                ),
            version INTEGER NOT NULL DEFAULT 0
                CHECK (typeof(version) = 'integer' AND version >= 0),
            staged_status_json TEXT
                CHECK (
                    staged_status_json IS NULL
                    OR (
                        typeof(staged_status_json) = 'text'
                        AND length(trim(staged_status_json)) > 0
                        AND length(CAST(staged_status_json AS BLOB)) <= 65536
                    )
                ),
            last_error TEXT
                CHECK (
                    last_error IS NULL
                    OR (
                        typeof(last_error) = 'text'
                        AND length(CAST(last_error AS BLOB)) <= 2048
                    )
                ),
            CHECK (
                (state IN ('claimed', 'routing') AND claim_token IS NOT NULL AND claim_deadline_unix_ms IS NOT NULL)
                OR (state NOT IN ('claimed', 'routing') AND claim_token IS NULL AND claim_deadline_unix_ms IS NULL)
            ),
            CHECK (
                (state = 'routing' AND staged_status_json IS NOT NULL)
                OR (state != 'routing' AND staged_status_json IS NULL)
            )
        )
            "#,
        );
        debug_assert_eq!(
            expected_table,
            normalize_index_schema_sql(SETTLEMENT_OBSERVER_OUTBOX_V3_TABLE_SQL)
        );
        expected_table
    };
    if normalize_index_schema_sql(&table_sql) != expected_table {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox table constraints are invalid".to_string(),
        ));
    }

    let mut foreign_key_statement =
        connection.prepare("PRAGMA foreign_key_list('chio_settlement_observer_outbox')")?;
    let mut foreign_key_rows = foreign_key_statement.query([])?;
    if foreign_key_rows.next()?.is_some() {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox must remain readable across live-receipt archival"
                .to_string(),
        ));
    }

    let pending_index_columns = connection
        .prepare("PRAGMA index_info(idx_chio_settlement_observer_outbox_pending)")?
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if pending_index_columns
        != vec![
            "state".to_string(),
            "finalized_at".to_string(),
            "receipt_id".to_string(),
        ]
    {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox pending index is missing or invalid".to_string(),
        ));
    }
    let pending_index_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_chio_settlement_observer_outbox_pending'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "settlement-observer outbox pending index is missing".to_string(),
            )
        })?;
    let expected_pending_index = normalize_index_schema_sql(
        "CREATE INDEX idx_chio_settlement_observer_outbox_pending ON chio_settlement_observer_outbox(state, finalized_at, receipt_id)",
    );
    if normalize_index_schema_sql(&pending_index_sql) != expected_pending_index {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox pending index definition is invalid".to_string(),
        ));
    }

    let triggers = connection
        .prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'chio_settlement_observer_outbox' ORDER BY name ASC",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                normalize_index_schema_sql(&row.get::<_, String>(1)?),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_triggers = [
        (
            "chio_settlement_observer_outbox_reject_unfinished_delete",
            normalize_index_schema_sql(
                r#"
                CREATE TRIGGER chio_settlement_observer_outbox_reject_unfinished_delete
                BEFORE DELETE ON chio_settlement_observer_outbox
                WHEN OLD.state != 'completed'
                BEGIN
                    SELECT RAISE(ABORT, 'unfinished settlement-observer outbox rows are durable');
                END
                "#,
            ),
        ),
        (
            "chio_settlement_observer_outbox_validate_update",
            normalize_index_schema_sql(
                r#"
                CREATE TRIGGER chio_settlement_observer_outbox_validate_update
                BEFORE UPDATE ON chio_settlement_observer_outbox
                WHEN NEW.receipt_id != OLD.receipt_id
                  OR NEW.finalized_at != OLD.finalized_at
                  OR OLD.state = 'completed'
                  OR NEW.version != OLD.version + 1
                  OR (OLD.state = 'pending' AND NEW.state != 'claimed')
                  OR (OLD.state = 'claimed' AND NEW.state NOT IN ('pending', 'claimed', 'routing'))
                  OR (OLD.state = 'routing' AND NEW.state NOT IN ('routing', 'completed'))
                  OR (
                      OLD.state = 'routing'
                      AND NEW.state = 'routing'
                      AND NEW.staged_status_json IS NOT OLD.staged_status_json
                  )
                BEGIN
                    SELECT RAISE(ABORT, 'invalid settlement-observer outbox transition');
                END
                "#,
            ),
        ),
    ];
    if triggers.len() != expected_triggers.len()
        || triggers.iter().zip(expected_triggers.iter()).any(
            |((actual_name, actual_sql), (expected_name, expected_sql))| {
                actual_name != expected_name || actual_sql != expected_sql
            },
        )
    {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox integrity triggers are missing or invalid".to_string(),
        ));
    }
    let has_invalid_row: i64 = connection.query_row(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM chio_settlement_observer_outbox
            WHERE typeof(receipt_id) != 'text'
               OR length(trim(receipt_id)) = 0
               OR length(CAST(receipt_id AS BLOB)) > 512
               OR typeof(finalized_at) != 'integer'
               OR finalized_at < 0
               OR typeof(state) != 'text'
               OR state NOT IN ('pending', 'claimed', 'routing', 'completed')
               OR (
                   claim_token IS NOT NULL
                   AND (
                       typeof(claim_token) != 'text'
                       OR length(trim(claim_token)) = 0
                       OR length(CAST(claim_token AS BLOB)) > 512
                   )
               )
               OR (
                   claim_deadline_unix_ms IS NOT NULL
                   AND (
                       typeof(claim_deadline_unix_ms) != 'integer'
                       OR claim_deadline_unix_ms < 0
                   )
               )
               OR typeof(version) != 'integer'
               OR version < 0
               OR (
                   staged_status_json IS NOT NULL
                   AND (
                       typeof(staged_status_json) != 'text'
                       OR length(trim(staged_status_json)) = 0
                       OR length(CAST(staged_status_json AS BLOB)) > 65536
                   )
               )
               OR (
                   last_error IS NOT NULL
                   AND (
                       typeof(last_error) != 'text'
                       OR length(CAST(last_error AS BLOB)) > 2048
                   )
               )
               OR (
                   state IN ('claimed', 'routing')
                   AND (claim_token IS NULL OR claim_deadline_unix_ms IS NULL)
               )
               OR (
                   state NOT IN ('claimed', 'routing')
                   AND (claim_token IS NOT NULL OR claim_deadline_unix_ms IS NOT NULL)
               )
               OR (state = 'routing' AND staged_status_json IS NULL)
               OR (state != 'routing' AND staged_status_json IS NOT NULL)
            LIMIT 1
        )
        "#,
        [],
        |row| row.get(0),
    )?;
    if has_invalid_row != 0 {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox contains an invalid persisted row".to_string(),
        ));
    }
    Ok(())
}

fn migrate_settlement_observer_outbox_v2_to_v3(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), ReceiptStoreError> {
    validate_settlement_observer_outbox_schema(transaction, true)?;
    let source_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM chio_settlement_observer_outbox",
        [],
        |row| row.get(0),
    )?;
    transaction.execute_batch(
        r#"
        DROP TRIGGER chio_settlement_observer_outbox_validate_update;
        DROP TRIGGER chio_settlement_observer_outbox_reject_unfinished_delete;
        DROP INDEX idx_chio_settlement_observer_outbox_pending;
        ALTER TABLE chio_settlement_observer_outbox
            RENAME TO chio_settlement_observer_outbox_v2;
        "#,
    )?;
    transaction.execute_batch(SETTLEMENT_OBSERVER_OUTBOX_DDL)?;
    transaction.execute(
        r#"
        INSERT INTO chio_settlement_observer_outbox (
            receipt_id,
            finalized_at,
            state,
            claim_token,
            claim_deadline_unix_ms,
            version,
            staged_status_json,
            last_error
        )
        SELECT
            receipt_id,
            finalized_at,
            state,
            claim_token,
            claim_deadline_unix_ms,
            version,
            staged_status_json,
            last_error
        FROM chio_settlement_observer_outbox_v2
        ORDER BY finalized_at, receipt_id
        "#,
        [],
    )?;
    let migrated_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM chio_settlement_observer_outbox",
        [],
        |row| row.get(0),
    )?;
    if migrated_count != source_count {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox v3 migration changed the row count".to_string(),
        ));
    }
    let rows_diverged: i64 = transaction.query_row(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM (
                SELECT
                    receipt_id,
                    finalized_at,
                    state,
                    claim_token,
                    claim_deadline_unix_ms,
                    version,
                    staged_status_json,
                    last_error
                FROM chio_settlement_observer_outbox_v2
                EXCEPT
                SELECT
                    receipt_id,
                    finalized_at,
                    state,
                    claim_token,
                    claim_deadline_unix_ms,
                    version,
                    staged_status_json,
                    last_error
                FROM chio_settlement_observer_outbox
            )
            UNION ALL
            SELECT 1
            FROM (
                SELECT
                    receipt_id,
                    finalized_at,
                    state,
                    claim_token,
                    claim_deadline_unix_ms,
                    version,
                    staged_status_json,
                    last_error
                FROM chio_settlement_observer_outbox
                EXCEPT
                SELECT
                    receipt_id,
                    finalized_at,
                    state,
                    claim_token,
                    claim_deadline_unix_ms,
                    version,
                    staged_status_json,
                    last_error
                FROM chio_settlement_observer_outbox_v2
            )
            LIMIT 1
        )
        "#,
        [],
        |row| row.get(0),
    )?;
    if rows_diverged != 0 {
        return Err(ReceiptStoreError::Conflict(
            "settlement-observer outbox v3 migration changed persisted values".to_string(),
        ));
    }
    transaction.execute_batch("DROP TABLE chio_settlement_observer_outbox_v2;")?;
    validate_settlement_observer_outbox_schema(transaction, false)
}

fn upgrade_receipt_store_schema(
    connection: &mut Connection,
    on_disk_version: i32,
) -> Result<(), ReceiptStoreError> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute_batch(DISPATCH_INTENT_JOURNAL_DDL)?;
    match on_disk_version {
        0 | 1 => transaction.execute_batch(SETTLEMENT_OBSERVER_OUTBOX_DDL)?,
        2 => {
            if table_exists(&transaction, "chio_settlement_observer_outbox")? {
                migrate_settlement_observer_outbox_v2_to_v3(&transaction)?;
            } else {
                transaction.execute_batch(SETTLEMENT_OBSERVER_OUTBOX_DDL)?;
            }
        }
        3 => {
            if !table_exists(&transaction, "chio_settlement_observer_outbox")? {
                transaction.execute_batch(SETTLEMENT_OBSERVER_OUTBOX_DDL)?;
            }
        }
        _ => {
            return Err(ReceiptStoreError::Conflict(format!(
                "unsupported receipt schema upgrade source revision {on_disk_version}"
            )));
        }
    }
    validate_settlement_observer_outbox_schema(&transaction, false)?;
    crate::receipt_store::support::drop_transparency_projection_guards(&transaction)?;
    crate::receipt_store::support::migrate_receipt_cost_projection(&transaction)?;
    crate::receipt_store::support::ensure_transparency_projection_guards(&transaction)?;
    crate::receipt_store::support::verify_receipt_cost_projection(&transaction)?;
    crate::stamp_schema_version(
        &transaction,
        RECEIPT_STORE_SCHEMA_KEY,
        RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
    transaction.commit()?;
    Ok(())
}

fn configure_sqlite_connection(
    connection: &mut Connection,
    max_page_count: Option<u32>,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
        PRAGMA auto_vacuum = INCREMENTAL;
        "#,
    )?;
    assert_sqlite_durability_pragmas(connection)?;
    if let Some(max_page_count) = max_page_count {
        connection.pragma_update(None, "max_page_count", max_page_count)?;
        let effective: i64 = connection.query_row("PRAGMA max_page_count", [], |row| row.get(0))?;
        if effective != i64::from(max_page_count) {
            return Err(ReceiptStoreError::Conflict(format!(
                "sqlite max_page_count requested {max_page_count} but effective limit is {effective}"
            )));
        }
    }
    Ok(())
}

fn assert_sqlite_durability_pragmas(connection: &Connection) -> Result<(), ReceiptStoreError> {
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store journal_mode must be WAL, got {journal_mode}"
        )));
    }

    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    if synchronous != 2 {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store synchronous must be FULL, got {synchronous}"
        )));
    }

    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if busy_timeout < 5000 {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store busy_timeout must be at least 5000ms, got {busy_timeout}"
        )));
    }

    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store foreign_keys must be ON, got {foreign_keys}"
        )));
    }

    Ok(())
}

fn ensure_indexed_security_evidence_schema(
    connection: &mut Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS chio_security_evidence_index (
            evidence_id TEXT NOT NULL PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE
                REFERENCES chio_tool_receipts(receipt_id) ON DELETE RESTRICT
        );

        CREATE TRIGGER IF NOT EXISTS chio_security_evidence_index_reject_update
        BEFORE UPDATE ON chio_security_evidence_index
        BEGIN
            SELECT RAISE(ABORT, 'security evidence index entries are immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS chio_security_evidence_index_reject_delete
        BEFORE DELETE ON chio_security_evidence_index
        BEGIN
            SELECT RAISE(ABORT, 'security evidence index entries are immutable');
        END;
        "#,
    )?;
    validate_indexed_security_evidence_schema(connection)
}

pub(in crate::receipt_store) fn validate_indexed_security_evidence_schema(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut columns_statement =
        connection.prepare("PRAGMA table_info(chio_security_evidence_index)")?;
    let columns = columns_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_columns = vec![
        ("evidence_id".to_string(), "TEXT".to_string(), 1, 1),
        ("receipt_id".to_string(), "TEXT".to_string(), 1, 0),
    ];
    if columns != expected_columns {
        return Err(ReceiptStoreError::Conflict(
            "security evidence index columns, types, nullability, or primary key are invalid"
                .to_string(),
        ));
    }

    let mut foreign_key_statement =
        connection.prepare("PRAGMA foreign_key_list(chio_security_evidence_index)")?;
    let foreign_keys = foreign_key_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if foreign_keys
        != vec![(
            "chio_tool_receipts".to_string(),
            "receipt_id".to_string(),
            "receipt_id".to_string(),
            "NO ACTION".to_string(),
            "RESTRICT".to_string(),
        )]
    {
        return Err(ReceiptStoreError::Conflict(
            "security evidence index receipt foreign key is invalid".to_string(),
        ));
    }

    let mut index_statement =
        connection.prepare("PRAGMA index_list(chio_security_evidence_index)")?;
    let indexes = index_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut receipt_id_is_unique = false;
    for (index_name, is_unique, is_partial) in indexes {
        if is_unique != 1 || is_partial != 0 {
            continue;
        }
        let escaped_name = index_name.replace('"', "\"\"");
        let mut indexed_columns_statement =
            connection.prepare(&format!("PRAGMA index_info(\"{escaped_name}\")"))?;
        let indexed_columns = indexed_columns_statement
            .query_map([], |row| row.get::<_, String>(2))?
            .collect::<Result<Vec<_>, _>>()?;
        if indexed_columns.len() == 1 && indexed_columns[0] == "receipt_id" {
            receipt_id_is_unique = true;
        }
    }
    if !receipt_id_is_unique {
        return Err(ReceiptStoreError::Conflict(
            "security evidence index receipt_id must be uniquely constrained".to_string(),
        ));
    }

    let expected_triggers = [
        (
            "chio_security_evidence_index_reject_delete",
            "create trigger chio_security_evidence_index_reject_delete before delete on chio_security_evidence_index begin select raise(abort, 'security evidence index entries are immutable'); end",
        ),
        (
            "chio_security_evidence_index_reject_update",
            "create trigger chio_security_evidence_index_reject_update before update on chio_security_evidence_index begin select raise(abort, 'security evidence index entries are immutable'); end",
        ),
    ];
    let mut trigger_statement = connection.prepare(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'chio_security_evidence_index' ORDER BY name ASC",
    )?;
    let triggers = trigger_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if triggers.len() != expected_triggers.len()
        || triggers.iter().zip(expected_triggers).any(
            |((actual_name, actual_sql), (expected_name, expected_sql))| {
                actual_name != expected_name
                    || normalize_index_schema_sql(actual_sql) != expected_sql
            },
        )
    {
        return Err(ReceiptStoreError::Conflict(
            "security evidence index immutability triggers are missing or invalid".to_string(),
        ));
    }
    Ok(())
}

fn normalize_index_schema_sql(sql: &str) -> String {
    sql.split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
        .replace(" if not exists", "")
        .trim_end_matches(';')
        .to_string()
}

fn ensure_capability_lineage_provenance_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    for table in ["capability_lineage", "federated_share_capability_lineage"] {
        for (column, definition) in [
            ("signed_capability_json", "TEXT"),
            ("federated_parent_capability_id", "TEXT"),
            (
                "provenance",
                "TEXT NOT NULL DEFAULT 'legacy_projection' CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection'))",
            ),
        ] {
            let mut statement =
                connection.prepare(&format!("PRAGMA table_info({table})"))?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?;
            if !columns.iter().any(|existing| existing == column) {
                connection.execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
        connection.execute(
            &format!(
                "UPDATE {table} SET provenance = 'signed_token' \
                 WHERE provenance = 'legacy_projection' \
                   AND signed_capability_json IS NOT NULL"
            ),
            [],
        )?;
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_capability_lineage_federated_parent \
         ON capability_lineage(federated_parent_capability_id)",
        [],
    )?;
    Ok(())
}
