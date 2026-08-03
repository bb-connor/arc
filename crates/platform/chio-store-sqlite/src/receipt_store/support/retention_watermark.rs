use super::*;

const RECEIPT_RETENTION_WATERMARK_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS receipt_retention_watermark (
    archived_through_entry_seq INTEGER NOT NULL,
    archived_through_timestamp INTEGER NOT NULL,
    archive_path               TEXT NOT NULL,
    archive_sha256             TEXT NOT NULL,
    archive_content_sha256     TEXT NOT NULL,
    rotated_at                 INTEGER NOT NULL,
    CHECK (archived_through_entry_seq >= 0),
    CHECK (length(archive_sha256) = 64 AND archive_sha256 NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(archive_content_sha256) = 64 AND archive_content_sha256 NOT GLOB '*[^0-9a-f]*')
);
"#;

const RECEIPT_RETENTION_WATERMARK_TRIGGERS_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS receipt_retention_watermark_reject_update
BEFORE UPDATE ON receipt_retention_watermark
BEGIN
    SELECT RAISE(ABORT, 'retention watermark ledger is append-only');
END;

CREATE TRIGGER IF NOT EXISTS receipt_retention_watermark_reject_delete
BEFORE DELETE ON receipt_retention_watermark
BEGIN
    SELECT RAISE(ABORT, 'retention watermark ledger is append-only');
END;

CREATE TRIGGER IF NOT EXISTS receipt_retention_watermark_reject_regression
BEFORE INSERT ON receipt_retention_watermark
WHEN NEW.archived_through_entry_seq
    <= (SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark)
BEGIN
    SELECT RAISE(ABORT, 'retention watermark must increase monotonically');
END;
"#;

const RECEIPT_RETENTION_TOMBSTONES_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS receipt_retention_tombstones (
    receipt_id                 TEXT PRIMARY KEY,
    receipt_kind               TEXT NOT NULL,
    archived_through_entry_seq INTEGER NOT NULL,
    tombstoned_at              INTEGER NOT NULL
);
"#;

const RECEIPT_RETENTION_TOMBSTONES_TRIGGERS_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS receipt_retention_tombstones_reject_update
BEFORE UPDATE ON receipt_retention_tombstones
BEGIN
    SELECT RAISE(ABORT, 'receipt retention tombstones are append-only');
END;

CREATE TRIGGER IF NOT EXISTS receipt_retention_tombstones_reject_delete
BEFORE DELETE ON receipt_retention_tombstones
BEGIN
    SELECT RAISE(ABORT, 'receipt retention tombstones are append-only');
END;

CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_archived_reuse
BEFORE INSERT ON chio_tool_receipts
WHEN EXISTS (SELECT 1 FROM receipt_retention_tombstones WHERE receipt_id = NEW.receipt_id)
BEGIN
    SELECT RAISE(ABORT, 'receipt_id was archived by retention and cannot be re-appended');
END;

CREATE TRIGGER IF NOT EXISTS chio_child_receipts_reject_archived_reuse
BEFORE INSERT ON chio_child_receipts
WHEN EXISTS (SELECT 1 FROM receipt_retention_tombstones WHERE receipt_id = NEW.receipt_id)
BEGIN
    SELECT RAISE(ABORT, 'receipt_id was archived by retention and cannot be re-appended');
END;
"#;

const RECEIPT_RETENTION_CAPABILITY_FREEZES_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS receipt_retention_capability_freezes (
    capability_id                 TEXT PRIMARY KEY,
    archived_through_entry_seq    INTEGER NOT NULL,
    frozen_at                     INTEGER NOT NULL,
    CHECK (archived_through_entry_seq > 0),
    CHECK (frozen_at >= 0)
);
"#;

const RECEIPT_RETENTION_CAPABILITY_FREEZES_TRIGGERS_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS receipt_retention_capability_freezes_reject_update
BEFORE UPDATE ON receipt_retention_capability_freezes
BEGIN
    SELECT RAISE(ABORT, 'retention capability freezes are append-only');
END;

CREATE TRIGGER IF NOT EXISTS receipt_retention_capability_freezes_reject_delete
BEFORE DELETE ON receipt_retention_capability_freezes
BEGIN
    SELECT RAISE(ABORT, 'retention capability freezes are append-only');
END;

CREATE TRIGGER IF NOT EXISTS capability_lineage_reject_archived_insert
BEFORE INSERT ON capability_lineage
WHEN EXISTS (
    SELECT 1 FROM receipt_retention_capability_freezes
    WHERE capability_id = NEW.capability_id
)
AND NOT EXISTS (
    SELECT 1 FROM capability_lineage AS existing
    WHERE existing.capability_id IS NEW.capability_id
      AND existing.subject_key IS NEW.subject_key
      AND existing.issuer_key IS NEW.issuer_key
      AND existing.issued_at IS NEW.issued_at
      AND existing.expires_at IS NEW.expires_at
      AND existing.grants_json IS NEW.grants_json
      AND existing.delegation_depth IS NEW.delegation_depth
      AND existing.parent_capability_id IS NEW.parent_capability_id
)
BEGIN
    SELECT RAISE(ABORT, 'capability lineage is frozen after archival');
END;

CREATE TRIGGER IF NOT EXISTS capability_lineage_reject_archived_update
BEFORE UPDATE ON capability_lineage
WHEN (
    EXISTS (
        SELECT 1 FROM receipt_retention_capability_freezes
        WHERE capability_id = OLD.capability_id
    )
    OR EXISTS (
        SELECT 1 FROM receipt_retention_capability_freezes
        WHERE capability_id = NEW.capability_id
    )
)
AND NOT (
    OLD.capability_id IS NEW.capability_id
    AND OLD.subject_key IS NEW.subject_key
    AND OLD.issuer_key IS NEW.issuer_key
    AND OLD.issued_at IS NEW.issued_at
    AND OLD.expires_at IS NEW.expires_at
    AND OLD.grants_json IS NEW.grants_json
    AND OLD.delegation_depth IS NEW.delegation_depth
    AND OLD.parent_capability_id IS NEW.parent_capability_id
)
BEGIN
    SELECT RAISE(ABORT, 'archived capability lineage is immutable');
END;

CREATE TRIGGER IF NOT EXISTS capability_lineage_reject_archived_delete
BEFORE DELETE ON capability_lineage
WHEN EXISTS (
    SELECT 1 FROM receipt_retention_capability_freezes
    WHERE capability_id = OLD.capability_id
)
BEGIN
    SELECT RAISE(ABORT, 'archived capability lineage is immutable');
END;
"#;

const RETENTION_ARCHIVE_IDENTITY_TABLE_SQL_MAIN: &str = r#"
CREATE TABLE IF NOT EXISTS chio_retention_archive_identity (
    identity_slot     INTEGER PRIMARY KEY CHECK (identity_slot = 1),
    nonce             TEXT NOT NULL UNIQUE,
    commitment_sha256 TEXT NOT NULL UNIQUE
);
"#;

const RETENTION_ARCHIVE_IDENTITY_DOMAIN: &str = "chio.retention-archive.identity.v1";

/// Append-only ledger of archival high-water marks. The effective watermark is
/// `MAX(archived_through_entry_seq)`; a rotation that would lower it is rejected
/// (`RetentionWatermarkRegression`). Created on every open (new and existing).
///
/// The ledger is SECURITY-LOAD-BEARING: watermark-aware chain verification
/// trusts `W = MAX(archived_through_entry_seq)` to SKIP the live
/// Merkle rebuild for every checkpoint with `batch_end_seq <= W`. A forged or
/// inflated `W` written by a raw `INSERT`/`UPDATE` would therefore skip
/// claim-log validation chain-wide. The three triggers below make the ledger's
/// append-only, strictly-monotonic guarantee DB-enforced, mirroring the
/// `reject_update`/`reject_delete` immutability guards used for the other
/// append-only projection tables (`TRANSPARENCY_PROJECTION_GUARDS_SQL`), so `W`
/// cannot be regressed or forged even by a writer that bypasses
/// `insert_receipt_retention_watermark`.
pub(crate) fn ensure_receipt_retention_watermark_table(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(RECEIPT_RETENTION_WATERMARK_TABLE_SQL)?;
    connection.execute_batch(RECEIPT_RETENTION_WATERMARK_TRIGGERS_SQL)?;
    validate_receipt_retention_watermark_schema(connection)
}

pub(crate) fn validate_receipt_retention_watermark_schema(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    validate_retention_table_contract(
        connection,
        "receipt_retention_watermark",
        RECEIPT_RETENTION_WATERMARK_TABLE_SQL,
    )?;
    validate_retention_triggers(
        connection,
        &[
            (
                "receipt_retention_watermark_reject_update",
                "CREATE TRIGGER receipt_retention_watermark_reject_update \
                 BEFORE UPDATE ON receipt_retention_watermark \
                 BEGIN SELECT RAISE(ABORT, 'retention watermark ledger is append-only'); END",
            ),
            (
                "receipt_retention_watermark_reject_delete",
                "CREATE TRIGGER receipt_retention_watermark_reject_delete \
                 BEFORE DELETE ON receipt_retention_watermark \
                 BEGIN SELECT RAISE(ABORT, 'retention watermark ledger is append-only'); END",
            ),
            (
                "receipt_retention_watermark_reject_regression",
                "CREATE TRIGGER receipt_retention_watermark_reject_regression \
                 BEFORE INSERT ON receipt_retention_watermark \
                 WHEN NEW.archived_through_entry_seq \
                 <= (SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark) \
                 BEGIN SELECT RAISE(ABORT, 'retention watermark must increase monotonically'); END",
            ),
        ],
    )?;
    Ok(())
}

/// Tombstones for receipt ids removed from the live store by a retention
/// rotation, plus the DB triggers that keep an archived id from being reused.
///
/// A rotation deletes the live receipt rows (and their `UNIQUE(receipt_id)`
/// sentinel) once they are co-archived. Without a record of what left, the
/// append path's `ON CONFLICT(receipt_id) DO NOTHING` sees an archived id as
/// brand new and inserts a second live receipt/claim-log entry for it, so a
/// retry or a forged append overlaps the archived and live histories and makes a
/// point lookup by receipt id ambiguous. The tombstone table preserves the
/// uniqueness sentinel across archival (one small row per archived id, not the
/// full receipt), and the two `BEFORE INSERT` triggers RAISE(ABORT) any source
/// insert whose id is tombstoned, DB-enforced like the immutability guards so a
/// writer that bypasses the Rust append path still cannot resurrect an archived
/// id. Created on every writable open (new and existing).
///
/// The tombstone rows are themselves append-only. Once a rotation deletes the
/// live receipt (and its `UNIQUE(receipt_id)` sentinel), the tombstone is the
/// only DB-level record that the id was archived, so it carries the same
/// immutability guarantee as the append-only projection tables: two
/// `BEFORE UPDATE`/`BEFORE DELETE` triggers RAISE(ABORT) so a writer that
/// bypasses the Rust path cannot delete or rewrite a tombstone and then
/// re-insert the archived id, recreating the archived/live ambiguity these
/// triggers exist to prevent.
pub(crate) fn ensure_receipt_retention_tombstones(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(RECEIPT_RETENTION_TOMBSTONES_TABLE_SQL)?;
    connection.execute_batch(RECEIPT_RETENTION_TOMBSTONES_TRIGGERS_SQL)?;
    connection.execute_batch(RECEIPT_RETENTION_CAPABILITY_FREEZES_TABLE_SQL)?;
    connection.execute_batch(RECEIPT_RETENTION_CAPABILITY_FREEZES_TRIGGERS_SQL)?;
    validate_receipt_retention_tombstones_schema(connection)
}

pub(crate) fn validate_receipt_retention_tombstones_schema(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    validate_retention_table_contract(
        connection,
        "receipt_retention_tombstones",
        RECEIPT_RETENTION_TOMBSTONES_TABLE_SQL,
    )?;
    validate_retention_table_contract(
        connection,
        "receipt_retention_capability_freezes",
        RECEIPT_RETENTION_CAPABILITY_FREEZES_TABLE_SQL,
    )?;
    validate_retention_triggers(connection, &[
        (
            "receipt_retention_tombstones_reject_update",
            "CREATE TRIGGER receipt_retention_tombstones_reject_update \
             BEFORE UPDATE ON receipt_retention_tombstones \
             BEGIN SELECT RAISE(ABORT, 'receipt retention tombstones are append-only'); END",
        ),
        (
            "receipt_retention_tombstones_reject_delete",
            "CREATE TRIGGER receipt_retention_tombstones_reject_delete \
             BEFORE DELETE ON receipt_retention_tombstones \
             BEGIN SELECT RAISE(ABORT, 'receipt retention tombstones are append-only'); END",
        ),
        (
            "chio_tool_receipts_reject_archived_reuse",
            "CREATE TRIGGER chio_tool_receipts_reject_archived_reuse \
             BEFORE INSERT ON chio_tool_receipts \
             WHEN EXISTS (SELECT 1 FROM receipt_retention_tombstones WHERE receipt_id = NEW.receipt_id) \
             BEGIN SELECT RAISE(ABORT, 'receipt_id was archived by retention and cannot be re-appended'); END",
        ),
        (
            "chio_child_receipts_reject_archived_reuse",
            "CREATE TRIGGER chio_child_receipts_reject_archived_reuse \
             BEFORE INSERT ON chio_child_receipts \
             WHEN EXISTS (SELECT 1 FROM receipt_retention_tombstones WHERE receipt_id = NEW.receipt_id) \
             BEGIN SELECT RAISE(ABORT, 'receipt_id was archived by retention and cannot be re-appended'); END",
        ),
        (
            "receipt_retention_capability_freezes_reject_update",
            "CREATE TRIGGER receipt_retention_capability_freezes_reject_update \
             BEFORE UPDATE ON receipt_retention_capability_freezes \
             BEGIN SELECT RAISE(ABORT, 'retention capability freezes are append-only'); END",
        ),
        (
            "receipt_retention_capability_freezes_reject_delete",
            "CREATE TRIGGER receipt_retention_capability_freezes_reject_delete \
             BEFORE DELETE ON receipt_retention_capability_freezes \
             BEGIN SELECT RAISE(ABORT, 'retention capability freezes are append-only'); END",
        ),
        (
            "capability_lineage_reject_archived_insert",
            "CREATE TRIGGER capability_lineage_reject_archived_insert \
             BEFORE INSERT ON capability_lineage \
             WHEN EXISTS ( SELECT 1 FROM receipt_retention_capability_freezes \
             WHERE capability_id = NEW.capability_id ) \
             AND NOT EXISTS ( SELECT 1 FROM capability_lineage AS existing \
             WHERE existing.capability_id IS NEW.capability_id \
             AND existing.subject_key IS NEW.subject_key \
             AND existing.issuer_key IS NEW.issuer_key \
             AND existing.issued_at IS NEW.issued_at \
             AND existing.expires_at IS NEW.expires_at \
             AND existing.grants_json IS NEW.grants_json \
             AND existing.delegation_depth IS NEW.delegation_depth \
             AND existing.parent_capability_id IS NEW.parent_capability_id ) \
             BEGIN SELECT RAISE(ABORT, 'capability lineage is frozen after archival'); END",
        ),
        (
            "capability_lineage_reject_archived_update",
            "CREATE TRIGGER capability_lineage_reject_archived_update \
             BEFORE UPDATE ON capability_lineage \
             WHEN ( EXISTS ( SELECT 1 FROM receipt_retention_capability_freezes \
             WHERE capability_id = OLD.capability_id ) \
             OR EXISTS ( SELECT 1 FROM receipt_retention_capability_freezes \
             WHERE capability_id = NEW.capability_id ) ) \
             AND NOT ( OLD.capability_id IS NEW.capability_id \
             AND OLD.subject_key IS NEW.subject_key \
             AND OLD.issuer_key IS NEW.issuer_key \
             AND OLD.issued_at IS NEW.issued_at \
             AND OLD.expires_at IS NEW.expires_at \
             AND OLD.grants_json IS NEW.grants_json \
             AND OLD.delegation_depth IS NEW.delegation_depth \
             AND OLD.parent_capability_id IS NEW.parent_capability_id ) \
             BEGIN SELECT RAISE(ABORT, 'archived capability lineage is immutable'); END",
        ),
        (
            "capability_lineage_reject_archived_delete",
            "CREATE TRIGGER capability_lineage_reject_archived_delete \
             BEFORE DELETE ON capability_lineage \
             WHEN EXISTS ( SELECT 1 FROM receipt_retention_capability_freezes \
             WHERE capability_id = OLD.capability_id ) \
             BEGIN SELECT RAISE(ABORT, 'archived capability lineage is immutable'); END",
        ),
    ])?;
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
#[allow(clippy::type_complexity)]
struct RetentionTableContract {
    columns: Vec<(i64, String, String, i64, Option<String>, i64, i64)>,
    indexes: Vec<RetentionIndexContract>,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
#[allow(clippy::type_complexity)]
struct RetentionIndexContract {
    unique: i64,
    origin: String,
    partial: i64,
    columns: Vec<(i64, i64, Option<String>, i64, Option<String>, i64)>,
}

fn validate_retention_table_contract(
    connection: &rusqlite::Connection,
    table: &str,
    expected_table_sql: &str,
) -> Result<(), ReceiptStoreError> {
    let actual_sql = connection
        .query_row(
            "SELECT sql FROM main.sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(format!("receipt retention table {table} is missing"))
        })?;
    if normalize_retention_schema_sql(&actual_sql)
        != normalize_retention_schema_sql(expected_table_sql)
    {
        return Err(ReceiptStoreError::Conflict(format!(
            "receipt retention table {table} does not match the required schema"
        )));
    }

    let expected = rusqlite::Connection::open_in_memory()?;
    expected.execute_batch(expected_table_sql)?;
    let actual_contract = load_retention_table_contract(connection, table)?;
    let expected_contract = load_retention_table_contract(&expected, table)?;
    if actual_contract != expected_contract {
        return Err(ReceiptStoreError::Conflict(format!(
            "receipt retention table {table} does not match the required catalog contract"
        )));
    }
    Ok(())
}

fn load_retention_table_contract(
    connection: &rusqlite::Connection,
    table: &str,
) -> Result<RetentionTableContract, ReceiptStoreError> {
    let escaped_table = table.replace('\'', "''");
    let mut columns_statement =
        connection.prepare(&format!("PRAGMA main.table_xinfo('{escaped_table}')"))?;
    let column_rows = columns_statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;
    let mut columns = Vec::new();
    for column in column_rows {
        columns.push(column?);
    }

    let mut indexes_statement =
        connection.prepare(&format!("PRAGMA main.index_list('{escaped_table}')"))?;
    let index_rows = indexes_statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut indexes = Vec::new();
    for index in index_rows {
        let (index_name, unique, origin, partial) = index?;
        if origin != "u" && origin != "pk" {
            continue;
        }
        let escaped_index = index_name.replace('\'', "''");
        let mut index_columns_statement =
            connection.prepare(&format!("PRAGMA main.index_xinfo('{escaped_index}')"))?;
        let index_column_rows = index_columns_statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut index_columns = Vec::new();
        for column in index_column_rows {
            index_columns.push(column?);
        }
        indexes.push(RetentionIndexContract {
            unique,
            origin,
            partial,
            columns: index_columns,
        });
    }
    indexes.sort();
    Ok(RetentionTableContract { columns, indexes })
}

fn validate_retention_triggers(
    connection: &rusqlite::Connection,
    expected_triggers: &[(&str, &str)],
) -> Result<(), ReceiptStoreError> {
    for (name, expected) in expected_triggers {
        let actual = connection
            .query_row(
                "SELECT sql FROM main.sqlite_master WHERE type = 'trigger' AND name = ?1",
                params![*name],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "receipt retention integrity trigger {name} is missing"
                ))
            })?;
        if normalize_retention_schema_sql(&actual) != normalize_retention_schema_sql(expected) {
            return Err(ReceiptStoreError::Conflict(format!(
                "receipt retention integrity trigger {name} is invalid"
            )));
        }
    }
    Ok(())
}

fn normalize_retention_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" IF NOT EXISTS", "")
        .trim_end_matches(';')
        .to_string()
}

/// The current effective archival watermark, or `None` if the store has never
/// archived (no ledger rows).
///
/// Called by `insert_receipt_retention_watermark`, the claim-log backfill
/// guard (`claim_log/validation.rs`), the Rotate command, and the
/// watermark-aware chain verification.
pub(crate) fn retention_watermark(
    connection: &rusqlite::Connection,
) -> Result<Option<u64>, ReceiptStoreError> {
    // A store created before the retention migration has no watermark ledger,
    // and read-only observers (the SIEM watchdog, CLI inspectors) open such a
    // store without the writable `open()` migration that creates the table. A
    // missing table means "never archived" (None), not a hard error that would
    // deny every reader a health report. Fail-closed safe: a None watermark
    // disables the chain-verification skip exemption, so even a store whose
    // ledger was dropped out of band falls back to full verification.
    if !receipt_retention_watermark_table_exists(connection)? {
        return Ok(None);
    }
    let value: Option<i64> = connection.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |row| row.get(0),
    )?;
    match value {
        None => Ok(None),
        Some(raw) => Ok(Some(sqlite_u64(raw, "retention watermark")?)),
    }
}

/// The archive path recorded by the most recent watermark row, or `None` when
/// the store has never archived.
///
/// Retention archives a contiguous `[1, W]` prefix, and every faithful archive
/// of that prefix holds ALL of `[1, W]`. Once the first rotation deletes the
/// live rows it can never re-copy them, so a later rotation pointed at a
/// DIFFERENT target would write only the new suffix there and leave the earlier
/// prefix stranded in the original archive, splitting one logical archive across
/// two files that neither alone can satisfy. Callers use this to pin the archive
/// path across rotations. Ordered by the watermark high-water mark (with
/// `rotated_at` as a tiebreak) so the most recently advanced mark wins.
pub(crate) fn latest_watermark_archive_path(
    connection: &rusqlite::Connection,
) -> Result<Option<String>, ReceiptStoreError> {
    if !receipt_retention_watermark_table_exists(connection)? {
        return Ok(None);
    }
    let path: Option<String> = connection
        .query_row(
            "SELECT archive_path FROM receipt_retention_watermark \
             ORDER BY archived_through_entry_seq DESC, rotated_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(path)
}

pub(crate) fn latest_watermark_archive_sha256(
    connection: &rusqlite::Connection,
) -> Result<Option<String>, ReceiptStoreError> {
    if !receipt_retention_watermark_table_exists(connection)? {
        return Ok(None);
    }
    let commitment: Option<String> = connection
        .query_row(
            "SELECT archive_sha256 FROM receipt_retention_watermark \
             ORDER BY archived_through_entry_seq DESC, rotated_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(commitment) = commitment.as_deref() {
        validate_retention_sha256_hex(commitment, "archive identity commitment")?;
    }
    Ok(commitment)
}

pub(crate) fn latest_watermark_archive_content_sha256(
    connection: &rusqlite::Connection,
) -> Result<Option<String>, ReceiptStoreError> {
    if !receipt_retention_watermark_table_exists(connection)? {
        return Ok(None);
    }
    let commitment: Option<String> = connection
        .query_row(
            "SELECT archive_content_sha256 FROM receipt_retention_watermark \
             ORDER BY archived_through_entry_seq DESC, rotated_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(commitment) = commitment.as_deref() {
        validate_retention_sha256_hex(commitment, "archive content commitment")?;
    }
    Ok(commitment)
}

/// Create or validate the archive-only identity through the archive database
/// already ATTACHed to the live writer connection. This avoids reopening a
/// security-sensitive pathname for writes after the copy. The returned
/// commitment is carried across DETACH and must be revalidated read-only under
/// the final live write lock before deletion.
pub(crate) fn ensure_attached_retention_archive_identity(
    connection: &rusqlite::Connection,
    expected_commitment: Option<&str>,
) -> Result<String, ReceiptStoreError> {
    let existing = load_retention_archive_identity_in_schema(connection, "archive")?;
    let commitment = match existing {
        Some((nonce, commitment)) => {
            let derived = retention_archive_identity_commitment(&nonce);
            if derived != commitment {
                return Err(ReceiptStoreError::Conflict(
                    "retention archive identity commitment does not match its nonce".to_string(),
                ));
            }
            if let Some(expected) = expected_commitment {
                if expected != commitment {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "retention archive identity {commitment:?} differs from the committed \
                         watermark identity {expected:?}"
                    )));
                }
            }
            commitment
        }
        None => {
            if let Some(expected) = expected_commitment {
                return Err(ReceiptStoreError::Conflict(format!(
                    "retention archive is missing the identity {expected:?} committed by its \
                     watermark"
                )));
            }
            let nonce = uuid::Uuid::now_v7().to_string();
            let commitment = retention_archive_identity_commitment(&nonce);
            connection.execute(
                "INSERT INTO archive.chio_retention_archive_identity \
                     (identity_slot, nonce, commitment_sha256) VALUES (1, ?1, ?2)",
                params![nonce.as_str(), commitment.as_str()],
            )?;
            commitment
        }
    };
    validate_retention_archive_identity_in_schema(connection, "archive", &commitment)?;
    Ok(commitment)
}

pub(crate) fn validate_retention_archive_identity(
    archive: &rusqlite::Connection,
    expected_commitment: &str,
) -> Result<(), ReceiptStoreError> {
    let commitment = load_validated_retention_archive_identity(archive)?;
    if commitment != expected_commitment {
        return Err(ReceiptStoreError::Conflict(
            "retention archive identity does not match the committed watermark identity"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn load_validated_retention_archive_identity(
    archive: &rusqlite::Connection,
) -> Result<String, ReceiptStoreError> {
    validate_retention_table_contract(
        archive,
        "chio_retention_archive_identity",
        RETENTION_ARCHIVE_IDENTITY_TABLE_SQL_MAIN,
    )?;
    let Some((nonce, commitment)) = load_retention_archive_identity(archive)? else {
        return Err(ReceiptStoreError::Conflict(
            "retention archive identity row is missing".to_string(),
        ));
    };
    if retention_archive_identity_commitment(&nonce) != commitment {
        return Err(ReceiptStoreError::Conflict(
            "retention archive identity commitment does not match its nonce".to_string(),
        ));
    }
    Ok(commitment)
}

fn validate_retention_archive_identity_in_schema(
    archive: &rusqlite::Connection,
    schema: &str,
    expected_commitment: &str,
) -> Result<(), ReceiptStoreError> {
    let Some((nonce, commitment)) = load_retention_archive_identity_in_schema(archive, schema)?
    else {
        return Err(ReceiptStoreError::Conflict(
            "retention archive identity row is missing".to_string(),
        ));
    };
    if commitment != expected_commitment
        || retention_archive_identity_commitment(&nonce) != commitment
    {
        return Err(ReceiptStoreError::Conflict(
            "retention archive identity does not match the committed watermark identity"
                .to_string(),
        ));
    }
    Ok(())
}

fn load_retention_archive_identity(
    archive: &rusqlite::Connection,
) -> Result<Option<(String, String)>, ReceiptStoreError> {
    load_retention_archive_identity_in_schema(archive, "main")
}

fn load_retention_archive_identity_in_schema(
    archive: &rusqlite::Connection,
    schema: &str,
) -> Result<Option<(String, String)>, ReceiptStoreError> {
    let qualified_table = match schema {
        "main" => "main.chio_retention_archive_identity",
        "archive" => "archive.chio_retention_archive_identity",
        _ => {
            return Err(ReceiptStoreError::Conflict(format!(
                "invalid SQLite schema name {schema:?} in retention archive identity validation"
            )))
        }
    };
    let row_count: i64 = archive.query_row(
        &format!("SELECT COUNT(*) FROM {qualified_table}"),
        [],
        |row| row.get(0),
    )?;
    if row_count > 1 {
        return Err(ReceiptStoreError::Conflict(
            "retention archive contains multiple identity rows".to_string(),
        ));
    }
    archive
        .query_row(
            &format!(
                "SELECT nonce, commitment_sha256 FROM {qualified_table} WHERE identity_slot = 1"
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(ReceiptStoreError::from)
}

fn retention_archive_identity_commitment(nonce: &str) -> String {
    let material = format!("{RETENTION_ARCHIVE_IDENTITY_DOMAIN}\0{nonce}");
    chio_core::sha256(material.as_bytes()).to_hex()
}

fn receipt_retention_watermark_table_exists(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    let exists: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master \
             WHERE type = 'table' AND name = 'receipt_retention_watermark'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

/// True if any checkpoint has ever been persisted. Called by the claim-log
/// backfill guard (`claim_log/validation.rs`) and the watermark-aware chain
/// verification.
pub(crate) fn kernel_checkpoints_exist(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
            row.get(0)
        })?;
    Ok(count > 0)
}

/// Record a new archival high-water mark. Fail-closed: a value below the
/// current MAX is a regression and is rejected without inserting. The DB-level
/// `receipt_retention_watermark_reject_regression` trigger additionally rejects
/// a non-strictly-increasing raw INSERT, so the monotonic guarantee holds even
/// for a writer that bypasses this helper.
///
/// `archive_sha256` is the domain-separated SHA-256 commitment to the archive's
/// random identity nonce. `archive_content_sha256` separately binds the
/// canonical logical schema and every typed row reachable through this exact
/// archival watermark. Rows copied for a later, uncommitted watermark do not
/// alter an earlier commitment. Neither commitment hashes mutable SQLite file
/// or WAL bytes.
///
/// Called on the writer connection by the Rotate command
/// (`delete_archived_prefix_in_tx`).
pub(crate) fn insert_receipt_retention_watermark(
    connection: &rusqlite::Connection,
    archived_through_entry_seq: u64,
    archived_through_timestamp: u64,
    archive_path: &str,
    archive_sha256: &str,
    archive_content_sha256: &str,
    rotated_at: u64,
) -> Result<(), ReceiptStoreError> {
    validate_retention_sha256_hex(archive_sha256, "archive identity commitment")?;
    validate_retention_sha256_hex(archive_content_sha256, "archive content commitment")?;
    if let Some(current) = retention_watermark(connection)? {
        if archived_through_entry_seq < current {
            return Err(ReceiptStoreError::RetentionWatermarkRegression {
                attempted: archived_through_entry_seq,
                current,
            });
        }
    }
    connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, \
          archive_content_sha256, rotated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            sqlite_i64(archived_through_entry_seq, "watermark entry_seq")?,
            sqlite_i64(archived_through_timestamp, "watermark timestamp")?,
            archive_path,
            archive_sha256,
            archive_content_sha256,
            sqlite_i64(rotated_at, "watermark rotated_at")?,
        ],
    )?;
    Ok(())
}

fn validate_retention_sha256_hex(value: &str, field: &str) -> Result<(), ReceiptStoreError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention {field} must be exactly 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

/// One-time migration: enable `PRAGMA auto_vacuum = INCREMENTAL` on a store
/// that predates the pragma.
///
/// SQLite only applies a changed `auto_vacuum` mode to a brand-new (empty)
/// database; on an existing populated database the pragma write is silently
/// a no-op until a full `VACUUM` runs, which is the only way to convert an
/// existing file's auto-vacuum mode (see the SQLite `auto_vacuum` pragma
/// docs). `PRAGMA auto_vacuum` reads back `0` (NONE) until that conversion
/// happens, so this helper checks the current mode and, only when it is
/// still `NONE`, sets the pragma and runs one full `VACUUM` to convert the
/// file. Idempotent: once converted, `PRAGMA auto_vacuum` reads back `2`
/// (INCREMENTAL) and this becomes a cheap no-op read on every subsequent
/// call. Called on the drained writer connection at the first rotation pass
/// (`rotate_on_writer_connection`) so a legacy store converts exactly once,
/// off the append hot path.
pub(crate) fn migrate_auto_vacuum_incremental_if_needed(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    let mode: i64 = connection.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if mode == 0 {
        connection.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
    }
    Ok(())
}
