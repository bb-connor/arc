use super::super::*;
use super::support::*;

fn attempted_receipt(id: &str, amount: Option<u64>) -> chio_core::error::Result<ChioReceipt> {
    let mut body = sample_financial_receipt(id, 7)?.body();
    let metadata = body.metadata.as_mut().test_expect("financial metadata");
    metadata["financial"]["attempted_cost"] = serde_json::to_value(amount)?;
    ChioReceipt::sign(body, &receipt_test_keypair())
}

fn schema_version(connection: &Connection) -> rusqlite::Result<i32> {
    connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
        [],
        |row| row.get(0),
    )
}

fn projections(connection: &Connection) -> rusqlite::Result<Vec<(String, Option<Vec<u8>>)>> {
    connection
        .prepare("SELECT raw_json, attempted_cost_be FROM chio_tool_receipts ORDER BY seq")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}

#[test]
fn version_five_migration_preserves_signed_bytes_and_unsigned_attempted_cost(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-attempted-migration");
    let store = SqliteReceiptStore::open(&path)?;
    for (index, value) in [
        None,
        Some(0),
        Some((1 << 53) + 1),
        Some(1 << 63),
        Some(u64::MAX),
    ]
    .into_iter()
    .enumerate()
    {
        store.append_chio_receipt(&attempted_receipt(&format!("attempt-{index}"), value)?)?;
    }
    let before = projections(&*store.connection()?)?;
    drop(store);
    let connection = Connection::open(&path)?;
    connection.execute_batch("ALTER TABLE chio_tool_receipts DROP COLUMN attempted_cost_be")?;
    crate::stamp_schema_version(&connection, "receipt", 5)?;
    drop(connection);
    assert!(matches!(SqliteReceiptStore::open_existing(&path),
        Err(ReceiptStoreError::Conflict(message)) if message ==
        format!("receipt database schema version 5 requires writable migration to version {RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION}; reopen it with SqliteReceiptStore::open")
    ));
    let migrated = SqliteReceiptStore::open(&path)?;
    assert_eq!(projections(&*migrated.connection()?)?, before);
    assert_eq!(
        schema_version(&*migrated.connection()?)?,
        RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    migrated.audit_receipt_cost_projection()?;
    drop(migrated);
    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(projections(&*reopened.connection()?)?, before);
    drop(reopened);
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn attempted_migration_rolls_back_on_invalid_signed_body_or_charged_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    for invalid_body in [false, true] {
        let path = unique_db_path("chio-attempted-migration-rollback");
        let store = SqliteReceiptStore::open(&path)?;
        store.append_chio_receipt(&attempted_receipt("first", Some(u64::MAX))?)?;
        store.append_chio_receipt(&attempted_receipt("second", Some(1))?)?;
        drop(store);
        let mut connection = Connection::open(&path)?;
        drop_transparency_projection_guards(&connection)?;
        connection.execute_batch("ALTER TABLE chio_tool_receipts DROP COLUMN attempted_cost_be")?;
        crate::stamp_schema_version(&connection, "receipt", 5)?;
        if invalid_body {
            connection.execute(
                "UPDATE chio_tool_receipts SET raw_json = '{' WHERE seq = 2",
                [],
            )?;
        } else {
            connection.execute("UPDATE chio_tool_receipts SET cost_currency = NULL, cost_charged_be = NULL WHERE seq = 2", [])?;
        }
        let tx = connection.transaction()?;
        let error = migrate_receipt_cost_projection(&tx, false)
            .test_expect_err("invalid evidence must abort the migration");
        match error {
            ReceiptStoreError::Conflict(message) if !invalid_body => {
                assert!(message.contains("already exists with different cost projection"));
            }
            ReceiptStoreError::UntrustedInput(source) if invalid_body => {
                assert!(matches!(
                    source.as_ref(),
                    chio_core::canonical::UntrustedJsonError::SignedInput(_)
                ));
            }
            other => panic!("wrong migration error: {other}"),
        }
        tx.rollback()?;
        let columns: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('chio_tool_receipts') WHERE name = 'attempted_cost_be'",
            [], |row| row.get(0),
        )?;
        assert_eq!(columns, 0);
        assert_eq!(schema_version(&connection)?, 5);
        drop(connection);
        fs::remove_file(path)?;
    }
    Ok(())
}

#[test]
fn attempted_projection_drift_is_rejected_by_audit_duplicate_and_migration(
) -> Result<(), Box<dyn std::error::Error>> {
    for replacement in [None, Some(0_u64.to_be_bytes().to_vec())] {
        let path = unique_db_path("chio-attempted-drift");
        let receipt = attempted_receipt("attempted-drift", Some(u64::MAX))?;
        let store = SqliteReceiptStore::open(&path)?;
        store.append_chio_receipt(&receipt)?;
        drop(store);
        let connection = Connection::open(&path)?;
        drop_transparency_projection_guards(&connection)?;
        connection.execute(
            "UPDATE chio_tool_receipts SET attempted_cost_be = ?1",
            [replacement],
        )?;
        ensure_transparency_projection_guards(&connection)?;
        drop(connection);
        let reopened = SqliteReceiptStore::open(&path)?;
        for outcome in [
            reopened.audit_receipt_cost_projection(),
            reopened.append_chio_receipt(&receipt),
        ] {
            assert!(matches!(outcome,
                Err(ReceiptStoreError::Conflict(message)) if message.contains("already exists with different cost projection")
            ));
        }
        drop(reopened);
        let connection = Connection::open(&path)?;
        crate::stamp_schema_version(&connection, "receipt", 5)?;
        drop(connection);
        assert!(matches!(SqliteReceiptStore::open(&path),
            Err(ReceiptStoreError::Conflict(message)) if message.contains("already exists with different cost projection")
        ));
        fs::remove_file(path)?;
    }
    Ok(())
}

#[test]
fn attempted_projection_constraints_reject_wrong_types_and_widths(
) -> Result<(), Box<dyn std::error::Error>> {
    use rusqlite::types::Value;
    let path = unique_db_path("chio-attempted-constraints");
    let store = SqliteReceiptStore::open(&path)?;
    store.append_chio_receipt(&attempted_receipt("attempt-constraints", Some(7))?)?;
    drop(store);
    let mut connection = Connection::open(&path)?;
    let tx = connection.transaction()?;
    drop_transparency_projection_guards(&tx)?;
    for invalid in [
        Value::Integer(7),
        Value::Text("00000007".into()),
        Value::Blob(vec![]),
        Value::Blob(vec![0; 7]),
        Value::Blob(vec![0; 9]),
    ] {
        assert!(
            matches!(tx.execute("UPDATE chio_tool_receipts SET attempted_cost_be = ?1", [invalid]),
                Err(rusqlite::Error::SqliteFailure(code, Some(message)))
                    if code.code == rusqlite::ErrorCode::ConstraintViolation && message.contains("attempted_cost_be")
            )
        );
    }
    tx.rollback()?;
    drop(connection);
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn archive_preserves_and_migrates_exact_attempted_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-attempted-retention");
    let archive = unique_db_path("chio-attempted-retention-archive");
    let archive_path = archive.to_str().ok_or("archive path is not UTF-8")?;
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&receipt_test_keypair(), 3))?;
    for (index, value) in [Some(u64::MAX), Some(0), None].into_iter().enumerate() {
        store.append_chio_receipt(&attempted_receipt(&format!("archive-{index}"), value)?)?;
    }
    store.flush_receipt_writes()?;
    let before = projections(&*store.connection()?)?;
    assert_eq!(store.archive_receipts_before(2, archive_path)?, 3);
    drop(store);
    let archived = SqliteReceiptStore::open_existing(&archive)?;
    assert_eq!(projections(&*archived.connection()?)?, before);
    archived.audit_receipt_cost_projection()?;
    drop(archived);
    let connection = Connection::open(&archive)?;
    connection.execute_batch("ALTER TABLE chio_tool_receipts DROP COLUMN attempted_cost_be")?;
    crate::stamp_schema_version(&connection, "receipt", 5)?;
    drop(connection);
    let mut connection = Connection::open_in_memory()?;
    connection.execute("ATTACH DATABASE ?1 AS archive", [archive_path])?;
    evidence_retention::create_archive_schema(&mut connection)?;
    // A subsequent rotation must also accept an inspected current archive.
    evidence_retention::create_archive_schema(&mut connection)?;
    assert!(
        matches!(connection.execute("UPDATE archive.chio_tool_receipts SET attempted_cost_be = NULL", []),
            Err(rusqlite::Error::SqliteFailure(code, Some(message)))
                if code.code == rusqlite::ErrorCode::ConstraintViolation && message == "tool receipts are immutable"
        )
    );
    connection.execute_batch("DETACH DATABASE archive")?;
    drop(connection);
    let archived = SqliteReceiptStore::open_existing(&archive)?;
    assert_eq!(projections(&*archived.connection()?)?, before);
    assert_eq!(
        schema_version(&*archived.connection()?)?,
        RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    archived.audit_receipt_cost_projection()?;
    drop(archived);
    fs::remove_file(path)?;
    fs::remove_file(archive)?;
    Ok(())
}

#[test]
fn version_five_migration_refuses_a_missing_charged_projection_column(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-attempted-missing-charged-column");
    let store = SqliteReceiptStore::open(&path)?;
    store.append_chio_receipt(&sample_receipt_with_id("no-financial-block"))?;
    drop(store);
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "DROP INDEX idx_chio_tool_receipts_cost; \
         DROP INDEX idx_chio_tool_receipts_cost_global; \
         ALTER TABLE chio_tool_receipts DROP COLUMN cost_charged_be; \
         ALTER TABLE chio_tool_receipts DROP COLUMN attempted_cost_be;",
    )?;
    crate::stamp_schema_version(&connection, "receipt", 5)?;
    drop(connection);
    assert!(matches!(SqliteReceiptStore::open(&path),
        Err(ReceiptStoreError::Conflict(message)) if message ==
            "receipt cost projection schema differs from the canonical definition"
    ));
    let connection = Connection::open(&path)?;
    assert_eq!(schema_version(&connection)?, 5);
    let columns: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('chio_tool_receipts') \
         WHERE name IN ('cost_charged_be', 'attempted_cost_be')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(columns, 0);
    drop(connection);
    fs::remove_file(path)?;
    Ok(())
}
