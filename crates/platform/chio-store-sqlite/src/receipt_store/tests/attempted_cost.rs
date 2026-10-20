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
fn attempted_projection_drift_is_rejected_by_audit_and_duplicate(
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
fn archive_preserves_exact_attempted_projection() -> Result<(), Box<dyn std::error::Error>> {
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
    let archived =
        Connection::open_with_flags(&archive, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    assert_eq!(projections(&archived)?, before);
    crate::receipt_store::support::audit_receipt_cost_projection(&archived)?;
    drop(archived);
    let mut connection = Connection::open_in_memory()?;
    connection.execute("ATTACH DATABASE ?1 AS archive", [archive_path])?;
    evidence_retention::create_archive_schema(&mut connection)?;
    assert!(
        matches!(connection.execute("UPDATE archive.chio_tool_receipts SET attempted_cost_be = NULL", []),
            Err(rusqlite::Error::SqliteFailure(code, Some(message)))
                if code.code == rusqlite::ErrorCode::ConstraintViolation && message == "tool receipts are immutable"
        )
    );
    connection.execute_batch("DETACH DATABASE archive")?;
    drop(connection);
    let archived =
        Connection::open_with_flags(&archive, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    assert_eq!(projections(&archived)?, before);
    assert_eq!(schema_version(&archived)?, RECEIPT_STORE_SCHEMA_VERSION);
    crate::receipt_store::support::audit_receipt_cost_projection(&archived)?;
    drop(archived);
    fs::remove_file(path)?;
    fs::remove_file(archive)?;
    Ok(())
}
