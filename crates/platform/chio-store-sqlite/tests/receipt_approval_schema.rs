use chio_kernel::{ApprovalStoreError, ReceiptStoreError};
use chio_store_sqlite::{SqliteApprovalStore, SqliteReceiptStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn receipt_reopen_refuses_missing_stamp_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("receipts.db");
    drop(SqliteReceiptStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM chio_store_schema_versions", [])?;
    let result = SqliteReceiptStore::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert!(matches!(result, Err(ReceiptStoreError::Conflict(message))
        if message == "schema namespace receipt is missing"));
    Ok(())
}

#[test]
fn receipt_reopen_refuses_missing_index_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("receipts.db");
    drop(SqliteReceiptStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("DROP INDEX idx_chio_tool_receipts_timestamp;")?;
    let result = SqliteReceiptStore::open(&path);
    let present: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'idx_chio_tool_receipts_timestamp')", [], |row| row.get(0))?;
    assert!(!present);
    assert!(matches!(result, Err(ReceiptStoreError::Conflict(message))
        if message == "schema catalog differs from its canonical definition"));
    Ok(())
}

#[test]
fn approval_reopen_refuses_missing_stamp_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("approvals.db");
    drop(SqliteApprovalStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM chio_store_schema_versions", [])?;
    let result = SqliteApprovalStore::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert!(matches!(result, Err(ApprovalStoreError::Backend(message))
        if message == "schema namespace approval is missing"));
    Ok(())
}

#[test]
fn explicit_pair_creation_reopens_both_stores() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("pair.db");
    chio_store_sqlite::initialize_receipt_approval_database(&path)?;
    drop(SqliteReceiptStore::open(&path)?);
    drop(SqliteApprovalStore::open_colocated_with_receipt_store(
        &path,
    )?);
    chio_store_sqlite::initialize_receipt_approval_database(&path)?;
    let connection = rusqlite::Connection::open(&path)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions WHERE version = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    let auto_vacuum: i64 = connection.pragma_query_value(None, "auto_vacuum", |row| row.get(0))?;
    assert_eq!(auto_vacuum, 2);
    Ok(())
}

#[test]
fn partial_pair_is_refused_without_restamping() -> TestResult {
    for namespace in ["receipt", "approval"] {
        let root = tempfile::tempdir()?;
        let path = root.path().join("pair.db");
        chio_store_sqlite::initialize_receipt_approval_database(&path)?;
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute(
            "DELETE FROM chio_store_schema_versions WHERE store_key = ?1",
            [namespace],
        )?;
        assert!(
            matches!(chio_store_sqlite::initialize_receipt_approval_database(&path), Err(ReceiptStoreError::Conflict(message))
            if message == format!("schema namespace {namespace} is missing"))
        );
        let receipt_error = if namespace == "approval" {
            "schema catalog differs from its canonical definition"
        } else {
            "schema namespace receipt is missing"
        };
        let receipt_result = SqliteReceiptStore::open(&path).map(drop);
        assert!(
            matches!(&receipt_result, Err(ReceiptStoreError::Conflict(message))
                if message == receipt_error),
            "{receipt_result:?}"
        );
        assert!(
            matches!(SqliteApprovalStore::open_colocated_with_receipt_store(&path), Err(ApprovalStoreError::Backend(message))
            if message == format!("schema namespace {namespace} is missing"))
        );
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM chio_store_schema_versions",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1);
    }
    Ok(())
}

#[test]
fn receipt_only_database_is_not_adopted_as_an_approval_pair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("receipts.db");
    drop(SqliteReceiptStore::open(&path)?);
    assert!(
        matches!(SqliteApprovalStore::open_colocated_with_receipt_store(&path), Err(ApprovalStoreError::Backend(message))
        if message == "schema namespace approval is missing")
    );
    assert!(
        matches!(chio_store_sqlite::initialize_receipt_approval_database(&path), Err(ReceiptStoreError::Conflict(message))
        if message == "schema namespace approval is missing")
    );
    let connection = rusqlite::Connection::open(&path)?;
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'chio_hitl_pending')",
        [],
        |row| row.get(0),
    )?;
    assert!(!present);
    Ok(())
}

#[test]
fn receipt_reopen_refuses_missing_generation_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("receipts.db");
    drop(SqliteReceiptStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM chio_receipt_sink_generation", [])?;
    assert!(matches!(
        SqliteReceiptStore::open(&path),
        Err(ReceiptStoreError::Sqlite(
            rusqlite::Error::QueryReturnedNoRows
        ))
    ));
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_receipt_sink_generation",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}
