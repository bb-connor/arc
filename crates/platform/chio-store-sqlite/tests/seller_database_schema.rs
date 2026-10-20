use chio_store_sqlite::{
    SqliteFindingOperatorBundleStore, SqliteFindingOperatorPaymentAdapter,
    SqliteFindingPayloadStore,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn bundle_reopen_refuses_deleted_stamp_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    drop(SqliteFindingOperatorBundleStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM chio_store_schema_versions", [])?;
    let result = SqliteFindingOperatorBundleStore::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert!(
        matches!(result, Err(chio_store_sqlite::finding_operator_bundle_store::FindingOperatorBundleStoreError::Unavailable(message))
        if message == "schema namespace finding_operator_bundle is missing")
    );
    Ok(())
}

#[test]
fn payment_reopen_refuses_deleted_stamp_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    drop(SqliteFindingOperatorPaymentAdapter::open(&path).map_err(std::io::Error::other)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM chio_store_schema_versions", [])?;
    let result = SqliteFindingOperatorPaymentAdapter::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert!(
        matches!(result, Err(message) if message == "schema namespace finding_operator_payment is missing")
    );
    Ok(())
}

#[test]
fn payload_reopen_refuses_deleted_stamp_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    drop(SqliteFindingPayloadStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM chio_store_schema_versions", [])?;
    let result = SqliteFindingPayloadStore::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert!(
        matches!(result, Err(chio_store_sqlite::finding_payload_store::FindingPayloadStoreError::Unavailable(message))
        if message == "schema namespace finding_payload is missing")
    );
    Ok(())
}

#[test]
fn declared_seller_creation_and_all_component_reopens_succeed() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    chio_store_sqlite::initialize_finding_operator_database(&path)
        .map_err(std::io::Error::other)?;
    drop(SqliteFindingOperatorBundleStore::open(&path)?);
    drop(SqliteFindingPayloadStore::open(&path)?);
    drop(SqliteFindingOperatorPaymentAdapter::open(&path).map_err(std::io::Error::other)?);
    chio_store_sqlite::initialize_finding_operator_database(&path)
        .map_err(std::io::Error::other)?;
    let connection = rusqlite::Connection::open(&path)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions WHERE version = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 3);
    Ok(())
}

#[test]
fn missing_composite_namespace_is_never_added_by_any_opener() -> TestResult {
    for namespace in [
        "finding_operator_bundle",
        "finding_payload",
        "finding_operator_payment",
    ] {
        let root = tempfile::tempdir()?;
        let path = root.path().join("seller.db");
        chio_store_sqlite::initialize_finding_operator_database(&path)
            .map_err(std::io::Error::other)?;
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute(
            "DELETE FROM chio_store_schema_versions WHERE store_key = ?1",
            [namespace],
        )?;
        assert_eq!(
            chio_store_sqlite::initialize_finding_operator_database(&path),
            Err(format!("schema namespace {namespace} is missing"))
        );
        assert!(SqliteFindingOperatorBundleStore::open(&path).is_err());
        assert!(SqliteFindingPayloadStore::open(&path).is_err());
        assert!(SqliteFindingOperatorPaymentAdapter::open(&path).is_err());
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM chio_store_schema_versions",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 2);
    }
    Ok(())
}

#[test]
fn standalone_database_cannot_be_promoted_by_composite_initialization() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    drop(SqliteFindingOperatorBundleStore::open(&path)?);
    assert_eq!(
        chio_store_sqlite::initialize_finding_operator_database(&path),
        Err("schema namespace finding_operator_payment is missing".to_owned())
    );
    let connection = rusqlite::Connection::open(&path)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    let payment: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'chio_finding_operator_payments')",
        [],
        |row| row.get(0),
    )?;
    assert!(!payment);
    Ok(())
}

#[test]
fn composite_component_refuses_missing_sibling_index_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    chio_store_sqlite::initialize_finding_operator_database(&path)
        .map_err(std::io::Error::other)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("DROP INDEX idx_chio_finding_payloads_tenant;")?;
    assert!(
        matches!(SqliteFindingOperatorPaymentAdapter::open(&path), Err(message)
        if message == "schema catalog differs from its canonical definition")
    );
    let present: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'idx_chio_finding_payloads_tenant')", [], |row| row.get(0))?;
    assert!(!present);
    Ok(())
}
