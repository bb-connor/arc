use chio_store_sqlite::finding_operator_bundle_store::FindingOperatorBundleStoreError;
use chio_store_sqlite::finding_payload_store::FindingPayloadStoreError;
use chio_store_sqlite::SchemaVersionError;

use chio_store_sqlite::{
    SqliteFindingOperatorBundleStore, SqliteFindingOperatorPaymentAdapter,
    SqliteFindingPayloadStore,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn bundle_reopen_refuses_deleted_stamp_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    chio_store_sqlite::initialize_finding_operator_database(&path)
        .map_err(std::io::Error::other)?;
    drop(SqliteFindingOperatorBundleStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = ?1",
        ["finding_operator_bundle"],
    )?;
    let result = SqliteFindingOperatorBundleStore::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    assert!(
        matches!(result, Err(FindingOperatorBundleStoreError::Schema(SchemaVersionError::MissingSchema { store_key }))
        if store_key == "finding_operator_bundle")
    );
    Ok(())
}

#[test]
fn payment_reopen_refuses_deleted_stamp_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    chio_store_sqlite::initialize_finding_operator_database(&path)
        .map_err(std::io::Error::other)?;
    drop(SqliteFindingOperatorPaymentAdapter::open(&path).map_err(std::io::Error::other)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = ?1",
        ["finding_operator_payment"],
    )?;
    let result = SqliteFindingOperatorPaymentAdapter::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    assert!(
        matches!(result, Err(message) if message == "schema namespace finding_operator_payment is missing")
    );
    Ok(())
}

#[test]
fn payload_reopen_refuses_deleted_stamp_without_repair() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("seller.db");
    chio_store_sqlite::initialize_finding_operator_database(&path)
        .map_err(std::io::Error::other)?;
    drop(SqliteFindingPayloadStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = ?1",
        ["finding_payload"],
    )?;
    let result = SqliteFindingPayloadStore::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    assert!(
        matches!(result, Err(FindingPayloadStoreError::Schema(SchemaVersionError::MissingSchema { store_key }))
        if store_key == "finding_payload")
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
        assert!(matches!(
            chio_store_sqlite::initialize_finding_operator_database(&path),
            Err(SchemaVersionError::MissingSchema { store_key }) if store_key == namespace
        ));
        let expected = format!("schema namespace {namespace} is missing");
        assert!(matches!(
            SqliteFindingOperatorBundleStore::open(&path),
            Err(FindingOperatorBundleStoreError::Schema(SchemaVersionError::MissingSchema { store_key }))
                if store_key == namespace
        ));
        assert!(matches!(
            SqliteFindingPayloadStore::open(&path),
            Err(FindingPayloadStoreError::Schema(SchemaVersionError::MissingSchema { store_key }))
                if store_key == namespace
        ));
        assert!(
            matches!(SqliteFindingOperatorPaymentAdapter::open(&path), Err(message) if message == expected)
        );
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

#[test]
fn components_refuse_empty_database_without_creating_partial_schema() -> TestResult {
    for component in ["bundle", "payload", "payment"] {
        let root = tempfile::tempdir()?;
        let path = root.path().join("seller.db");
        let connection = rusqlite::Connection::open(&path)?;
        let result = match component {
            "bundle" => SqliteFindingOperatorBundleStore::open(&path)
                .map(drop)
                .map_err(|error| error.to_string()),
            "payload" => SqliteFindingPayloadStore::open(&path)
                .map(drop)
                .map_err(|error| error.to_string()),
            "payment" => SqliteFindingOperatorPaymentAdapter::open(&path).map(drop),
            _ => unreachable!(),
        };
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0, "{component} created a partial schema");
        let prefix = match component {
            "bundle" => "",
            "payload" => "",
            "payment" => "",
            _ => unreachable!(),
        };
        assert_eq!(
            result,
            Err(format!(
                "{prefix}schema creation is not allowed for this namespace"
            )),
            "{component}",
        );
    }
    Ok(())
}
