use chio_credit::IouEnvelopeStoreError;
use chio_kernel::{ApprovalStoreError, ReceiptStoreError};
use chio_security_types::schema::SchemaRefusal;
use chio_settle::SettlementRouteError;
use chio_store_sqlite::dead_letters::{DeadLetterStoreError, SqliteDeadLetterStore};
use chio_store_sqlite::{
    SqliteApprovalStore, SqliteIouEnvelopeStore, SqliteReceiptStore, SqliteSettlementOutcomeStore,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn empty_companion_opens_preserve_typed_creation_refusal() -> TestResult {
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .build(r2d2_sqlite::SqliteConnectionManager::memory())?;
    assert!(matches!(
        SqliteIouEnvelopeStore::open_with_pool(pool.clone()),
        Err(IouEnvelopeStoreError::Schema(
            SchemaRefusal::CreationNotAllowed
        ))
    ));
    assert!(matches!(
        SqliteDeadLetterStore::open_with_pool(pool.clone()),
        Err(DeadLetterStoreError::Schema(
            SchemaRefusal::CreationNotAllowed
        ))
    ));
    let Err(error) = SqliteSettlementOutcomeStore::open_with_pool(pool) else {
        return Err("empty settlement companion was admitted".into());
    };
    assert_eq!(
        error.class(),
        chio_settle::SettlementRouteErrorClass::Backend
    );
    assert!(matches!(
        error,
        SettlementRouteError::Schema(SchemaRefusal::CreationNotAllowed)
    ));
    Ok(())
}

#[test]
fn receipt_open_preserves_missing_namespace_refusal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipts.sqlite");
    drop(SqliteReceiptStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'receipt'",
        [],
    )?;
    drop(connection);
    assert!(matches!(SqliteReceiptStore::open(&path),
        Err(ReceiptStoreError::Schema(SchemaRefusal::MissingSchema { store_key })) if store_key == "receipt"));
    Ok(())
}

#[test]
fn approval_open_preserves_missing_namespace_refusal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approvals.sqlite");
    drop(SqliteApprovalStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'approval'",
        [],
    )?;
    drop(connection);
    assert!(matches!(SqliteApprovalStore::open(&path),
        Err(ApprovalStoreError::Schema(SchemaRefusal::MissingSchema { store_key })) if store_key == "approval"));
    Ok(())
}
