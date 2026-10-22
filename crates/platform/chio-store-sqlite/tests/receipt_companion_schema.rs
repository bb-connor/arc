use chio_credit::IouEnvelopeStoreError;
use chio_settle::SettlementRouteError;
use chio_store_sqlite::dead_letters::{DeadLetterStoreError, SqliteDeadLetterStore};
use chio_store_sqlite::{SqliteIouEnvelopeStore, SqliteSettlementOutcomeStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn companion_openers_refuse_empty_catalog_without_creating_tables() -> TestResult {
    for component in ["iou", "dead_letter", "settlement"] {
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(r2d2_sqlite::SqliteConnectionManager::memory())?;
        let result = open_component(component, &pool);
        let count: i64 =
            pool.get()?
                .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))?;
        assert_eq!(count, 0, "{component} created a partial schema");
        assert_eq!(
            result,
            Err("conflict: schema creation is not allowed for this namespace".to_owned())
        );
    }
    Ok(())
}

fn open_component(
    component: &str,
    pool: &r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
) -> Result<(), String> {
    match component {
        "iou" => SqliteIouEnvelopeStore::open_with_pool(pool.clone())
            .map(drop)
            .map_err(|error| match error {
                IouEnvelopeStoreError::Backend(message) => message,
                other => panic!("unexpected IOU refusal: {other:?}"),
            }),
        "dead_letter" => SqliteDeadLetterStore::open_with_pool(pool.clone())
            .map(drop)
            .map_err(|error| match error {
                DeadLetterStoreError::Backend(message) => message,
                other => panic!("unexpected dead-letter refusal: {other:?}"),
            }),
        "settlement" => SqliteSettlementOutcomeStore::open_with_pool(pool.clone())
            .map(drop)
            .map_err(|error| match error {
                SettlementRouteError::Backend { detail } => detail,
                other => panic!("unexpected settlement refusal: {other:?}"),
            }),
        _ => unreachable!(),
    }
}

#[test]
fn companion_openers_accept_complete_schema_and_refuse_missing_objects() -> TestResult {
    for component in ["iou", "dead_letter", "settlement"] {
        for object_type in ["table", "index"] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("receipt.sqlite");
            drop(chio_store_sqlite::SqliteReceiptStore::open(&path)?);
            let pool = r2d2::Pool::builder()
                .max_size(1)
                .build(r2d2_sqlite::SqliteConnectionManager::file(&path))?;
            assert_eq!(open_component(component, &pool), Ok(()));
            let connection = pool.get()?;
            let prefix = match component {
                "iou" => "%iou%",
                "dead_letter" => "%dead_letter%",
                "settlement" => "%settle_attempt%",
                _ => unreachable!(),
            };
            let name: String = connection.query_row(
                "SELECT name FROM sqlite_schema WHERE type = ?1 AND name LIKE ?2 AND sql IS NOT NULL ORDER BY name LIMIT 1",
                rusqlite::params![object_type, prefix], |row| row.get(0))?;
            connection.execute_batch(&format!(
                "DROP {object_type} \"{}\"",
                name.replace('"', "\"\"")
            ))?;
            let catalog = |connection: &rusqlite::Connection| -> rusqlite::Result<Vec<(String, String, Option<String>)>> {
                connection.prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name")?
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?.collect()
            };
            let before = catalog(&connection)?;
            drop(connection);
            assert_eq!(
                open_component(component, &pool),
                Err("conflict: schema catalog differs from its canonical definition".to_owned())
            );
            assert_eq!(catalog(&*pool.get()?)?, before);
        }
    }
    Ok(())
}

#[test]
fn alongside_openers_refuse_missing_companion_index() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipt.sqlite");
    let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path)?;
    drop(SqliteIouEnvelopeStore::open_alongside(&receipts)?);
    drop(SqliteDeadLetterStore::open_alongside(&receipts)?);
    drop(SqliteSettlementOutcomeStore::open_alongside(&receipts)?);
    let connection = rusqlite::Connection::open(&path)?;
    let index: String = connection.query_row(
        "SELECT name FROM sqlite_schema WHERE type = 'index' AND name LIKE '%iou%' AND sql IS NOT NULL ORDER BY name LIMIT 1",
        [], |row| row.get(0))?;
    connection.execute_batch(&format!("DROP INDEX \"{}\"", index.replace('"', "\"\"")))?;
    assert!(matches!(SqliteIouEnvelopeStore::open_alongside(&receipts),
        Err(IouEnvelopeStoreError::Backend(message))
        if message == "conflict: schema catalog differs from its canonical definition"));
    assert!(matches!(SqliteDeadLetterStore::open_alongside(&receipts),
        Err(DeadLetterStoreError::Backend(message))
        if message == "receipt writer conflict: schema catalog differs from its canonical definition"));
    assert!(
        matches!(SqliteSettlementOutcomeStore::open_alongside(&receipts),
        Err(SettlementRouteError::Backend { detail })
        if detail == "receipt writer conflict: schema catalog differs from its canonical definition")
    );
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name = ?1",
        [&index],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}
