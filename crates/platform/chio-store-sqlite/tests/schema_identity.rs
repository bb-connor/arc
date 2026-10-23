use chio_store_sqlite::{inspect_schema, SchemaVersionError, CHIO_SQLITE_APPLICATION_ID};
use rusqlite::Connection;

type CatalogRow = (String, String, String, Option<String>);

#[test]
fn single_schema_refuses_populated_unstamped_database_with_sqlite_prefix(
) -> Result<(), Box<dyn std::error::Error>> {
    for table in ["sqlitex_user_data", "SQLiteX_user_data", "sqlite"] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(&format!(
            "CREATE TABLE \"{table}\" (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO \"{table}\" (id, value) VALUES (7, 'preserved');"
        ))?;
        let before = catalog(&connection)?;
        let result = inspect_schema(&connection, &["schema_identity"]);
        assert!(
            matches!(
                &result,
                Err(SchemaVersionError::ForeignDatabase { found: 0, expected })
                    if *expected == CHIO_SQLITE_APPLICATION_ID
            ),
            "{table}: {result:?}"
        );
        let application_id: i32 =
            connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        assert_eq!(application_id, 0);
        let after = catalog(&connection)?;
        assert_eq!(after, before);
        let rows = connection
            .prepare(&format!("SELECT id, value FROM \"{table}\" ORDER BY id"))?
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(rows, vec![(7, "preserved".to_string())]);
    }
    Ok(())
}

#[test]
fn single_schema_refuses_unrecognized_stamped_database_with_sqlite_prefix(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&format!(
        "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID};
         CREATE TABLE sqlitex_user_data (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
         INSERT INTO sqlitex_user_data (id, value) VALUES (7, 'preserved');"
    ))?;
    let before = catalog(&connection)?;
    let result = inspect_schema(&connection, &["schema_identity"]);
    assert!(
        matches!(&result, Err(SchemaVersionError::MalformedMetadata)),
        "{result:?}"
    );
    let application_id: i32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    assert_eq!(application_id, CHIO_SQLITE_APPLICATION_ID);
    assert_eq!(catalog(&connection)?, before);
    let rows = connection
        .prepare("SELECT id, value FROM sqlitex_user_data ORDER BY id")?
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows, vec![(7, "preserved".to_string())]);
    Ok(())
}

fn catalog(connection: &Connection) -> rusqlite::Result<Vec<CatalogRow>> {
    connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect()
}
