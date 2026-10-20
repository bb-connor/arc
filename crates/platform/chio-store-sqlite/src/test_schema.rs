use crate::schema_version::{SchemaTransaction, SchemaVersionError};
use rusqlite::Connection;

pub(crate) fn apply<E>(
    connection: &mut Connection,
    namespaces: &[&str],
    initialize: impl FnOnce(&SchemaTransaction<'_>) -> Result<(), E>,
    map_error: impl Fn(SchemaVersionError) -> E,
) -> Result<(), E> {
    let schema = SchemaTransaction::begin(connection, namespaces).map_err(&map_error)?;
    initialize(&schema)?;
    schema.commit().map_err(map_error)
}

pub(crate) fn write_version(
    connection: &Connection,
    key: &str,
    version: i32,
) -> rusqlite::Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'chio_store_schema_versions')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        connection.execute_batch(
            "CREATE TABLE chio_store_schema_versions (
    store_key TEXT NOT NULL PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version = 1)
) STRICT",
        )?;
    }
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    let result = connection.execute(
        "INSERT INTO chio_store_schema_versions(store_key, version) VALUES(?1, ?2)
         ON CONFLICT(store_key) DO UPDATE SET version = excluded.version",
        rusqlite::params![key, version],
    );
    connection.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
    result.map(|_| ())
}
