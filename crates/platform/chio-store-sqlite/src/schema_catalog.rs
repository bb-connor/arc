use rusqlite::Connection;

use crate::schema_version::SchemaVersionError;

type CatalogEntry = (String, String, String, Option<String>);

pub(crate) fn validate(
    connection: &Connection,
    canonical_ddl: &str,
) -> Result<(), SchemaVersionError> {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(canonical_ddl)?;
    validate_against(connection, &canonical)
}

pub(crate) fn validate_against(
    connection: &Connection,
    canonical: &Connection,
) -> Result<(), SchemaVersionError> {
    if catalog(connection)? != catalog(canonical)? {
        return Err(SchemaVersionError::CatalogMismatch);
    }
    Ok(())
}

fn catalog(connection: &Connection) -> rusqlite::Result<Vec<CatalogEntry>> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect();
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    const DDL: &str = "CREATE TABLE owned (id TEXT PRIMARY KEY, value INTEGER NOT NULL);
         CREATE INDEX owned_by_value ON owned(value);";

    #[test]
    fn complete_catalog_matches_and_refuses_undeclared_objects() -> rusqlite::Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(DDL)?;
        assert!(validate(&connection, DDL).is_ok());
        connection.execute_batch("CREATE TABLE sibling (id INTEGER);")?;
        assert!(matches!(
            validate(&connection, DDL),
            Err(SchemaVersionError::CatalogMismatch)
        ));
        Ok(())
    }

    #[test]
    fn altered_column_missing_index_and_extra_trigger_are_rejected() -> rusqlite::Result<()> {
        for altered in [
            "CREATE TABLE owned (id TEXT PRIMARY KEY, value INTEGER);
             CREATE INDEX owned_by_value ON owned(value);",
            "CREATE TABLE owned (id TEXT PRIMARY KEY, value INTEGER NOT NULL);",
            "CREATE TABLE owned (id TEXT PRIMARY KEY, value INTEGER NOT NULL);
             CREATE INDEX owned_by_value ON owned(value);
             CREATE TRIGGER owned_noop AFTER INSERT ON owned BEGIN SELECT 1; END;",
        ] {
            let connection = Connection::open_in_memory()?;
            connection.execute_batch(altered)?;
            assert!(matches!(
                validate(&connection, DDL),
                Err(SchemaVersionError::CatalogMismatch)
            ));
        }
        Ok(())
    }
}
