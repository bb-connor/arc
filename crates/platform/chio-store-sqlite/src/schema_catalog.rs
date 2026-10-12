//! Exact schema comparison for stores that own a single schema.

use rusqlite::Connection;

type CatalogEntry = (String, String, String, Option<String>);

/// Whether `tables`, with every index and trigger defined on them, carry exactly
/// the definitions `canonical_ddl` creates in an empty database.
///
/// Objects on other tables are ignored, so stores that share one database file
/// each verify only their own tables.
pub(crate) fn matches_canonical_schema(
    connection: &Connection,
    canonical_ddl: &str,
    tables: &[&str],
) -> rusqlite::Result<bool> {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(canonical_ddl)?;
    Ok(schema_catalog(connection, tables)? == schema_catalog(&canonical, tables)?)
}

fn schema_catalog(connection: &Connection, tables: &[&str]) -> rusqlite::Result<Vec<CatalogEntry>> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema \
         WHERE tbl_name = ?1 ORDER BY type, name",
    )?;
    let mut entries = Vec::new();
    for table in tables {
        let rows = statement.query_map([table], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        for row in rows {
            entries.push(row?);
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DDL: &str =
        "CREATE TABLE IF NOT EXISTS owned (id TEXT PRIMARY KEY, value INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS owned_by_value ON owned(value);";

    #[test]
    fn canonical_schema_matches_and_ignores_other_tables() -> rusqlite::Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(DDL)?;
        connection.execute_batch("CREATE TABLE sibling (id INTEGER);")?;
        assert!(matches_canonical_schema(&connection, DDL, &["owned"])?);
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
            assert!(!matches_canonical_schema(&connection, DDL, &["owned"])?);
        }
        Ok(())
    }
}
