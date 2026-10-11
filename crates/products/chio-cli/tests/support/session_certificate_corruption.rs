use std::path::Path;

type Catalog = Vec<(String, String, String, i64, Option<String>)>;

fn catalog(connection: &rusqlite::Connection) -> rusqlite::Result<Catalog> {
    connection
        .prepare(
            "SELECT type, name, tbl_name, rootpage, sql FROM sqlite_schema ORDER BY type, name",
        )?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect()
}

/// Construct corruption in a fresh temporary test database, preserving its
/// original immutability trigger and complete schema catalog before readback.
pub(crate) fn corrupt_temporary_tool_receipt(
    path: &Path,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = rusqlite::Connection::open(path)?;
    let original_catalog = catalog(&connection)?;
    let transaction = connection.transaction()?;
    let original_trigger: String = transaction.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' \
         AND name = 'chio_tool_receipts_reject_update'",
        [],
        |row| row.get(0),
    )?;
    // This is the same offline fixture construction used by the store's tenant
    // isolation tests. No qualified read occurs while the trigger is absent.
    transaction.execute_batch("DROP TRIGGER chio_tool_receipts_reject_update")?;
    assert_eq!(transaction.execute(sql, parameters)?, 1);
    transaction.execute_batch(&original_trigger)?;
    assert_eq!(catalog(&transaction)?, original_catalog);
    transaction.commit()?;
    Ok(())
}
