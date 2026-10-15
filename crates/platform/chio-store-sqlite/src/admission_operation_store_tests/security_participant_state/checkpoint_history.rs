use super::*;

fn table_rows(connection: &Connection, table: &str) -> AnchoredTestResult<Vec<Vec<Value>>> {
    let mut primary_key =
        connection.prepare("SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk")?;
    let columns = primary_key
        .query_map([table], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns.is_empty() {
        return Err("migration fixture table has no declared primary key".into());
    }
    let order = columns
        .iter()
        .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(", ");
    let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
    let count = statement.column_count();
    let rows = statement
        .query_map([], |row| {
            (0..count)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[test]
fn native_journal_migration_immutable_checkpoint_history_is_enforced() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let connection = fixture.store.connection()?;
    for table in [
        "security_participant_checkpoint_events",
        "security_participant_checkpoint_rows",
    ] {
        let before = table_rows(&connection, table)?;
        assert!(connection
            .execute(&format!("DELETE FROM {table}"), [])
            .is_err());
        assert!(connection
            .execute(
                &format!("UPDATE {table} SET security_authority_id = security_authority_id"),
                []
            )
            .is_err());
        assert!(connection
            .execute(
                &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                []
            )
            .is_err());
        assert_eq!(table_rows(&connection, table)?, before);
    }
    Ok(())
}
