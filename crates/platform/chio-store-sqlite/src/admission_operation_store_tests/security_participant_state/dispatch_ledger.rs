use super::*;

pub(super) fn remove_empty_v31_ledger(connection: &Connection) -> rusqlite::Result<()> {
    super::output::remove_empty_v32_output(connection)?;
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM admission_operation_native_dispatch_ledger",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'native_dispatch_ledger'", [], |row| row.get::<_, i64>(0))?, 0);
    connection.execute_batch("DROP TABLE admission_operation_native_dispatch_ledger")
}

#[cfg(unix)]
#[test]
fn v30_upgrade_adds_empty_dispatch_ledger_without_rewriting_native_history() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    remove_empty_v31_ledger(&connection)?;
    connection.execute_batch("UPDATE chio_store_schema_versions SET version = 30 WHERE store_key = 'admission_operation'")?;
    let before: Vec<(i64, String)> = {
        let mut statement = connection.prepare("SELECT commit_sequence, chain_digest FROM authority_global_commits ORDER BY commit_sequence")?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows
    };
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM admission_operation_native_dispatch_ledger",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    let mut statement = connection.prepare("SELECT commit_sequence, chain_digest FROM authority_global_commits ORDER BY commit_sequence")?;
    assert_eq!(
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<(i64, String)>>>()?,
        before
    );
    assert_eq!(native::verify_all(&connection)?, vec![initialized]);
    drop(statement);
    drop(connection);
    SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn v30_dispatch_ledger_upgrade_rejects_partial_future_catalog_without_repair() -> AnchoredTestResult
{
    for sql in [
        "CREATE TABLE admission_operation_native_dispatch_future(value TEXT)",
        "CREATE TABLE ADMISSION_OPERATION_NATIVE_DISPATCH_alias(value TEXT)",
        "CREATE VIEW admission_operation_native_dispatch_ledger AS SELECT 1",
    ] {
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            ..
        } = fixture();
        drop(store);
        drop(authority);
        let connection = Connection::open(&database)?;
        remove_empty_v31_ledger(&connection)?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 30 WHERE store_key = 'admission_operation'")?;
        connection.execute_batch(sql)?;
        let before: (i64, String) = connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
        assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
        assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, 30);
        assert_eq!(connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?, before);
    }
    Ok(())
}
