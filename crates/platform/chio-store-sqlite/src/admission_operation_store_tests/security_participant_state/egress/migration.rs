use super::*;

fn drop_empty_egress(connection: &Connection) -> rusqlite::Result<()> {
    super::super::dispatch_ledger::remove_empty_v31_ledger(connection)?;
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM security_participant_egress_events",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'security_participant_egress'", [], |row| row.get::<_, i64>(0))?, 0);
    connection.execute_batch("DROP TABLE security_participant_egress_events")
}

fn global_history(connection: &Connection) -> AnchoredTestResult<Vec<(i64, String)>> {
    let mut statement = connection.prepare("SELECT commit_sequence, chain_digest FROM authority_global_commits ORDER BY commit_sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[test]
fn v29_upgrade_preserves_native_initialization_join_bytes_and_global_digests() -> AnchoredTestResult
{
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let mut pending = pending(&fixture, "egress-upgrade", None)?;
    let before_joins = joins(&fixture)?;
    let before_global = global_history(&*fixture.store.connection()?)?;
    let Fixture {
        _temp,
        database,
        lock_root,
        store,
        authority,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    drop_empty_egress(&connection)?;
    connection.execute_batch("UPDATE chio_store_schema_versions SET version = 29 WHERE store_key = 'admission_operation'")?;
    native::verify_coverage(&connection)?;
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let connection = Connection::open(&database)?;
    assert_eq!(global_history(&connection)?, before_global);
    assert_eq!(native::verify_all(&connection)?, vec![initialized.clone()]);
    assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
    drop(connection);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fixture = Fixture {
        _temp,
        database,
        lock_root,
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
    };
    assert_eq!(joins(&fixture)?, before_joins);
    pending.operation = fixture
        .store
        .load_by_operation_id(pending.operation.binding().operation_id())?
        .ok_or("operation absent")?;
    pending.lease = renew(&fixture, &pending.operation, &pending.lease)?;
    let acquired = pending.acquire(&fixture)?;
    pending.commit(&fixture, &commitment(&acquired)?)?;
    assert_eq!(joins(&fixture)?, before_joins);
    assert_eq!(
        fixture.store.load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms()
        )?,
        Some(initialized)
    );
    Ok(())
}

#[test]
fn v29_upgrade_rejects_partial_or_alias_future_catalog_without_repair() -> AnchoredTestResult {
    for sql in [
        "CREATE TABLE security_participant_egress_future(value TEXT)",
        "CREATE TABLE SECURITY_PARTICIPANT_EGRESS_alias(value TEXT)",
        "CREATE VIEW security_participant_egress_events AS SELECT 1",
    ] {
        let fixture = fixture();
        let Fixture {
            _temp,
            database,
            lock_root,
            store,
            authority,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let connection = Connection::open(&database)?;
        drop_empty_egress(&connection)?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 29 WHERE store_key = 'admission_operation'")?;
        connection.execute_batch(sql)?;
        let before = global_history(&connection)?;
        assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
        assert_eq!(global_history(&connection)?, before);
        assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, 29);
    }
    Ok(())
}

#[test]
fn missing_current_egress_catalog_is_not_repaired() -> AnchoredTestResult {
    for sql in [
        "DROP TABLE security_participant_egress_events",
        "DROP TRIGGER security_participant_egress_events_no_update",
    ] {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        fixture.store.connection()?.execute_batch(sql)?;
        assert!(
            fixture
                .store
                .load_security_participant_state(
                    initialized.security_authority_id(),
                    &fixture.fence,
                    now_ms(),
                )
                .is_err(),
            "live reads must reject a missing current catalog"
        );
        let Fixture {
            _temp,
            database,
            lock_root,
            store,
            authority,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let connection = Connection::open(&database)?;
        let before = global_history(&connection)?;
        assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
        assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
        assert_eq!(global_history(&connection)?, before);
    }
    Ok(())
}
