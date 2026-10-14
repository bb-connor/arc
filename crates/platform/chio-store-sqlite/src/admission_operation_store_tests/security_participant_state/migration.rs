use super::*;

#[cfg(unix)]
#[test]
fn pre_recovery_initialization_survives_index_publication_without_rewriting_history(
) -> AnchoredTestResult {
    let fixture = pre_recovery_fixture();
    let source = imported(&fixture, "source")?;
    {
        let connection = fixture.store.connection()?;
        remove_empty_v28_tables(&connection)?;
        connection.execute_batch(&native::schema::predecessor_sql())?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 28 WHERE store_key = 'admission_operation'")?;
    }
    let initialized =
        native::hydrate_predecessor_fixture(&fixture.store, &source, &fixture.fence, now_ms())?;
    let before: Vec<(i64, String)> = {
        let connection = fixture.store.connection()?;
        let mut statement = connection.prepare("SELECT commit_sequence, chain_digest FROM authority_global_commits ORDER BY commit_sequence")?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
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
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let connection = Connection::open(&database)?;
    let mut statement = connection.prepare("SELECT commit_sequence, chain_digest FROM authority_global_commits ORDER BY commit_sequence")?;
    assert_eq!(
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<(i64, String)>>>()?,
        before
    );
    assert_eq!(native::verify_all(&connection)?, vec![initialized.clone()]);
    assert!(initialized.requires_imported_influence_upgrade()?);
    drop(statement);
    drop(connection);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(
        authority
            .admission_operation_store()
            .load_security_participant_state(
                initialized.security_authority_id(),
                &authority.mutation_fence(),
                now_ms()
            )?,
        Some(initialized.clone())
    );
    let imported_root = |connection: &Connection| -> rusqlite::Result<Vec<(String, i64, String)>> {
        let mut statement = connection.prepare(
            "SELECT projection_reference_digest, store_owner_epoch, store_lease_id
             FROM authority_global_commits WHERE projection_kind='recovery'
               AND projection_key GLOB 'knowledge-imported-influence-root:*'
             ORDER BY commit_sequence",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect();
        rows
    };
    let root = {
        let connection = Connection::open(&database)?;
        let mut statement = connection.prepare(
            "SELECT commit_sequence, chain_digest FROM authority_global_commits
             WHERE commit_sequence <= ?1 ORDER BY commit_sequence",
        )?;
        let old_head = before.last().ok_or("pre-recovery history is absent")?.0;
        let retained = statement
            .query_map([old_head], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(retained, before);
        let root = imported_root(&connection)?;
        assert_eq!(root.len(), 1);
        assert_eq!(
            u64::try_from(root[0].1)?,
            authority.mutation_fence().owner_epoch
        );
        assert_eq!(root[0].2, authority.mutation_fence().lease_id);
        crate::admission_operation_store::verify_initialized_scope_projections(&connection)?;
        root
    };
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(imported_root(&Connection::open(&database)?)?, root);
    let fixture = Fixture {
        _temp,
        database,
        lock_root,
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
    };
    // Index publication preserves the exact observation of the retained source,
    // including after a second normal serving reopen.
    let key = chio_security_types::ports::FlowStateKey {
        tenant_id: chio_security_types::ports::TenantId::new("tenant")?,
        principal_id: chio_security_types::PrincipalId::new("principal")?,
        lineage_id: chio_security_types::ports::LineageId::new("lineage")?,
        isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("epoch")?,
        session_id: chio_security_types::ports::SessionId::new("session")?,
    };
    {
        let connection = fixture.store.connection()?;
        let expected = native::knowledge::full_scan_commitment(&connection, &initialized, &key)?;
        assert!(expected.is_some());
        let mut budget = chio_semantic_contracts::VerificationBudget::new(4096)?;
        let observed = native::knowledge::budgeted_observed_influence(
            &connection,
            &initialized.admission_binding()?,
            &key,
            &mut budget,
        )?;
        assert_eq!(observed.map(|influence| influence.commitment), expected);
    }
    let (context, request) = super::mutations::request("post-migration-join")?;
    let (operation, lease) =
        super::mutations::setup(&fixture, "post-migration-operation", &context)?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    assert_eq!(
        fixture.store.load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms()
        )?,
        Some(initialized.clone())
    );
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn v27_upgrade_adds_empty_native_tables_but_rejects_partial_future_and_aliases(
) -> AnchoredTestResult {
    for damage in [
        None,
        Some("CREATE TABLE security_participant_state_future(value TEXT)"),
        Some("CREATE TABLE SECURITY_PARTICIPANT_STATE_alias(value TEXT)"),
        Some("DROP TRIGGER security_participant_migration_rows_no_replace"),
    ] {
        let fixture = pre_recovery_fixture();
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
        remove_empty_v28_tables(&connection)?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 27 WHERE store_key = 'admission_operation'")?;
        if let Some(sql) = damage {
            connection.execute_batch(sql)?;
        }
        let head: (i64, String) = connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
        drop(connection);
        let result = SqliteAuthorityStore::provision(&database, &lock_root);
        let connection = Connection::open(&database)?;
        let version: i32 = connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get(0))?;
        assert_eq!(connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?, head);
        if damage.is_some() {
            assert!(result.is_err());
            assert_eq!(version, 27);
        } else {
            result?;
            assert_eq!(version, ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
            assert!(native::verify_all(&connection)?.is_empty());
            SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        }
    }
    Ok(())
}

#[test]
fn missing_current_native_barrier_is_never_repaired() -> AnchoredTestResult {
    let fixture = fixture();
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
    connection.execute_batch("DROP TRIGGER security_participant_state_0_inactive_insert")?;
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'security_participant_state_0_inactive_insert'", [], |row| row.get::<_, i64>(0))?, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn v27_import_history_and_global_digests_survive_empty_v28_upgrade() -> AnchoredTestResult {
    let fixture = pre_recovery_fixture();
    let source = imported(&fixture, "source")?;
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
    remove_empty_v28_tables(&connection)?;
    connection.execute_batch("UPDATE chio_store_schema_versions SET version = 27 WHERE store_key = 'admission_operation'")?;
    let history = |connection: &Connection| -> rusqlite::Result<Vec<(i64, String)>> {
        let mut statement = connection.prepare("SELECT commit_sequence, chain_digest FROM authority_global_commits ORDER BY commit_sequence")?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect();
        rows
    };
    let before = history(&connection)?;
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let connection = Connection::open(&database)?;
    assert_eq!(history(&connection)?, before);
    assert!(native::verify_all(&connection)?.is_empty());
    drop(connection);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    let key = identifier("security_authority_id", "source");
    assert_eq!(
        store.load_security_participant_migration(&key, &authority.mutation_fence(), now_ms())?,
        Some(source.clone())
    );
    store.hydrate_security_participant_state(
        &key,
        source.expectation_id(),
        &authority.mutation_fence(),
        now_ms(),
    )?;
    Ok(())
}
