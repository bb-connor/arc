use super::*;

#[test]
fn v25_upgrade_preserves_activated_dpop_and_existing_admission_without_adopting_claims(
) -> AnchoredTestResult {
    for damage in [
        None,
        Some("CREATE TABLE dpop_replay_claim_unqualified(value TEXT)"),
        Some("DROP TRIGGER dpop_replay_authority_activations_immutable"),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let domain = activate(&fixture, &source)?;
        let (operation, _, credential) = setup(
            &fixture,
            &domain,
            "v25-operation",
            "nonce",
            DpopReplayClaimPhase::Dispatch,
        )?;
        let expected = load(&fixture)?.ok_or("source absent")?;
        let before = global_count(&fixture);
        drop(source);
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
        remove_empty_v26_claims(&connection)?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 25 WHERE store_key = 'admission_operation'")?;
        if let Some(sql) = damage {
            connection.execute_batch(sql)?;
        }
        drop(connection);
        let upgraded = SqliteAuthorityStore::provision(&database, &lock_root);
        if damage.is_some() {
            assert!(upgraded.is_err());
            let connection = Connection::open(&database)?;
            assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i64>(0))?, 25);
            continue;
        }
        upgraded?;
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fixture = Fixture {
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
            _temp,
            database,
            lock_root,
        };
        assert_eq!(load(&fixture)?, Some(expected));
        assert_eq!(global_count(&fixture), before);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation.clone())
        );
        assert!(fixture
            .store
            .load_dpop_replay_claim_history(
                operation.binding().operation_id(),
                &fixture.fence,
                now_ms()
            )?
            .ok_or("operation absent")?
            .1
            .is_empty());
        let lease = claim(&fixture, &operation, "after-upgrade", now_ms());
        let intent = candidate(
            &operation,
            "new-claim",
            credential,
            DpopReplayClaimPhase::Dispatch,
        )?;
        fixture
            .store
            .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
    }
    Ok(())
}

/// Shape a predecessor only after proving the new custody namespace is empty.
/// Existing activation, source, approval and runtime history remain untouched.
pub(in super::super) fn remove_empty_v26_claims(connection: &Connection) -> rusqlite::Result<()> {
    crate::admission_operation_store::tests::security_participant_migration::remove_empty_v27_tables(connection)?;
    // Match the production migration's parent-name preservation. A default
    // ALTER TABLE would redirect other tables' triggers to the temporary name.
    let foreign_keys: bool =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let legacy_alter: bool =
        connection.pragma_query_value(None, "legacy_alter_table", |row| row.get(0))?;
    if !connection.is_autocommit() {
        // Older populated fixtures already own the rebuild transaction and
        // establish these settings before beginning it. Do not pretend that
        // changing foreign_keys inside that transaction would have an effect.
        assert!(
            !foreign_keys && legacy_alter,
            "nested fixture must preserve parent names"
        );
        return remove_empty_claims_preserving_parents(connection);
    }
    let result = (|| {
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.pragma_update(None, "legacy_alter_table", true)?;
        remove_empty_claims_preserving_parents(connection)
    })();
    let restore_foreign = connection.pragma_update(None, "foreign_keys", foreign_keys);
    let restore_legacy = connection.pragma_update(None, "legacy_alter_table", legacy_alter);
    restore_foreign?;
    restore_legacy?;
    result
}

fn remove_empty_claims_preserving_parents(connection: &Connection) -> rusqlite::Result<()> {
    for table in [
        "dpop_replay_claim_releases",
        "dpop_replay_claim_resources",
        "dpop_replay_claim_episodes",
    ] {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        if exists {
            assert_eq!(
                connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))?,
                0,
                "predecessor fixture cannot discard DPoP custody"
            );
            connection.execute_batch(&format!("DROP TABLE {table}"))?;
        }
    }
    let sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'admission_operation_commits'",
        [],
        |row| row.get(0),
    )?;
    if sql.contains("'dpop_replay_claim'") {
        assert_eq!(connection.query_row("SELECT COUNT(*) FROM admission_operation_commits WHERE mutation_kind IN ('dpop_replay_claim', 'dpop_replay_release')", [], |row| row.get::<_, i64>(0))?, 0, "predecessor cannot discard DPoP commits");
        connection.execute_batch(
            "DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits RENAME TO admission_commits_v26_fixture;",
        )?;
        let ddl = crate::admission_operation_store::schema::pre_dpop_claim_schema_fixture();
        connection.execute_batch(&ddl)?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;
            INSERT INTO admission_operation_commits SELECT * FROM admission_commits_v26_fixture ORDER BY commit_sequence;
            DROP TABLE admission_commits_v26_fixture;")?;
        connection.execute_batch(&ddl)?;
    }
    Ok(())
}
