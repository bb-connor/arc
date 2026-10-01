use super::*;
use chio_kernel::dpop::authority::{DpopReplayAuthorityInputV1, DpopReplayAuthorityV1};

pub(super) fn domain(
    record: &DpopReplayMigrationRecordV1,
) -> AnchoredTestResult<DpopReplayAuthorityV1> {
    Ok(DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
        destination_store_uuid: identifier(
            "destination",
            record.snapshot().destination_authority_id(),
        ),
        dpop_authority_id: identifier("authority", AUTHORITY_ID),
        expectation_id: AdmissionDigest::try_new("expectation", record.expectation_id().as_str())?,
        proof_ttl_secs: 300,
        max_clock_skew_secs: 30,
    })?)
}

fn activate(
    fixture: &Fixture,
    source: &dyn DpopReplaySourcePort,
    domain: &DpopReplayAuthorityV1,
) -> Result<DpopReplayMigrationRecordV1, AdmissionOperationStoreError> {
    fixture
        .store
        .activate_dpop_replay_source(domain, source, &fixture.fence, now_ms())
}

#[test]
fn explicit_activation_is_atomic_immutable_and_never_a_legacy_cache_reset() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let pinned = pin(&fixture, &source)?;
    let authority = domain(&pinned)?;
    assert!(activate(&fixture, &source, &authority).is_err());
    assert_eq!(source.calls(), ["preview"]);
    let imported = import(&fixture, &source, &pinned)?;
    let before = global_count(&fixture);
    let active = activate(&fixture, &source, &authority)?;
    assert!(active.is_active());
    assert!(active.is_imported());
    assert!(!active.imported_inactive());
    assert_eq!(active.event_sequence(), 3);
    assert_eq!(active.authority(), Some(&authority));
    assert_eq!(active.snapshot(), imported.snapshot());
    assert_eq!(counts(&fixture), [3, 3, 1]);
    assert_eq!(global_count(&fixture), before + 1);
    assert!(source
        .raw
        .check_and_insert("new-proof", "capability")
        .is_err());
    let calls = source.calls().len();
    assert_eq!(activate(&fixture, &source, &authority)?, active);
    assert_eq!(source.calls().len(), calls);
    assert_eq!(global_count(&fixture), before + 1);
    assert_eq!(
        fixture
            .store
            .load_dpop_replay_activation(&authority, &fixture.fence, now_ms())?,
        authority
    );
    Ok(())
}

#[test]
fn committed_activation_survives_source_loss_but_inactive_import_does_not_activate_itself(
) -> AnchoredTestResult {
    for committed in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
        let domain = domain(&imported)?;
        if committed {
            activate(&fixture, &source, &domain)?;
        }
        drop(source);
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            fence,
        } = fixture;
        drop(store);
        drop(authority);
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fixture = Fixture {
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
            _temp,
            database,
            lock_root,
        };
        let replacement = Source::new(&fixture, true)?;
        assert!(fixture
            .store
            .load_dpop_replay_activation(&domain, &fence, now_ms())
            .is_err());
        assert_eq!(
            fixture
                .store
                .load_dpop_replay_activation(&domain, &fixture.fence, now_ms())
                .is_ok(),
            committed
        );
        assert_eq!(activate(&fixture, &replacement, &domain).is_ok(), committed);
        assert_eq!(
            replacement.calls(),
            if committed { vec![] } else { vec!["verify"] }
        );
        assert_eq!(counts(&fixture), [3, if committed { 3 } else { 2 }, 1]);
    }
    Ok(())
}

#[test]
fn activation_rejects_wrong_generation_stale_owner_and_policy_replacement() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
    let domain = domain(&imported)?;
    let mut wrong: serde_json::Value = serde_json::to_value(&domain)?;
    wrong["expectation_id"] = "b".repeat(64).into();
    let wrong: DpopReplayAuthorityV1 = serde_json::from_value(wrong)?;
    let calls = source.calls().len();
    assert!(activate(&fixture, &source, &wrong).is_err());
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert!(fixture
        .store
        .activate_dpop_replay_source(&domain, &source, &stale, now_ms())
        .is_err());
    assert_eq!(source.calls().len(), calls);
    activate(&fixture, &source, &domain)?;
    let mut changed = serde_json::to_value(&domain)?;
    changed["proof_ttl_secs"] = 301.into();
    let changed = serde_json::from_value(changed)?;
    let calls = source.calls().len();
    assert!(activate(&fixture, &source, &changed).is_err());
    assert!(fixture
        .store
        .load_dpop_replay_activation(&changed, &fixture.fence, now_ms())
        .is_err());
    assert_eq!(source.calls().len(), calls);
    Ok(())
}

#[test]
fn activation_cutpoints_never_leave_a_domain_without_its_event_and_global_commit(
) -> AnchoredTestResult {
    for (table, predicate) in [
        ("dpop_replay_authority_activations", "1"),
        ("dpop_replay_migration_events", "NEW.sequence = 3"),
        (
            "authority_global_commits",
            "NEW.mutation_kind = 'activate_dpop_replay_source'",
        ),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
        let domain = domain(&imported)?;
        let before = global_count(&fixture);
        fixture.store.connection()?.execute_batch(&format!("CREATE TEMP TRIGGER fail_dpop_activation BEFORE INSERT ON main.{table} WHEN {predicate} BEGIN SELECT RAISE(ABORT, 'injected activation failure'); END;"))?;
        assert!(activate(&fixture, &source, &domain).is_err(), "{table}");
        assert_eq!(load(&fixture)?, Some(imported));
        assert_eq!(global_count(&fixture), before);
        assert_eq!(
            fixture.store.connection()?.query_row(
                "SELECT COUNT(*) FROM dpop_replay_authority_activations",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER temp.fail_dpop_activation")?;
        assert!(activate(&fixture, &source, &domain)?.is_active());
    }
    Ok(())
}

#[test]
fn activation_policy_tampering_is_covered_by_the_existing_global_chain() -> AnchoredTestResult {
    for mutation in [
        "UPDATE dpop_replay_authority_activations SET canonical_authority = CAST('{}' AS BLOB)",
        "UPDATE dpop_replay_authority_activations SET canonical_authority = CAST(replace(CAST(canonical_authority AS TEXT), '\"proof_ttl_secs\":300', '\"proof_ttl_secs\":301') AS BLOB)",
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
        let domain = domain(&imported)?;
        activate(&fixture, &source, &domain)?;
        let connection = fixture.store.connection()?;
        let ddl: String = connection.query_row("SELECT sql FROM sqlite_schema WHERE name = 'dpop_replay_authority_activations_immutable'", [], |row| row.get(0))?;
        connection.execute_batch(&format!("DROP TRIGGER dpop_replay_authority_activations_immutable; {mutation}; {ddl};"))?;
        assert!(crate::admission_operation_store::verify_dpop_replay_projection_coverage(&connection).is_err());
        drop(connection);
        assert!(fixture.store.load_dpop_replay_activation(&domain, &fixture.fence, now_ms()).is_err());
        drop(source);
        let Fixture { _temp, database, lock_root, authority, store, .. } = fixture;
        drop(store);
        drop(authority);
        assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    }
    Ok(())
}

#[test]
fn activation_guards_reject_replace_update_and_delete_without_recursive_triggers(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
    let domain = domain(&imported)?;
    activate(&fixture, &source, &domain)?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("PRAGMA recursive_triggers = OFF")?;
    for sql in ["INSERT OR REPLACE INTO dpop_replay_authority_activations SELECT * FROM dpop_replay_authority_activations",
        "UPDATE dpop_replay_authority_activations SET dpop_authority_id = dpop_authority_id",
        "DELETE FROM dpop_replay_authority_activations"] {
        assert!(connection.execute(sql, []).is_err(), "{sql}");
    }
    crate::admission_operation_store::verify_dpop_replay_projection_coverage(&connection)?;
    Ok(())
}

#[test]
fn active_authority_lookup_reuses_verified_records_without_skipping_global_coverage(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
    let domain = domain(&imported)?;
    let active = activate(&fixture, &source, &domain)?;
    let connection = fixture.store.connection()?;
    let lookup = || {
        crate::admission_operation_store::dpop_replay::require_active_authority(
            &connection,
            &domain,
        )
    };
    assert_eq!(lookup()?, active);
    // Mutate through the owning test connection so external-write detection
    // cannot mask a missing local-to-global coverage check.
    let ddl: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'authority_global_commits_no_delete'",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch(&format!(
        "DROP TRIGGER authority_global_commits_no_delete;
         DELETE FROM authority_global_commits WHERE projection_kind = 'dpop_replay_migration'
           AND projection_sequence = 1;
         {ddl}"
    ))?;
    assert!(lookup().is_err());
    Ok(())
}

#[test]
fn failed_or_panicking_source_verification_leaves_activation_inactive_and_retryable(
) -> AnchoredTestResult {
    for panic in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
        let domain = domain(&imported)?;
        let before = global_count(&fixture);
        {
            let mut state = source.state.lock().expect("state");
            state.unavailable = !panic;
            state.panic_on = panic.then_some("verify");
        }
        assert!(activate(&fixture, &source, &domain).is_err());
        assert_eq!(load(&fixture)?, Some(imported));
        assert_eq!(global_count(&fixture), before);
        {
            let mut state = source.state.lock().expect("state");
            state.unavailable = false;
            state.panic_on = None;
        }
        assert!(activate(&fixture, &source, &domain)?.is_active());
    }
    Ok(())
}

#[test]
fn v24_upgrade_preserves_import_events_and_bytes_without_inventing_activation() -> AnchoredTestResult
{
    for damage in [
        None,
        Some("CREATE TABLE dpop_replay_authority_unknown(value TEXT)"),
        Some("DROP TRIGGER dpop_replay_migration_events_immutable"),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
        let domain = domain(&imported)?;
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
        remove_empty_v25_activation(&connection)?;
        connection.execute_batch(
            "DROP TRIGGER dpop_replay_migration_events_no_replace;
            DROP TRIGGER dpop_replay_migration_events_immutable;
            DROP TRIGGER dpop_replay_migration_events_no_delete;
            ALTER TABLE dpop_replay_migration_events RENAME TO dpop_v25_fixture_events;",
        )?;
        connection.execute_batch(
            &crate::admission_operation_store::schema::pre_dpop_activation_schema_fixture(),
        )?;
        connection.execute_batch("INSERT INTO dpop_replay_migration_events SELECT * FROM dpop_v25_fixture_events;
            DROP TABLE dpop_v25_fixture_events;
            UPDATE chio_store_schema_versions SET version = 24 WHERE store_key = 'admission_operation';")?;
        if let Some(sql) = damage {
            connection.execute_batch(sql)?;
        }
        drop(connection);
        let result = SqliteAuthorityStore::provision(&database, &lock_root);
        if damage.is_some() {
            assert!(result.is_err());
            assert_eq!(Connection::open(&database)?.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'", [], |row| row.get::<_, i32>(0))?, 24);
        } else {
            result?;
            let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
            let store = authority.admission_operation_store();
            let fence = authority.mutation_fence();
            assert_eq!(
                store.load_dpop_replay_migration(
                    &identifier("authority", AUTHORITY_ID),
                    &fence,
                    now_ms()
                )?,
                Some(imported)
            );
            assert!(store
                .load_dpop_replay_activation(&domain, &fence, now_ms())
                .is_err());
            assert_eq!(
                store.connection()?.query_row(
                    "SELECT COUNT(*) FROM authority_global_commits",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                before
            );
        }
    }
    Ok(())
}

pub(super) fn remove_empty_v25_activation(connection: &Connection) -> rusqlite::Result<()> {
    super::claims::migration::remove_empty_v26_claims(connection)?;
    let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'dpop_replay_authority_activations')", [], |row| row.get(0))?;
    if exists {
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM dpop_replay_authority_activations",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0,
            "predecessor fixture cannot discard an activated DPoP domain"
        );
        connection.execute_batch("DROP TABLE dpop_replay_authority_activations")?;
    }
    Ok(())
}
