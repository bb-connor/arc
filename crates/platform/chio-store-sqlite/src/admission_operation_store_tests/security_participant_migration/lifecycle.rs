use super::*;

#[test]
fn copies_all_actual_flow_and_declassification_history_but_never_activates_it() -> AnchoredTestResult
{
    let fixture = fixture();
    let source = source(&fixture)?;
    let before = global_count(&fixture)?;
    let expected = pin(&fixture, &source)?;
    assert_eq!(
        expected.phase(),
        SecurityParticipantMigrationPhase::Expected
    );
    assert_eq!(
        expected
            .snapshot()
            .binding()
            .destination_store_uuid()
            .as_str(),
        fixture.fence.store_uuid
    );
    assert!(source.load_seal()?.is_none());
    assert_eq!(pin(&fixture, &source)?, expected);
    assert_eq!(global_count(&fixture)?, before + 1);
    let imported = import(&fixture, &source, &expected)?;
    assert_eq!(
        imported.phase(),
        SecurityParticipantMigrationPhase::ImportedInactive
    );
    assert_eq!(global_count(&fixture)?, before + 2);
    let exported = source.read_sealed_rows(expected.snapshot())?;
    {
        let connection = fixture.store.connection()?;
        let mut copied_count = 0_i64;
        for (table, rows) in exported.tables {
            let mut statement = connection.prepare(
                "SELECT canonical_row FROM security_participant_migration_rows
                WHERE security_authority_id = ?1 AND table_name = ?2 ORDER BY row_index",
            )?;
            let stored = statement
                .query_map(params![authority_id().as_str(), table], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(stored, rows, "{table}");
            copied_count += i64::try_from(rows.len())?;
        }
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM security_participant_migration_rows",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            copied_count
        );
        for (table, count) in [
            ("security_declassification_uses", 2),
            ("security_declassification_receipt_outbox", 3),
            ("security_declassification_evidence_identity", 5),
            ("security_declassification_tombstones", 1),
        ] {
            assert_eq!(connection.query_row("SELECT COUNT(*) FROM security_participant_migration_rows WHERE table_name = ?1",
                [table], |row| row.get::<_, i64>(0))?, count);
        }
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM admission_operations", [], |row| row
                .get::<_, i64>(
                0
            ))?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'security_flow_contexts'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
    }
    assert_eq!(import(&fixture, &source, &expected)?, imported);
    assert_eq!(pin(&fixture, &source)?, imported);
    assert_eq!(global_count(&fixture)?, before + 2);
    assert!(
        crate::SqliteSecurityStateStore::open(fixture._temp.path().join("security-source.db"))
            .is_err()
    );
    assert!(!format!("{imported:?}").contains("private-source"));
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
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(
        authority
            .admission_operation_store()
            .load_security_participant_migration(
                &authority_id(),
                &authority.mutation_fence(),
                now_ms()
            )?,
        Some(imported)
    );
    Ok(())
}

#[test]
fn stale_pin_rejects_changed_source_before_retirement() -> AnchoredTestResult {
    let fixture = fixture();
    let source = source(&fixture)?;
    let expected = pin(&fixture, &source)?;
    let connection = Connection::open(fixture._temp.path().join("security-source.db"))?;
    connection.execute_batch(
        "UPDATE security_flow_sequences SET last_generation = last_generation + 1",
    )?;
    assert!(import(&fixture, &source, &expected).is_err());
    assert!(source.load_seal()?.is_none());
    assert_eq!(load(&fixture)?, Some(expected));
    Ok(())
}

#[test]
fn identity_and_authority_conflicts_do_not_retire_a_source() -> AnchoredTestResult {
    let fixture = fixture();
    let source = source(&fixture)?;
    let expected = pin(&fixture, &source)?;
    let before = global_count(&fixture)?;
    for (source_id, authority) in [
        ("different", "security-authority"),
        ("private-source", "different"),
        ("different", "different"),
    ] {
        assert!(fixture
            .store
            .expect_security_participant_source(
                &identifier("source_id", source_id),
                &identifier("security_authority_id", authority),
                &source,
                &fixture.fence,
                now_ms()
            )
            .is_err());
    }
    assert!(fixture
        .store
        .import_security_participant_source(
            &authority_id(),
            &identifier("expectation_id", "wrong"),
            &source,
            &fixture.fence,
            now_ms()
        )
        .is_err());
    let mut wrong_fence = fixture.fence.clone();
    wrong_fence.owner_epoch += 1;
    assert!(fixture
        .store
        .import_security_participant_source(
            &authority_id(),
            expected.expectation_id(),
            &source,
            &wrong_fence,
            now_ms()
        )
        .is_err());
    assert!(fixture
        .store
        .load_security_participant_migration(&authority_id(), &wrong_fence, now_ms())
        .is_err());
    assert_eq!(global_count(&fixture)?, before);
    assert!(source.load_seal()?.is_none());
    Ok(())
}

#[test]
fn missing_source_does_not_erase_archive_and_import_retry_cannot_repair_it() -> AnchoredTestResult {
    let fixture = fixture();
    let source = source(&fixture)?;
    let expected = pin(&fixture, &source)?;
    let imported = import(&fixture, &source, &expected)?;
    let path = fixture._temp.path().join("security-source.db");
    fs::rename(
        &path,
        fixture._temp.path().join("retired-source-unavailable.db"),
    )?;
    let before = global_count(&fixture)?;
    assert_eq!(load(&fixture)?, Some(imported));
    assert!(import(&fixture, &source, &expected).is_err());
    assert!(!path.exists());
    assert_eq!(global_count(&fixture)?, before);
    Ok(())
}

#[test]
fn competing_imports_converge_without_duplicate_history() -> AnchoredTestResult {
    let fixture = fixture();
    let source = source(&fixture)?;
    let expected = pin(&fixture, &source)?;
    let before = global_count(&fixture)?;
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let run = || {
            barrier.wait();
            import(&fixture, &source, &expected).is_ok()
        };
        let first = scope.spawn(run);
        let second = run();
        assert!(first.join().map_err(|_| "import thread panicked")? || second);
        Ok::<_, Box<dyn Error>>(())
    })?;
    assert_eq!(
        import(&fixture, &source, &expected)?.phase(),
        SecurityParticipantMigrationPhase::ImportedInactive
    );
    assert_eq!(global_count(&fixture)?, before + 1);
    Ok(())
}

#[test]
fn observed_clock_rollback_cannot_be_hidden_by_a_plausible_caller_timestamp() -> AnchoredTestResult
{
    let fixture = fixture();
    let source = source(&fixture)?;
    let now = now_ms() / 1_000 * 1_000;
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(now / 1_000, std::iter::empty());
    let expected = pin(&fixture, &source)?;
    let before = global_count(&fixture)?;
    {
        let _rollback = chio_kernel::scope_fixed_runtime_for_current_thread(
            now / 1_000 - 1,
            std::iter::empty(),
        );
        assert!(fixture
            .store
            .import_security_participant_source(
                &authority_id(),
                expected.expectation_id(),
                &source,
                &fixture.fence,
                now
            )
            .is_err());
        assert!(fixture
            .store
            .load_security_participant_migration(&authority_id(), &fixture.fence, now)
            .is_err());
        assert!(source.load_seal()?.is_none());
    }
    assert_eq!(global_count(&fixture)?, before);
    assert_eq!(load(&fixture)?, Some(expected.clone()));
    assert!(fixture
        .store
        .import_security_participant_source(
            &authority_id(),
            expected.expectation_id(),
            &source,
            &fixture.fence,
            now + 300_001
        )
        .is_err());
    // An allowed ahead caller does not stamp its future time onto the ledger.
    fixture.store.import_security_participant_source(
        &authority_id(),
        expected.expectation_id(),
        &source,
        &fixture.fence,
        now + 1_000,
    )?;
    assert_eq!(
        load(&fixture)?.ok_or("missing import")?.phase(),
        SecurityParticipantMigrationPhase::ImportedInactive
    );
    Ok(())
}

#[test]
fn physical_identity_check_rejects_same_file_and_accepts_distinct_destination() -> AnchoredTestResult
{
    use crate::admission_operation_store::security_participant_migration::require_distinct_source;
    let fixture = fixture();
    let source = source(&fixture)?;
    let expected = pin(&fixture, &source)?;
    require_distinct_source(&*fixture.store.connection()?, expected.snapshot())?;
    let source_connection = Connection::open(fixture._temp.path().join("security-source.db"))?;
    let error = require_distinct_source(&source_connection, expected.snapshot())
        .err()
        .ok_or("same-file source was accepted")?;
    assert!(
        error
            .to_string()
            .contains("cannot be its own security source"),
        "{error}"
    );
    assert!(source.load_seal()?.is_none());
    assert_eq!(load(&fixture)?, Some(expected));
    Ok(())
}
