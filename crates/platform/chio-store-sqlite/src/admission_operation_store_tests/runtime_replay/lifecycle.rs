use super::*;

#[test]
fn pins_then_imports_complete_inventory_as_inactive_permanent_tombstones() -> AnchoredTestResult {
    for empty in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, empty);
        let before = global_count(&fixture.store);
        assert!(load(&fixture)?.is_none());
        let expected = pin(&fixture, &source)?;
        assert!(!expected.imported_inactive());
        assert_eq!(expected.event_sequence(), 1);
        assert_eq!(expected.snapshot().source_id(), SOURCE_ID);
        assert_eq!(expected.snapshot().runtime_authority_id(), RUNTIME_ID);
        assert_eq!(
            expected.snapshot().destination_authority_id(),
            fixture.fence.store_uuid
        );
        assert_eq!(expected.snapshot().device(), u64::MAX);
        assert_eq!(expected.snapshot().inode(), u64::MAX - 1);
        assert_eq!(
            expected.snapshot().markers().len(),
            if empty { 0 } else { 3 }
        );
        assert_eq!(source.calls(), ["preview"]);
        assert_eq!(global_count(&fixture.store), before + 1);
        assert_record_equal(&load(&fixture)?.expect("retained expectation"), &expected);
        assert_record_equal(&pin(&fixture, &source)?, &expected);
        assert_eq!(
            global_count(&fixture.store),
            before + 1,
            "exact pin retry is read-only"
        );
        assert_eq!(
            source.calls(),
            ["preview"],
            "retry uses retained expectation, not a fresh discovery"
        );

        let imported = import(&fixture, &source, &expected)?;
        assert!(imported.imported_inactive());
        assert_eq!(imported.event_sequence(), 2);
        assert_eq!(imported.expectation_id(), expected.expectation_id());
        assert_eq!(imported.expectation_digest(), expected.expectation_digest());
        assert_eq!(
            imported.snapshot().canonical_bytes(),
            expected.snapshot().canonical_bytes()
        );
        assert_eq!(global_count(&fixture.store), before + 2);
        assert_record_equal(&load(&fixture)?.expect("retained import"), &imported);
        assert_record_equal(&import(&fixture, &source, &expected)?, &imported);
        assert_record_equal(&pin(&fixture, &source)?, &imported);
        assert_eq!(
            global_count(&fixture.store),
            before + 2,
            "retries do not create a new generation"
        );
        assert!(source.calls().contains(&"seal"));
        assert!(source.calls().contains(&"verify"));
        assert_eq!(
            source
                .calls()
                .iter()
                .filter(|call| **call == "preview")
                .count(),
            1
        );

        let connection = fixture.store.connection()?;
        let actual: Vec<(String, String, String, String, String, String)> = connection.prepare(
            "SELECT runtime_authority_id, participant_kind, resource_id, source_id, expectation_id, historical_admission_id
             FROM runtime_replay_legacy_tombstones ORDER BY participant_kind",
        )?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)))?
            .collect::<Result<_, _>>()?;
        let wanted = if empty {
            vec![]
        } else {
            [
                ("destructive_lease", "historical-admission-0"),
                ("swarm_continuation", "historical-swarm"),
                ("treaty_continuation", "historical-treaty"),
            ]
            .into_iter()
            .map(|(kind, historical)| {
                (
                    RUNTIME_ID.into(),
                    kind.into(),
                    "same-resource".into(),
                    SOURCE_ID.into(),
                    expected.expectation_id().as_str().into(),
                    historical.into(),
                )
            })
            .collect()
        };
        assert_eq!(
            actual, wanted,
            "each kind retains its original replay key and historical owner only"
        );
        let operation_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM admission_operations", [], |row| {
                row.get(0)
            })?;
        assert_eq!(
            operation_count, 0,
            "migration must not fabricate admission operation ownership"
        );
        verify_admission_operation_invariants(&connection)?;
    }
    Ok(())
}

#[test]
fn qualified_restart_recovers_pin_and_import_without_rediscovering_source() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let expected = pin(&fixture, &source)?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(source);
    drop(store);
    drop(authority);

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    let runtime = identifier("runtime_authority_id", RUNTIME_ID);
    let recovered = store
        .load_runtime_replay_migration(&runtime, &fence, now_ms())?
        .expect("pin survives restart");
    assert_record_equal(&recovered, &expected);
    let source = Source {
        connection: Arc::clone(&store.connection),
        state: Mutex::new(SourceState::default()),
    };
    let imported = store.import_runtime_replay_source(
        &runtime,
        expected.expectation_id(),
        &source,
        &fence,
        now_ms(),
    )?;
    assert!(imported.imported_inactive());
    assert!(!source.calls().contains(&"preview"));
    let sealed = source.state.lock().expect("source state").sealed.clone();
    drop(source);
    drop(store);
    drop(authority);

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    let recovered = store
        .load_runtime_replay_migration(&runtime, &fence, now_ms())?
        .expect("import survives restart");
    assert_record_equal(&recovered, &imported);
    let source = Source {
        connection: Arc::clone(&store.connection),
        state: Mutex::new(SourceState {
            sealed,
            ..SourceState::default()
        }),
    };
    let before = global_count(&store);
    assert_record_equal(
        &store.import_runtime_replay_source(
            &runtime,
            expected.expectation_id(),
            &source,
            &fence,
            now_ms(),
        )?,
        &imported,
    );
    assert_eq!(global_count(&store), before);
    assert!(!source.calls().contains(&"preview"));
    Ok(())
}

#[test]
fn missing_pin_and_wrong_expectation_cannot_seal_a_source() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let runtime = identifier("runtime_authority_id", RUNTIME_ID);
    let wrong = identifier("expectation_id", "not-retained");
    let error = fixture
        .store
        .import_runtime_replay_source(&runtime, &wrong, &source, &fixture.fence, now_ms())
        .expect_err("pin required before source mutation");
    assert!(
        matches!(error, AdmissionOperationStoreError::Invariant(ref message) if message.contains("runtime replay migration expectation not found")),
        "{error:?}"
    );
    assert!(source.calls().is_empty());
    let expected = pin(&fixture, &source)?;
    let error = fixture
        .store
        .import_runtime_replay_source(&runtime, &wrong, &source, &fixture.fence, now_ms())
        .expect_err("exact pinned ID required");
    assert!(
        matches!(error, AdmissionOperationStoreError::Invariant(ref message) if message.contains("runtime replay migration source generation mismatch")),
        "{error:?}"
    );
    assert_eq!(source.calls(), ["preview"]);
    assert_record_equal(&load(&fixture)?.expect("pin remains"), &expected);
    Ok(())
}

#[test]
fn stale_fences_reject_before_every_source_callback() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    let source_id = identifier("source_id", SOURCE_ID);
    let runtime = identifier("runtime_authority_id", RUNTIME_ID);
    assert_eq!(
        fixture
            .store
            .expect_runtime_replay_source(&source_id, &runtime, &source, &stale, now_ms())
            .expect_err("pin fenced"),
        AdmissionOperationStoreError::Fenced
    );
    assert!(source.calls().is_empty());
    let expected = pin(&fixture, &source)?;
    assert_eq!(
        fixture
            .store
            .import_runtime_replay_source(
                &runtime,
                expected.expectation_id(),
                &source,
                &stale,
                now_ms()
            )
            .expect_err("import fenced"),
        AdmissionOperationStoreError::Fenced
    );
    assert_eq!(
        fixture
            .store
            .load_runtime_replay_migration(&runtime, &stale, now_ms())
            .expect_err("read fenced"),
        AdmissionOperationStoreError::Fenced
    );
    assert_eq!(source.calls(), ["preview"]);
    Ok(())
}

#[test]
fn changed_source_after_pin_is_not_replaced_or_imported() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let expected = pin(&fixture, &source)?;
    source.state.lock().expect("source state").revision = 1;
    let before = global_count(&fixture.store);
    let error = import(&fixture, &source, &expected).expect_err("changed source cannot be sealed");
    assert!(
        matches!(error, AdmissionOperationStoreError::Invariant(ref message) if message.contains("fixture source changed before sealing")),
        "{error:?}"
    );
    assert!(source.state.lock().expect("source state").sealed.is_none());
    assert_record_equal(&load(&fixture)?.expect("original pin remains"), &expected);
    assert_record_equal(&pin(&fixture, &source)?, &expected);
    assert_eq!(global_count(&fixture.store), before);
    let connection = fixture.store.connection()?;
    let tombstones: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_replay_legacy_tombstones",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(tombstones, 0);
    Ok(())
}

#[test]
fn lost_source_seal_acknowledgement_retries_the_exact_pinned_generation() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let expected = pin(&fixture, &source)?;
    source
        .state
        .lock()
        .expect("source state")
        .lose_seal_ack_once = true;
    let before = global_count(&fixture.store);
    let error =
        import(&fixture, &source, &expected).expect_err("lost seal acknowledgement is not success");
    assert!(
        matches!(error, AdmissionOperationStoreError::OutcomeUnknown(ref message) if message.contains("fixture seal committed")),
        "{error:?}"
    );
    assert_eq!(
        source.state.lock().expect("source state").sealed.as_deref(),
        Some(expected.snapshot().canonical_bytes())
    );
    assert_record_equal(
        &load(&fixture)?.expect("pending pin survives uncertain source outcome"),
        &expected,
    );
    assert_eq!(global_count(&fixture.store), before);
    let imported = import(&fixture, &source, &expected)?;
    assert!(imported.imported_inactive());
    assert_eq!(global_count(&fixture.store), before + 1);
    assert_eq!(
        source
            .calls()
            .iter()
            .filter(|call| **call == "preview")
            .count(),
        1
    );
    Ok(())
}

#[test]
fn runtime_and_source_namespaces_cannot_be_rebound_or_replaced() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let expected = pin(&fixture, &source)?;
    let before = global_count(&fixture.store);
    for (source_id, runtime_id) in [("other-source", RUNTIME_ID), (SOURCE_ID, "other-runtime")] {
        let error = fixture
            .store
            .expect_runtime_replay_source(
                &identifier("source_id", source_id),
                &identifier("runtime_authority_id", runtime_id),
                &source,
                &fixture.fence,
                now_ms(),
            )
            .expect_err("a retained migration namespace cannot be rebound");
        let reason = if runtime_id == RUNTIME_ID {
            "runtime replay migration source binding mismatch"
        } else {
            "runtime replay migration expectation conflict"
        };
        assert!(
            matches!(error, AdmissionOperationStoreError::Invariant(ref message) if message.contains(reason)),
            "{error:?}"
        );
    }
    assert_record_equal(&load(&fixture)?.expect("unchanged pin"), &expected);
    assert_eq!(global_count(&fixture.store), before);
    assert!(!source.calls().contains(&"seal"));
    Ok(())
}

#[test]
fn imported_retry_verifies_live_barriers_without_resealing_missing_source_history(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let expected = pin(&fixture, &source)?;
    let imported = import(&fixture, &source, &expected)?;
    let before = global_count(&fixture.store);
    {
        let mut state = source.state.lock().expect("source state");
        // Model lost source barrier history while preserving identity and
        // inventory. The qualified destination knows import already happened.
        state.sealed = None;
        state.calls.clear();
    }
    let error = import(&fixture, &source, &expected)
        .expect_err("known-imported source cannot be silently resealed");
    assert!(
        matches!(error, AdmissionOperationStoreError::Invariant(ref message)
        if message.contains("fixture live source does not match its retained seal")),
        "{error:?}"
    );
    assert_eq!(source.calls(), ["verify"]);
    assert!(source.state.lock().expect("source state").sealed.is_none());
    assert_record_equal(
        &load(&fixture)?.expect("destination history remains immutable"),
        &imported,
    );
    assert_eq!(global_count(&fixture.store), before);
    Ok(())
}

#[test]
fn migration_authority_clock_regression_rejects_reads_imports_and_new_namespaces(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let now = now_ms() / 1_000;
    let expected = {
        let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(now, std::iter::empty());
        pin(&fixture, &source)?
    };
    source.state.lock().expect("source state").calls.clear();
    let before = global_count(&fixture.store);
    {
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(now - 1, std::iter::empty());
        let errors = [
            load(&fixture).expect_err("historical reads still require a current authority clock"),
            import(&fixture, &source, &expected)
                .expect_err("clock regression cannot seal or import"),
            fixture
                .store
                .expect_runtime_replay_source(
                    &identifier("source_id", "new-source"),
                    &identifier("runtime_authority_id", "new-runtime"),
                    &source,
                    &fixture.fence,
                    now_ms(),
                )
                .expect_err("a new namespace cannot bypass the migration-wide clock high-water"),
        ];
        for error in errors {
            assert!(
                matches!(error, AdmissionOperationStoreError::Invariant(ref message)
                if message.contains("runtime replay migration authority time regressed")),
                "{error:?}"
            );
        }
    }
    assert!(source.calls().is_empty());
    assert_eq!(global_count(&fixture.store), before);
    assert_record_equal(
        &load(&fixture)?.expect("same pinned generation after clock recovers"),
        &expected,
    );
    Ok(())
}
