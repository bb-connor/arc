use super::*;

#[test]
fn exact_pin_import_and_retry_preserve_every_marker_without_activation() -> AnchoredTestResult {
    for empty in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, empty)?;
        let before = global_count(&fixture);
        let expected = pin(&fixture, &source)?;
        assert_eq!(counts(&fixture), [0, 1, 1]);
        assert!(!expected.is_imported());
        assert_eq!(expected.event_sequence(), 1);
        assert_eq!(pin(&fixture, &source)?, expected);
        assert_eq!(source.calls(), ["preview"]);
        let imported = import(&fixture, &source, &expected)?;
        assert!(imported.imported_inactive());
        assert_eq!(imported.event_sequence(), 2);
        assert_eq!(imported.snapshot(), expected.snapshot());
        assert_eq!(counts(&fixture), [if empty { 0 } else { 3 }, 2, 1]);
        assert_eq!(global_count(&fixture), before + 2);
        assert_eq!(pin(&fixture, &source)?, imported);
        assert_eq!(import(&fixture, &source, &expected)?, imported);
        assert_eq!(source.calls(), ["preview", "seal", "verify", "verify"]);
        assert_eq!(global_count(&fixture), before + 2);
        assert!(source.raw.check_and_insert("new", "capability").is_err());
        assert!(source
            .raw
            .preview_unsealed(expected.snapshot().binding())
            .is_err());
        let connection = fixture.store.connection()?;
        let mut statement = connection.prepare("SELECT canonical_marker FROM dpop_replay_legacy_tombstones ORDER BY capability_id COLLATE BINARY, nonce COLLATE BINARY")?;
        let markers = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            markers,
            expected
                .snapshot()
                .markers()
                .iter()
                .map(chio_core::canonical::canonical_json_bytes)
                .collect::<Result<Vec<_>, _>>()?
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM admission_operation_commits",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
    }
    Ok(())
}

#[test]
fn destination_reopen_preserves_pending_and_imported_history_but_requires_the_live_source(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    let raw = Arc::clone(&source.raw);
    let instance = source.instance.clone();
    drop(source);
    let (fixture, stale) = reopen(fixture)?;
    let source = Source::attach(Arc::clone(&raw), instance.clone(), &fixture.store);
    assert!(fixture
        .store
        .load_dpop_replay_migration(&identifier("authority", AUTHORITY_ID), &stale, now_ms())
        .is_err());
    assert_eq!(pin(&fixture, &source)?, expected);
    assert!(source.calls().is_empty());
    let imported = import(&fixture, &source, &expected)?;
    drop(source);
    let (fixture, _) = reopen(fixture)?;
    let source = Source::attach(raw, instance, &fixture.store);
    assert_eq!(load(&fixture)?, Some(imported.clone()));
    assert_eq!(import(&fixture, &source, &expected)?, imported);
    assert_eq!(source.calls(), ["verify"]);
    let replacement = Source::new(&fixture, true)?;
    assert!(pin(&fixture, &replacement).is_err());
    assert!(replacement.calls().is_empty());
    assert!(import(&fixture, &replacement, &expected).is_err());
    assert_eq!(replacement.calls(), ["verify"]);
    assert_eq!(counts(&fixture), [3, 2, 1]);
    Ok(())
}

fn reopen(fixture: Fixture) -> AnchoredTestResult<(Fixture, StoreMutationFence)> {
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
    Ok((
        Fixture {
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
            _temp,
            database,
            lock_root,
        },
        fence,
    ))
}

#[test]
fn source_replacement_before_seal_cannot_complete_the_pinned_generation() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    drop(source);
    let replacement = Source::new(&fixture, true)?;
    assert!(import(&fixture, &replacement, &expected).is_err());
    assert_eq!(replacement.calls(), ["seal"]);
    assert_eq!(counts(&fixture), [0, 1, 1]);
    assert_eq!(load(&fixture)?, Some(expected));
    assert!(replacement
        .raw
        .check_and_insert("still-unsealed", "capability")?);
    Ok(())
}

#[test]
fn source_instance_cannot_be_pinned_under_a_second_authority() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    assert!(fixture
        .store
        .expect_dpop_replay_source(
            &source.instance,
            &identifier("authority", "different"),
            &source,
            &fixture.fence,
            now_ms()
        )
        .is_err());
    assert_eq!(counts(&fixture), [0, 1, 1]);
    assert!(import(&fixture, &source, &expected)?.imported_inactive());
    Ok(())
}

#[test]
fn stale_fences_wrong_instances_and_generations_deny_before_callbacks() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert!(fixture
        .store
        .expect_dpop_replay_source(
            &source.instance,
            &identifier("authority", AUTHORITY_ID),
            &source,
            &stale,
            now_ms()
        )
        .is_err());
    assert!(source.calls().is_empty());
    let expected = pin(&fixture, &source)?;
    assert!(fixture
        .store
        .expect_dpop_replay_source(
            &identifier("instance", "wrong"),
            &identifier("authority", AUTHORITY_ID),
            &source,
            &fixture.fence,
            now_ms()
        )
        .is_err());
    assert!(fixture
        .store
        .import_dpop_replay_source(
            &identifier("authority", AUTHORITY_ID),
            expected.expectation_id(),
            &source,
            &stale,
            now_ms()
        )
        .is_err());
    assert!(fixture
        .store
        .import_dpop_replay_source(
            &identifier("authority", AUTHORITY_ID),
            &identifier("generation", "wrong"),
            &source,
            &fixture.fence,
            now_ms()
        )
        .is_err());
    assert_eq!(source.calls(), ["preview"]);
    assert_eq!(counts(&fixture), [0, 1, 1]);
    Ok(())
}

#[test]
fn mutation_after_pin_refuses_seal_without_repinning_or_source_repair() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    assert!(source.raw.check_and_insert("changed", "capability")?);
    assert!(import(&fixture, &source, &expected).is_err());
    assert_eq!(pin(&fixture, &source)?, expected);
    assert_eq!(counts(&fixture), [0, 1, 1]);
    assert!(source
        .raw
        .check_and_insert("still-unsealed", "capability")?);
    Ok(())
}

#[test]
fn authority_clock_regression_denies_before_source_access() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let now = now_ms() / 1000 + 5;
    let expected = {
        let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(now, std::iter::empty());
        fixture.store.expect_dpop_replay_source(
            &source.instance,
            &identifier("authority", AUTHORITY_ID),
            &source,
            &fixture.fence,
            now * 1000,
        )?
    };
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(now - 1, std::iter::empty());
    assert!(fixture
        .store
        .import_dpop_replay_source(
            &identifier("authority", AUTHORITY_ID),
            expected.expectation_id(),
            &source,
            &fixture.fence,
            (now - 1) * 1000
        )
        .is_err());
    assert_eq!(source.calls(), ["preview"]);
    drop(_clock);
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(now, std::iter::empty());
    assert!(fixture
        .store
        .import_dpop_replay_source(
            &identifier("authority", AUTHORITY_ID),
            expected.expectation_id(),
            &source,
            &fixture.fence,
            now * 1000
        )?
        .imported_inactive());
    Ok(())
}
