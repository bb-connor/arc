use super::*;

#[test]
fn lost_seal_acknowledgement_leaves_pending_history_and_retries_exactly_once() -> AnchoredTestResult
{
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    source.state.lock().expect("state").lose_seal_ack_once = true;
    let error = import(&fixture, &source, &expected).expect_err("lost acknowledgement");
    assert!(!error.to_string().contains("private source failure detail"));
    assert_eq!(load(&fixture)?, Some(expected.clone()));
    assert_eq!(counts(&fixture), [0, 1, 1]);
    source.raw.verify_exact(expected.snapshot())?;
    assert!(source
        .raw
        .check_and_insert("after-seal", "capability")
        .is_err());
    let before = global_count(&fixture);
    assert!(import(&fixture, &source, &expected)?.imported_inactive());
    assert_eq!(global_count(&fixture), before + 1);
    assert_eq!(source.calls(), ["preview", "seal", "seal", "verify"]);
    Ok(())
}

#[test]
fn panicking_callbacks_release_the_import_guard_and_never_grant_partial_history(
) -> AnchoredTestResult {
    for call in ["preview", "seal", "verify"] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let expected = (call != "preview")
            .then(|| pin(&fixture, &source))
            .transpose()?;
        source.state.lock().expect("state").panic_on = Some(call);
        let result = match &expected {
            Some(expected) => import(&fixture, &source, expected),
            None => pin(&fixture, &source),
        };
        assert!(result
            .expect_err("panic denies")
            .to_string()
            .contains("source panicked"));
        assert_eq!(
            counts(&fixture),
            if expected.is_some() {
                [0, 1, 1]
            } else {
                [0, 0, 0]
            }
        );
        source.state.lock().expect("state").panic_on = None;
        let expected = pin(&fixture, &source)?;
        assert!(import(&fixture, &source, &expected)?.imported_inactive());
        assert_eq!(counts(&fixture), [3, 2, 1]);
    }
    Ok(())
}

#[test]
fn unavailable_sources_never_complete_or_reseal_imported_history() -> AnchoredTestResult {
    for already_imported in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let expected = pin(&fixture, &source)?;
        if already_imported {
            import(&fixture, &source, &expected)?;
        }
        let retained = load(&fixture)?;
        let before = global_count(&fixture);
        let calls = source.calls().len();
        source.state.lock().expect("state").unavailable = true;
        assert!(import(&fixture, &source, &expected).is_err());
        assert_eq!(
            &source.calls()[calls..],
            if already_imported {
                &["verify"]
            } else {
                &["seal"]
            }
        );
        assert_eq!(load(&fixture)?, retained);
        assert_eq!(global_count(&fixture), before);
        source.state.lock().expect("state").unavailable = false;
        assert!(import(&fixture, &source, &expected)?.imported_inactive());
    }
    Ok(())
}

#[test]
fn destination_write_cutpoints_rollback_rows_events_and_global_commits() -> AnchoredTestResult {
    for (table, predicate, importing) in [
        ("dpop_replay_migration_expectations", "1", false),
        ("dpop_replay_migration_events", "NEW.sequence = 1", false),
        (
            "authority_global_commits",
            "NEW.projection_kind = 'dpop_replay_migration'",
            false,
        ),
        (
            "dpop_replay_legacy_tombstones",
            "NEW.nonce = 'signed'",
            true,
        ),
        ("dpop_replay_migration_events", "NEW.sequence = 2", true),
        (
            "authority_global_commits",
            "NEW.projection_kind = 'dpop_replay_migration'",
            true,
        ),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let expected = importing.then(|| pin(&fixture, &source)).transpose()?;
        let before = global_count(&fixture);
        fixture.store.connection()?.execute_batch(&format!("CREATE TEMP TRIGGER fail_dpop_migration BEFORE INSERT ON main.{table} WHEN {predicate} BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;"))?;
        if let Some(expected) = &expected {
            assert!(import(&fixture, &source, expected).is_err(), "{table}");
            assert_eq!(load(&fixture)?, Some(expected.clone()));
            source.raw.verify_exact(expected.snapshot())?;
            assert_eq!(counts(&fixture), [0, 1, 1]);
        } else {
            assert!(pin(&fixture, &source).is_err(), "{table}");
            assert_eq!(counts(&fixture), [0, 0, 0]);
            assert_eq!(source.calls(), ["preview"]);
        }
        assert_eq!(global_count(&fixture), before);
        fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER temp.fail_dpop_migration")?;
        let expected = pin(&fixture, &source)?;
        assert!(import(&fixture, &source, &expected)?.imported_inactive());
        assert_eq!(counts(&fixture), [3, 2, 1]);
    }
    Ok(())
}

#[test]
fn owner_wide_migration_guard_rejects_concurrent_import_without_source_access() -> AnchoredTestResult
{
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    let guard = fixture
        .store
        .serving_owner
        .begin_replay_source_migration()?;
    assert!(import(&fixture, &source, &expected).is_err());
    assert_eq!(source.calls(), ["preview"]);
    assert_eq!(counts(&fixture), [0, 1, 1]);
    drop(guard);
    assert!(import(&fixture, &source, &expected)?.imported_inactive());
    Ok(())
}
