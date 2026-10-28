use super::*;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;

#[test]
fn activation_requires_exact_imported_source_and_is_immutable() -> AnchoredTestResult {
    for empty in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, empty);
        let expected = pin(&fixture, &source)?;
        let binding = RuntimeParticipantAuthorityBindingV1::new(
            identifier("runtime", RUNTIME_ID),
            expected.expectation_id().clone(),
        );
        assert!(fixture
            .store
            .load_runtime_source_qualification(&binding, &fixture.fence, now_ms())
            .is_err());
        assert!(fixture
            .store
            .activate_runtime_replay_source(&binding, &source, &fixture.fence, now_ms())
            .is_err());
        import(&fixture, &source, &expected)?;
        assert!(fixture
            .store
            .load_runtime_source_qualification(&binding, &fixture.fence, now_ms())
            .is_err());
        let before = global_count(&fixture.store);
        let active = fixture.store.activate_runtime_replay_source(
            &binding,
            &source,
            &fixture.fence,
            now_ms(),
        )?;
        assert!(active.is_active());
        assert!(active.is_imported());
        assert!(!active.imported_inactive());
        assert_eq!(active.event_sequence(), 3);
        assert_eq!(global_count(&fixture.store), before + 1);
        assert_eq!(
            &fixture.store.load_runtime_source_qualification(
                &binding,
                &fixture.fence,
                now_ms()
            )?,
            expected.snapshot()
        );
        assert_eq!(
            fixture.store.activate_runtime_replay_source(
                &binding,
                &source,
                &fixture.fence,
                now_ms()
            )?,
            active
        );
        assert_eq!(import(&fixture, &source, &expected)?, active);
        assert_eq!(global_count(&fixture.store), before + 1);
        let wrong = RuntimeParticipantAuthorityBindingV1::new(
            identifier("runtime", RUNTIME_ID),
            identifier("expectation", "wrong-generation"),
        );
        assert!(fixture
            .store
            .activate_runtime_replay_source(&wrong, &source, &fixture.fence, now_ms())
            .is_err());
        // Exact retry must verify, never silently repair a missing physical seal.
        source.state.lock().expect("source state").sealed = None;
        let calls = source.calls().len();
        assert!(fixture
            .store
            .activate_runtime_replay_source(&binding, &source, &fixture.fence, now_ms())
            .is_err());
        assert_eq!(&source.calls()[calls..], &["verify"]);
        assert_eq!(global_count(&fixture.store), before + 1);
    }
    Ok(())
}

#[test]
fn activation_sql_cutpoints_leave_import_inactive_and_retry_exactly_once() -> AnchoredTestResult {
    for (table, predicate) in [
        ("runtime_replay_migration_events", "NEW.sequence = 3"),
        (
            "authority_global_commits",
            "NEW.mutation_kind = 'activate_runtime_replay_source'",
        ),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false);
        let expected = pin(&fixture, &source)?;
        let imported = import(&fixture, &source, &expected)?;
        let binding = RuntimeParticipantAuthorityBindingV1::new(
            identifier("runtime", RUNTIME_ID),
            expected.expectation_id().clone(),
        );
        let before = global_count(&fixture.store);
        fixture.store.connection()?.execute_batch(&format!(
            "CREATE TEMP TRIGGER runtime_activation_cutpoint BEFORE INSERT ON main.{table}
             WHEN {predicate} BEGIN SELECT RAISE(ABORT, 'injected activation cutpoint'); END;"
        ))?;
        let error = fixture
            .store
            .activate_runtime_replay_source(&binding, &source, &fixture.fence, now_ms())
            .expect_err("injected SQL failure");
        assert!(
            error.to_string().contains("injected activation cutpoint"),
            "{error}"
        );
        assert_eq!(load(&fixture)?, Some(imported));
        assert_eq!(global_count(&fixture.store), before);
        fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER temp.runtime_activation_cutpoint")?;
        let active = fixture.store.activate_runtime_replay_source(
            &binding,
            &source,
            &fixture.fence,
            now_ms(),
        )?;
        assert_eq!(active.event_sequence(), 3);
        assert_eq!(global_count(&fixture.store), before + 1);
    }
    Ok(())
}
