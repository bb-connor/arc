use super::*;

const INJECTED_FAILURE: &str = "injected runtime replay migration SQL cutpoint";

fn install_cutpoint(fixture: &Fixture, table: &str, predicate: &str) -> AnchoredTestResult {
    // TEMP triggers exercise the actual write path without altering the
    // canonical main-schema catalog that is verified before each mutation.
    fixture.store.connection()?.execute_batch(&format!(
        "CREATE TEMP TRIGGER runtime_migration_cutpoint
         BEFORE INSERT ON main.{table}
         WHEN {predicate}
         BEGIN SELECT RAISE(ABORT, '{INJECTED_FAILURE}'); END;"
    ))?;
    Ok(())
}

fn remove_cutpoint(fixture: &Fixture) -> AnchoredTestResult {
    fixture
        .store
        .connection()?
        .execute_batch("DROP TRIGGER temp.runtime_migration_cutpoint;")?;
    Ok(())
}

fn assert_injected_failure(error: AdmissionOperationStoreError, cutpoint: &str) {
    assert!(
        matches!(error, AdmissionOperationStoreError::Unavailable(ref detail)
            | AdmissionOperationStoreError::Invariant(ref detail)
            if detail.contains(INJECTED_FAILURE)),
        "{cutpoint} must reach its injected SQL error, not reject at schema verification: {error:?}"
    );
}

fn migration_counts(fixture: &Fixture) -> AnchoredTestResult<(i64, i64, i64)> {
    let connection = fixture.store.connection()?;
    assert!(
        connection.is_autocommit(),
        "failed writes must close their transaction"
    );
    Ok(connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM runtime_replay_migration_expectations),
            (SELECT COUNT(*) FROM runtime_replay_migration_events),
            (SELECT COUNT(*) FROM runtime_replay_legacy_tombstones)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

#[test]
fn pin_sql_cutpoints_leave_no_durable_expectation_or_source_seal() -> AnchoredTestResult {
    for (cutpoint, table, predicate) in [
        (
            "expectation insert",
            "runtime_replay_migration_expectations",
            "1",
        ),
        (
            "expectation event",
            "runtime_replay_migration_events",
            "NEW.sequence = 1",
        ),
        (
            "expectation global commit",
            "authority_global_commits",
            "NEW.projection_kind = 'runtime_replay_migration'
             AND NEW.mutation_kind = 'expect_runtime_replay_source'",
        ),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false);
        let before = global_count(&fixture.store);
        install_cutpoint(&fixture, table, predicate)?;

        assert_injected_failure(pin(&fixture, &source).expect_err(cutpoint), cutpoint);
        assert_eq!(source.calls(), ["preview"], "{cutpoint}");
        assert!(source.state.lock().expect("source state").sealed.is_none());
        assert_eq!(migration_counts(&fixture)?, (0, 0, 0), "{cutpoint}");
        assert_eq!(global_count(&fixture.store), before, "{cutpoint}");
        assert!(load(&fixture)?.is_none(), "{cutpoint}");

        remove_cutpoint(&fixture)?;
        let expected = pin(&fixture, &source)?;
        assert!(!expected.imported_inactive());
        assert_eq!(expected.event_sequence(), 1);
        assert_eq!(migration_counts(&fixture)?, (1, 1, 0), "{cutpoint}");
        assert_eq!(global_count(&fixture.store), before + 1, "{cutpoint}");
        assert!(source.state.lock().expect("source state").sealed.is_none());
        assert_record_equal(
            &load(&fixture)?.expect("retry retained the full pin"),
            &expected,
        );
    }
    Ok(())
}

#[test]
fn import_sql_cutpoints_preserve_only_the_pin_and_retry_the_complete_sealed_inventory(
) -> AnchoredTestResult {
    for (cutpoint, table, predicate) in [
        (
            "second tombstone",
            "runtime_replay_legacy_tombstones",
            "NEW.participant_kind = 'treaty_continuation'
             AND (SELECT COUNT(*) FROM runtime_replay_legacy_tombstones) = 1",
        ),
        (
            "third tombstone",
            "runtime_replay_legacy_tombstones",
            "NEW.participant_kind = 'swarm_continuation'
             AND (SELECT COUNT(*) FROM runtime_replay_legacy_tombstones) = 2",
        ),
        (
            "import event",
            "runtime_replay_migration_events",
            "NEW.sequence = 2",
        ),
        (
            "import global commit",
            "authority_global_commits",
            "NEW.projection_kind = 'runtime_replay_migration'
             AND NEW.mutation_kind = 'import_runtime_replay_source'",
        ),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false);
        let expected = pin(&fixture, &source)?;
        let before = global_count(&fixture.store);
        install_cutpoint(&fixture, table, predicate)?;

        assert_injected_failure(
            import(&fixture, &source, &expected).expect_err(cutpoint),
            cutpoint,
        );
        assert_eq!(source.calls(), ["preview", "seal", "verify"], "{cutpoint}");
        assert_eq!(
            source.state.lock().expect("source state").sealed.as_deref(),
            Some(expected.snapshot().canonical_bytes()),
            "destination rollback must not reopen a successfully sealed source: {cutpoint}"
        );
        assert_eq!(migration_counts(&fixture)?, (1, 1, 0), "{cutpoint}");
        assert_eq!(global_count(&fixture.store), before, "{cutpoint}");
        assert_record_equal(
            &load(&fixture)?.expect("only the original pin survives"),
            &expected,
        );

        remove_cutpoint(&fixture)?;
        let imported = import(&fixture, &source, &expected)?;
        assert!(imported.imported_inactive());
        assert_eq!(imported.event_sequence(), 2);
        assert_eq!(imported.expectation_id(), expected.expectation_id());
        assert_eq!(
            imported.snapshot().canonical_bytes(),
            expected.snapshot().canonical_bytes()
        );
        assert_eq!(migration_counts(&fixture)?, (1, 2, 3), "{cutpoint}");
        assert_eq!(global_count(&fixture.store), before + 1, "{cutpoint}");
        assert_eq!(
            source.calls(),
            ["preview", "seal", "verify", "seal", "verify"],
            "{cutpoint}"
        );
        assert_record_equal(
            &load(&fixture)?.expect("retry imported the complete inventory"),
            &imported,
        );
    }
    Ok(())
}
