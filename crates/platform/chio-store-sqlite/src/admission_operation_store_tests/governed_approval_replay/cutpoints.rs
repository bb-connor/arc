use super::*;

#[test]
fn destination_sql_failures_leave_no_partial_pin_or_import() -> AnchoredTestResult {
    for (table, predicate, importing) in [
        (
            "governed_approval_replay_migration_expectations",
            "1",
            false,
        ),
        (
            "governed_approval_replay_migration_events",
            "NEW.sequence = 1",
            false,
        ),
        (
            "authority_global_commits",
            "NEW.projection_kind = 'governed_approval_replay_migration'",
            false,
        ),
        (
            "governed_approval_replay_legacy_tombstones",
            "NEW.request_id = 'reserved'",
            true,
        ),
        (
            "governed_approval_replay_migration_events",
            "NEW.sequence = 2",
            true,
        ),
        (
            "authority_global_commits",
            "NEW.projection_kind = 'governed_approval_replay_migration'",
            true,
        ),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let expected = importing.then(|| pin(&fixture, &source)).transpose()?;
        let before = global_count(&fixture);
        fixture.store.connection()?.execute_batch(&format!("CREATE TEMP TRIGGER fail_approval_migration BEFORE INSERT ON main.{table} WHEN {predicate} BEGIN SELECT RAISE(ABORT, 'injected migration write failure'); END;"))?;
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
            .execute_batch("DROP TRIGGER temp.fail_approval_migration;")?;
        let expected = pin(&fixture, &source)?;
        assert!(import(&fixture, &source, &expected)?.imported_inactive());
        assert_eq!(counts(&fixture), [3, 2, 1]);
    }
    Ok(())
}
