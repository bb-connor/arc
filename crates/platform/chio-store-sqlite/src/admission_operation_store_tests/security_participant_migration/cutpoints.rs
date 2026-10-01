use super::*;

#[test]
fn every_destination_error_cutpoint_has_an_exact_safe_retry() -> AnchoredTestResult {
    let _reset = ResetCutpoint;
    for stage in 1..=8 {
        let fixture = fixture();
        let source = source(&fixture)?;
        let before = global_count(&fixture)?;
        let expected = if stage > 3 {
            Some(pin(&fixture, &source)?)
        } else {
            None
        };
        FAIL_AFTER.set(stage);
        let result = if let Some(expected) = &expected {
            import(&fixture, &source, expected)
        } else {
            pin(&fixture, &source)
        };
        FAIL_AFTER.set(0);
        assert!(result.is_err(), "stage {stage}");
        let retained = load(&fixture)?;
        assert_eq!(retained.is_some(), stage >= 3, "stage {stage}");
        assert_eq!(
            retained.as_ref().is_some_and(
                |record| record.phase() == SecurityParticipantMigrationPhase::ImportedInactive
            ),
            stage == 8
        );
        assert_eq!(
            global_count(&fixture)?,
            before
                + if stage < 3 {
                    0
                } else if stage == 8 {
                    2
                } else {
                    1
                }
        );
        assert_eq!(source.load_seal()?.is_some(), stage >= 4);
        let expected = pin(&fixture, &source)?;
        assert_eq!(
            import(&fixture, &source, &expected)?.phase(),
            SecurityParticipantMigrationPhase::ImportedInactive
        );
        assert_eq!(global_count(&fixture)?, before + 2);
    }
    Ok(())
}

#[test]
fn child_process_crash() -> AnchoredTestResult {
    let Some(directory) = std::env::var_os("CHIO_SECURITY_DESTINATION_CRASH_DIRECTORY") else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    let authority = SqliteAuthorityStore::open_serving(
        directory.join("authority.db"),
        directory.join("locks"),
    )?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let source = SqliteSecurityParticipantSource::open(directory.join("security-source.db"))?;
    let expected = store.expect_security_participant_source(
        &identifier("source_id", "private-source"),
        &authority_id(),
        &source,
        &fence,
        now_ms(),
    )?;
    store.import_security_participant_source(
        &authority_id(),
        expected.expectation_id(),
        &source,
        &fence,
        now_ms(),
    )?;
    Err("child did not reach the requested destination crash cutpoint".into())
}

#[test]
fn process_abort_never_exposes_partial_import_and_new_owner_recovers_exact_pin(
) -> AnchoredTestResult {
    for stage in 1..=10 {
        let fixture = fixture();
        drop(source(&fixture)?);
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
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "admission_operation_store::tests::security_participant_migration::cutpoints::child_process_crash", "--nocapture"])
            .env("CHIO_SECURITY_DESTINATION_CRASH_STAGE", stage.to_string())
            .env("CHIO_SECURITY_DESTINATION_CRASH_DIRECTORY", _temp.path())
            .current_dir(_temp.path()).output()?;
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            output.status.signal(),
            Some(6),
            "stage {stage}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fixture = Fixture {
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
            _temp,
            database,
            lock_root,
        };
        assert!(fixture
            .store
            .load_security_participant_migration(&authority_id(), &fence, now_ms())
            .is_err());
        let retained = load(&fixture)?;
        assert_eq!(retained.is_some(), stage >= 3, "stage {stage}");
        assert_eq!(
            retained.as_ref().is_some_and(
                |record| record.phase() == SecurityParticipantMigrationPhase::ImportedInactive
            ),
            matches!(stage, 8 | 10)
        );
        let source =
            SqliteSecurityParticipantSource::open(fixture._temp.path().join("security-source.db"))?;
        assert_eq!(
            source.load_seal()?.is_some(),
            (4..=8).contains(&stage) || stage == 10
        );
        let expected = pin(&fixture, &source)?;
        assert_eq!(
            import(&fixture, &source, &expected)?.phase(),
            SecurityParticipantMigrationPhase::ImportedInactive
        );
    }
    Ok(())
}
