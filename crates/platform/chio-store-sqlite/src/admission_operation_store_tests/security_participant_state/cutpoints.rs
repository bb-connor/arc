use super::*;

#[test]
fn every_error_cutpoint_rolls_back_or_recovers_the_exact_committed_projection() -> AnchoredTestResult
{
    let _reset = ResetCutpoint;
    for stage in 1..=5 {
        let fixture = fixture();
        let source = imported(&fixture, "source")?;
        FAIL_AFTER.set(stage);
        let result = hydrate(&fixture, &source);
        FAIL_AFTER.set(0);
        assert!(result.is_err(), "stage {stage}");
        let connection = fixture.store.connection()?;
        assert_eq!(
            native::verify_all(&connection)?.len(),
            usize::from(stage == 5)
        );
        assert_eq!(global_count(&connection)?, i64::from(stage == 5));
        drop(connection);
        let record = hydrate(&fixture, &source)?;
        assert_eq!(hydrate(&fixture, &source)?, record);
        assert_eq!(global_count(&*fixture.store.connection()?)?, 1);
    }
    Ok(())
}

#[test]
fn child_process_crash() -> AnchoredTestResult {
    let Some(directory) = std::env::var_os("CHIO_SECURITY_NATIVE_CRASH_DIRECTORY") else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    let authority = SqliteAuthorityStore::open_serving(
        directory.join("authority.db"),
        directory.join("locks"),
    )?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let key = identifier("security_authority_id", "source");
    let source = store
        .load_security_participant_migration(&key, &fence, now_ms())?
        .ok_or("import absent")?;
    store.hydrate_security_participant_state(&key, source.expectation_id(), &fence, now_ms())?;
    Err("child did not reach native hydration cutpoint".into())
}

#[test]
fn independent_process_abort_and_owner_rotation_never_expose_partial_native_state(
) -> AnchoredTestResult {
    for stage in 1..=6 {
        let fixture = fixture();
        let source = imported(&fixture, "source")?;
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
            .args(["--exact", "admission_operation_store::tests::security_participant_state::cutpoints::child_process_crash", "--nocapture"])
            .env("CHIO_SECURITY_NATIVE_CRASH_STAGE", stage.to_string())
            .env("CHIO_SECURITY_NATIVE_CRASH_DIRECTORY", _temp.path())
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
        let store = authority.admission_operation_store();
        let key = identifier("security_authority_id", "source");
        assert!(store
            .load_security_participant_state(&key, &fence, now_ms())
            .is_err());
        assert_eq!(
            store
                .load_security_participant_state(&key, &authority.mutation_fence(), now_ms())?
                .is_some(),
            stage >= 5
        );
        let record = store.hydrate_security_participant_state(
            &key,
            source.expectation_id(),
            &authority.mutation_fence(),
            now_ms(),
        )?;
        assert_eq!(
            store.load_security_participant_state(&key, &authority.mutation_fence(), now_ms())?,
            Some(record)
        );
        assert_eq!(global_count(&*store.connection()?)?, 1);
    }
    Ok(())
}
