use super::*;
use chio_kernel::SecurityInvocationContext;

fn join(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
    context: &mut SecurityInvocationContext,
    name: &str,
) -> AnchoredTestResult<AdmissionOperationId> {
    let (_, request) = mutations::request(&format!("{name}-join"))?;
    let (operation, lease) = mutations::setup(fixture, name, context)?;
    let result = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        initialized,
        context,
        &request,
        now_ms(),
    )?;
    *context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(result.context_generation),
    );
    Ok(operation.binding().operation_id().clone())
}

fn events(fixture: &Fixture) -> AnchoredTestResult<i64> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM security_participant_checkpoint_events",
        [],
        |row| row.get(0),
    )?)
}

fn archived(fixture: &Fixture) -> AnchoredTestResult<Vec<Vec<u8>>> {
    let connection = fixture.store.connection()?;
    let mut statement = connection.prepare(
        "SELECT canonical_record FROM security_participant_state_mutations ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn coverage_overhead(fixture: &Fixture) -> AnchoredTestResult<usize> {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let connection = fixture.store.connection()?;
    let steps = Arc::new(AtomicUsize::new(0));
    let callback = Arc::clone(&steps);
    connection.progress_handler(
        1,
        Some(move || {
            callback.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )?;
    let row_result = native::verify_all(&connection);
    let row_steps = steps.swap(0, Ordering::Relaxed);
    let coverage_result = native::verify_coverage(&connection);
    let coverage_steps = steps.load(Ordering::Relaxed);
    connection.progress_handler(0, None::<fn() -> bool>)?;
    row_result?;
    coverage_result?;
    coverage_steps
        .checked_sub(row_steps)
        .ok_or_else(|| "coverage cost omitted current-row verification".into())
}

#[test]
fn native_journal_checkpoint_ordinary_coverage_work_ignores_sealed_archive() -> AnchoredTestResult {
    native::with_test_journal_bounds(1, 67_108_864, || {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let (mut context, _) = mutations::request("coverage")?;
        let mut small = 0;
        for index in 0..128 {
            join(
                &fixture,
                &initialized,
                &mut context,
                &format!("coverage-operation-{index:03}"),
            )?;
            fixture.store.checkpoint_security_participant_history(
                &initialized,
                &fixture.fence,
                now_ms(),
            )?;
            if index == 1 {
                small = coverage_overhead(&fixture)?;
            }
        }
        let large = coverage_overhead(&fixture)?;
        // Current snapshot verification is measured separately and subtracted.
        // With one root and an empty suffix, sealed archive growth may add only
        // constant index-height overhead, not a lifetime coverage scan.
        assert!(
            large <= small + 1024,
            "ordinary coverage grew from {small} to {large} VM steps after sealing128 segments"
        );
        Ok(())
    })
}

fn reopen(fixture: Fixture) -> AnchoredTestResult<Fixture> {
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
    let authority = crate::test_authority::open_serving(&database, &lock_root)?;
    Ok(Fixture {
        _temp,
        database,
        lock_root,
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
    })
}

#[test]
fn native_journal_checkpoint_repeated_segments_keep_archived_bytes_and_current_labels(
) -> AnchoredTestResult {
    native::with_test_journal_bounds(2, 67_108_864, || {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let (mut context, _) = mutations::request("segments")?;
        let first = join(&fixture, &initialized, &mut context, "segment-first")?;
        let original = fixture
            .store
            .load_security_participant_flow_join(&first, &fixture.fence, now_ms())?
            .ok_or("first history absent")?;
        let mut retained = Vec::new();
        for segment in 0..17 {
            join(
                &fixture,
                &initialized,
                &mut context,
                &format!("segment-{segment}"),
            )?;
            let current = archived(&fixture)?;
            assert_eq!(&current[..retained.len()], retained.as_slice());
            retained = current;
            fixture.store.checkpoint_security_participant_history(
                &initialized,
                &fixture.fence,
                now_ms(),
            )?;
        }
        assert_eq!(events(&fixture)?, 17);
        assert_eq!(
            fixture
                .store
                .load_security_participant_flow_join(&first, &fixture.fence, now_ms())?,
            Some(original.clone())
        );
        let fixture = reopen(fixture)?;
        assert_eq!(
            fixture.store.load_security_participant_state(
                initialized.security_authority_id(),
                &fixture.fence,
                now_ms()
            )?,
            Some(initialized.clone())
        );
        assert_eq!(
            fixture
                .store
                .load_security_participant_flow_join(&first, &fixture.fence, now_ms())?,
            Some(original)
        );
        assert_eq!(archived(&fixture)?, retained);
        join(&fixture, &initialized, &mut context, "segment-after-reopen")?;
        Ok(())
    })
}

#[test]
fn native_journal_checkpoint_byte_cap_resumes_after_checkpoint() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (mut context, _) = mutations::request("bytes")?;
    join(&fixture, &initialized, &mut context, "byte-first")?;
    join(&fixture, &initialized, &mut context, "byte-other")?;
    let bytes = archived(&fixture)?.iter().map(Vec::len).sum::<usize>();
    let (_, request) = mutations::request("byte-next-join")?;
    let (operation, lease) = mutations::setup(&fixture, "byte-next-0", &context)?;
    native::with_test_journal_bounds(65_536, i64::try_from(bytes)?, || {
        assert!(fixture
            .store
            .join_security_participant_flow(
                &operation,
                &lease,
                &initialized,
                &context,
                &request,
                now_ms()
            )
            .is_err());
        fixture.store.checkpoint_security_participant_history(
            &initialized,
            &fixture.fence,
            now_ms(),
        )?;
        fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms(),
        )?;
        assert_eq!(archived(&fixture)?.len(), 3);
        Ok(())
    })
}

#[test]
fn native_journal_checkpoint_rejects_foreign_initialization_or_stale_fence() -> AnchoredTestResult {
    let other = fixture();
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let foreign = hydrate(&other, &imported(&other, "source")?)?;
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert!(fixture
        .store
        .checkpoint_security_participant_history(&foreign, &fixture.fence, now_ms())
        .is_err());
    assert!(fixture
        .store
        .checkpoint_security_participant_history(&initialized, &stale, now_ms())
        .is_err());
    assert_eq!(events(&fixture)?, 0);
    Ok(())
}

#[test]
fn native_journal_checkpoint_cancelled_transactions_are_atomic() -> AnchoredTestResult {
    let _reset = ResetCutpoint;
    for stage in 70..=72 {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let before: (i64,String) = fixture.store.connection()?.query_row("SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1",[],|row|Ok((row.get(0)?,row.get(1)?)))?;
        FAIL_AFTER.set(stage);
        assert!(fixture
            .store
            .checkpoint_security_participant_history(&initialized, &fixture.fence, now_ms())
            .is_err());
        FAIL_AFTER.set(0);
        assert_eq!(events(&fixture)?, 0);
        assert_eq!(
            fixture.store.connection()?.query_row(
                "SELECT COUNT(*) FROM security_participant_checkpoint_rows",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        assert_eq!(fixture.store.connection()?.query_row("SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1",[],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?)))?,before);
        fixture.store.checkpoint_security_participant_history(
            &initialized,
            &fixture.fence,
            now_ms(),
        )?;
        assert_eq!(events(&fixture)?, 1);
    }
    Ok(())
}

#[test]
fn native_journal_checkpoint_snapshot_corruption_and_missing_global_reference_refuse(
) -> AnchoredTestResult {
    for tamper in [
        "DROP TRIGGER security_participant_checkpoint_rows_no_update;
         UPDATE security_participant_checkpoint_rows SET canonical_row = X'7b7d' WHERE rowid = (SELECT MIN(rowid) FROM security_participant_checkpoint_rows);",
        "DROP TRIGGER authority_global_commits_no_delete;
         DELETE FROM authority_global_commits WHERE projection_kind = 'security_participant_checkpoint';",
    ] {
        let fixture = fixture();
        let initialized = hydrate(&fixture,&imported(&fixture,"source")?)?;
        fixture.store.checkpoint_security_participant_history(&initialized,&fixture.fence,now_ms())?;
        {
            let connection = fixture.store.connection()?;
            connection.execute_batch(tamper)?;
            connection.execute_batch(native::checkpoint::sql())?;
            connection.execute_batch("CREATE TRIGGER IF NOT EXISTS authority_global_commits_no_delete
BEFORE DELETE ON authority_global_commits
BEGIN
    SELECT RAISE(ABORT, 'global authority commit is immutable');
END;")?;
        }
        assert!(fixture.store.load_security_participant_state(initialized.security_authority_id(),&fixture.fence,now_ms()).is_err());
        let Fixture { _temp,database,lock_root,authority,store,.. } = fixture;
        drop(store);
        drop(authority);
        assert!(crate::test_authority::open_serving(&database,&lock_root).is_err());
    }
    Ok(())
}

#[test]
fn native_journal_checkpoint_rehashed_local_record_cannot_replace_global_authority(
) -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    {
        let connection = fixture.store.connection()?;
        let bytes: Vec<u8> = connection.query_row(
            "SELECT canonical_record FROM security_participant_checkpoint_events",
            [],
            |row| row.get(0),
        )?;
        let mut body: serde_json::Value = serde_json::from_slice(&bytes)?;
        body["segment_bytes"] = serde_json::json!(1);
        let bytes = canonical_json_bytes(&body)?;
        let mut committed = b"chio.native-security-checkpoint.commit.v1\0".to_vec();
        committed.extend(&bytes);
        connection
            .execute_batch("DROP TRIGGER security_participant_checkpoint_events_no_update")?;
        connection.execute("UPDATE security_participant_checkpoint_events SET canonical_record = ?1,checkpoint_digest = ?2",params![bytes,sha256_hex(&committed)])?;
        connection.execute_batch(native::checkpoint::sql())?;
    }
    assert!(fixture
        .store
        .load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms()
        )
        .is_err());
    Ok(())
}

#[test]
fn native_journal_checkpoint_older_journal_corruption_refuses_reopen() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (mut context, _) = mutations::request("tamper")?;
    join(&fixture, &initialized, &mut context, "archived-tamper")?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
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
    connection.execute_batch(
        "DROP TRIGGER security_participant_state_mutations_no_update;
        UPDATE security_participant_state_mutations SET canonical_record = X'7b7d';",
    )?;
    connection.execute_batch(include_str!(
        "../../admission_operation_security_participant_mutations.sql"
    ))?;
    drop(connection);
    assert!(crate::test_authority::open_serving(&database, &lock_root).is_err());
    Ok(())
}

#[test]
fn native_journal_checkpoint_wrong_owner_clock_refuses() -> AnchoredTestResult {
    let now = now_ms() / 1000 * 1000;
    let _clock = chio_test_support::clock::scope_unix_secs(now / 1000);
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    fixture
        .store
        .checkpoint_security_participant_history(&initialized, &fixture.fence, now)?;
    let _rollback = chio_test_support::clock::scope_unix_secs(now / 1000 - 1);
    assert!(fixture
        .store
        .checkpoint_security_participant_history(&initialized, &fixture.fence, now)
        .is_err());
    assert_eq!(events(&fixture)?, 1);
    Ok(())
}

#[test]
fn checkpoint_abort_child() -> AnchoredTestResult {
    let Some(directory) = std::env::var_os("CHIO_NATIVE_CHECKPOINT_CRASH_DIRECTORY") else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    let authority = crate::test_authority::open_serving(
        directory.join("authority.db"),
        directory.join("locks"),
    )?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let initialized = store
        .load_security_participant_state(&identifier("authority", "source"), &fence, now_ms())?
        .ok_or("initialization absent")?;
    store.checkpoint_security_participant_history(&initialized, &fence, now_ms())?;
    Err("checkpoint child did not reach abort cutpoint".into())
}

#[test]
fn native_journal_checkpoint_abort_reopens_complete_old_or_new_state() -> AnchoredTestResult {
    use std::os::unix::process::ExitStatusExt as _;
    for stage in 70..=74 {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
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
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact","admission_operation_store::tests::security_participant_state::checkpoint::checkpoint_abort_child","--nocapture"])
            .env("CHIO_NATIVE_CHECKPOINT_CRASH_DIRECTORY",_temp.path())
            .env("CHIO_SECURITY_NATIVE_CRASH_STAGE",stage.to_string()).current_dir(_temp.path()).output()?;
        assert_eq!(
            output.status.signal(),
            Some(6),
            "stage {stage}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let authority = crate::test_authority::open_serving(&database, &lock_root)?;
        let fixture = Fixture {
            _temp,
            database,
            lock_root,
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
        };
        assert_eq!(events(&fixture)?, i64::from(stage >= 73));
        assert_eq!(
            fixture.store.load_security_participant_state(
                initialized.security_authority_id(),
                &fixture.fence,
                now_ms()
            )?,
            Some(initialized.clone())
        );
        fixture.store.checkpoint_security_participant_history(
            &initialized,
            &fixture.fence,
            now_ms(),
        )?;
        assert_eq!(events(&fixture)?, 1);
    }
    Ok(())
}

fn malformed_native_checkpoint_diagnostic_refusal(utf8: bool) -> AnchoredTestResult {
    use chio_kernel::admission_operation::AdmissionOperationError;
    use std::error::Error;
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "diagnostic-source")?)?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let connection = fixture.store.connection()?;
    assert_eq!(native::verify_all(&connection)?, vec![initialized.clone()]);
    let before: (i64,i64) = connection.query_row("SELECT (SELECT COUNT(*) FROM security_participant_checkpoint_events), (SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1)", [], |row|Ok((row.get(0)?,row.get(1)?)))?;
    let mut bytes: Vec<u8> = connection.query_row("SELECT canonical_record FROM security_participant_checkpoint_events WHERE security_authority_id=?1 AND sequence=1", [initialized.security_authority_id().as_str()], |row|row.get(0))?;
    if utf8 {
        bytes = vec![b'{', 0xff, b'}'];
    } else {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
        value["sequence"] = serde_json::json!("CHECKPOINT_SHAPE_CANARY");
        bytes = canonical_json_bytes(&value)?;
    }
    // Isolated fixture corruption and exact catalog restoration; use the real
    // native owner verifier, with no new authority or decoder test port.
    connection.execute_batch("DROP TRIGGER security_participant_checkpoint_events_no_update")?;
    connection.execute("UPDATE security_participant_checkpoint_events SET canonical_record=?1 WHERE security_authority_id=?2 AND sequence=1", params![&bytes,initialized.security_authority_id().as_str()])?;
    connection.execute_batch(native::checkpoint::sql())?;
    let error = native::verify_all(&connection)
        .err()
        .ok_or("malformed retained checkpoint must refuse")?;
    let after: (i64,i64) = connection.query_row("SELECT (SELECT COUNT(*) FROM security_participant_checkpoint_events), (SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1)", [], |row|Ok((row.get(0)?,row.get(1)?)))?;
    assert_eq!(
        after, before,
        "refusal must not create checkpoint or global authority"
    );
    assert_eq!(fixture.authority.mutation_fence(), fixture.fence);
    assert!(
        matches!(
            &error,
            AdmissionOperationStoreError::Operation(AdmissionOperationError::UntrustedInput(_))
        ),
        "native checkpoint failure must keep its existing typed owner"
    );
    let expected = if utf8 {
        "urn:chio:error:attest:signed-json-not-utf8"
    } else {
        "urn:chio:error:attest:signed-json-invalid-shape"
    };
    assert!(error.to_string().contains(expected));
    assert!(!error.to_string().contains("CHECKPOINT_SHAPE_CANARY"));
    assert!(!format!("{error:?}").contains("CHECKPOINT_SHAPE_CANARY"));
    let mut source = error.source();
    let mut found = false;
    while let Some(cause) = source {
        found |= if utf8 {
            cause
                .downcast_ref::<std::str::Utf8Error>()
                .is_some_and(|error| error.valid_up_to() == 1 && error.error_len() == Some(1))
        } else {
            cause
                .downcast_ref::<serde_json::Error>()
                .is_some_and(serde_json::Error::is_data)
        };
        source = cause.source();
    }
    assert!(
        found,
        "native checkpoint refusal must keep its concrete native source kind"
    );
    Ok(())
}
#[test]
fn native_journal_checkpoint_reader_preserves_utf8_source_without_mutation() -> AnchoredTestResult {
    malformed_native_checkpoint_diagnostic_refusal(true)
}
#[test]
fn native_journal_checkpoint_reader_preserves_serde_data_source_without_mutation(
) -> AnchoredTestResult {
    malformed_native_checkpoint_diagnostic_refusal(false)
}
