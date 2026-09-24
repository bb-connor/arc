use super::*;

#[test]
fn native_join_sql_scope_cannot_mutate_another_operations_recovery_claim() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, request) = request("native-sql-scope-join")?;
    let (operation, _) = setup(&fixture, "native-sql-scope-owner", &context)?;
    let (_, other_lease) = setup(&fixture, "native-sql-scope-other", &context)?;
    let lease = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant", "native-sql-scope-owner"),
        now_ms(),
        now_ms() + 120_000,
        &fixture.fence,
    )?;
    let before = global_count(&*fixture.store.connection()?)?;
    fixture.store.connection()?.execute_batch(
        "CREATE TEMP TRIGGER native_test_join_other_claim AFTER INSERT ON main.security_participant_state_flow_contexts
         WHEN NEW.tenant_id = 'native-tenant' BEGIN
         UPDATE admission_operations SET recovery_expires_at_unix_ms = recovery_expires_at_unix_ms + 1
         WHERE request_id = 'native-sql-scope-other';
         END;",
    )?;
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms(),
        )
        .is_err());
    assert_eq!(count(&fixture)?, 0);
    let connection = fixture.store.connection()?;
    assert!(connection.is_autocommit());
    assert_eq!(global_count(&connection)?, before);
    assert_eq!(connection.query_row("SELECT recovery_expires_at_unix_ms FROM admission_operations WHERE request_id = 'native-sql-scope-other'", [], |row| row.get::<_, i64>(0))?, i64::try_from(other_lease.expires_at_unix_ms())?);
    connection.execute_batch("DROP TRIGGER temp.native_test_join_other_claim")?;
    native::verify_coverage(&connection)?;
    drop(connection);
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    Ok(())
}

#[test]
fn a_nested_delete_cannot_escape_the_monotone_join_contract() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    let before = global_count(&*fixture.store.connection()?)?;
    fixture.store.connection()?.execute_batch(
        "CREATE TEMP TRIGGER native_test_delete_sequence AFTER INSERT ON main.security_participant_state_flow_contexts
         WHEN NEW.tenant_id = 'native-tenant' BEGIN
         DELETE FROM security_participant_state_flow_sequences
         WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id;
         END;",
    )?;
    assert!(
        fixture
            .store
            .join_security_participant_flow(
                &operation,
                &lease,
                &initialized,
                &context,
                &request,
                now_ms(),
            )
            .is_err(),
        "a join must not commit history that recovery rejects as non-monotone"
    );
    assert_eq!(count(&fixture)?, 0);
    let connection = fixture.store.connection()?;
    assert!(connection.is_autocommit());
    assert_eq!(global_count(&connection)?, before);
    connection.execute_batch("DROP TRIGGER temp.native_test_delete_sequence")?;
    native::verify_coverage(&connection)?;
    drop(connection);
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn restoring_database_before_join_cannot_erase_acknowledged_mutation_history() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    let backup = fixture._temp.path().join("before-join.db");
    fixture
        .store
        .connection()?
        .execute("VACUUM INTO ?1", [backup.to_str().ok_or("backup path")?])?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
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
    fs::copy(backup, &database)?;
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    Ok(())
}

#[test]
fn late_domain_failure_rolls_back_earlier_rows_and_disables_the_callback() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    fixture.store.connection()?.execute_batch(
        "CREATE TEMP TRIGGER native_test_reject_context BEFORE INSERT ON main.security_participant_state_flow_contexts
         WHEN NEW.tenant_id = 'native-tenant' BEGIN SELECT RAISE(ABORT, 'injected late native join failure'); END;",
    )?;
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
    assert_eq!(count(&fixture)?, 0);
    let connection = fixture.store.connection()?;
    assert!(connection.is_autocommit());
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM security_participant_state_flow_sequences WHERE tenant_id = 'native-tenant'", [], |row| row.get::<_, i64>(0))?, 0);
    connection.execute_batch("DROP TRIGGER temp.native_test_reject_context")?;
    assert!(connection.execute("UPDATE security_participant_state_flow_sequences SET last_generation = last_generation + 1 WHERE security_authority_id = 'source'", []).is_err());
    native::verify_coverage(&connection)?;
    drop(connection);
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    Ok(())
}

#[test]
fn external_row_tampering_with_restored_catalog_is_rejected_on_reopen() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
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
        "DROP TRIGGER security_participant_state_7_inactive_update;
        DROP TRIGGER security_participant_state_7_capture_update;
        UPDATE security_participant_state_flow_sequences SET last_generation = last_generation + 1
        WHERE security_authority_id = 'source' AND tenant_id = 'native-tenant';",
    )?;
    connection.execute_batch(&native::schema::sql()?)?;
    assert!(native::verify_all(&connection).is_err());
    drop(connection);
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn child_process_native_join_crash() -> TestResult {
    let Some(directory) = std::env::var_os("CHIO_NATIVE_JOIN_CRASH_DIRECTORY") else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    let authority = SqliteAuthorityStore::open_serving(
        directory.join("authority.db"),
        directory.join("locks"),
    )?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let initialized = store
        .load_security_participant_state(
            &identifier("security_authority_id", "source"),
            &fence,
            now_ms(),
        )?
        .ok_or("initialization")?;
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &identifier("request", "native-operation"),
            &fence,
            now_ms(),
        )?
        .ok_or("operation")?;
    let (context, request) = request("native-join")?;
    let now = now_ms();
    let lease = store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant", "child"),
        now,
        now + 10000,
        &fence,
    )?;
    if std::env::var("CHIO_NATIVE_JOIN_CRASH_FAMILY").as_deref() == Ok("input") {
        let input = chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1::new(
            operation.binding().operation_id().clone(),
            request.key.clone(),
            InformationLabel::bottom(),
        )?;
        store.join_native_security_input(
            &operation,
            &lease,
            &initialized.admission_binding()?,
            &context,
            &input,
            now_ms(),
        )?;
    } else {
        store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms(),
        )?;
    }
    Err("child did not reach native join cutpoint".into())
}

#[cfg(unix)]
#[test]
fn independent_process_abort_and_takeover_preserve_exact_mutation_custody() -> TestResult {
    for family in ["raw", "input"] {
        for stage in 7..=11 {
            let fixture = fixture();
            let source = imported(&fixture, "source")?;
            let initialized = hydrate(&fixture, &source)?;
            let (context, request) = request("native-join")?;
            let (operation, _) = setup(&fixture, "native-operation", &context)?;
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
            .args(["--exact", "admission_operation_store::tests::security_participant_state::mutations::faults::child_process_native_join_crash", "--nocapture"])
            .env("CHIO_SECURITY_NATIVE_CRASH_STAGE", stage.to_string())
            .env("CHIO_NATIVE_JOIN_CRASH_DIRECTORY", _temp.path())
            .env("CHIO_NATIVE_JOIN_CRASH_FAMILY", family)
            .current_dir(_temp.path()).output()?;
            use std::os::unix::process::ExitStatusExt as _;
            assert_eq!(
                output.status.signal(),
                Some(libc::SIGABRT),
                "family {family}, stage {stage}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
            let store = authority.admission_operation_store();
            assert_eq!(
                store.connection()?.query_row(
                    "SELECT COUNT(*) FROM security_participant_state_mutations",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                i64::from(stage >= 10)
            );
            let operation = store
                .load_by_operation_id(operation.binding().operation_id())?
                .ok_or("operation")?;
            let now = now_ms();
            let lease = store.claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &identifier("claimant", "parent"),
                now,
                now + 10000,
                &authority.mutation_fence(),
            )?;
            if family == "input" {
                let input =
                    chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1::new(
                        operation.binding().operation_id().clone(),
                        request.key.clone(),
                        InformationLabel::bottom(),
                    )?;
                let result = store.join_native_security_input(
                    &operation,
                    &lease,
                    &initialized.admission_binding()?,
                    &context,
                    &input,
                    now_ms(),
                )?;
                result.validate()?;
                let (_, history) = store
                    .load_native_security_input_join(
                        operation.binding().operation_id(),
                        &authority.mutation_fence(),
                        now_ms(),
                    )?
                    .ok_or("input operation")?;
                assert_eq!(history, Some(result));
                assert!(store
                    .join_native_security_flow(
                        &operation,
                        &lease,
                        &initialized.admission_binding()?,
                        &context,
                        &request,
                        now_ms()
                    )
                    .is_err());
            } else {
                store.join_security_participant_flow(
                    &operation,
                    &lease,
                    &initialized,
                    &context,
                    &request,
                    now_ms(),
                )?;
            }
            assert_eq!(
                store.connection()?.query_row(
                    "SELECT COUNT(*) FROM security_participant_state_mutations",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                1
            );
            native::verify_coverage(&*store.connection()?)?;
        }
    }
    Ok(())
}
