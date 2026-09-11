use super::*;

#[test]
fn decision_and_observation_clocks_keep_their_distinct_causal_order() -> TestResult {
    let observed = now_ms().div_ceil(1000) * 1000;
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(observed / 1000, std::iter::empty());
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let decision = observed + 2000;
    let (operation, lease, _) = setup_at(&fixture, "native-operation", &context, decision)?;
    let first = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        decision,
    )?;
    let connection = fixture.store.connection()?;
    let (recorded_decision, recorded_observation): (i64, i64) = connection.query_row(
        "SELECT json_extract(canonical_record, '$.decision_at'), observed_at FROM security_participant_state_mutations",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(recorded_decision, i64::try_from(decision)?);
    assert_eq!(recorded_observation, i64::try_from(observed)?);
    native::verify_coverage(&connection)?;
    drop(connection);
    // A different operation may arrive with an earlier decision timestamp.
    // Only authority observations impose a global chronological order.
    let context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(first.context_generation),
    );
    let (second, lease, _) = setup_at(&fixture, "earlier-decision", &context, observed)?;
    let mut request = request;
    request.transition_id = RecordId::new("earlier-decision-join")?;
    fixture.store.join_security_participant_flow(
        &second,
        &lease,
        &initialized,
        &context,
        &request,
        observed,
    )?;
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn a_later_authority_observation_cannot_hide_a_regressed_operation_decision() -> TestResult {
    let decision = now_ms().div_ceil(1000) * 1000;
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(decision / 1000, std::iter::empty());
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease, _) = setup_at(&fixture, "native-operation", &context, decision)?;
    let _advanced = chio_kernel::scope_fixed_runtime_for_current_thread(
        decision / 1000 + 1,
        std::iter::empty(),
    );
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            decision - 1
        )
        .is_err());
    assert_eq!(count(&fixture)?, 0);
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        decision,
    )?;
    Ok(())
}

#[test]
fn a_caller_clock_ahead_of_authority_cannot_extend_the_mutation_lease() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    {
        let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
            lease.expires_at_unix_ms() / 1000 - 1,
            std::iter::empty(),
        );
        let result = fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            lease.expires_at_unix_ms(),
        );
        assert!(
            result.is_err(),
            "caller-observed lease expiry must deny even when authority time is earlier"
        );
    }
    assert_eq!(count(&fixture)?, 0);
    Ok(())
}

#[test]
fn expired_join_readback_returns_history_without_fresh_authority_or_writes() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    assert!(fixture
        .store
        .load_security_participant_flow_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms()
        )?
        .is_none());
    let snapshot = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let before = global_count(&*fixture.store.connection()?)?;
    let now = lease.expires_at_unix_ms().div_ceil(1000) * 1000;
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(now / 1000, std::iter::empty());
    let history = fixture
        .store
        .load_security_participant_flow_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now,
        )?
        .ok_or("join history")?;
    assert_eq!(history.historical_snapshot(), &snapshot);
    assert_eq!(history.operation_id(), operation.binding().operation_id());
    assert_eq!(
        history.security_authority_id(),
        initialized.security_authority_id()
    );
    assert_eq!(
        history.initialization_digest(),
        initialized.initialization_digest()
    );
    assert_eq!(history.mutation_digest().len(), 64);
    assert!(!format!("{history:?}").contains("native-principal"));
    assert!(fixture
        .store
        .join_security_participant_flow(&operation, &lease, &initialized, &context, &request, now)
        .is_err());
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    Ok(())
}

#[test]
fn stale_version_and_expired_leases_cannot_mutate_native_flow() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let (operation, lease, stale) = setup_with_stale_lease(&fixture, "native-operation", &context)?;
    assert!(stale.claimed_version() < operation.version());
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &stale,
            &initialized,
            &context,
            &request,
            now_ms()
        )
        .is_err());
    {
        let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
            lease.expires_at_unix_ms().div_ceil(1000),
            std::iter::empty(),
        );
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
    }
    assert_eq!(count(&fixture)?, 0);
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
fn shared_generation_changes_are_captured_and_old_retry_is_historical_only() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, first) = request("first-join")?;
    let (operation, lease) = setup(&fixture, "first-operation", &context)?;
    let original = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &first,
        now_ms(),
    )?;
    let mut second = first.clone();
    second.transition_id = RecordId::new("second-join")?;
    second.key.session_id = SessionId::new("second-session")?;
    second.principal_join = InformationLabel::try_known(
        Default::default(),
        std::collections::BTreeSet::from([chio_security_types::Compartment::new("restricted")?]),
    )?;
    let second_context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        second.key.tenant_id.clone(),
        second.key.session_id.clone(),
        second.key.principal_id.clone(),
        second.key.isolation_epoch_id.clone(),
        second.key.lineage_id.clone(),
        1,
    ));
    let (second_operation, second_lease) = setup(&fixture, "second-operation", &second_context)?;
    let advanced = fixture.store.join_security_participant_flow(
        &second_operation,
        &second_lease,
        &initialized,
        &second_context,
        &second,
        now_ms(),
    )?;
    assert!(advanced.context_generation > original.context_generation);
    let connection = fixture.store.connection()?;
    assert_eq!(connection.query_row("SELECT generation FROM security_participant_state_flow_contexts WHERE security_authority_id = 'source' AND tenant_id = 'native-tenant' AND session_id = 'native-session'", [], |row| row.get::<_, i64>(0))?, i64::try_from(advanced.context_generation)?);
    native::verify_coverage(&connection)?;
    drop(connection);
    let current = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(advanced.context_generation),
    );
    assert_eq!(
        fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &current,
            &first,
            now_ms()
        )?,
        original
    );
    let (new_operation, new_lease) = setup(&fixture, "third-operation", &context)?;
    assert!(fixture
        .store
        .join_security_participant_flow(
            &new_operation,
            &new_lease,
            &initialized,
            &context,
            &first,
            now_ms()
        )
        .is_err());
    let mut third = first.clone();
    third.transition_id = RecordId::new("third-join")?;
    assert!(fixture
        .store
        .join_security_participant_flow(
            &new_operation,
            &new_lease,
            &initialized,
            &context,
            &third,
            now_ms()
        )
        .is_err());
    fixture.store.join_security_participant_flow(
        &new_operation,
        &new_lease,
        &initialized,
        &current,
        &third,
        now_ms(),
    )?;
    assert_eq!(count(&fixture)?, 3);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn excessive_row_capture_aborts_the_complete_owned_join() -> TestResult {
    use rusqlite::functions::FunctionFlags;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let (context, request) = request("native-join")?;
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = attempts.clone();
    fixture.store.connection()?.create_scalar_function(
        "native_test_capture_attempt",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(1_i64)
        },
    )?;
    // Same-tenant, same-identity, nonregressing updates pass semantic checks.
    // Count attempts outside SQLite rollback to prove the capture limit, not
    // rejection of unrelated transition IDs by the row policy.
    let updates = "SELECT native_test_capture_attempt();
         UPDATE security_participant_state_flow_sequences SET last_generation = last_generation
         WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id;"
        .repeat(4097);
    fixture.store.connection()?.execute_batch(&format!(
        "CREATE TEMP TRIGGER native_test_fanout AFTER INSERT ON main.security_participant_state_flow_sequences
         WHEN NEW.tenant_id = 'native-tenant' BEGIN
         {updates} END;",
    ))?;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
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
    // One genesis epoch plus 4,095 accepted updates fill the 4,096-row budget.
    assert_eq!(attempts.load(Ordering::SeqCst), 4096);
    assert_eq!(count(&fixture)?, 0);
    let connection = fixture.store.connection()?;
    assert!(connection.is_autocommit());
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM security_participant_state_transitions WHERE tenant_id = 'native-tenant'", [], |row| row.get::<_, i64>(0))?, 0);
    connection.execute_batch("DROP TRIGGER temp.native_test_fanout")?;
    connection.remove_function("native_test_capture_attempt", 0)?;
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
