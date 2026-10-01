use super::*;

fn fixed_clock(milliseconds: u64) -> chio_kernel::FixedRuntimeScope {
    chio_kernel::scope_fixed_runtime_for_current_thread(milliseconds / 1_000, std::iter::empty())
}

#[test]
fn authority_clock_rollback_is_rejected_without_mutating_history() -> AnchoredTestResult {
    let fixture = fixture();
    let now = now_ms() / 1_000 * 1_000;
    let _clock = fixed_clock(now);
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "clock-first",
        "clock-cap",
    );
    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "clock-second",
        "clock-cap",
    );
    fixture.store.begin(&first, &fixture.fence, now)?;
    let head = load_admission_commit_head(&*fixture.store.connection()?)?;
    let _rollback = fixed_clock(now - 1_000);
    assert!(matches!(
        fixture.store.begin(&second, &fixture.fence, now),
        Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("authority time regressed")
    ));
    assert_eq!(
        load_admission_commit_head(&*fixture.store.connection()?)?,
        head
    );
    assert!(fixture
        .store
        .load_by_operation_id(second.binding().operation_id())?
        .is_none());
    Ok(())
}

#[test]
fn decision_order_is_local_but_observation_order_is_global() -> AnchoredTestResult {
    let fixture = fixture();
    let now = now_ms() / 1_000 * 1_000;
    let _clock = fixed_clock(now);
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "order-first",
        "order-cap",
    );
    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "order-second",
        "order-cap",
    );
    fixture.store.begin(&first, &fixture.fence, now + 100)?;
    let _later = fixed_clock(now + 1_000);
    fixture.store.begin(&second, &fixture.fence, now)?;
    assert!(matches!(
        fixture.store.claim_recovery(first.binding().operation_id(), 1,
            &identifier("claimant_id", "order-worker"), now + 99, now + 60_000, &fixture.fence),
        Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("operation time regressed")
    ));
    fixture.store.claim_recovery(
        first.binding().operation_id(),
        1,
        &identifier("claimant_id", "order-worker"),
        now + 101,
        now + 60_000,
        &fixture.fence,
    )?;
    let connection = fixture.store.connection()?;
    let mut statement = connection.prepare("SELECT recorded_at_unix_ms, observed_at_unix_ms FROM admission_operation_commits ORDER BY commit_sequence")?;
    let times = statement
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let signed_now = i64::try_from(now)?;
    assert_eq!(
        times,
        vec![
            (signed_now + 100, signed_now),
            (signed_now, signed_now + 1_000),
            (signed_now + 101, signed_now + 1_000)
        ]
    );
    assert_eq!(
        load_admission_commit_head(&connection)?.trusted_time_high_water_unix_ms,
        now + 1_000
    );
    verify_admission_operation_invariants(&connection)?;
    drop(statement);
    drop(connection);
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
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(
        reopened
            .admission_operation_store()
            .load_by_operation_id(second.binding().operation_id())?,
        Some(second)
    );
    Ok(())
}

#[test]
fn delayed_time_cannot_create_revalidate_or_use_an_expired_lease() -> AnchoredTestResult {
    let fixture = fixture();
    let now = now_ms() / 1_000 * 1_000;
    let _clock = fixed_clock(now);
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "expired-clock",
        "expired-cap",
    );
    fixture.store.begin(&operation, &fixture.fence, now)?;
    let worker = identifier("claimant_id", "expired-worker");
    let claim = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        1,
        &worker,
        now,
        now + 1_000,
        &fixture.fence,
    )?;
    let command = command(
        &operation,
        claim.clone(),
        vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
            &operation,
            "expired-attempt",
        ))],
        AdmissionOperationState::BrokerAttemptRegistered,
        None,
    );
    let _expired = fixed_clock(now + 1_000);
    for result in [
        fixture.store.revalidate_recovery_claim(
            &operation,
            claim.untrusted_claim(),
            now,
            &fixture.fence,
        ),
        fixture.store.compare_and_swap(&command, now).map(|_| ()),
        fixture
            .store
            .claim_recovery(
                operation.binding().operation_id(),
                1,
                &worker,
                now,
                now + 1_000,
                &fixture.fence,
            )
            .map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(AdmissionOperationStoreError::Operation(
                AdmissionOperationError::LeaseExpired
            ))
        ));
    }
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}
