//! Real authority status CAS, tombstone retention and restart controls.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionRecoveryDeferralClear, AdmissionRecoveryDeferralV1, AdmissionRecoveryDeferralWrite,
    AdmissionRecoveryFailureKind, AdmissionRecoveryPageQuery, AdmissionRecoveryPhase,
    AdmissionRecoveryPortError, AdmissionRecoveryStatusV1,
};

pub(super) fn deferral(
    operation: &AdmissionOperationV1,
    previous: Option<&AdmissionRecoveryStatusV1>,
    at: u64,
) -> Result<AdmissionRecoveryDeferralV1, AdmissionOperationStoreError> {
    AdmissionRecoveryDeferralV1::after_failure(
        operation,
        previous.map(|status| &status.deferral),
        AdmissionRecoveryPhase::Inspection,
        AdmissionRecoveryFailureKind::ParticipantUnavailable,
        digest("diagnostic_digest", 'a'),
        at,
    )
}

pub(super) fn defer(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    at: u64,
) -> AnchoredTestResult<(AdmissionRecoveryLease, AdmissionRecoveryStatusV1)> {
    let lease = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant_id", "deferred-control-worker"),
        at,
        at.checked_add(1_000).ok_or("claim deadline")?,
        &fixture.fence,
    )?;
    let value = deferral(operation, None, at)?;
    let status = fixture
        .store
        .defer_recovery(AdmissionRecoveryDeferralWrite {
            operation,
            lease: &lease,
            expected: None,
            deferral: &value,
            fence: &fixture.fence,
            trusted_now_unix_ms: at,
        })?;
    Ok((lease, status))
}

#[test]
fn recovery_status_cas_and_clear_tombstone_survive_new_serving_owner() -> AnchoredTestResult {
    let at = 1_800_000_000_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "deferred-restart-request",
        "deferred-restart-capability",
    );
    fixture.store.begin(&operation, &fixture.fence, at)?;
    let (lease, first) = defer(&fixture, &operation, at)?;
    assert_eq!(first.deferral.attempt_count, 1);
    assert_eq!(first.deferral.retry_not_before_unix_ms, at + 60_000);
    let connection = Connection::open(&fixture.database)?;
    let before = admission_commit_rows(&connection)?;
    let anchor = fixture.authority.anchor_generation()?;
    let replay = fixture
        .store
        .defer_recovery(AdmissionRecoveryDeferralWrite {
            operation: &operation,
            lease: &lease,
            expected: None,
            deferral: &first.deferral,
            fence: &fixture.fence,
            trusted_now_unix_ms: at,
        })?;
    assert_eq!(replay, first);
    assert_eq!(admission_commit_rows(&connection)?, before);
    assert_eq!(fixture.authority.anchor_generation()?, anchor);
    let next = deferral(&operation, Some(&first), at)?;
    assert!(matches!(
        fixture
            .store
            .defer_recovery(AdmissionRecoveryDeferralWrite {
                operation: &operation,
                lease: &lease,
                expected: None,
                deferral: &next,
                fence: &fixture.fence,
                trusted_now_unix_ms: at,
            }),
        Err(AdmissionRecoveryPortError::Local(
            AdmissionOperationStoreError::Invariant(_)
        ))
    ));
    assert_eq!(admission_commit_rows(&connection)?, before);
    let clear = || AdmissionRecoveryDeferralClear {
        operation: &operation,
        lease: Some(&lease),
        expected: &first,
        fence: &fixture.fence,
        trusted_now_unix_ms: at,
    };
    fixture.store.clear_recovery_deferral(clear())?;
    let tombstone = fixture
        .store
        .load_recovery_status(operation.binding().operation_id(), &fixture.fence, at)?
        .ok_or("retained clear tombstone")?;
    assert!(!tombstone.quarantined);
    assert_eq!(tombstone.deferral, first.deferral);
    let after_clear = admission_commit_rows(&connection)?;
    let clear_anchor = fixture.authority.anchor_generation()?;
    fixture.store.clear_recovery_deferral(clear())?;
    assert_eq!(admission_commit_rows(&connection)?, after_clear);
    assert_eq!(fixture.authority.anchor_generation()?, clear_anchor);
    drop(connection);
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence: old_fence,
    } = fixture;
    drop(store);
    drop(authority);
    let authority = crate::test_authority::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    assert_ne!(fence, old_fence);
    assert_eq!(
        store.load_recovery_status(operation.binding().operation_id(), &fence, at)?,
        Some(tombstone.clone())
    );
    assert!(matches!(
        store.load_recovery_status(operation.binding().operation_id(), &old_fence, at),
        Err(AdmissionRecoveryPortError::Local(
            AdmissionOperationStoreError::Fenced
        ))
    ));
    let lease = store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant_id", "deferred-control-worker"),
        at,
        at + 1_000,
        &fence,
    )?;
    let second = deferral(&operation, Some(&tombstone), at)?;
    let stored = store.defer_recovery(AdmissionRecoveryDeferralWrite {
        operation: &operation,
        lease: &lease,
        expected: Some(&tombstone),
        deferral: &second,
        fence: &fence,
        trusted_now_unix_ms: at,
    })?;
    assert_eq!(stored.deferral.attempt_count, 2);
    assert_eq!(stored.deferral.retry_not_before_unix_ms, at + 120_000);
    assert!(stored.quarantined);
    let _due_clock =
        chio_test_support::clock::scope_unix_secs(stored.deferral.retry_not_before_unix_ms / 1_000);
    let due = store.recovery_page(AdmissionRecoveryPageQuery {
        not_after_unix_ms: stored.deferral.retry_not_before_unix_ms,
        candidate_limit: 1,
        after_operation_id: None,
        fence: &fence,
    })?;
    assert_eq!(due.operations, vec![operation.clone()]);
    drop(store);
    drop(authority);
    drop(_temp);
    Ok(())
}

#[test]
fn recovery_backoff_due_and_global_integrity_are_checked_before_skipping() -> AnchoredTestResult {
    let at = 1_800_000_100_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "deferred-integrity-request",
        "deferred-integrity-capability",
    );
    fixture.store.begin(&operation, &fixture.fence, at)?;
    defer(&fixture, &operation, at)?;
    let query = |now| AdmissionRecoveryPageQuery {
        not_after_unix_ms: now,
        candidate_limit: 1,
        after_operation_id: None,
        fence: &fixture.fence,
    };
    let page = fixture.store.recovery_page(query(at + 2_000))?;
    assert!(page.operations.is_empty());
    assert_eq!(page.scanned_candidates, 1);
    assert_eq!(
        page.next_cursor.as_ref(),
        Some(operation.binding().operation_id())
    );
    let connection = Connection::open(&fixture.database)?;
    connection.execute(
        "UPDATE admission_operation_recovery_deferrals SET status_digest=?1 WHERE operation_id=?2",
        params!["b".repeat(64), operation.binding().operation_id().as_str()],
    )?;
    assert!(matches!(
        fixture.store.recovery_page(query(at + 2_000)),
        Err(AdmissionRecoveryPortError::Local(
            AdmissionOperationStoreError::Invariant(_)
        ))
    ));
    assert!(matches!(
        fixture.store.load_recovery_status(
            operation.binding().operation_id(),
            &fixture.fence,
            at + 2_000
        ),
        Err(AdmissionRecoveryPortError::Local(
            AdmissionOperationStoreError::Invariant(_)
        ))
    ));
    Ok(())
}

#[test]
fn recovery_backoff_progression_is_bounded_and_overflow_is_global() -> AnchoredTestResult {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "deferred-overflow-request",
        "deferred-overflow-capability",
    );
    let at = now_ms();
    let mut previous = None;
    for (count, delay) in [
        (1, 60_000),
        (2, 120_000),
        (3, 240_000),
        (4, 300_000),
        (5, 300_000),
    ] {
        let value = deferral(&operation, previous.as_ref(), at)?;
        assert_eq!(value.attempt_count, count);
        assert_eq!(value.retry_not_before_unix_ms, at + delay);
        previous = Some(AdmissionRecoveryStatusV1 {
            quarantined: false,
            deferral: value,
        });
    }
    let mut maximum = previous.ok_or("prior status")?;
    maximum.deferral.attempt_count = u32::MAX;
    assert!(matches!(
        deferral(&operation, Some(&maximum), at),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    let mut regressed = maximum;
    regressed.deferral.attempt_count = 5;
    assert!(matches!(
        deferral(&operation, Some(&regressed), at - 1),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    Ok(())
}
