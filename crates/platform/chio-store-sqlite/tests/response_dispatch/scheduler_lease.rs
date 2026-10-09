use super::*;
use chio_security_types::ports::{
    SchedulerRelativeRetryRequest, SchedulerWorkKey, MAX_SCHEDULER_RETRY_BACKOFF_MS,
};

#[test]
fn terminal_response_work_rejects_scheduler_lease_renewal() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("terminal-work-renewal.db"))
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let machine = ResponseStateMachine::new(Arc::clone(&store));
    let terminal_states = [
        ResponseState::Cancelled,
        ResponseState::Expired,
        ResponseState::Failed,
        ResponseState::Lifted,
    ];
    assert!(terminal_states.into_iter().all(ResponseState::is_terminal));
    for (index, terminal_state) in terminal_states.into_iter().enumerate() {
        let action_id = format!("action-terminal-work-renewal-{index}");
        let claim_id = format!("terminal-work-claim-{index}");
        let lease_owner_id = format!("terminal-work-owner-{index}");
        let claim_now_unix_ms = now_unix_ms();
        let (planned, work) = claim_due_planned_response(
            &store,
            &action_id,
            &claim_id,
            &lease_owner_id,
            claim_now_unix_ms,
        );
        let terminal = terminalize_planned_response(&machine, &planned, terminal_state);
        assert_eq!(
            decode_response_record(&terminal)
                .unwrap_or_else(|error| panic!("terminal response decode failed: {error}"))
                .state,
            terminal_state
        );

        let renewal_now_unix_ms = now_unix_ms();
        let error = rejected(
            store.renew_lease(&SchedulerLeaseRenewRequest {
                work: work.clone(),
                now_unix_ms: renewal_now_unix_ms,
                lease_expires_at_unix_ms: work
                    .lease_expires_at_unix_ms
                    .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
                transition_id: record_id(&format!("terminal-work-renewal-{index}")),
            }),
            "terminal response work unexpectedly renewed",
        );
        assert_eq!(error.kind(), PortErrorKind::Conflict);
        store
            .validate_lease(&work)
            .unwrap_or_else(|error| panic!("terminal rejection changed the lease: {error}"));
    }

    let corrupt_path = directory.path().join("corrupt-work-renewal.db");
    let corrupt_store = Arc::new(
        SqliteSecurityStateStore::open(&corrupt_path)
            .unwrap_or_else(|error| panic!("corrupt security store open failed: {error}")),
    );
    let corrupt_claim_now_unix_ms = now_unix_ms();
    let (corrupt_plan, corrupt_work) = claim_due_planned_response(
        &corrupt_store,
        "action-corrupt-work-renewal",
        "corrupt-work-claim",
        "corrupt-work-owner",
        corrupt_claim_now_unix_ms,
    );
    let connection = rusqlite::Connection::open(&corrupt_path)
        .unwrap_or_else(|error| panic!("corrupt state connection failed: {error}"));
    connection
        .execute(
            "UPDATE security_response_plans SET state = 'active' WHERE tenant_id = ?1 AND action_id = ?2",
            rusqlite::params![
                corrupt_plan.tenant_id.as_str(),
                corrupt_plan.action_id.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("corrupt response state failed: {error}"));
    let state_renewal_now_unix_ms = now_unix_ms();
    let state_error = rejected(
        corrupt_store.renew_lease(&SchedulerLeaseRenewRequest {
            work: corrupt_work.clone(),
            now_unix_ms: state_renewal_now_unix_ms,
            lease_expires_at_unix_ms: corrupt_work
                .lease_expires_at_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            transition_id: record_id("corrupt-state-work-renewal"),
        }),
        "state-corrupt response work unexpectedly renewed",
    );
    assert_eq!(state_error.kind(), PortErrorKind::IntegrityFailure);
    corrupt_store
        .validate_lease(&corrupt_work)
        .unwrap_or_else(|error| panic!("state rejection changed the lease: {error}"));

    let malformed_body = CanonicalBody::new(b"{}".to_vec())
        .unwrap_or_else(|error| panic!("malformed response body: {error}"));
    let malformed_hash = Digest32::new(*chio_core::sha256(malformed_body.as_bytes()).as_bytes());
    connection
        .execute(
            r#"
            UPDATE security_response_plans
            SET state = 'planned', body = ?3, body_hash = ?4
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                corrupt_plan.tenant_id.as_str(),
                corrupt_plan.action_id.as_str(),
                malformed_body.as_bytes(),
                malformed_hash.as_bytes().as_slice(),
            ],
        )
        .unwrap_or_else(|error| panic!("corrupt response body failed: {error}"));
    let body_renewal_now_unix_ms = now_unix_ms();
    let body_error = rejected(
        corrupt_store.renew_lease(&SchedulerLeaseRenewRequest {
            work: corrupt_work.clone(),
            now_unix_ms: body_renewal_now_unix_ms,
            lease_expires_at_unix_ms: corrupt_work
                .lease_expires_at_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            transition_id: record_id("corrupt-body-work-renewal"),
        }),
        "body-corrupt response work unexpectedly renewed",
    );
    assert_eq!(body_error.kind(), PortErrorKind::IntegrityFailure);
    corrupt_store
        .validate_lease(&corrupt_work)
        .unwrap_or_else(|error| panic!("body rejection changed the lease: {error}"));
}

#[test]
fn corrupt_scheduler_lease_expiry_blocks_validation_effect_renew_retry_and_release() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-work-provenance.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let claim_now_unix_ms = now_unix_ms();
    let (_, work) = claim_due_planned_response(
        &store,
        "action-corrupt-work-provenance",
        "corrupt-work-provenance-claim",
        "corrupt-work-provenance-owner",
        claim_now_unix_ms,
    );
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("corrupt provenance connection failed: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET lease_expires_at = lease_expires_at + 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt lease provenance failed: {error}"));

    let identity_error = rejected(
        store.validate_lease_identity(
            &work.tenant_id,
            &work.action_id,
            &work.lease_owner_id,
            work.fencing_token,
        ),
        "expiry-corrupt scheduler identity unexpectedly validated",
    );
    assert_eq!(identity_error.kind(), PortErrorKind::IntegrityFailure);

    let effect_body = CanonicalBody::new(b"{}".to_vec())
        .unwrap_or_else(|error| panic!("effect body failed: {error}"));
    let effect_error = rejected(
        store.persist_effect(&ResponseEffectRecord {
            tenant_id: work.tenant_id.clone(),
            action_id: work.action_id.clone(),
            effect_id: EffectId::new("effect-corrupt-work-provenance")
                .unwrap_or_else(|error| panic!("effect id failed: {error}")),
            generation: 0,
            scheduler_lease_owner_id: work.lease_owner_id.clone(),
            scheduler_fencing_token: work.fencing_token,
            state: record_id("requested"),
            body_hash: Digest32::new(*chio_core::sha256(effect_body.as_bytes()).as_bytes()),
            canonical_body: effect_body,
            encrypted_rollback_ref: None,
        }),
        "expiry-corrupt scheduler lease unexpectedly authorized an effect",
    );
    assert_eq!(effect_error.kind(), PortErrorKind::IntegrityFailure);

    let renewal_now_unix_ms = now_unix_ms();
    let renewal_error = rejected(
        store.renew_lease(&SchedulerLeaseRenewRequest {
            work: work.clone(),
            now_unix_ms: renewal_now_unix_ms,
            lease_expires_at_unix_ms: work
                .lease_expires_at_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            transition_id: record_id("corrupt-provenance-renewal"),
        }),
        "expiry-corrupt scheduler lease unexpectedly renewed",
    );
    assert_eq!(renewal_error.kind(), PortErrorKind::IntegrityFailure);

    let retry_now_unix_ms = now_unix_ms();
    let retry_error = rejected(
        store.record_retry(&SchedulerRetryRequest {
            work: work.clone(),
            expected_attempts: 0,
            error_code: ErrorCode::new("response.corrupt_provenance_test")
                .unwrap_or_else(|error| panic!("retry error code failed: {error}")),
            first_failure_at_unix_ms: retry_now_unix_ms,
            now_unix_ms: retry_now_unix_ms,
            not_before_unix_ms: retry_now_unix_ms.saturating_add(60_000),
            health_event_id: None,
            transition_id: record_id("corrupt-provenance-retry"),
        }),
        "expiry-corrupt scheduler lease unexpectedly recorded a retry",
    );
    assert_eq!(retry_error.kind(), PortErrorKind::IntegrityFailure);

    let release_error = rejected(
        store.release_lease(&SchedulerLeaseReleaseRequest {
            work: work.clone(),
            clear_retry_state: true,
            transition_id: record_id("corrupt-provenance-release"),
        }),
        "expiry-corrupt scheduler lease unexpectedly released",
    );
    assert_eq!(release_error.kind(), PortErrorKind::IntegrityFailure);

    let durable = connection
        .query_row(
            r#"
            SELECT claim_ordinal, lease_owner_id, lease_expires_at, fencing_token,
                   (SELECT COUNT(*) FROM security_scheduler_retries
                    WHERE tenant_id = ?1 AND action_id = ?2),
                   (SELECT COUNT(*) FROM security_response_effects
                    WHERE tenant_id = ?1 AND action_id = ?2),
                   (SELECT COUNT(*) FROM security_transitions
                    WHERE tenant_id = ?1
                      AND transition_id IN (
                          'corrupt-provenance-renewal',
                          'corrupt-provenance-retry',
                          'corrupt-provenance-release'
                      ))
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("corrupt provenance readback failed: {error}"));
    assert_eq!(durable.0, 0);
    assert_eq!(durable.1, work.lease_owner_id.as_str());
    assert_eq!(
        u64::try_from(durable.2)
            .unwrap_or_else(|error| panic!("lease expiry conversion failed: {error}")),
        work.lease_expires_at_unix_ms.saturating_add(1)
    );
    assert_eq!(
        u64::try_from(durable.3)
            .unwrap_or_else(|error| panic!("fencing token conversion failed: {error}")),
        work.fencing_token
    );
    assert_eq!((durable.4, durable.5, durable.6), (0, 0, 0));
}

#[test]
fn scheduler_renewal_replay_rejects_corrupt_lease_provenance() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory
        .path()
        .join("corrupt-renewal-replay-provenance.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let claim_now_unix_ms = now_unix_ms();
    let (_, work) = claim_due_planned_response(
        &store,
        "action-corrupt-renewal-replay",
        "corrupt-renewal-replay-claim",
        "corrupt-renewal-replay-owner",
        claim_now_unix_ms,
    );
    let request = SchedulerLeaseRenewRequest {
        work: work.clone(),
        now_unix_ms: now_unix_ms(),
        lease_expires_at_unix_ms: work
            .lease_expires_at_unix_ms
            .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
        transition_id: record_id("corrupt-renewal-replay-transition"),
    };
    let renewed = store
        .renew_lease(&request)
        .unwrap_or_else(|error| panic!("initial renewal failed: {error}"));
    assert_eq!(
        renewed.lease_expires_at_unix_ms,
        request.lease_expires_at_unix_ms
    );

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("renewal replay connection failed: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET claim_ordinal = 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt renewed lease provenance failed: {error}"));

    let replay_error = rejected(
        store.renew_lease(&request),
        "provenance-corrupt renewal replay unexpectedly succeeded",
    );
    assert_eq!(replay_error.kind(), PortErrorKind::IntegrityFailure);
    let durable = connection
        .query_row(
            r#"
            SELECT claim_ordinal, lease_expires_at,
                   (SELECT COUNT(*) FROM security_transitions
                    WHERE tenant_id = ?1
                      AND transition_id = 'corrupt-renewal-replay-transition')
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("renewal replay readback failed: {error}"));
    assert_eq!(durable.0, 1);
    assert_eq!(
        u64::try_from(durable.1)
            .unwrap_or_else(|error| panic!("renewed expiry conversion failed: {error}")),
        renewed.lease_expires_at_unix_ms
    );
    assert_eq!(durable.2, 1);
}

#[test]
fn scheduler_claim_replay_rejects_corrupt_lease_provenance() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-claim-replay-provenance.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let claim_now_unix_ms = now_unix_ms();
    let claim_id = "corrupt-claim-replay-claim";
    let lease_owner_id = "corrupt-claim-replay-owner";
    let (planned, work) = claim_due_planned_response(
        &store,
        "action-corrupt-claim-replay",
        claim_id,
        lease_owner_id,
        claim_now_unix_ms,
    );
    let request = SchedulerClaimRequest {
        tenant_id: planned.tenant_id,
        claim_id: record_id(claim_id),
        lease_owner_id: LeaseOwnerId::new(lease_owner_id)
            .unwrap_or_else(|error| panic!("lease owner failed: {error}")),
        now_unix_ms: claim_now_unix_ms,
        lease_expires_at_unix_ms: claim_now_unix_ms.saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
        max_claims: 1,
    };
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("claim replay connection failed: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET claim_ordinal = 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt claimed lease provenance failed: {error}"));

    let replay_error = rejected(
        store.claim_due(&request),
        "provenance-corrupt claim replay unexpectedly succeeded",
    );
    assert_eq!(replay_error.kind(), PortErrorKind::IntegrityFailure);
    let durable = connection
        .query_row(
            r#"
            SELECT claim_ordinal, lease_expires_at, fencing_token,
                   (SELECT COUNT(*) FROM security_scheduler_claims
                    WHERE tenant_id = ?1 AND claim_id = ?3)
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                work.tenant_id.as_str(),
                work.action_id.as_str(),
                request.claim_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("claim replay readback failed: {error}"));
    assert_eq!(durable.0, 1);
    assert_eq!(
        u64::try_from(durable.1)
            .unwrap_or_else(|error| panic!("claim expiry conversion failed: {error}")),
        work.lease_expires_at_unix_ms
    );
    assert_eq!(
        u64::try_from(durable.2)
            .unwrap_or_else(|error| panic!("claim token conversion failed: {error}")),
        work.fencing_token
    );
    assert_eq!(durable.3, 1);
}

#[test]
fn scheduler_claim_replay_rejects_a_missing_claim_row() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("missing-claim-replay.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let claim_now_unix_ms = now_unix_ms();
    let claim_id = "missing-claim-replay-claim";
    let lease_owner_id = "missing-claim-replay-owner";
    let (planned, work) = claim_due_planned_response(
        &store,
        "action-missing-claim-replay",
        claim_id,
        lease_owner_id,
        claim_now_unix_ms,
    );
    let request = SchedulerClaimRequest {
        tenant_id: planned.tenant_id,
        claim_id: record_id(claim_id),
        lease_owner_id: LeaseOwnerId::new(lease_owner_id)
            .unwrap_or_else(|error| panic!("lease owner failed: {error}")),
        now_unix_ms: claim_now_unix_ms,
        lease_expires_at_unix_ms: work.lease_expires_at_unix_ms,
        max_claims: 1,
    };
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("missing claim replay connection failed: {error}"));
    let deleted = connection
        .execute(
            "DELETE FROM security_scheduler_claims WHERE tenant_id = ?1 AND claim_id = ?2",
            rusqlite::params![request.tenant_id.as_str(), request.claim_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("delete scheduler claim failed: {error}"));
    assert_eq!(deleted, 1);

    let replay_error = rejected(
        store.claim_due(&request),
        "missing-row scheduler claim replay unexpectedly succeeded",
    );
    assert_eq!(replay_error.kind(), PortErrorKind::IntegrityFailure);
    let durable = connection
        .query_row(
            r#"
            SELECT claim_id, claim_ordinal, lease_owner_id,
                   lease_expires_at, fencing_token,
                   (SELECT COUNT(*) FROM security_scheduler_claims
                    WHERE tenant_id = ?1 AND claim_id = ?3)
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                work.tenant_id.as_str(),
                work.action_id.as_str(),
                request.claim_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("missing claim replay readback failed: {error}"));
    assert_eq!(durable.0, request.claim_id.as_str());
    assert_eq!(durable.1, 0);
    assert_eq!(durable.2, work.lease_owner_id.as_str());
    assert_eq!(
        u64::try_from(durable.3)
            .unwrap_or_else(|error| panic!("claim expiry conversion failed: {error}")),
        work.lease_expires_at_unix_ms
    );
    assert_eq!(
        u64::try_from(durable.4)
            .unwrap_or_else(|error| panic!("claim token conversion failed: {error}")),
        work.fencing_token
    );
    assert_eq!(durable.5, 0);
}

#[test]
fn relative_retry_deadline_follows_trusted_time_read_after_the_write_lock() {
    const SAMPLED_AT: u64 = 100_000;
    const BACKOFF_MS: u64 = 1_000;
    const LOCK_WAIT_MS: u64 = 2_000;
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("relative-retry-write-lock.db");
    let clock = Arc::new(MutableSecurityStateClock::new(SAMPLED_AT));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &path,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let (_, relative_work) = claim_due_planned_response(
        &store,
        "action-relative-retry-lock",
        "relative-retry-lock-claim",
        "relative-retry-lock-owner",
        SAMPLED_AT,
    );
    let (_, absolute_work) = claim_due_planned_response(
        &store,
        "action-absolute-retry-lock",
        "absolute-retry-lock-claim",
        "absolute-retry-lock-owner",
        SAMPLED_AT,
    );
    let error_code = ErrorCode::new("response.rollback_partial")
        .unwrap_or_else(|error| panic!("retry error code failed: {error}"));
    // Both requests carry the trusted time sampled before waiting for the
    // write lock.
    let relative = SchedulerRelativeRetryRequest {
        work: relative_work.clone(),
        expected_attempts: 0,
        error_code: error_code.clone(),
        first_failure_at_unix_ms: SAMPLED_AT,
        now_unix_ms: SAMPLED_AT,
        backoff_ms: BACKOFF_MS,
        health_event_id: None,
        transition_id: record_id("relative-retry-after-lock-wait"),
    };
    let absolute = SchedulerRetryRequest {
        work: absolute_work.clone(),
        expected_attempts: 0,
        error_code: error_code.clone(),
        first_failure_at_unix_ms: SAMPLED_AT,
        now_unix_ms: SAMPLED_AT,
        not_before_unix_ms: SAMPLED_AT + BACKOFF_MS,
        health_event_id: None,
        transition_id: record_id("absolute-retry-after-lock-wait"),
    };

    // Another writer holds the lock while trusted time passes beyond the
    // backoff. Neither call can acquire the lock before the release, so the
    // store's trusted read follows the advance wherever each call waits.
    let writer = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("lock holder connection failed: {error}"));
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .unwrap_or_else(|error| panic!("write lock acquisition failed: {error}"));
    let (relative_result, absolute_result) = thread::scope(|scope| {
        let relative_call = scope.spawn(|| store.record_relative_retry(&relative));
        let absolute_call = scope.spawn(|| store.record_retry(&absolute));
        clock.set(SAMPLED_AT + LOCK_WAIT_MS);
        writer
            .execute_batch("COMMIT")
            .unwrap_or_else(|error| panic!("write lock release failed: {error}"));
        (
            relative_call
                .join()
                .unwrap_or_else(|_| panic!("relative retry call panicked")),
            absolute_call
                .join()
                .unwrap_or_else(|_| panic!("absolute retry call panicked")),
        )
    });

    let recorded = relative_result
        .unwrap_or_else(|error| panic!("relative retry after a write lock wait failed: {error}"));
    assert_eq!(
        (
            recorded.attempts,
            recorded.first_failure_at_unix_ms,
            recorded.not_before_unix_ms
        ),
        (1, SAMPLED_AT, SAMPLED_AT + LOCK_WAIT_MS + BACKOFF_MS)
    );
    let relative_key = SchedulerWorkKey {
        tenant_id: relative_work.tenant_id.clone(),
        action_id: relative_work.action_id.clone(),
    };
    assert_eq!(
        store
            .load_retry(&relative_key)
            .unwrap_or_else(|error| panic!("relative retry readback failed: {error}")),
        Some(recorded.clone())
    );
    assert_eq!(
        store
            .record_relative_retry(&relative)
            .unwrap_or_else(|error| panic!("relative retry replay failed: {error}")),
        recorded
    );

    let refusal = rejected(
        absolute_result,
        "an absolute retry deadline that fell due during the lock wait was recorded",
    );
    assert_eq!(refusal.kind(), PortErrorKind::InvalidData);
    let absolute_key = SchedulerWorkKey {
        tenant_id: absolute_work.tenant_id.clone(),
        action_id: absolute_work.action_id.clone(),
    };
    assert_eq!(
        store
            .load_retry(&absolute_key)
            .unwrap_or_else(|error| panic!("absolute retry readback failed: {error}")),
        None
    );
    store
        .validate_lease(&absolute_work)
        .unwrap_or_else(|error| panic!("refused retry changed the lease: {error}"));

    for backoff_ms in [0, MAX_SCHEDULER_RETRY_BACKOFF_MS + 1] {
        let error = rejected(
            store.record_relative_retry(&SchedulerRelativeRetryRequest {
                work: absolute_work.clone(),
                expected_attempts: 0,
                error_code: error_code.clone(),
                first_failure_at_unix_ms: SAMPLED_AT + LOCK_WAIT_MS,
                now_unix_ms: SAMPLED_AT + LOCK_WAIT_MS,
                backoff_ms,
                health_event_id: None,
                transition_id: record_id(&format!("relative-retry-backoff-{backoff_ms}")),
            }),
            "an unbounded relative retry backoff was recorded",
        );
        assert_eq!(error.kind(), PortErrorKind::InvalidData);
    }
    store
        .validate_lease(&absolute_work)
        .unwrap_or_else(|error| panic!("refused backoffs changed the lease: {error}"));
}
