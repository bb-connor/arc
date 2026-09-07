#[test]
fn empty_scheduler_claim_replay_rejects_corrupt_commit_time() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-empty-claim-replay.db");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let claim_now_unix_ms = now_unix_ms();
    let request = SchedulerClaimRequest {
        tenant_id: TenantId::new("tenant-empty-claim-replay")
            .unwrap_or_else(|error| panic!("tenant id failed: {error}")),
        claim_id: record_id("empty-claim-replay-claim"),
        lease_owner_id: LeaseOwnerId::new("empty-claim-replay-owner")
            .unwrap_or_else(|error| panic!("lease owner failed: {error}")),
        now_unix_ms: claim_now_unix_ms,
        lease_expires_at_unix_ms: claim_now_unix_ms.saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
        max_claims: 1,
    };
    assert!(store
        .claim_due(&request)
        .unwrap_or_else(|error| panic!("empty claim failed: {error}"))
        .is_empty());
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("empty claim replay connection failed: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_scheduler_claims
            SET committed_at = lease_expires_at
            WHERE tenant_id = ?1 AND claim_id = ?2
            "#,
            rusqlite::params![request.tenant_id.as_str(), request.claim_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt empty claim commit time failed: {error}"));

    let replay_error = rejected(
        store.claim_due(&request),
        "commit-time-corrupt empty claim replay unexpectedly succeeded",
    );
    assert_eq!(replay_error.kind(), PortErrorKind::IntegrityFailure);
    let durable = connection
        .query_row(
            r#"
            SELECT result_count, committed_at, lease_expires_at,
                   (SELECT COUNT(*) FROM security_scheduler_leases
                    WHERE tenant_id = ?1)
            FROM security_scheduler_claims
            WHERE tenant_id = ?1 AND claim_id = ?2
            "#,
            rusqlite::params![request.tenant_id.as_str(), request.claim_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("empty claim replay readback failed: {error}"));
    assert_eq!(durable.0, 0);
    assert_eq!(durable.1, durable.2);
    assert_eq!(durable.3, 0);
}

#[test]
fn delayed_scheduler_renewal_and_retry_replays_remain_idempotent() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("delayed-scheduler-replays.db");
    let initial_now_unix_ms = 100_000;
    let clock = Arc::new(MutableSecurityStateClock::new(initial_now_unix_ms));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &path,
            Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
        )
        .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let (_, work) = claim_due_planned_response(
        &store,
        "action-delayed-scheduler-replays",
        "delayed-scheduler-replays-claim",
        "delayed-scheduler-replays-owner",
        initial_now_unix_ms,
    );
    let renewal_request = SchedulerLeaseRenewRequest {
        work: work.clone(),
        now_unix_ms: initial_now_unix_ms,
        lease_expires_at_unix_ms: work
            .lease_expires_at_unix_ms
            .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
        transition_id: record_id("delayed-scheduler-renewal"),
    };
    let renewed = store
        .renew_lease(&renewal_request)
        .unwrap_or_else(|error| panic!("initial renewal failed: {error}"));
    let delayed_renewal_now_unix_ms = initial_now_unix_ms.saturating_add(10_000);
    clock.set(delayed_renewal_now_unix_ms);
    assert_eq!(
        store
            .renew_lease(&renewal_request)
            .unwrap_or_else(|error| panic!("delayed renewal replay failed: {error}")),
        renewed
    );

    let retry_request = SchedulerRetryRequest {
        work: renewed,
        expected_attempts: 0,
        error_code: ErrorCode::new("response.delayed_retry_replay")
            .unwrap_or_else(|error| panic!("retry error code failed: {error}")),
        first_failure_at_unix_ms: delayed_renewal_now_unix_ms,
        now_unix_ms: delayed_renewal_now_unix_ms,
        not_before_unix_ms: delayed_renewal_now_unix_ms.saturating_add(100),
        health_event_id: None,
        transition_id: record_id("delayed-scheduler-retry"),
    };
    let retry = store
        .record_retry(&retry_request)
        .unwrap_or_else(|error| panic!("initial retry failed: {error}"));
    clock.set(retry_request.not_before_unix_ms.saturating_add(10_000));
    assert_eq!(
        store
            .record_retry(&retry_request)
            .unwrap_or_else(|error| panic!("delayed retry replay failed: {error}")),
        retry
    );

    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("delayed replay readback failed: {error}"));
    let durable = connection
        .query_row(
            r#"
            SELECT attempts,
                   (SELECT COUNT(*) FROM security_transitions
                    WHERE tenant_id = ?1
                      AND transition_id IN (
                          'delayed-scheduler-renewal',
                          'delayed-scheduler-retry'
                      ))
            FROM security_scheduler_retries
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![retry.key.tenant_id.as_str(), retry.key.action_id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap_or_else(|error| panic!("delayed replay durable state failed: {error}"));
    assert_eq!(durable, (1, 2));
}

#[test]
fn exact_claim_replay_returns_the_current_renewed_lease() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let initial_now_unix_ms = 100_000;
    let clock = Arc::new(MutableSecurityStateClock::new(initial_now_unix_ms));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("claim-renewal-replay.db"),
            Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
        )
        .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let (planned, work) = claim_due_planned_response(
        &store,
        "action-claim-renewal-replay",
        "claim-renewal-replay-claim",
        "claim-renewal-replay-owner",
        initial_now_unix_ms,
    );
    let claim_request = SchedulerClaimRequest {
        tenant_id: planned.tenant_id,
        claim_id: record_id("claim-renewal-replay-claim"),
        lease_owner_id: work.lease_owner_id.clone(),
        now_unix_ms: initial_now_unix_ms,
        lease_expires_at_unix_ms: work.lease_expires_at_unix_ms,
        max_claims: 1,
    };
    let renewed = store
        .renew_lease(&SchedulerLeaseRenewRequest {
            work: work.clone(),
            now_unix_ms: initial_now_unix_ms,
            lease_expires_at_unix_ms: work
                .lease_expires_at_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            transition_id: record_id("claim-renewal-replay-renew"),
        })
        .unwrap_or_else(|error| panic!("lease renewal failed: {error}"));
    clock.set(work.lease_expires_at_unix_ms.saturating_add(1));

    assert_eq!(
        store
            .claim_due(&claim_request)
            .unwrap_or_else(|error| panic!("exact renewed claim replay failed: {error}")),
        vec![renewed]
    );
}

#[test]
fn earlier_renewal_replay_returns_the_current_successor_lease() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let initial_now_unix_ms = 100_000;
    let clock = Arc::new(MutableSecurityStateClock::new(initial_now_unix_ms));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("renewal-successor-replay.db"),
            Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
        )
        .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let (_, work) = claim_due_planned_response(
        &store,
        "action-renewal-successor-replay",
        "renewal-successor-replay-claim",
        "renewal-successor-replay-owner",
        initial_now_unix_ms,
    );
    let first_request = SchedulerLeaseRenewRequest {
        work: work.clone(),
        now_unix_ms: initial_now_unix_ms,
        lease_expires_at_unix_ms: work
            .lease_expires_at_unix_ms
            .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
        transition_id: record_id("renewal-successor-replay-first"),
    };
    let first = store
        .renew_lease(&first_request)
        .unwrap_or_else(|error| panic!("first lease renewal failed: {error}"));
    let second = store
        .renew_lease(&SchedulerLeaseRenewRequest {
            work: first,
            now_unix_ms: initial_now_unix_ms,
            lease_expires_at_unix_ms: first_request
                .lease_expires_at_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            transition_id: record_id("renewal-successor-replay-second"),
        })
        .unwrap_or_else(|error| panic!("second lease renewal failed: {error}"));

    assert_eq!(
        store
            .renew_lease(&first_request)
            .unwrap_or_else(|error| panic!("first renewal replay failed: {error}")),
        second
    );
}

#[test]
fn superseded_retry_replay_returns_a_stale_conflict() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let initial_now_unix_ms = 100_000;
    let clock = Arc::new(MutableSecurityStateClock::new(initial_now_unix_ms));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("retry-successor-replay.db"),
            Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
        )
        .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let (planned, first_work) = claim_due_planned_response(
        &store,
        "action-retry-successor-replay",
        "retry-successor-replay-first-claim",
        "retry-successor-replay-owner",
        initial_now_unix_ms,
    );
    let first_request = SchedulerRetryRequest {
        work: first_work,
        expected_attempts: 0,
        error_code: ErrorCode::new("response.retry_successor_first")
            .unwrap_or_else(|error| panic!("retry error code failed: {error}")),
        first_failure_at_unix_ms: initial_now_unix_ms,
        now_unix_ms: initial_now_unix_ms,
        not_before_unix_ms: initial_now_unix_ms.saturating_add(1_000),
        health_event_id: None,
        transition_id: record_id("retry-successor-replay-first"),
    };
    store
        .record_retry(&first_request)
        .unwrap_or_else(|error| panic!("first retry failed: {error}"));
    let second_now_unix_ms = first_request.not_before_unix_ms;
    clock.set(second_now_unix_ms);
    let second_work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: planned.tenant_id,
            claim_id: record_id("retry-successor-replay-second-claim"),
            lease_owner_id: first_request.work.lease_owner_id.clone(),
            now_unix_ms: second_now_unix_ms,
            lease_expires_at_unix_ms: second_now_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("second work claim failed: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("second work claim missing"));
    store
        .record_retry(&SchedulerRetryRequest {
            work: second_work,
            expected_attempts: 1,
            error_code: ErrorCode::new("response.retry_successor_second")
                .unwrap_or_else(|error| panic!("retry error code failed: {error}")),
            first_failure_at_unix_ms: initial_now_unix_ms,
            now_unix_ms: second_now_unix_ms,
            not_before_unix_ms: second_now_unix_ms.saturating_add(1_000),
            health_event_id: None,
            transition_id: record_id("retry-successor-replay-second"),
        })
        .unwrap_or_else(|error| panic!("second retry failed: {error}"));

    let replay_error = rejected(
        store.record_retry(&first_request),
        "superseded retry replay unexpectedly succeeded",
    );
    assert_eq!(replay_error.kind(), PortErrorKind::Conflict);
}

#[test]
fn automatic_dispatch_fence_wins_before_commit() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("fence-wins.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-fence-wins",
        "dispatch-fence-wins",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let fence = automatic_fence_request(&dispatch);
    let outcome = store
        .fence_uncommitted_automatic_dispatch(&fence)
        .unwrap_or_else(|error| panic!("automatic dispatch fence failed: {error}"));
    assert!(matches!(
        outcome,
        AutomaticResponseDispatchFenceOutcome::Fenced(_)
    ));

    let error = rejected(
        store.commit_dispatch(&dispatch),
        "fenced automatic dispatch commit must fail",
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(
        store
            .load_dispatch(&dispatch.authorization.body.key)
            .unwrap_or_else(|error| panic!("fenced dispatch load failed: {error}")),
        ResponseDispatchLoadOutcome::Missing
    );
}

#[test]
fn automatic_dispatch_commit_wins_before_fence() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("commit-wins.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-commit-wins",
        "dispatch-commit-wins",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let committed = match store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first dispatch commit unexpectedly existed")
        }
    };
    let outcome = store
        .fence_uncommitted_automatic_dispatch(&automatic_fence_request(&dispatch))
        .unwrap_or_else(|error| panic!("automatic dispatch fence lookup failed: {error}"));
    assert_eq!(
        outcome,
        AutomaticResponseDispatchFenceOutcome::Committed(Box::new(committed))
    );
}

#[test]
fn simultaneous_two_handle_commit_and_fence_preserve_durable_exclusivity() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("simultaneous-commit-fence.db");
    let bootstrap = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store bootstrap failed: {error}"));
    drop(bootstrap);
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-simultaneous-commit-fence",
        "dispatch-simultaneous-commit-fence",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let fence_request = automatic_fence_request(&dispatch);

    let (commit_result, fence_result) = race_dispatch_commit_and_fence(&path, &dispatch);
    let commit_won = match (commit_result, fence_result) {
        (
            Ok(ResponseDispatchCommitOutcome::Committed(committed)),
            Ok(AutomaticResponseDispatchFenceOutcome::Committed(observed)),
        ) => {
            assert_eq!(observed, Box::new(committed));
            true
        }
        (
            Err(commit_error),
            Ok(AutomaticResponseDispatchFenceOutcome::Fenced(fenced)),
        ) => {
            assert_eq!(commit_error.kind(), PortErrorKind::Conflict);
            assert_eq!(
                fenced.prepared_dispatch_binding,
                fence_request.prepared_dispatch_binding
            );
            false
        }
        (unexpected_commit, unexpected_fence) => panic!(
            "simultaneous dispatch race produced an invalid result pair: commit={unexpected_commit:?}, fence={unexpected_fence:?}"
        ),
    };

    assert_eq!(
        durable_dispatch_fence_counts(&path, &dispatch),
        if commit_won { (1, 0) } else { (0, 1) }
    );
    let verifier = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store verifier open failed: {error}"));
    verifier
        .ensure_dispatch_ready()
        .unwrap_or_else(|error| panic!("exclusive race result is not ready: {error}"));
}

#[test]
fn durable_fence_winner_survives_simultaneous_two_handle_retries() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("durable-fence-winner-race.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-durable-fence-winner",
        "dispatch-durable-fence-winner",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let fence_request = automatic_fence_request(&dispatch);
    let seed_store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store seed open failed: {error}"));
    assert!(matches!(
        seed_store
            .fence_uncommitted_automatic_dispatch(&fence_request)
            .unwrap_or_else(|error| panic!("durable fence seed failed: {error}")),
        AutomaticResponseDispatchFenceOutcome::Fenced(_)
    ));
    drop(seed_store);

    let (commit_result, fence_result) = race_dispatch_commit_and_fence(&path, &dispatch);
    let commit_error = rejected(
        commit_result,
        "durable fence winner must reject the competing commit",
    );
    assert_eq!(commit_error.kind(), PortErrorKind::Conflict);
    let AutomaticResponseDispatchFenceOutcome::ExistingFence(existing) =
        fence_result.unwrap_or_else(|error| panic!("durable fence retry failed: {error}"))
    else {
        panic!("durable fence retry did not recover the existing fence");
    };
    assert_eq!(
        existing.prepared_dispatch_binding,
        fence_request.prepared_dispatch_binding
    );
    assert_eq!(durable_dispatch_fence_counts(&path, &dispatch), (0, 1));
}

#[test]
fn durable_commit_winner_survives_simultaneous_two_handle_retries() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("durable-commit-winner-race.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-durable-commit-winner",
        "dispatch-durable-commit-winner",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let seed_store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store seed open failed: {error}"));
    let committed = match seed_store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("durable commit seed failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first durable commit unexpectedly existed")
        }
    };
    drop(seed_store);

    let (commit_result, fence_result) = race_dispatch_commit_and_fence(&path, &dispatch);
    let ResponseDispatchCommitOutcome::Existing(existing) =
        commit_result.unwrap_or_else(|error| panic!("durable commit retry failed: {error}"))
    else {
        panic!("durable commit retry did not recover the existing dispatch");
    };
    assert_eq!(existing, committed);
    let AutomaticResponseDispatchFenceOutcome::Committed(observed) = fence_result
        .unwrap_or_else(|error| panic!("durable commit fence readback failed: {error}"))
    else {
        panic!("fence did not recover the durable committed dispatch");
    };
    assert_eq!(observed, Box::new(committed));
    assert_eq!(durable_dispatch_fence_counts(&path, &dispatch), (1, 0));
}

#[test]
fn automatic_dispatch_fence_rejects_alternate_id_for_same_action() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("alternate-id.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let first = dispatch_request(
        "action-alternate-id",
        "dispatch-alternate-id-first",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let alternate = dispatch_request(
        "action-alternate-id",
        "dispatch-alternate-id-second",
        created_at_unix_ms,
        created_at_unix_ms + 1,
        created_at_unix_ms + 10_000,
    );
    store
        .fence_uncommitted_automatic_dispatch(&automatic_fence_request(&first))
        .unwrap_or_else(|error| panic!("first automatic dispatch fence failed: {error}"));

    let error = rejected(
        store.fence_uncommitted_automatic_dispatch(&automatic_fence_request(&alternate)),
        "alternate dispatch identifier must not replace the existing fence",
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(
        rejected(
            store.commit_dispatch(&alternate),
            "alternate dispatch commit must remain fenced",
        )
        .kind(),
        PortErrorKind::Conflict
    );
}

#[test]
fn automatic_dispatch_fences_are_tenant_independent() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("tenant-fences.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    for tenant in ["tenant-fence-one", "tenant-fence-two"] {
        let dispatch = dispatch_request_for_tenant(
            tenant,
            "action-shared-fence",
            "dispatch-shared-fence",
            created_at_unix_ms,
            created_at_unix_ms,
            created_at_unix_ms + 10_000,
        );
        let outcome = store
            .fence_uncommitted_automatic_dispatch(&automatic_fence_request(&dispatch))
            .unwrap_or_else(|error| panic!("tenant automatic dispatch fence failed: {error}"));
        assert!(matches!(
            outcome,
            AutomaticResponseDispatchFenceOutcome::Fenced(_)
        ));
    }
}

#[test]
fn automatic_dispatch_fence_retry_recovers_after_persisted_result_is_lost() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("persisted-fence-retry.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-persisted-fence",
        "dispatch-persisted-fence",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let request = automatic_fence_request(&dispatch);
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let _lost_result = store
        .fence_uncommitted_automatic_dispatch(&request)
        .unwrap_or_else(|error| panic!("automatic dispatch fence failed: {error}"));
    drop(store);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    let retried = reopened
        .fence_uncommitted_automatic_dispatch(&request)
        .unwrap_or_else(|error| panic!("automatic dispatch fence retry failed: {error}"));
    assert!(matches!(
        retried,
        AutomaticResponseDispatchFenceOutcome::ExistingFence(_)
    ));
    assert_eq!(
        rejected(
            reopened.commit_dispatch(&dispatch),
            "reopened automatic dispatch commit must remain fenced",
        )
        .kind(),
        PortErrorKind::Conflict
    );
}

#[test]
fn automatic_dispatch_fence_retry_rejects_corrupt_persisted_hash() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-persisted-fence-hash.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-corrupt-fence-hash",
        "dispatch-corrupt-fence-hash",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let request = automatic_fence_request(&dispatch);
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .fence_uncommitted_automatic_dispatch(&request)
        .unwrap_or_else(|error| panic!("automatic dispatch fence failed: {error}"));
    drop(store);

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("raw sqlite open failed: {error}"));
    connection
        .execute(
            "UPDATE security_response_dispatch_fences SET prepared_binding_hash = zeroblob(32)",
            [],
        )
        .unwrap_or_else(|error| panic!("fence hash corruption failed: {error}"));
    drop(connection);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    let error = rejected(
        reopened.fence_uncommitted_automatic_dispatch(&request),
        "corrupt persisted fence hash must fail",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn dispatch_readiness_rejects_canonical_but_invalid_fence_binding() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("invalid-persisted-fence-binding.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-invalid-fence-binding",
        "dispatch-invalid-fence-binding",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let request = automatic_fence_request(&dispatch);
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .fence_uncommitted_automatic_dispatch(&request)
        .unwrap_or_else(|error| panic!("automatic dispatch fence failed: {error}"));
    drop(store);

    let mut invalid_binding = request.prepared_dispatch_binding.clone();
    invalid_binding.governed_intent_hash = Digest32::new([0_u8; 32]);
    let body = chio_core::canonical_json_bytes(&invalid_binding)
        .unwrap_or_else(|error| panic!("invalid fence binding canonicalization failed: {error}"));
    let hash = chio_core::sha256(&body);
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("raw sqlite open failed: {error}"));
    connection
        .execute(
            "UPDATE security_response_dispatch_fences SET prepared_binding_body = ?1, prepared_binding_hash = ?2",
            rusqlite::params![body, hash.as_bytes().as_slice()],
        )
        .unwrap_or_else(|error| panic!("fence binding corruption failed: {error}"));
    drop(connection);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    let error = rejected(
        reopened.ensure_dispatch_ready(),
        "invalid persisted fence binding must fail readiness",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn load_dispatch_reports_missing_explicitly() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("missing-dispatch.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let key = ResponseDispatchKey {
        tenant_id: TenantId::new("tenant-dispatch")
            .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
        dispatch_id: record_id("missing-dispatch"),
    };
    assert_eq!(
        store
            .load_dispatch(&key)
            .unwrap_or_else(|error| panic!("missing dispatch load failed: {error}")),
        ResponseDispatchLoadOutcome::Missing
    );
}

#[test]
fn historical_governed_commit_is_unclaimable_until_zero_effect_terminalization() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("historical-dispatch.db"))
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let trusted_now = now_unix_ms();
    let created_at_unix_ms = trusted_now.saturating_sub(10_000);
    let plan = response_plan_with_approval(
        "action-historical-dispatch",
        created_at_unix_ms,
        1_000,
        ResponseApprovalRequirement::Governed {
            policy_id: record_id("historical-dispatch-policy"),
        },
    );
    let request = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        plan: plan.clone(),
        dispatch_id: record_id("historical-governed-dispatch"),
        authorization_capability_hash: digest(30),
        governed_intent_hash: digest(32),
        policy_decision_hash: digest(33),
        executor_authority_id: record_id("executor-authority"),
        executor_authority_generation: 4,
        approval: ResponseDispatchApproval::Governed {
            admission_operation_id: record_id("historical-admission-operation"),
            admission_operation_version: 1,
            approval_set_hash: digest(34),
        },
        authorized_at_unix_ms: created_at_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("historical-response-worker")
                .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
            lease_expires_at_unix_ms: plan.expires_at_unix_ms,
        },
        commit_mode: ResponseDispatchCommitMode::GovernedCommittedExpiredResume,
    })
    .unwrap_or_else(|error| panic!("historical dispatch preparation failed: {error}"));
    let committed = store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("historical dispatch commit failed: {error}"));
    let committed_record = match committed {
        ResponseDispatchCommitOutcome::Committed(record) => record,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first historical dispatch unexpectedly existed")
        }
    };

    let claims = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: plan.tenant_id.clone(),
            claim_id: record_id("historical-dispatch-claim"),
            lease_owner_id: LeaseOwnerId::new("historical-scheduler")
                .unwrap_or_else(|error| panic!("invalid scheduler owner: {error}")),
            now_unix_ms: trusted_now,
            lease_expires_at_unix_ms: trusted_now.saturating_add(5_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("historical dispatch claim failed: {error}"));
    assert!(claims.is_empty());

    let recovered = store
        .recover_dispatch_work(&ResponseDispatchRecoveryRequest {
            key: request.authorization.body.key.clone(),
            action_id: plan.action_id.clone(),
            recovery_id: record_id("historical-dispatch-recovery"),
            lease_owner_id: LeaseOwnerId::new("historical-recovery-worker")
                .unwrap_or_else(|error| panic!("invalid recovery owner: {error}")),
            expected_fencing_token: Some(committed_record.initial_work.fencing_token),
            now_unix_ms: trusted_now,
            lease_expires_at_unix_ms: trusted_now.saturating_add(5_000),
        })
        .unwrap_or_else(|error| panic!("historical dispatch recovery failed: {error}"));
    let recovery_work = match recovered {
        ResponseDispatchRecoveryOutcome::LiveLease(work)
        | ResponseDispatchRecoveryOutcome::Takeover(work) => work,
    };

    let key = ResponsePlanKey {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
    };
    let current = store
        .load_plan(&key)
        .unwrap_or_else(|error| panic!("historical response load failed: {error}"))
        .unwrap_or_else(|| panic!("historical response is missing"));
    let failed = ResponseStateMachine::new(Arc::clone(&store))
        .fail_expired_dispatch_committed_resume_scheduled(
            &current,
            &recovery_work,
            current.generation,
            trusted_now,
        )
        .unwrap_or_else(|error| panic!("historical response terminalization failed: {error}"));
    let snapshot = decode_response_record(&failed)
        .unwrap_or_else(|error| panic!("historical response decode failed: {error}"));
    assert_eq!(snapshot.state, ResponseState::Failed);
    assert!(plan.effects.as_slice().iter().all(|effect| {
        snapshot.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::Planned)
    }));
}

#[test]
fn live_dispatch_recovery_rejects_unfenced_wrong_owner_and_stale_fencing_token() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let request = dispatch_request(
        "action-live-recovery-binding",
        "active-response-live-recovery-binding",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let store = SqliteSecurityStateStore::open(directory.path().join("recovery-binding.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let initial_work = match store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record.initial_work,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first bound recovery dispatch unexpectedly existed")
        }
    };
    let base = ResponseDispatchRecoveryRequest {
        key: request.authorization.body.key.clone(),
        action_id: request.authorization.body.action_id.clone(),
        recovery_id: record_id("bound-live-recovery"),
        lease_owner_id: initial_work.lease_owner_id.clone(),
        expected_fencing_token: Some(initial_work.fencing_token),
        now_unix_ms: created_at_unix_ms,
        lease_expires_at_unix_ms: initial_work.lease_expires_at_unix_ms,
    };

    let mut unfenced = base.clone();
    unfenced.recovery_id = record_id("unfenced-live-recovery");
    unfenced.expected_fencing_token = None;
    let unfenced_error = match store.recover_dispatch_work(&unfenced) {
        Ok(_) => panic!("unfenced live recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(unfenced_error.kind(), PortErrorKind::InvalidData);

    let mut wrong_owner = base.clone();
    wrong_owner.recovery_id = record_id("wrong-owner-live-recovery");
    wrong_owner.lease_owner_id = LeaseOwnerId::new("different-response-worker")
        .unwrap_or_else(|error| panic!("invalid wrong lease owner: {error}"));
    let wrong_owner_error = match store.recover_dispatch_work(&wrong_owner) {
        Ok(_) => panic!("wrong-owner live recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(wrong_owner_error.kind(), PortErrorKind::Conflict);

    let mut stale_fence = base;
    stale_fence.recovery_id = record_id("stale-fence-live-recovery");
    stale_fence.expected_fencing_token = Some(initial_work.fencing_token.saturating_add(1));
    let stale_fence_error = match store.recover_dispatch_work(&stale_fence) {
        Ok(_) => panic!("stale-fence live recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(stale_fence_error.kind(), PortErrorKind::Conflict);
}

#[test]
fn scheduler_lease_body_hash_covers_dispatch_and_takeover_origins() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let initial_now_unix_ms = 100_000;
    let initial_clock = Arc::new(MutableSecurityStateClock::new(initial_now_unix_ms));
    let initial_path = directory.path().join("dispatch-lease-body-hash.db");
    let initial_store = SqliteSecurityStateStore::open_with_trusted_clock(
        &initial_path,
        Arc::clone(&initial_clock) as Arc<dyn SecurityStateClock>,
    )
    .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let initial_request = dispatch_request(
        "action-dispatch-lease-body-hash",
        "dispatch-lease-body-hash",
        initial_now_unix_ms,
        initial_now_unix_ms,
        initial_now_unix_ms.saturating_add(10_000),
    );
    let initial_work = match initial_store
        .commit_dispatch(&initial_request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record.initial_work,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first dispatch unexpectedly existed")
        }
    };
    let initial_connection = rusqlite::Connection::open(&initial_path)
        .unwrap_or_else(|error| panic!("dispatch corruption connection failed: {error}"));
    initial_connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET lease_expires_at = lease_expires_at + 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                initial_work.tenant_id.as_str(),
                initial_work.action_id.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("dispatch lease corruption failed: {error}"));
    let initial_validation_error = rejected(
        initial_store.validate_lease(&initial_work),
        "expiry-corrupt dispatch lease unexpectedly validated",
    );
    assert_eq!(
        initial_validation_error.kind(),
        PortErrorKind::IntegrityFailure
    );
    let initial_recovery_error = rejected(
        initial_store.recover_dispatch_work(&ResponseDispatchRecoveryRequest {
            key: initial_request.authorization.body.key.clone(),
            action_id: initial_work.action_id.clone(),
            recovery_id: record_id("dispatch-lease-body-hash-recovery"),
            lease_owner_id: initial_work.lease_owner_id.clone(),
            expected_fencing_token: Some(initial_work.fencing_token),
            now_unix_ms: initial_now_unix_ms,
            lease_expires_at_unix_ms: initial_work.lease_expires_at_unix_ms,
        }),
        "expiry-corrupt dispatch lease unexpectedly recovered",
    );
    assert_eq!(
        initial_recovery_error.kind(),
        PortErrorKind::IntegrityFailure
    );

    let takeover_now_unix_ms = 200_000;
    let takeover_clock = Arc::new(MutableSecurityStateClock::new(takeover_now_unix_ms));
    let takeover_path = directory.path().join("takeover-lease-body-hash.db");
    let takeover_store = SqliteSecurityStateStore::open_with_trusted_clock(
        &takeover_path,
        Arc::clone(&takeover_clock) as Arc<dyn SecurityStateClock>,
    )
    .unwrap_or_else(|error| panic!("takeover store open failed: {error}"));
    let takeover_dispatch = dispatch_request(
        "action-takeover-lease-body-hash",
        "takeover-lease-body-hash-dispatch",
        takeover_now_unix_ms,
        takeover_now_unix_ms,
        takeover_now_unix_ms.saturating_add(100),
    );
    let stale_work = match takeover_store
        .commit_dispatch(&takeover_dispatch)
        .unwrap_or_else(|error| panic!("takeover dispatch commit failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record.initial_work,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first takeover dispatch unexpectedly existed")
        }
    };
    let recovery_now_unix_ms = stale_work.lease_expires_at_unix_ms.saturating_add(1);
    takeover_clock.set(recovery_now_unix_ms);
    let takeover_request = ResponseDispatchRecoveryRequest {
        key: takeover_dispatch.authorization.body.key,
        action_id: stale_work.action_id.clone(),
        recovery_id: record_id("takeover-lease-body-hash-recovery"),
        lease_owner_id: LeaseOwnerId::new("takeover-lease-body-hash-owner")
            .unwrap_or_else(|error| panic!("takeover owner failed: {error}")),
        expected_fencing_token: Some(stale_work.fencing_token),
        now_unix_ms: recovery_now_unix_ms,
        lease_expires_at_unix_ms: recovery_now_unix_ms.saturating_add(5_000),
    };
    let takeover_work = match takeover_store
        .recover_dispatch_work(&takeover_request)
        .unwrap_or_else(|error| panic!("lease takeover failed: {error}"))
    {
        ResponseDispatchRecoveryOutcome::Takeover(work) => work,
        ResponseDispatchRecoveryOutcome::LiveLease(_) => {
            panic!("expired lease unexpectedly remained live")
        }
    };
    let takeover_connection = rusqlite::Connection::open(&takeover_path)
        .unwrap_or_else(|error| panic!("takeover corruption connection failed: {error}"));
    takeover_connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET lease_expires_at = lease_expires_at + 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                takeover_work.tenant_id.as_str(),
                takeover_work.action_id.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("takeover lease corruption failed: {error}"));
    let takeover_validation_error = rejected(
        takeover_store.validate_lease(&takeover_work),
        "expiry-corrupt takeover lease unexpectedly validated",
    );
    assert_eq!(
        takeover_validation_error.kind(),
        PortErrorKind::IntegrityFailure
    );
    let takeover_replay_error = rejected(
        takeover_store.recover_dispatch_work(&takeover_request),
        "expiry-corrupt takeover replay unexpectedly succeeded",
    );
    assert_eq!(
        takeover_replay_error.kind(),
        PortErrorKind::IntegrityFailure
    );
}

#[test]
fn exact_dispatch_recovery_is_live_idempotent_and_fenced_after_restart() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("response-recovery.db");
    let created_at_unix_ms = now_unix_ms();
    let initial_lease_expires_at_unix_ms = created_at_unix_ms + 2_000;
    let request = dispatch_request(
        "action-recovery",
        "active-response-recovery",
        created_at_unix_ms,
        created_at_unix_ms,
        initial_lease_expires_at_unix_ms,
    );
    let key = request.authorization.body.key.clone();
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let committed = store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"));
    let initial_work = match committed {
        ResponseDispatchCommitOutcome::Committed(record) => record.initial_work,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first recovery dispatch unexpectedly existed")
        }
    };
    let live_request = ResponseDispatchRecoveryRequest {
        key: key.clone(),
        action_id: request.authorization.body.action_id.clone(),
        recovery_id: record_id("recovery-live"),
        lease_owner_id: initial_work.lease_owner_id.clone(),
        expected_fencing_token: Some(initial_work.fencing_token),
        now_unix_ms: now_unix_ms(),
        lease_expires_at_unix_ms: initial_work.lease_expires_at_unix_ms,
    };
    let live = store
        .recover_dispatch_work(&live_request)
        .unwrap_or_else(|error| panic!("live lease recovery failed: {error}"));
    assert_eq!(
        live,
        ResponseDispatchRecoveryOutcome::LiveLease(initial_work.clone())
    );
    assert_eq!(
        store
            .recover_dispatch_work(&live_request)
            .unwrap_or_else(|error| panic!("ack-loss live recovery retry failed: {error}")),
        live
    );
    let renewed_live_work = store
        .renew_lease(&SchedulerLeaseRenewRequest {
            work: initial_work.clone(),
            now_unix_ms: now_unix_ms(),
            lease_expires_at_unix_ms: initial_work.lease_expires_at_unix_ms.saturating_add(250),
            transition_id: record_id("recovery-live-renewal"),
        })
        .unwrap_or_else(|error| panic!("live recovery lease renewal failed: {error}"));
    assert_eq!(
        store
            .recover_dispatch_work(&live_request)
            .unwrap_or_else(|error| panic!("renewed live recovery retry failed: {error}")),
        ResponseDispatchRecoveryOutcome::LiveLease(renewed_live_work.clone())
    );

    let mut mismatched_retry = live_request.clone();
    mismatched_retry.action_id =
        ActionId::new("action-wrong").unwrap_or_else(|error| panic!("invalid action id: {error}"));
    let mismatch = match store.recover_dispatch_work(&mismatched_retry) {
        Ok(_) => panic!("mismatched recovery retry unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(mismatch.kind(), PortErrorKind::Conflict);

    drop(store);
    let sleep_ms = renewed_live_work
        .lease_expires_at_unix_ms
        .saturating_sub(now_unix_ms())
        .saturating_add(50);
    thread::sleep(Duration::from_millis(sleep_ms));

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    let takeover_now = now_unix_ms();
    let takeover_request = ResponseDispatchRecoveryRequest {
        key,
        action_id: request.authorization.body.action_id,
        recovery_id: record_id("recovery-takeover"),
        lease_owner_id: LeaseOwnerId::new("recovery-worker")
            .unwrap_or_else(|error| panic!("invalid recovery owner: {error}")),
        expected_fencing_token: Some(initial_work.fencing_token),
        now_unix_ms: takeover_now,
        lease_expires_at_unix_ms: takeover_now + 5_000,
    };
    let takeover = reopened
        .recover_dispatch_work(&takeover_request)
        .unwrap_or_else(|error| panic!("expired lease takeover failed: {error}"));
    let takeover_work = match &takeover {
        ResponseDispatchRecoveryOutcome::Takeover(work) => work,
        ResponseDispatchRecoveryOutcome::LiveLease(_) => {
            panic!("expired lease recovery returned the stale live lease")
        }
    };
    assert!(takeover_work.fencing_token > initial_work.fencing_token);
    assert_eq!(
        takeover_work.lease_owner_id,
        takeover_request.lease_owner_id
    );
    assert_eq!(
        reopened
            .recover_dispatch_work(&takeover_request)
            .unwrap_or_else(|error| panic!("ack-loss takeover retry failed: {error}")),
        takeover
    );

    let mut stale = takeover_request.clone();
    stale.recovery_id = record_id("recovery-stale-fence");
    let stale_error = match reopened.recover_dispatch_work(&stale) {
        Ok(_) => panic!("stale fencing recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(stale_error.kind(), PortErrorKind::Conflict);

    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("recovery replay mutation connection failed: {error}"));
    let deleted = connection
        .execute(
            "DELETE FROM security_scheduler_leases WHERE tenant_id = ?1 AND action_id = ?2",
            rusqlite::params![
                takeover_work.tenant_id.as_str(),
                takeover_work.action_id.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("delete recovered lease failed: {error}"));
    assert_eq!(deleted, 1);
    let missing_replay_error = match reopened.recover_dispatch_work(&takeover_request) {
        Ok(_) => panic!("missing-lease recovery replay unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(missing_replay_error.kind(), PortErrorKind::Conflict);
}

#[test]
fn dispatch_recovery_rejects_non_due_work_without_a_live_lease() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let request = dispatch_request(
        "action-not-due",
        "active-response-not-due",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let store = SqliteSecurityStateStore::open(directory.path().join("not-due.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let initial_work = match store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record.initial_work,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first not-due dispatch unexpectedly existed")
        }
    };
    store
        .release_lease(&SchedulerLeaseReleaseRequest {
            work: initial_work.clone(),
            clear_retry_state: false,
            transition_id: record_id("release-before-due"),
        })
        .unwrap_or_else(|error| panic!("initial lease release failed: {error}"));
    let recovery_now = now_unix_ms();
    let recovery = ResponseDispatchRecoveryRequest {
        key: request.authorization.body.key,
        action_id: request.authorization.body.action_id,
        recovery_id: record_id("recovery-before-due"),
        lease_owner_id: LeaseOwnerId::new("early-recovery-worker")
            .unwrap_or_else(|error| panic!("invalid recovery owner: {error}")),
        expected_fencing_token: Some(initial_work.fencing_token),
        now_unix_ms: recovery_now,
        lease_expires_at_unix_ms: recovery_now + 5_000,
    };
    let error = match store.recover_dispatch_work(&recovery) {
        Ok(_) => panic!("non-due recovery unexpectedly allocated work"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
}

#[test]
fn response_receipt_cursor_is_plan_bound_and_exactly_cas_idempotent() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let request = dispatch_request(
        "action-receipt-cursor",
        "active-response-receipt-cursor",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let store = SqliteSecurityStateStore::open(directory.path().join("receipt-cursor.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"));
    let snapshot = decode_response_record(&request.response_plan)
        .unwrap_or_else(|error| panic!("response plan decode failed: {error}"));
    let key = ResponsePlanKey {
        tenant_id: snapshot.plan.tenant_id.clone(),
        action_id: snapshot.plan.action_id.clone(),
    };
    let initial = ResponseReceiptCursor {
        tenant_id: key.tenant_id.clone(),
        action_id: key.action_id.clone(),
        plan_hash: snapshot.plan.plan_hash,
        generation: 0,
        current_evidence_id: snapshot.plan.trigger_finding_receipt_id.clone(),
    };
    let mut wrong_plan = initial.clone();
    wrong_plan.plan_hash = digest(99);
    let wrong_plan_error = match store.initialize_receipt_cursor(&wrong_plan) {
        Ok(_) => panic!("wrong-plan receipt cursor unexpectedly initialized"),
        Err(error) => error,
    };
    assert_eq!(wrong_plan_error.kind(), PortErrorKind::InvalidData);
    assert_eq!(
        store
            .initialize_receipt_cursor(&initial)
            .unwrap_or_else(|error| panic!("receipt cursor initialization failed: {error}")),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .initialize_receipt_cursor(&initial)
            .unwrap_or_else(|error| panic!("receipt cursor replay failed: {error}")),
        CreateOutcome::Existing
    );

    let next = ResponseReceiptCursor {
        generation: 1,
        current_evidence_id: OpaqueReceiptRef::new("response-plan-evidence")
            .unwrap_or_else(|error| panic!("invalid response evidence id: {error}")),
        ..initial.clone()
    };
    let transition_id = record_id("receipt-cursor-transition");
    let valid = ResponseReceiptCursorCasRequest {
        cursor: next.clone(),
        expected_generation: 0,
        expected_evidence_id: initial.current_evidence_id.clone(),
        transition_id: transition_id.clone(),
    };
    let mut wrong_prior = valid.clone();
    wrong_prior.expected_evidence_id = OpaqueReceiptRef::new("wrong-prior-evidence")
        .unwrap_or_else(|error| panic!("invalid wrong evidence id: {error}"));
    let wrong_prior_error = match store.compare_and_swap_receipt_cursor(&wrong_prior) {
        Ok(_) => panic!("wrong-prior receipt cursor CAS unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(wrong_prior_error.kind(), PortErrorKind::Conflict);
    assert_eq!(
        store
            .compare_and_swap_receipt_cursor(&valid)
            .unwrap_or_else(|error| panic!("receipt cursor CAS failed: {error}")),
        next
    );
    assert_eq!(
        store
            .compare_and_swap_receipt_cursor(&valid)
            .unwrap_or_else(|error| panic!("receipt cursor CAS replay failed: {error}")),
        next
    );
    assert_eq!(
        store
            .load_receipt_cursor(&key)
            .unwrap_or_else(|error| panic!("receipt cursor load failed: {error}")),
        Some(next)
    );
}

#[test]
fn dispatch_readiness_rejects_a_corrupt_schema() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-dispatch-schema.db");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .ensure_dispatch_ready()
        .unwrap_or_else(|error| panic!("fresh dispatch schema is not ready: {error}"));
    drop(store);

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("raw sqlite open failed: {error}"));
    connection
        .execute_batch(
            "DROP TABLE security_response_dispatches;
             CREATE TABLE security_response_dispatches (broken TEXT);",
        )
        .unwrap_or_else(|error| panic!("dispatch schema corruption failed: {error}"));
    drop(connection);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    assert!(reopened.ensure_dispatch_ready().is_err());
}
