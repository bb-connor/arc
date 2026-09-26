use super::*;

#[test]
fn terminal_response_work_rejects_scheduler_lease_renewal() {
    let directory = tempfile::tempdir()
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
    let directory = tempfile::tempdir()
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
    let directory = tempfile::tempdir()
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
    let directory = tempfile::tempdir()
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
    let directory = tempfile::tempdir()
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
