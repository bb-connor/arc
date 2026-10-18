//! Exact durable dispatch readback and scheduler lease commitments.
use super::*;

fn recovery_rows(path: &std::path::Path) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("snapshot open failed: {error}"));
    [
        "security_scheduler_leases",
        "security_scheduler_fence_sequences",
        "security_response_dispatch_recoveries",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1, 2"))
            .unwrap_or_else(|error| panic!("snapshot prepare failed: {error}"));
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns).map(|column| row.get(column)).collect()
            })
            .unwrap_or_else(|error| panic!("snapshot query failed: {error}"));
        rows.collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("snapshot read failed: {error}"))
    })
    .collect()
}

#[test]
fn live_dispatch_recovery_rejects_unfenced_wrong_owner_and_stale_fencing_token() {
    let directory = chio_test_support::private_tempdir()
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
    pin_automatic_fixture(&store, &request);
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
        expected_fencing_token: core::num::NonZeroU64::new(initial_work.fencing_token)
            .unwrap_or_else(|| panic!("fixture fence is zero")),
        now_unix_ms: created_at_unix_ms,
        lease_expires_at_unix_ms: initial_work.lease_expires_at_unix_ms,
    };

    let before = recovery_rows(&directory.path().join("recovery-binding.db"));
    let mut zero_fence = serde_json::to_value(&base)
        .unwrap_or_else(|error| panic!("recovery serialization failed: {error}"));
    zero_fence["expected_fencing_token"] = serde_json::json!(0);
    let zero_error = serde_json::from_value::<ResponseDispatchRecoveryRequest>(zero_fence)
        .err()
        .unwrap_or_else(|| panic!("zero-fence recovery decoded"));
    assert_eq!(zero_error.classify(), serde_json::error::Category::Data);
    assert_eq!(
        zero_error.to_string(),
        "invalid value: integer `0`, expected a nonzero u64"
    );

    let mut wrong_owner = base.clone();
    wrong_owner.recovery_id = record_id("wrong-owner-live-recovery");
    wrong_owner.lease_owner_id = LeaseOwnerId::new("different-response-worker")
        .unwrap_or_else(|error| panic!("invalid wrong lease owner: {error}"));
    let wrong_owner_error = match store.recover_dispatch_work(&wrong_owner) {
        Ok(_) => panic!("wrong-owner live recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(wrong_owner_error.kind(), PortErrorKind::Conflict);
    assert_eq!(wrong_owner_error.code().as_str(), "store.conflict");
    assert_eq!(
        recovery_rows(&directory.path().join("recovery-binding.db")),
        before
    );

    let mut stale_fence = base;
    stale_fence.recovery_id = record_id("stale-fence-live-recovery");
    stale_fence.expected_fencing_token =
        core::num::NonZeroU64::new(initial_work.fencing_token.saturating_add(1))
            .unwrap_or_else(|| panic!("fixture fence is zero"));
    let stale_fence_error = match store.recover_dispatch_work(&stale_fence) {
        Ok(_) => panic!("stale-fence live recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(stale_fence_error.kind(), PortErrorKind::Conflict);
    assert_eq!(stale_fence_error.code().as_str(), "store.conflict");
    assert_eq!(
        recovery_rows(&directory.path().join("recovery-binding.db")),
        before
    );
}

#[test]
fn scheduler_lease_body_hash_covers_dispatch_and_takeover_origins() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let initial_now_unix_ms = 100_000;
    let initial_clock = Arc::new(MutableSecurityStateClock::new(initial_now_unix_ms));
    let initial_path = directory.path().join("dispatch-lease-body-hash.db");
    let initial_store = SqliteSecurityStateStore::open_with_trusted_clock(
        &initial_path,
        Arc::clone(&initial_clock) as Arc<dyn Clock>,
    )
    .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let initial_request = dispatch_request(
        "action-dispatch-lease-body-hash",
        "dispatch-lease-body-hash",
        initial_now_unix_ms,
        initial_now_unix_ms,
        initial_now_unix_ms.saturating_add(10_000),
    );
    pin_automatic_fixture(&initial_store, &initial_request);
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
            SET fencing_token = fencing_token + 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                initial_work.tenant_id.as_str(),
                initial_work.action_id.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("dispatch lease corruption failed: {error}"));
    let initial_before = recovery_rows(&initial_path);
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
            expected_fencing_token: core::num::NonZeroU64::new(initial_work.fencing_token)
                .unwrap_or_else(|| panic!("fixture fence is zero")),
            now_unix_ms: initial_now_unix_ms,
            lease_expires_at_unix_ms: initial_work.lease_expires_at_unix_ms,
        }),
        "expiry-corrupt dispatch lease unexpectedly recovered",
    );
    assert_eq!(
        initial_recovery_error.kind(),
        PortErrorKind::IntegrityFailure
    );
    assert_eq!(
        initial_validation_error.code().as_str(),
        "store.integrity_failure"
    );
    assert_eq!(
        initial_recovery_error.code().as_str(),
        "store.integrity_failure"
    );
    assert_eq!(recovery_rows(&initial_path), initial_before);

    let takeover_now_unix_ms = 200_000;
    let takeover_clock = Arc::new(MutableSecurityStateClock::new(takeover_now_unix_ms));
    let takeover_path = directory.path().join("takeover-lease-body-hash.db");
    let takeover_store = SqliteSecurityStateStore::open_with_trusted_clock(
        &takeover_path,
        Arc::clone(&takeover_clock) as Arc<dyn Clock>,
    )
    .unwrap_or_else(|error| panic!("takeover store open failed: {error}"));
    let takeover_dispatch = dispatch_request(
        "action-takeover-lease-body-hash",
        "takeover-lease-body-hash-dispatch",
        takeover_now_unix_ms,
        takeover_now_unix_ms,
        takeover_now_unix_ms.saturating_add(100),
    );
    pin_automatic_fixture(&takeover_store, &takeover_dispatch);
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
        expected_fencing_token: core::num::NonZeroU64::new(stale_work.fencing_token)
            .unwrap_or_else(|| panic!("fixture fence is zero")),
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
    assert!(takeover_work.fencing_token > stale_work.fencing_token);
    let before = recovery_rows(&takeover_path);
    let mut stale_request = takeover_request.clone();
    stale_request.recovery_id = record_id("stale-below-live-takeover");
    let error = rejected(
        takeover_store.recover_dispatch_work(&stale_request),
        "stale fence below live takeover was accepted",
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(error.code().as_str(), "store.conflict");
    assert_eq!(recovery_rows(&takeover_path), before);
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
