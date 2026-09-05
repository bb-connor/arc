use super::*;

fn prepared(fixture: &Fixture, now: u64) -> AdmissionOperationV1 {
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::GovernedActiveResponse,
        "qualified-threshold-request",
        "qualified-threshold-capability",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now)
        .expect("begin");
    operation
}

fn reservation(created_at: u64) -> ThresholdApprovalReplayReservationV1 {
    replay_reservation(
        "qualified-threshold-proposal",
        "qualified-threshold-request",
        ["qualified-token-a", "qualified-token-b"],
        created_at,
    )
}

fn counts(fixture: &Fixture) -> (i64, i64, i64) {
    fixture
        .store
        .connection()
        .expect("connection")
        .query_row(
            "SELECT (SELECT COUNT(*) FROM threshold_approval_proposals),
                    (SELECT COUNT(*) FROM threshold_approval_tokens),
                    (SELECT COUNT(*) FROM admission_operation_commits)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("counts")
}

fn assert_unchanged(fixture: &Fixture, operation: &AdmissionOperationV1, before: (i64, i64, i64)) {
    assert_eq!(counts(fixture), before);
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .expect("readable operation"),
        Some(operation.clone())
    );
}

#[test]
fn threshold_reservation_rejects_foreign_participant_attachments_atomically() {
    for extra in [
        AdmissionAttachment::ExecutionNonceId(identifier("nonce_id", "unreserved-nonce")),
        AdmissionAttachment::SupplementalAuthorizationDigest(digest("supplemental", 'e')),
    ] {
        let fixture = fixture();
        let now = now_ms();
        let mut operation = prepared_approval_and_budget_operation(
            &fixture.fence,
            "qualified-threshold-request",
            "qualified-threshold-capability",
            true,
        );
        fixture
            .store
            .begin(&operation, &fixture.fence, now)
            .expect("begin");
        for (state, attachment) in [
            (
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "threshold-attempt",
                )),
            ),
            (
                AdmissionOperationState::BudgetAuthorized,
                AdmissionAttachment::BudgetHoldId(identifier("hold", "threshold-hold")),
            ),
        ] {
            let lease = claim(&fixture, &operation, "threshold-worker", now);
            let command = AdmissionOperationCommand::new(
                operation.binding().operation_id().clone(),
                operation.version(),
                lease,
                vec![attachment],
                Some(state),
                None,
                None,
            )
            .expect("participant command");
            operation = fixture
                .store
                .compare_and_swap(&command, now)
                .expect("participant metadata")
                .into_operation();
        }
        let reservation = reservation(now / 1_000);
        let valid = reservation_command(&fixture, &operation, &reservation, now);
        let mut attachments = valid.attachments().to_vec();
        attachments.push(extra);
        let command = AdmissionOperationCommand::new(
            valid.operation_id().clone(),
            valid.expected_version(),
            valid.recovery_lease().clone(),
            attachments,
            valid.next_state(),
            None,
            None,
        )
        .expect("cross-participant command");
        let before = counts(&fixture);
        assert!(
            fixture
                .store
                .reserve_threshold_approval_and_commit_admission(&command, &reservation, now,)
                .is_err(),
            "threshold reservation accepted another participant's attachment"
        );
        assert_unchanged(&fixture, &operation, before);
    }
}

#[test]
fn threshold_reservation_replay_rechecks_the_exact_packet() {
    let fixture = fixture();
    let now = now_ms();
    let operation = prepared(&fixture, now);
    let first = reservation(now / 1_000);
    let reserved = reserve(&fixture, &operation, &first, now).expect("reserve");
    let command = reservation_command(&fixture, &reserved, &first, now);
    let replacement = reservation(now / 1_000);
    assert_ne!(first, replacement);
    let before = counts(&fixture);
    assert!(
        fixture
            .store
            .reserve_threshold_approval_and_commit_admission(&command, &replacement, now,)
            .is_err(),
        "idempotence accepted a replacement signed packet"
    );
    assert_unchanged(&fixture, &reserved, before);
}

#[test]
fn threshold_reservation_replay_rechecks_expiry() {
    let fixture = fixture();
    let now = now_ms();
    let operation = prepared(&fixture, now);
    let reservation = reservation(now / 1_000);
    let reserved = reserve(&fixture, &operation, &reservation, now).expect("reserve");
    let deadline = reservation.proposal().body.proposal_deadline * 1_000;
    let command = reservation_command(&fixture, &reserved, &reservation, deadline);
    let before = counts(&fixture);
    assert!(
        fixture
            .store
            .reserve_threshold_approval_and_commit_admission(&command, &reservation, deadline,)
            .is_err(),
        "idempotence accepted expired approval authority"
    );
    assert_unchanged(&fixture, &reserved, before);
}

#[test]
fn threshold_reservation_rejects_future_issuance_before_mutation() {
    let fixture = fixture();
    let now = now_ms();
    let operation = prepared(&fixture, now);
    let reservation = reservation(now / 1_000 + 20);
    let command = reservation_command(&fixture, &operation, &reservation, now);
    let before = counts(&fixture);
    assert!(
        fixture
            .store
            .reserve_threshold_approval_and_commit_admission(&command, &reservation, now,)
            .is_err(),
        "future-issued approval authority was reserved"
    );
    assert_unchanged(&fixture, &operation, before);
}

#[test]
fn threshold_reservation_replay_requires_durable_participant_evidence() {
    let fixture = fixture();
    let now = now_ms();
    let operation = prepared(&fixture, now);
    let reservation = reservation(now / 1_000);
    let command = reservation_command(&fixture, &operation, &reservation, now);
    let metadata_only = fixture
        .store
        .compare_and_swap(&command, now)
        .expect("generic metadata transition")
        .into_operation();
    let command = reservation_command(&fixture, &metadata_only, &reservation, now);
    let before = counts(&fixture);
    assert_eq!(before.0, 0);
    assert!(
        fixture
            .store
            .reserve_threshold_approval_and_commit_admission(&command, &reservation, now,)
            .is_err(),
        "idempotence manufactured an absent physical reservation"
    );
    assert_unchanged(&fixture, &metadata_only, before);
}

#[test]
fn threshold_reservation_exact_replay_preserves_rows_and_reopens() {
    let fixture = fixture();
    let now = now_ms();
    let operation = prepared(&fixture, now);
    let reservation = reservation(now / 1_000);
    let reserved = reserve(&fixture, &operation, &reservation, now).expect("reserve");
    let command = reservation_command(&fixture, &reserved, &reservation, now);
    let before = counts(&fixture);
    assert!(matches!(
        fixture
            .store
            .reserve_threshold_approval_and_commit_admission(&command, &reservation, now,)
            .expect("exact replay"),
        AdmissionCommandResult::Idempotent(_)
    ));
    assert_unchanged(&fixture, &reserved, before);
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
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("reopen");
    assert_eq!(
        reopened
            .admission_operation_store()
            .load_by_operation_id(reserved.binding().operation_id())
            .expect("recovered"),
        Some(reserved)
    );
}

fn short_lived_tokens(
    created_at: u64,
    issued_at: u64,
    expires_at: u64,
) -> ThresholdApprovalReplayReservationV1 {
    replay_reservation_with_token_window(
        "qualified-threshold-proposal",
        "qualified-threshold-request",
        ["qualified-token-a", "qualified-token-b"],
        created_at,
        issued_at,
        expires_at,
    )
}

#[test]
fn threshold_reservation_checks_each_token_window_before_mutation() {
    for future in [false, true] {
        let fixture = fixture();
        let now = now_ms();
        let operation = prepared(&fixture, now);
        let seconds = now / 1_000;
        let (issued_at, expires_at) = if future {
            (seconds + 10, seconds + 20)
        } else {
            (seconds - 10, seconds)
        };
        let reservation = short_lived_tokens(seconds - 20, issued_at, expires_at);
        let command = reservation_command(&fixture, &operation, &reservation, now);
        let before = counts(&fixture);
        assert!(
            fixture
                .store
                .reserve_threshold_approval_and_commit_admission(&command, &reservation, now,)
                .is_err(),
            "valid proposal hid an invalid token lifetime"
        );
        assert_unchanged(&fixture, &operation, before);
    }
}

#[test]
fn threshold_reservation_replay_checks_token_expiry_before_proposal_expiry() {
    let fixture = fixture();
    let now = now_ms();
    let operation = prepared(&fixture, now);
    let seconds = now / 1_000;
    let reservation = short_lived_tokens(seconds, seconds, seconds + 10);
    let reserved = reserve(&fixture, &operation, &reservation, now).expect("reserve");
    let deadline = (seconds + 10) * 1_000;
    assert!(deadline < reservation.proposal().body.proposal_deadline * 1_000);
    let command = reservation_command(&fixture, &reserved, &reservation, deadline);
    let before = counts(&fixture);
    assert!(
        fixture
            .store
            .reserve_threshold_approval_and_commit_admission(&command, &reservation, deadline,)
            .is_err(),
        "replay accepted an expired token under a live proposal"
    );
    assert_unchanged(&fixture, &reserved, before);
}

#[test]
fn threshold_reservation_sql_failures_roll_back_all_participants() {
    for (table, mutation) in [
        ("threshold_approval_proposals", "INSERT"),
        ("threshold_approval_tokens", "INSERT"),
        ("admission_operations", "UPDATE"),
        ("admission_operation_commits", "INSERT"),
    ] {
        let fixture = fixture();
        let now = now_ms();
        let operation = prepared(&fixture, now);
        let reservation = reservation(now / 1_000);
        let command = reservation_command(&fixture, &operation, &reservation, now);
        fixture
            .store
            .connection()
            .expect("connection")
            .execute_batch(&format!(
                "CREATE TEMP TRIGGER fail_threshold_write BEFORE {mutation} ON {table}
             BEGIN SELECT RAISE(ABORT, 'injected threshold failure'); END;"
            ))
            .expect("inject SQL failure");
        let before = counts(&fixture);
        let error = fixture
            .store
            .reserve_threshold_approval_and_commit_admission(&command, &reservation, now)
            .expect_err("injected write must fail");
        assert!(
            error.to_string().contains("injected threshold failure"),
            "wrong failure: {error}"
        );
        assert_unchanged(&fixture, &operation, before);
    }
}

#[test]
fn threshold_reservation_replay_rejects_changed_or_missing_storage() {
    for mutation in [
        "DROP TRIGGER threshold_approval_tokens_no_delete;
         DELETE FROM threshold_approval_tokens WHERE token_id = 'qualified-token-a';",
        "DROP TRIGGER threshold_approval_tokens_immutable;
         UPDATE threshold_approval_tokens SET token_json = zeroblob(262144)
         WHERE token_id = 'qualified-token-a';",
        "DROP TRIGGER threshold_approval_proposals_immutable;
         UPDATE threshold_approval_proposals SET proposal_json = zeroblob(262144);",
        "UPDATE threshold_approval_proposals SET state = 'cancelled';",
    ] {
        let fixture = fixture();
        let now = now_ms();
        let operation = prepared(&fixture, now);
        let reservation = reservation(now / 1_000);
        let reserved = reserve(&fixture, &operation, &reservation, now).expect("reserve");
        let command = reservation_command(&fixture, &reserved, &reservation, now);
        fixture
            .store
            .connection()
            .expect("connection")
            .execute_batch(mutation)
            .expect("corrupt physical participant");
        let before = counts(&fixture);
        let error = fixture
            .store
            .reserve_threshold_approval_and_commit_admission(&command, &reservation, now)
            .expect_err("replay must not hide corrupted participant evidence");
        assert!(
            error.to_string().contains("threshold replay"),
            "wrong failure: {error}"
        );
        assert_unchanged(&fixture, &reserved, before);
    }
}
