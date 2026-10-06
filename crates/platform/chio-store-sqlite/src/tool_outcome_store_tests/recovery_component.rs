//! Qualified outcome/recovery component controls; no rail or nonce is created.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionRecoveryDeferralClear, AdmissionRecoveryDeferralV1, AdmissionRecoveryDeferralWrite,
    AdmissionRecoveryFailureKind, AdmissionRecoveryPhase, AdmissionRecoveryStatusV1,
};
use chio_kernel::tool_outcome::test_support::prepared_pure_evaluation;

fn resolved() -> (Fixture, AdmissionOperationV1, u64, AdmissionRecoveryLease) {
    let fixture = fixture();
    let at = now_ms();
    let committed = committed(&fixture, "outcome-recovery-component", at);
    let (operation, outcome) = record_return(&fixture, &committed, at + 20);
    let prepared = prepared_pure_evaluation(&operation, &outcome, at + 22).expect("pure plan");
    let lease = claim(&fixture, &operation, at + 22);
    fixture
        .outcomes
        .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, at + 23)
        .expect("begin");
    let results = [digest("result", 'a'), digest("result", 'b')];
    let done = prepared
        .record_next_pure_result(results[0].clone())
        .expect("first")
        .record_next_pure_result(results[1].clone())
        .expect("second");
    let (terminal, resolved, blob) =
        resolve_with_blob(&outcome, &done, SettlementDispositionV1::NotApplicable)
            .expect("resolve");
    fixture
        .outcomes
        .finalize_post_return_with_pure_results(
            operation.binding().operation_id(),
            prepared.version(),
            &results,
            &lease,
            &terminal,
            outcome.version(),
            &resolved,
            Some(&blob),
            &fixture.fence,
            at + 24,
        )
        .expect("finalize");
    assert!(
        verify(&fixture, &operation).is_ok(),
        "ordinary resolved baseline is healthy before recovery bookkeeping"
    );
    (fixture, operation, at, lease)
}
fn defer(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    previous: Option<&AdmissionRecoveryStatusV1>,
    at: u64,
) -> AdmissionRecoveryStatusV1 {
    let deferral = AdmissionRecoveryDeferralV1::after_failure(
        operation,
        previous.map(|p| &p.deferral),
        AdmissionRecoveryPhase::Returned,
        AdmissionRecoveryFailureKind::UnsupportedState,
        digest("diagnostic", 'd'),
        at,
    )
    .expect("deferral");
    fixture
        .operations
        .defer_recovery(AdmissionRecoveryDeferralWrite {
            operation,
            lease,
            expected: previous,
            deferral: &deferral,
            fence: &fixture.fence,
            trusted_now_unix_ms: at,
        })
        .expect("persist canonical recovery")
}
fn verify(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
) -> Result<(), ToolOutcomeStoreError> {
    let connection = fixture.outcomes.connection().expect("owner connection");
    super::super::projection::verify_outcome_projection(
        &connection,
        operation.binding().operation_id().as_str(),
    )
}
#[test]
fn recovery_bookkeeping_preserves_exact_latest_outcome_through_defer_clear_retry() {
    let (fixture, operation, at, _) = resolved();
    assert!(verify(&fixture, &operation).is_ok());
    let lease = claim(&fixture, &operation, at + 25);
    let status = defer(&fixture, &operation, &lease, None, at + 26);
    assert!(
        verify(&fixture, &operation).is_ok(),
        "independent recovery must not shadow an anchored outcome"
    );
    fixture
        .operations
        .clear_recovery_deferral(AdmissionRecoveryDeferralClear {
            operation: &operation,
            lease: Some(&lease),
            expected: &status,
            fence: &fixture.fence,
            trusted_now_unix_ms: at + 27,
        })
        .expect("clear");
    let cleared = fixture
        .operations
        .load_recovery_status(operation.binding().operation_id(), &fixture.fence, at + 27)
        .expect("status")
        .expect("tombstone");
    assert!(!cleared.quarantined);
    assert!(verify(&fixture, &operation).is_ok());
    let next = defer(&fixture, &operation, &lease, Some(&cleared), at + 28);
    assert_eq!(next.deferral.attempt_count, 2);
    assert!(verify(&fixture, &operation).is_ok());
}
fn require_invariant(result: Result<(), ToolOutcomeStoreError>, expected: &str) {
    let error = match result {
        Ok(()) => panic!("controlled tamper must be rejected"),
        Err(error) => error,
    };
    match error {
        ToolOutcomeStoreError::Invariant(context) => assert_eq!(context, expected),
        _ => panic!("controlled tamper must retain the invariant family"),
    }
}
#[test]
fn recovery_bookkeeping_rejects_missing_or_corrupt_current_component() {
    let malformed = chio_core::canonical::UntrustedJsonText::from_wire(b"{}", 4096)
        .and_then(|input| input.decode_canonical::<AdmissionRecoveryStatusV1>())
        .expect_err("known malformed canonical status");
    let malformed_context = match AdmissionOperationStoreError::from(malformed) {
        AdmissionOperationStoreError::Operation(error) => error.to_string(),
        _ => panic!("known status input must retain its parser error"),
    };
    for (statement, expected) in [
        ("DROP TRIGGER admission_operation_recovery_no_delete; DELETE FROM admission_operation_recovery_deferrals",
            "recovery status and committed history disagree"),
        ("UPDATE admission_operation_recovery_deferrals SET canonical_status=CAST('{}' AS BLOB)",
            malformed_context.as_str()),
        ("UPDATE admission_operation_recovery_deferrals SET status_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
            "recovery status does not match its anchored canonical record"),
        ("UPDATE admission_operation_recovery_deferrals SET quarantined=0",
            "recovery status does not match its anchored canonical record"),
    ] {
        let (fixture, operation, at, _) = resolved();
        let lease = claim(&fixture, &operation, at + 25);
        defer(&fixture, &operation, &lease, None, at + 26);
        fixture.outcomes.connection().expect("connection").execute_batch(statement).expect("controlled component corruption");
        require_invariant(verify(&fixture, &operation), expected);
    }
}
#[test]
fn recovery_bookkeeping_rejects_unrelated_intervening_participant() {
    let (fixture, operation, at, _) = resolved();
    let lease = claim(&fixture, &operation, at + 25);
    defer(&fixture, &operation, &lease, None, at + 26);
    let mut connection = fixture.outcomes.connection().expect("connection");
    let transaction = connection.transaction().expect("transaction");
    append_participant_update_tx(
        &transaction,
        &fixture.outcomes.serving_owner,
        &operation,
        &lease,
        digest("unrelated_participant", 'f').as_str(),
        at + 27,
    )
    .expect("validly anchored unrelated component");
    let latest: (String, String) = transaction.query_row(
        "SELECT mutation_kind, participant_digest FROM admission_operation_commits
         WHERE operation_id=?1 AND participant_digest IS NOT NULL ORDER BY commit_sequence DESC LIMIT 1",
        [operation.binding().operation_id().as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).expect("actual appended participant");
    assert_eq!(latest.0, "participant_update");
    assert_eq!(latest.1, digest("unrelated_participant", 'f').as_str());
    require_invariant(
        super::super::projection::verify_outcome_projection(
            &transaction,
            operation.binding().operation_id().as_str(),
        ),
        "tool outcome projection is not bound to the admission commit chain",
    );
    transaction.rollback().expect("rollback control");
}
#[test]
fn recovery_bookkeeping_does_not_mask_altered_outcome_or_evaluation_commitment() {
    for (table, trigger, expected) in [
        (
            "tool_outcomes",
            "tool_outcomes_versioned_body",
            "tool outcome row has an invalid participant commitment",
        ),
        (
            "post_return_evaluations",
            "post_return_evaluations_versioned_body",
            "post-return evaluation row has an invalid participant commitment",
        ),
    ] {
        let (fixture, operation, at, _) = resolved();
        let lease = claim(&fixture, &operation, at + 25);
        defer(&fixture, &operation, &lease, None, at + 26);
        // Remove only the private fixture guard to test detection of damaged stored evidence.
        fixture.outcomes.connection().expect("connection").execute_batch(&format!(
            "DROP TRIGGER {trigger}; UPDATE {table} SET participant_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'"
        )).expect("controlled outcome corruption");
        require_invariant(verify(&fixture, &operation), expected);
    }
}
#[test]
fn recovery_bookkeeping_qualified_owner_rejects_external_chain_damage() {
    let (fixture, operation, at, _) = resolved();
    let lease = claim(&fixture, &operation, at + 25);
    defer(&fixture, &operation, &lease, None, at + 26);
    let external = Connection::open(&fixture.database).expect("external test connection");
    // A distinct connection's committed write is rejected by the owner's data-version fence.
    external
        .execute(
            "UPDATE admission_operation_commit_meta SET head_chain_digest=?1 WHERE singleton=1",
            ["f".repeat(64)],
        )
        .expect("damage head");
    let error = match fixture
        .outcomes
        .lookup_by_operation(operation.binding().operation_id())
    {
        Ok(_) => panic!("outside-connection damage must poison the qualified owner"),
        Err(error) => error,
    };
    match error {
        ToolOutcomeStoreError::Unavailable(context) => assert_eq!(
            context,
            crate::serving_owner::SqliteServingOwnerError::OutcomeUnknown(
                "authority database changed outside its serving-owner connection".into()
            )
            .to_string()
        ),
        _ => panic!("owner data-version refusal must retain Unavailable"),
    }
}

#[test]
fn recovery_bookkeeping_rejects_a_mismatched_latest_recovery_kind() {
    let (fixture, operation, at, _) = resolved();
    let lease = claim(&fixture, &operation, at + 25);
    defer(&fixture, &operation, &lease, None, at + 26);
    // Deliberately damage the private fixture's immutable journal. The direct
    // component verifier must reject even without relying on a new owner read.
    fixture
        .outcomes
        .connection()
        .expect("connection")
        .execute_batch(
            "DROP TRIGGER admission_operation_commits_immutable;
         UPDATE admission_operation_commits SET mutation_kind='recovery_deferral_cleared'
         WHERE mutation_kind='recovery_deferred'",
        )
        .expect("controlled wrong-kind corruption");
    require_invariant(
        verify(&fixture, &operation),
        "recovery status does not match its anchored canonical record",
    );
}

#[test]
fn recovery_bookkeeping_does_not_accept_a_malformed_release_checkpoint() {
    let (fixture, operation, at, _) = resolved();
    let lease = claim(&fixture, &operation, at + 25);
    defer(&fixture, &operation, &lease, None, at + 26);
    // This is untrusted malformed storage, never an acknowledged owner result.
    fixture
        .outcomes
        .connection()
        .expect("connection")
        .execute(
            "INSERT INTO tool_outcome_security_releases(operation_id, canonical_record,
         participant_digest, acknowledged_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                operation.binding().operation_id().as_str(),
                b"{}".as_slice(),
                "f".repeat(64),
                sqlite_u64(at + 27, "release time").expect("checked SQL release time"),
                &fixture.fence.store_uuid,
                &fixture.fence.lease_id,
                sqlite_u64(fixture.fence.owner_epoch, "release epoch")
                    .expect("checked SQL release epoch")
            ],
        )
        .expect("controlled malformed checkpoint");
    let parser_error = SecurityReleaseRecordV1::from_canonical_bytes(b"{}")
        .expect_err("known malformed checkpoint");
    require_invariant(verify(&fixture, &operation), &parser_error.to_string());
}
