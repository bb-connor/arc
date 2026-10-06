use std::fs;
use std::path::PathBuf;

use chio_core::capability::scope::MonetaryAmount;
use chio_kernel::admission_operation::{
    qualified_lease, AdmissionAttachment, AdmissionDigest, AdmissionIdentifier,
    AdmissionOperationBindingInputV1, AdmissionOperationBindingV1, AdmissionOperationCommand,
    AdmissionOperationKind, AdmissionOperationState, AdmissionOperationStore, AdmissionOperationV1,
    AdmissionParticipantRequirements, AdmissionRecoveryLease, AdmissionRequestBindingV1,
    AuthenticatedRequestNamespace, ProviderAttemptBindingV1, QualifiedAdmissionOperationStore,
    QualifiedAdmissionOperationStoreExt, RecoveryClaimRequest, SideEffectClass, StoreMutationFence,
};
use chio_kernel::tool_outcome::test_support::{
    prepared_evaluation, record_external_step, record_pure_step, resolve_with_blob, returned_value,
};
use chio_kernel::tool_outcome::{
    CanonicalResolvedOutputBlobV1, SettlementDispositionV1, ToolOutcomeInsertResultV1,
    ToolOutcomeStore, ToolOutcomeStoreError,
};
use tempfile::TempDir;

use super::*;
use crate::{SqliteAdmissionOperationStore, SqliteAuthorityStore};

#[path = "tool_outcome_store_tests/pure_finalization.rs"]
mod pure_finalization;
#[path = "tool_outcome_store_tests/qualified_claims.rs"]
mod qualified_claims;

#[path = "tool_outcome_store_tests/compaction_fixture.rs"]
mod compaction_fixture;
use compaction_fixture::completed_return;

struct Fixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
    authority: SqliteAuthorityStore,
    operations: SqliteAdmissionOperationStore,
    outcomes: SqliteToolOutcomeStore,
    fence: StoreMutationFence,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
    }
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    let authority =
        crate::test_authority::open_serving(&database, &lock_root).expect("open authority");
    let fence = authority.mutation_fence();
    let operations = authority.admission_operation_store();
    let outcomes = authority.tool_outcome_store();
    Fixture {
        _temp: temp,
        database,
        lock_root,
        authority,
        operations,
        outcomes,
        fence,
    }
}

fn now_ms() -> u64 {
    chio_test_support::clock::unix_millis()
}

fn id(field: &'static str, value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new(field, value).expect("valid identifier")
}

fn digest(field: &'static str, byte: char) -> AdmissionDigest {
    AdmissionDigest::try_new(field, byte.to_string().repeat(64)).expect("valid digest")
}

fn prepared(fence: &StoreMutationFence, request_id: &str) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(id(
        "coordinator_authority_id",
        "tool-outcome-test-authority",
    ))
    .expect("request namespace");
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: id("request_id", request_id),
        capability_id: id("capability_id", "tool-outcome-capability"),
        authorization_capability_hash: digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", 'b'),
            requirements,
        )
        .expect("request binding"),
        policy_hash: digest("policy_hash", 'c'),
        effect_class: SideEffectClass::SideEffecting,
    })
    .expect("operation binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

fn claim(fixture: &Fixture, operation: &AdmissionOperationV1, at: u64) -> AdmissionRecoveryLease {
    fixture
        .operations
        .claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &id("claimant_id", "tool-outcome-worker"),
            at,
            at + 60_000,
            &fixture.fence,
        )
        .expect("claim operation")
}

fn advance(
    fixture: &Fixture,
    operation: AdmissionOperationV1,
    next: AdmissionOperationState,
    attachments: Vec<AdmissionAttachment>,
    at: u64,
) -> AdmissionOperationV1 {
    let lease = claim(fixture, &operation, at);
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(next),
        None,
        None,
    )
    .expect("operation command");
    fixture
        .operations
        .compare_and_swap(&command, at + 1)
        .expect("advance operation")
        .into_operation()
}

fn committed(fixture: &Fixture, request_id: &str, begun_at: u64) -> AdmissionOperationV1 {
    let mut operation = prepared(&fixture.fence, request_id);
    fixture
        .operations
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin operation");
    let attempt = ProviderAttemptBindingV1 {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        attempt_id: format!("attempt:{}", operation.binding().operation_id().as_str()),
        transport_id: "tool-outcome-test-transport".to_owned(),
        transport_key_epoch: fixture.fence.owner_epoch,
    };
    let transitions = [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(attempt)],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(id(
                "budget_hold_id",
                "tool-outcome-test-hold",
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, Vec::new()),
        (AdmissionOperationState::CapturePending, Vec::new()),
        (AdmissionOperationState::DispatchCommitted, Vec::new()),
    ];
    for (index, (next, attachments)) in transitions.into_iter().enumerate() {
        operation = advance(
            fixture,
            operation,
            next,
            attachments,
            begun_at + 1 + u64::try_from(index).expect("transition index") * 2,
        );
    }
    operation
}

fn record_return(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    at: u64,
) -> (
    AdmissionOperationV1,
    chio_kernel::tool_outcome::ToolOutcomeRecordV1,
) {
    let (blob, outcome) = returned_value(
        operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({"completed": true}),
        Some(MonetaryAmount {
            units: 25,
            currency: "USD".to_owned(),
        }),
    )
    .expect("returned outcome");
    let lease = claim(fixture, operation, at);
    let inserted = fixture
        .outcomes
        .record_tool_returned(operation, &lease, &blob, &outcome, &fixture.fence, at + 1)
        .expect("record tool return");
    let (stored, finalizing) = inserted.into_parts();
    (finalizing, stored)
}

#[test]
fn tool_return_atomically_persists_blob_and_advances_operation() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = committed(&fixture, "atomic-return", begun_at);
    let at = begun_at + 20;
    let (blob, outcome) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({"completed": true}),
        None,
    )
    .expect("returned outcome");
    let mut stale_fence = fixture.fence.clone();
    stale_fence.owner_epoch += 1;
    let lease = claim(&fixture, &operation, at);
    assert_eq!(
        fixture.outcomes.record_tool_returned(
            &operation,
            &lease,
            &blob,
            &outcome,
            &stale_fence,
            at + 1,
        ),
        Err(ToolOutcomeStoreError::Fenced)
    );
    let counts: (i64, i64) = fixture
        .outcomes
        .connection()
        .expect("connection")
        .query_row(
            "SELECT (SELECT COUNT(*) FROM tool_outcome_blobs), (SELECT COUNT(*) FROM tool_outcomes)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("outcome counts");
    assert_eq!(counts, (0, 0));

    let inserted = fixture
        .outcomes
        .record_tool_returned(&operation, &lease, &blob, &outcome, &fixture.fence, at + 1)
        .expect("atomic return commit");
    let ToolOutcomeInsertResultV1::Inserted {
        outcome: stored,
        operation: finalizing,
    } = inserted
    else {
        panic!("first return must insert");
    };
    assert_eq!(stored, outcome);
    assert_eq!(finalizing.state(), AdmissionOperationState::Finalizing);
    assert_eq!(finalizing.tool_outcome_id(), Some(outcome.outcome_id()));
    assert_eq!(
        fixture
            .outcomes
            .load_raw_invocation_by_operation(operation.binding().operation_id())
            .expect("load raw outcome")
            .expect("raw outcome")
            .canonical_blob()
            .expect("canonical raw blob"),
        blob
    );
    assert_eq!(
        fixture
            .operations
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load operation"),
        Some(finalizing)
    );
}

/// A claimed tool return and a claimed post-return begin are one durable
/// write each: the anchor advances once per joint transaction where a
/// separately claimed return advances it twice, and the lease the begin
/// returns carries the later stages.

#[test]
fn replayed_post_return_begin_anchors_a_renewed_claim_before_the_next_stage() {
    let fixture = fixture();
    let at = now_ms();
    let committed = committed(&fixture, "replay-renewed-claim", at);
    let (operation, outcome) = record_return(&fixture, &committed, at + 20);
    let prepared = prepared_evaluation(&operation, &outcome, at + 22).expect("evaluation");
    let lease = claim(&fixture, &operation, at + 23);
    fixture
        .outcomes
        .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, at + 24)
        .expect("first begin");
    let before = fixture.authority.anchor_generation().expect("anchor");
    let later = at + 60_100;
    let claimant = id("claimant_id", "recovery-worker");
    let request = RecoveryClaimRequest {
        operation_id: operation.binding().operation_id(),
        expected_version: operation.version(),
        claimant_id: &claimant,
        expires_at_unix_ms: later + 60_000,
        fence: &fixture.fence,
    };
    let (replayed, lease) = fixture
        .outcomes
        .claim_and_begin_post_return_evaluation(
            &fixture.operations,
            request,
            &mut qualified_lease(request, later),
            &prepared,
            &fixture.fence,
            later,
        )
        .expect("renewed claim on replay");
    assert_eq!(replayed, prepared);
    assert_eq!(
        fixture.authority.anchor_generation().expect("anchor"),
        before + 1
    );
    let pure = record_pure_step(&prepared).expect("pure step");
    assert_eq!(
        fixture
            .outcomes
            .stage_post_return_evaluation(
                operation.binding().operation_id(),
                prepared.version(),
                &lease,
                &pure,
                &fixture.fence,
                later + 1,
            )
            .expect("stage after replay"),
        pure
    );
}

#[test]
fn post_return_evaluation_is_fenced_staged_and_finalized_by_cas() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "evaluation-journal", begun_at);
    let (operation, outcome) = record_return(&fixture, &committed, begun_at + 20);
    let prepared =
        prepared_evaluation(&operation, &outcome, begun_at + 22).expect("prepared evaluation");
    let lease = claim(&fixture, &operation, begun_at + 22);
    assert_eq!(
        fixture
            .outcomes
            .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, begun_at + 23,)
            .expect("begin evaluation"),
        prepared
    );
    let pure = record_pure_step(&prepared).expect("pure result");
    assert_eq!(
        fixture
            .outcomes
            .stage_post_return_evaluation(
                operation.binding().operation_id(),
                prepared.version(),
                &lease,
                &pure,
                &fixture.fence,
                begun_at + 24,
            )
            .expect("stage pure result"),
        pure
    );
    assert_eq!(
        fixture.outcomes.stage_post_return_evaluation(
            operation.binding().operation_id(),
            prepared.version(),
            &lease,
            &pure,
            &fixture.fence,
            begun_at + 25,
        ),
        Err(ToolOutcomeStoreError::CasConflict)
    );
    let external = record_external_step(&pure, begun_at + 25).expect("external result");
    fixture
        .outcomes
        .stage_post_return_evaluation(
            operation.binding().operation_id(),
            pure.version(),
            &lease,
            &external,
            &fixture.fence,
            begun_at + 25,
        )
        .expect("stage external result");
    let (terminal_evaluation, terminal_outcome, resolved_blob) =
        resolve_with_blob(&outcome, &external, SettlementDispositionV1::NotApplicable)
            .expect("terminal records");
    assert!(matches!(
        fixture.outcomes.finalize_post_return(
            operation.binding().operation_id(),
            external.version(),
            &lease,
            &terminal_evaluation,
            outcome.version(),
            &terminal_outcome,
            None,
            &fixture.fence,
            begun_at + 26,
        ),
        Err(ToolOutcomeStoreError::Invariant(_))
    ));
    let substituted_blob =
        CanonicalResolvedOutputBlobV1::from_signing_preimage(b"substitute".to_vec())
            .expect("substituted blob");
    assert!(matches!(
        fixture.outcomes.finalize_post_return(
            operation.binding().operation_id(),
            external.version(),
            &lease,
            &terminal_evaluation,
            outcome.version(),
            &terminal_outcome,
            Some(&substituted_blob),
            &fixture.fence,
            begun_at + 26,
        ),
        Err(ToolOutcomeStoreError::Invariant(_))
    ));
    assert_eq!(
        fixture
            .outcomes
            .lookup_post_return_evaluation(operation.binding().operation_id())
            .expect("lookup uncommitted evaluation"),
        Some(external.clone())
    );
    assert_eq!(
        fixture
            .outcomes
            .lookup_by_operation(operation.binding().operation_id())
            .expect("lookup uncommitted outcome"),
        Some(outcome.clone())
    );
    assert_eq!(
        fixture
            .outcomes
            .load_resolved_output_by_operation(operation.binding().operation_id())
            .expect("lookup uncommitted resolved output"),
        None
    );
    let finalized = fixture
        .outcomes
        .finalize_post_return(
            operation.binding().operation_id(),
            external.version(),
            &lease,
            &terminal_evaluation,
            outcome.version(),
            &terminal_outcome,
            Some(&resolved_blob),
            &fixture.fence,
            begun_at + 26,
        )
        .expect("finalize evaluation and outcome");
    assert_eq!(
        finalized,
        (terminal_evaluation.clone(), terminal_outcome.clone())
    );
    assert_eq!(
        fixture
            .outcomes
            .lookup_post_return_evaluation(operation.binding().operation_id())
            .expect("lookup evaluation"),
        Some(terminal_evaluation)
    );
    assert_eq!(
        fixture
            .outcomes
            .lookup_by_operation(operation.binding().operation_id())
            .expect("lookup outcome"),
        Some(terminal_outcome)
    );
    assert_eq!(
        fixture
            .outcomes
            .load_resolved_output_by_operation(operation.binding().operation_id())
            .expect("lookup resolved output"),
        Some(resolved_blob)
    );
}

#[test]
fn outcome_journal_survives_owner_rotation_and_detects_tampering() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "outcome-restart", begun_at);
    let (operation, outcome) = record_return(&fixture, &committed, begun_at + 20);
    let operation_id = operation.binding().operation_id().clone();
    let database = fixture.database.clone();
    let lock_root = fixture.lock_root.clone();
    let Fixture {
        _temp,
        authority,
        operations,
        outcomes,
        ..
    } = fixture;
    drop(outcomes);
    drop(operations);
    drop(authority);

    let reopened = crate::test_authority::open_serving(&database, &lock_root)
        .expect("reopen outcome authority");
    assert_eq!(
        reopened
            .tool_outcome_store()
            .lookup_by_operation(&operation_id)
            .expect("lookup after reopen"),
        Some(outcome)
    );
    drop(reopened);

    let connection = Connection::open(&database).expect("open database for tamper");
    connection
        .execute_batch(
            "UPDATE tool_outcomes
             SET participant_digest =
                    '0000000000000000000000000000000000000000000000000000000000000000',
                 outcome_version = outcome_version + 1,
                 store_uuid = (SELECT store_uuid FROM chio_serving_owner WHERE singleton = 1),
                 store_lease_id = (SELECT lease_id FROM chio_serving_owner WHERE singleton = 1),
                 store_owner_epoch = (SELECT owner_epoch FROM chio_serving_owner WHERE singleton = 1);",
        )
        .expect("tamper outcome commitment");
    drop(connection);
    assert!(SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock()
    )
    .is_err());
    drop(_temp);
}

fn mark_operation_terminal(fixture: &Fixture, operation_id: &AdmissionOperationId) {
    // Negative custody fixture: a terminal bit alone cannot authenticate a
    // Completed replay contract. Positive erasure uses completed_return().
    let connection = fixture.outcomes.connection().expect("connection");
    let changed = connection
        .execute(
            "UPDATE admission_operations
             SET terminal = 1, version = version + 1
             WHERE operation_id = ?1",
            [operation_id.as_str()],
        )
        .expect("mark operation terminal");
    assert_eq!(changed, 1);
}

fn blob_state(fixture: &Fixture, digest: &str) -> (i64, bool) {
    let connection = fixture.outcomes.connection().expect("connection");
    connection
        .query_row(
            "SELECT blob_size_bytes, canonical_bytes IS NOT NULL
             FROM tool_outcome_blobs WHERE digest = ?1",
            [digest],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)? != 0)),
        )
        .expect("blob row")
}

#[test]
fn compaction_page_keeps_work_to_one_inspected_blob() {
    let _time = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let fixture = fixture();
    let begun_at = now_ms();
    let mut digests = Vec::new();
    for name in ["page-a", "page-b", "page-c"] {
        let (_, outcome) = completed_return(&fixture, name, false).expect("signed completion");
        digests.push(outcome.raw_output_digest().as_str().to_owned());
    }
    let summary = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(
            begun_at + 1_000,
            &fixture.fence,
            begun_at + 1_000,
            None,
            1,
        )
        .expect("one compaction page");
    assert_eq!(summary.inspected, 1);
    assert!(
        summary.compacted <= 1,
        "one metadata row may be a resolved blob"
    );
    assert_eq!(
        digests
            .iter()
            .filter(|digest| !blob_state(&fixture, digest).1)
            .count(),
        usize::try_from(summary.compacted).expect("bounded count")
    );
    let mut total = summary.compacted;
    let mut cursor = summary.next_digest;
    while cursor.is_some() {
        let page = fixture
            .outcomes
            .compact_retained_invocation_blobs_page(
                begun_at + 1_000,
                &fixture.fence,
                begun_at + 1_000,
                cursor.as_ref(),
                1,
            )
            .expect("next compaction page");
        assert!(page.inspected <= 1);
        assert!(page.compacted <= 1);
        total += page.compacted;
        cursor = page.next_digest;
    }
    assert_eq!(total, 3);
}

#[test]
fn compaction_page_refuses_a_payload_beyond_its_byte_budget() {
    let _time = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let fixture = fixture();
    let begun_at = now_ms();
    let (_, outcome) = completed_return(&fixture, "byte-budget", false).expect("signed completion");
    let error = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            begun_at + 100,
            &fixture.fence,
            begun_at + 200,
            None,
            ToolOutcomeCompactionLimits {
                max_payload_bytes: 1,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
        .expect_err("compaction must refuse a payload beyond its byte ceiling");
    assert!(
        matches!(error, ToolOutcomeStoreError::Unavailable(ref reason) if reason.contains("payload byte budget"))
    );
    assert!(blob_state(&fixture, outcome.raw_output_digest().as_str()).1);
}

#[test]
fn compaction_page_sql_ceiling_refuses_before_unbounded_custody_work_and_recovers() {
    let _time = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let fixture = fixture();
    let begun_at = now_ms();
    let (_, outcome) = completed_return(&fixture, "sql-budget", false).expect("signed completion");
    let error = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            begun_at + 100,
            &fixture.fence,
            begun_at + 200,
            None,
            ToolOutcomeCompactionLimits {
                max_sql_steps: 1,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
        .expect_err("SQL work must be limited before custody verification");
    assert!(
        matches!(error, ToolOutcomeStoreError::Unavailable(ref reason) if reason.contains("SQL work budget"))
    );
    assert!(blob_state(&fixture, outcome.raw_output_digest().as_str()).1);
    let page = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(
            begun_at + 100,
            &fixture.fence,
            begun_at + 201,
            None,
            64,
        )
        .expect("interruption must be cleared before returning the connection");
    assert_eq!(page.compacted, 1);
    assert!(page.sql_steps > 1);
}

#[test]
fn compaction_page_partial_byte_progress_preserves_its_resume_cursor() {
    let _time = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let fixture = fixture();
    let begun_at = now_ms();
    let mut digests = Vec::new();
    for name in ["byte-page-a", "byte-page-b", "byte-page-c"] {
        let (_, outcome) = completed_return(&fixture, name, false).expect("signed completion");
        digests.push(outcome.raw_output_digest().as_str().to_owned());
    }
    let one_payload_size = u64::try_from(blob_state(&fixture, &digests[0]).0).unwrap();
    assert!(digests
        .iter()
        .all(|digest| u64::try_from(blob_state(&fixture, digest).0).unwrap() == one_payload_size));
    let limits = ToolOutcomeCompactionLimits {
        // The same ceiling includes the original payload plus qualified
        // request/operation/evaluation/projection/receipt verification reads.
        max_payload_bytes: one_payload_size * 12,
        ..ToolOutcomeCompactionLimits::default()
    };
    let mut cursor = None;
    let mut total = 0;
    for index in 0..3 {
        let page = fixture
            .outcomes
            .compact_retained_invocation_blobs_page_with_limits(
                begun_at + 1_000,
                &fixture.fence,
                begun_at + 1_000,
                cursor.as_ref(),
                limits,
            )
            .expect("bounded byte page");
        assert_eq!(page.compacted, 1);
        assert_eq!(page.compacted_bytes, one_payload_size);
        assert!(
            page.inspected_payload_bytes + page.inspected_verification_bytes
                <= limits.max_payload_bytes
        );
        assert_eq!(page.byte_budget_exhausted, index < 2);
        total += page.compacted;
        cursor = page.next_digest;
    }
    assert_eq!(total, 3);
    assert!(cursor.is_none());
    assert!(digests.iter().all(|digest| !blob_state(&fixture, digest).1));
}

#[test]
fn compaction_page_holds_actual_completed_resolved_alias_and_independent_trigger() {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let fixture = fixture();
    let (first, first_outcome) =
        completed_return(&fixture, "completed-raw-alias", false).expect("first completion");
    let raw = fixture
        .outcomes
        .load_raw_invocation_by_operation(first.binding().operation_id())
        .expect("raw read")
        .expect("raw");
    let bytes = raw.canonical_blob().expect("blob").bytes().to_vec();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("canonical raw value");
    let (second, _) = compaction_fixture::completed_return_with_value(
        &fixture,
        "completed-resolved-alias",
        false,
        value,
    )
    .expect("second actual completion");
    let resolved = fixture
        .outcomes
        .load_resolved_output_by_operation(second.binding().operation_id())
        .expect("resolved read")
        .expect("resolved");
    assert_eq!(
        resolved.blob_ref().digest(),
        first_outcome.raw_output_digest()
    );
    assert_eq!(resolved.bytes(), bytes);
    {
        let connection = fixture.outcomes.connection().expect("connection");
        let error = connection
            .execute(
                "UPDATE tool_outcome_blobs SET canonical_bytes=NULL WHERE digest=?1",
                [first_outcome.raw_output_digest().as_str()],
            )
            .expect_err("independent resolved-custody trigger");
        assert!(
            matches!(error,rusqlite::Error::SqliteFailure(ref cause,_) if cause.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER)
        );
    }
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let now = now_ms();
    let page = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(now, &fixture.fence, now, None, 64)
        .expect("verified alias page");
    assert_eq!(page.retained_resolved, 1);
    assert_eq!(
        page.compacted, 1,
        "only the independent second raw envelope qualifies"
    );
    assert!(blob_state(&fixture, first_outcome.raw_output_digest().as_str()).1);
    assert_eq!(
        fixture
            .outcomes
            .load_resolved_output_by_operation(second.binding().operation_id())
            .expect("terminal resolved read"),
        Some(resolved)
    );
}

#[test]
fn compaction_page_refuses_unowned_large_sidecar_before_payload_column_access() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let fixture = fixture();
    let (operation, outcome) = completed_return(&fixture, "unexpected-large-sidecar", false)
        .expect("actual signed completed value");
    assert!(operation.caller_dispatch_context_digest().is_none());
    let accesses = Arc::new(AtomicUsize::new(0));
    {
        let connection = fixture.outcomes.connection().expect("connection");
        // Deliberately corrupt this isolated fixture. This is not a legitimate
        // runtime/caller claim or an authority witness. The authorizer records
        // column access at statement preparation, not Rust allocation bytes.
        let context = canonical_json_bytes(&serde_json::json!("x".repeat(512 * 1024)))
            .expect("sidecar bytes");
        connection.execute("INSERT INTO admission_operation_caller_contexts(operation_id,context_json) VALUES(?1,?2)",params![operation.binding().operation_id().as_str(),context]).expect("inject fixture-only unexpected sidecar");
        let observe = accesses.clone();
        connection
            .authorizer(Some(move |context: AuthContext<'_>| {
                if matches!(
                    context.action,
                    AuthAction::Read {
                        table_name: "admission_operation_caller_contexts",
                        column_name: "context_json"
                    }
                ) {
                    observe.fetch_add(1, Ordering::SeqCst);
                }
                Authorization::Allow
            }))
            .expect("install column observation");
    }
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let now = now_ms();
    let error = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            now,
            &fixture.fence,
            now,
            None,
            ToolOutcomeCompactionLimits {
                max_payload_bytes: 128 * 1024,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
        .expect_err("unexpected sidecar custody must refuse");
    {
        let connection = fixture.outcomes.connection().expect("connection");
        connection
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .expect("clear column observation");
    }
    assert_eq!(accesses.load(Ordering::SeqCst),0,"bounded retention must reject unexpected512KiB sidecar before preparing any payload-column read under128KiB cap; actual refusal: {error:?}");
    assert!(
        matches!(error,ToolOutcomeStoreError::Invariant(ref reason) if reason.contains("unexpected sidecar custody"))
    );
    assert!(blob_state(&fixture, outcome.raw_output_digest().as_str()).1);
    assert_eq!(fixture.authority.mutation_fence(), fixture.fence);
}

#[test]
fn compaction_page_holds_shared_live_ownership_and_refuses_stale_fences() {
    let fixture = fixture();
    let begun_at = now_ms();
    let first = committed(&fixture, "shared-terminal", begun_at);
    let (operation, outcome) = record_return(&fixture, &first, begun_at + 20);
    mark_operation_terminal(&fixture, operation.binding().operation_id());
    let live = committed(&fixture, "shared-live", begun_at + 100);
    {
        // Isolate the conservative custody predicate by introducing a second
        // raw owner. The shared raw envelope is never trusted for execution.
        let connection = fixture.outcomes.connection().expect("connection");
        connection
            .execute(
                "INSERT INTO tool_outcomes (
                operation_id, outcome_id, request_id, raw_output_digest, outcome_version,
                lifecycle_digest, participant_digest, outcome_json, recorded_at_unix_ms,
                updated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch)
             SELECT ?1, ?2, 'shared-live', raw_output_digest, outcome_version,
                lifecycle_digest, participant_digest, outcome_json, recorded_at_unix_ms,
                updated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
             FROM tool_outcomes WHERE operation_id = ?3",
                params![
                    live.binding().operation_id().as_str(),
                    "f".repeat(64),
                    operation.binding().operation_id().as_str()
                ],
            )
            .expect("shared live owner");
    }
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert_eq!(
        fixture.outcomes.compact_retained_invocation_blobs_page(
            begun_at + 1_000,
            &stale,
            begun_at + 1_000,
            None,
            1,
        ),
        Err(ToolOutcomeStoreError::Fenced)
    );
    let page = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(
            begun_at + 1_000,
            &fixture.fence,
            begun_at + 1_000,
            None,
            1,
        )
        .expect("live shared owner remains retained");
    assert_eq!(page.retained_live, 1);
    assert_eq!(page.compacted, 0);
    assert!(blob_state(&fixture, outcome.raw_output_digest().as_str()).1);
}

#[test]
fn compaction_page_refuses_poison_before_recovery_and_resumes_after_qualified_read() {
    let _time = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let fixture = fixture();
    let begun_at = now_ms();
    let (operation, outcome) =
        completed_return(&fixture, "poisoned-maintenance", false).expect("signed completion");
    let poisoned_store = fixture.outcomes.clone();
    let poison = std::thread::spawn(move || {
        let _connection = poisoned_store
            .connection()
            .expect("owned authority connection");
        panic!("intentional maintenance poison fixture");
    });
    assert!(poison.join().is_err());
    let error = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(
            begun_at + 100,
            &fixture.fence,
            begun_at + 200,
            None,
            1,
        )
        .expect_err("maintenance must refuse before running unbudgeted connection recovery");
    assert!(
        matches!(error, ToolOutcomeStoreError::Unavailable(ref reason) if reason.contains("poisoned"))
    );
    // The ordinary qualified port keeps its existing recovery and anchor proof.
    assert_eq!(
        fixture
            .outcomes
            .lookup_by_operation(operation.binding().operation_id())
            .expect("qualified recovery"),
        Some(outcome.clone())
    );
    assert!(blob_state(&fixture, outcome.raw_output_digest().as_str()).1);
    let page = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(
            begun_at + 100,
            &fixture.fence,
            begun_at + 201,
            None,
            64,
        )
        .expect("bounded maintenance resumes after qualified recovery");
    assert_eq!(page.compacted, 1);
    assert!(page.inspected <= 64);
}

#[test]
fn compaction_page_holds_resolved_alias_while_live_and_after_terminal() {
    use chio_kernel::tool_outcome::test_support::{
        prepared_pure_evaluation, resolve_output_with_blob,
    };
    let fixture = fixture();
    let at = now_ms();
    let first = committed(&fixture, "alias-raw-owner", at);
    let (first_operation, first_outcome) = record_return(&fixture, &first, at + 20);
    let raw = fixture
        .outcomes
        .load_raw_invocation_by_operation(first_operation.binding().operation_id())
        .expect("first raw envelope")
        .expect("present raw envelope");
    let raw_bytes = raw
        .canonical_blob()
        .expect("canonical raw envelope")
        .bytes()
        .to_vec();
    let alias_output = chio_kernel::ToolCallOutput::Value(
        serde_json::from_slice(&raw_bytes).expect("raw JSON value"),
    );
    let second = committed(&fixture, "alias-resolved-owner", at + 100);
    let (second_operation, second_outcome) = record_return(&fixture, &second, at + 120);
    let prepared =
        prepared_pure_evaluation(&second_operation, &second_outcome, at + 122).expect("evaluation");
    let lease = claim(&fixture, &second_operation, at + 122);
    fixture
        .outcomes
        .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, at + 123)
        .expect("begin evaluation");
    let results = [digest("pure_result", 'a'), digest("pure_result", 'b')];
    let first_result = prepared
        .record_next_pure_result(results[0].clone())
        .expect("first pure result");
    let second_result = first_result
        .record_next_pure_result(results[1].clone())
        .expect("second pure result");
    let (terminal, resolved, blob) = resolve_output_with_blob(
        &second_outcome,
        &second_result,
        SettlementDispositionV1::NotApplicable,
        &alias_output,
    )
    .expect("alias resolution");
    assert_eq!(blob.bytes(), raw_bytes);
    assert_eq!(blob.blob_ref().digest(), first_outcome.raw_output_digest());
    fixture
        .outcomes
        .finalize_post_return_with_pure_results(
            second_operation.binding().operation_id(),
            prepared.version(),
            &results,
            &lease,
            &terminal,
            second_outcome.version(),
            &resolved,
            Some(&blob),
            &fixture.fence,
            at + 124,
        )
        .expect("qualified resolved alias publication");
    mark_operation_terminal(&fixture, first_operation.binding().operation_id());
    let page = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(at + 1_000, &fixture.fence, at + 1_000, None, 64)
        .expect("shared resolved custody page");
    assert_eq!(
        page.compacted, 0,
        "a live resolved owner keeps the raw alias bytes"
    );
    assert!(blob_state(&fixture, first_outcome.raw_output_digest().as_str()).1);
    assert_eq!(
        fixture
            .outcomes
            .load_resolved_output_by_operation(second_operation.binding().operation_id())
            .expect("live resolved alias remains available"),
        Some(blob.clone())
    );
    mark_operation_terminal(&fixture, second_operation.binding().operation_id());
    let terminal_page = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(at + 1_000, &fixture.fence, at + 1_001, None, 64)
        .expect("terminal resolved custody page");
    assert_eq!(
        terminal_page.compacted, 0,
        "terminal-bit-only fixture rows have no authenticated Completed replay contract"
    );
    assert!(blob_state(&fixture, first_outcome.raw_output_digest().as_str()).1);
    assert_eq!(
        fixture
            .outcomes
            .load_resolved_output_by_operation(second_operation.binding().operation_id())
            .expect("terminal resolved replay bytes remain available"),
        Some(blob)
    );
}

#[test]
fn legacy_compaction_refuses_unsupported_replay_profile() {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let fixture = fixture();
    let (operation, outcome) = completed_return(&fixture, "legacy-held-profile", true)
        .expect("actual completed stream invocation");
    let raw = fixture
        .outcomes
        .load_raw_invocation_by_operation(operation.binding().operation_id())
        .expect("load completed raw")
        .expect("raw envelope");
    assert!(!raw.supports_compacted_value_replay());
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let cutoff = now_ms();
    let recorded: i64 = fixture
        .outcomes
        .connection()
        .expect("connection")
        .query_row(
            "SELECT recorded_at_unix_ms FROM tool_outcome_blobs WHERE digest = ?1",
            [outcome.raw_output_digest().as_str()],
            |row| row.get(0),
        )
        .expect("raw age");
    assert!(u64::try_from(recorded).expect("nonnegative raw time") < cutoff);
    assert!(blob_state(&fixture, outcome.raw_output_digest().as_str()).1);
    let summary = fixture
        .outcomes
        .compact_retained_invocation_blobs(cutoff, &fixture.fence, cutoff)
        .expect("legacy bounded pass");
    assert_eq!(
        summary.compacted, 0,
        "legacy erasure must use the same supported replay gate"
    );
    assert!(blob_state(&fixture, outcome.raw_output_digest().as_str()).1);
}

#[test]
fn legacy_compaction_obeys_a_bounded_page_instead_of_global_erasure() {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let fixture = fixture();
    let mut digests = Vec::new();
    for index in 0..65 {
        let (_, outcome) = completed_return(&fixture, &format!("legacy-row-{index:02}"), false)
            .expect("actual completed value invocation");
        digests.push(outcome.raw_output_digest().as_str().to_owned());
    }
    assert_eq!(
        digests
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        65
    );
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let cutoff = now_ms();
    let eligible: i64 = fixture.outcomes.connection().expect("connection").query_row(
        "SELECT COUNT(*) FROM tool_outcome_blobs b
         WHERE b.canonical_bytes IS NOT NULL AND b.recorded_at_unix_ms < ?1
           AND EXISTS (SELECT 1 FROM tool_outcomes o WHERE o.raw_output_digest=b.digest)
           AND NOT EXISTS (SELECT 1 FROM tool_outcomes o JOIN admission_operations a ON a.operation_id=o.operation_id
               WHERE o.raw_output_digest=b.digest AND (a.terminal=0 OR a.state <> 'completed'))
           AND NOT EXISTS (SELECT 1 FROM tool_outcomes o WHERE json_extract(o.outcome_json,'$.disposition.resolved_output.digest')=b.digest)
           AND NOT EXISTS (SELECT 1 FROM post_return_evaluations e WHERE json_extract(e.evaluation_json,'$.state.resolution.resolved_output.digest')=b.digest)",
        [i64::try_from(cutoff).expect("SQLite cutoff")], |row| row.get(0),
    ).expect("independent aged completed-owner count");
    assert_eq!(eligible,65,"all65 distinct completed raw envelopes must really be past the cutoff before the erase attempt");
    let summary = fixture
        .outcomes
        .compact_retained_invocation_blobs(cutoff, &fixture.fence, cutoff)
        .expect("legacy pass");
    assert!(
        summary.compacted <= 64,
        "legacy compatibility may not erase all 65 rows in a one-page pass"
    );
    assert!(summary.inspected <= 64);
    assert!(
        summary.next_digest.is_some(),
        "a bounded first page must expose continuation for all65 eligible raw owners"
    );
    assert!(digests.iter().any(|digest| blob_state(&fixture, digest).1));
}

#[test]
fn compaction_clears_a_terminal_blob_and_reports_compacted_reads() {
    let _time = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let fixture = fixture();
    let begun_at = now_ms();
    let (operation, outcome) =
        completed_return(&fixture, "compaction-terminal", false).expect("signed completion");
    let operation_id = operation.binding().operation_id().clone();
    let digest = outcome.raw_output_digest().as_str().to_owned();

    let (size_before, present_before) = blob_state(&fixture, &digest);
    assert!(present_before, "blob payload is present before compaction");

    let summary = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 200)
        .expect("compact terminal blob");
    assert_eq!(summary.compacted, 1);
    assert_eq!(summary.retained_live, 0);

    let (size_after, present_after) = blob_state(&fixture, &digest);
    assert!(!present_after, "blob payload is cleared after compaction");
    assert_eq!(size_after, size_before, "blob size is retained");

    let error = fixture
        .outcomes
        .load_raw_invocation_by_operation(&operation_id)
        .expect_err("a compacted raw invocation must not load silently");
    assert!(
        matches!(&error, ToolOutcomeStoreError::Compacted { raw_output_digest, raw_output_size_bytes }
            if raw_output_digest.as_str() == digest && *raw_output_size_bytes == u64::try_from(size_before).expect("retained size")),
        "compacted read reports a defined error, got {error:?}"
    );

    assert_eq!(
        fixture
            .outcomes
            .lookup_by_operation(&operation_id)
            .expect("outcome record survives compaction"),
        Some(outcome)
    );

    // A second pass is idempotent: the payload is already cleared.
    let repeat = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 201)
        .expect("second compaction pass");
    assert_eq!(repeat.compacted, 0);
    assert_eq!(repeat.retained_live, 0);
}

#[test]
fn reinserting_verified_bytes_rehydrates_a_compacted_blob() {
    let _time = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let fixture = fixture();
    let begun_at = now_ms();
    let (finalizing, outcome) =
        completed_return(&fixture, "compaction-rehydrate", false).expect("signed completion");
    let blob = fixture
        .outcomes
        .load_raw_invocation_by_operation(finalizing.binding().operation_id())
        .expect("raw read")
        .expect("present raw")
        .canonical_blob()
        .expect("raw blob");
    let bytes = blob.bytes().to_vec();
    let operation_id = finalizing.binding().operation_id().clone();
    let digest = outcome.raw_output_digest().as_str().to_owned();

    fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 200)
        .expect("compact terminal blob");
    assert!(!blob_state(&fixture, &digest).1, "blob starts compacted");

    let rehydrated_at = begun_at + 300;
    let mut connection = fixture.outcomes.connection().expect("connection");
    let transaction = fixture
        .outcomes
        .begin_write(&mut connection, &fixture.fence, rehydrated_at)
        .expect("begin rehydration write");
    insert_blob_bytes_tx(&transaction, &digest, &bytes, &fixture.fence, rehydrated_at)
        .expect("rehydrate verified bytes");
    fixture
        .outcomes
        .commit_write(transaction)
        .expect("commit rehydration");
    drop(connection);

    assert!(blob_state(&fixture, &digest).1, "blob payload is restored");
    assert!(
        fixture
            .outcomes
            .load_raw_invocation_by_operation(&operation_id)
            .expect("load rehydrated invocation")
            .is_some(),
        "the newly supplied canonical bytes can be loaded"
    );
}

#[test]
fn compaction_is_refused_while_an_owning_operation_is_live() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "compaction-live", begun_at);
    let (operation, _outcome) = record_return(&fixture, &committed, begun_at + 20);
    let operation_id = operation.binding().operation_id().clone();
    let digest = fixture
        .outcomes
        .lookup_by_operation(&operation_id)
        .expect("lookup outcome")
        .expect("outcome present")
        .raw_output_digest()
        .as_str()
        .to_owned();

    let summary = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 200)
        .expect("compaction pass over a live operation");
    assert_eq!(summary.compacted, 0, "a live operation is never compacted");
    assert_eq!(summary.retained_live, 1);

    let (_size, present) = blob_state(&fixture, &digest);
    assert!(present, "the live operation keeps its raw payload");
    assert!(
        fixture
            .outcomes
            .load_raw_invocation_by_operation(&operation_id)
            .expect("load raw invocation")
            .is_some(),
        "the raw invocation still reads back while the operation is live"
    );
}

#[test]
fn compaction_respects_the_retention_cutoff() {
    let _time = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let fixture = fixture();
    let begun_at = now_ms();
    let (_, outcome) =
        completed_return(&fixture, "compaction-cutoff", false).expect("signed completion");
    let digest = outcome.raw_output_digest().as_str().to_owned();

    // The injected authority clock fixes the blob's real recording time.
    let early = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at - 1, &fixture.fence, begun_at + 200)
        .expect("compaction below the cutoff");
    assert_eq!(
        early.compacted, 0,
        "a payload newer than the cutoff is kept"
    );
    assert_eq!(early.retained_live, 0);
    assert!(
        blob_state(&fixture, &digest).1,
        "payload retained below cutoff"
    );

    let due = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 201)
        .expect("compaction at the cutoff");
    assert_eq!(due.compacted, 1, "a payload past the cutoff is compacted");
    assert!(
        !blob_state(&fixture, &digest).1,
        "payload cleared past cutoff"
    );
}

fn secure_temp_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("secure temp directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[path = "tool_outcome_store_tests/connection_recovery.rs"]
#[cfg(unix)]
mod connection_recovery;
