use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_view,
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicContentV1,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicEffectTerminalV1,
    EconomicRequestBindingV1, EconomicResourceHeadV1, EconomicResourceKeyV1,
    EconomicStateAnchorError, EconomicStateAnchorPins, EconomicStateAnchorViewV1,
    EconomicStateBatchV1, EconomicStateTransitionV1, EconomicTerminalResultV1,
    EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_kernel::admission_operation::{
    qualified_lease, AdmissionAttachment, AdmissionBeginResult, AdmissionDigest,
    AdmissionIdentifier, AdmissionIncident, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationCommand, AdmissionOperationKind,
    AdmissionOperationState, AdmissionOperationStore, AdmissionOperationStoreError,
    AdmissionOperationV1, AdmissionParticipantRequirements, AdmissionProjectionContext,
    AdmissionRecoveryLease, AdmissionRequestBindingV1, AdmissionTerminalProjection,
    AdmissionTerminalReplay, AuthenticatedRequestNamespace, ClaimedTransition,
    ProviderAttemptBindingV1, QualifiedAdmissionOperationStoreExt, QualifiedAdmissionTransitionExt,
    RecoveryClaimRequest, SideEffectClass, SignedAdmissionTerminalProjectionV1,
    UntrustedAdmissionRecoveryClaim,
};
use chio_kernel::budget_store::{
    BudgetAdmissionBinding, BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCaptureInvocationRequest, BudgetEventAuthority, BudgetInvocationCaptureDecision,
    BudgetReconcileHoldRequest,
};
use chio_kernel::payment::{
    PaymentJournalRecord, PaymentJournalState, PaymentJournalTransition, PaymentRailMode,
};
use chio_kernel::receipt_store::{
    AnchoredAdmissionProjectionStore, ReceiptStore, ReceiptStoreError,
};
use chio_kernel::{AdmissionPaymentSettlementBegin, BudgetStore, CanonicalRevocationSet};
use rusqlite::types::Value;
use rusqlite::{params, Connection};
use tempfile::TempDir;

use super::*;

#[path = "admission_operation_store_tests/anchored_terminal.rs"]
mod anchored_terminal;
#[path = "admission_operation_store_tests/authority_clock.rs"]
mod authority_clock;
#[path = "admission_operation_store_tests/budget_atomicity.rs"]
mod budget_atomicity;
#[path = "admission_operation_store_tests/clock_migration.rs"]
mod clock_migration;
#[path = "admission_operation_store_tests/credit_authorization.rs"]
mod credit_authorization;
#[path = "admission_operation_store_tests/credit_exposure.rs"]
mod credit_exposure;
#[path = "admission_operation_store_tests/dpop_replay.rs"]
mod dpop_replay;
#[path = "admission_operation_store_tests/execution_nonce.rs"]
mod execution_nonce;
#[path = "admission_operation_store_tests/factor_assignment.rs"]
mod factor_assignment;
#[path = "admission_operation_store_tests/governed_approval_replay.rs"]
mod governed_approval_replay;
#[path = "admission_operation_store_tests/integrity.rs"]
mod integrity;
#[path = "admission_operation_store_tests/legacy_clock.rs"]
pub(super) mod legacy_clock;
#[path = "admission_operation_store_tests/obligation.rs"]
mod obligation;
#[path = "admission_operation_store_tests/recovery.rs"]
mod recovery;
#[path = "admission_operation_store_tests/retained_request.rs"]
mod retained_request;
#[path = "admission_operation_store_tests/runtime_replay.rs"]
mod runtime_replay;
#[path = "admission_operation_store_tests/schema.rs"]
mod schema;
#[path = "admission_operation_store_tests/security_participant_migration.rs"]
pub(super) mod security_participant_migration;
#[path = "admission_operation_store_tests/security_participant_state.rs"]
pub(super) mod security_participant_state;
#[path = "admission_operation_store_tests/threshold_approval.rs"]
mod threshold_approval;
use crate::{
    admission_terminal_projection_effect_result, EconomicStateCacheError, EconomicStateStageStatus,
    SqliteAuthorityStore, SqliteServingOwnerError,
};

type AnchoredTestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
    authority: SqliteAuthorityStore,
    store: SqliteAdmissionOperationStore,
    fence: StoreMutationFence,
}

/// An authority opened by the current binary: both mandatory startup
/// baselines (handle index and import manifest) are published, and their
/// recovery events carry the startup observation time.
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_lock_root(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    Fixture {
        _temp: temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    }
}

/// A modeled supported pre-recovery predecessor, for explicit predecessor
/// construction only. The current binary opens the authority with the
/// prior-format startup guards armed, so neither the handle-index nor the
/// import-manifest baseline is published and the store holds no recovery
/// custody. The guards drop on return: the next plain `open_serving` is the
/// current startup and publishes both baselines under its own owner.
fn pre_recovery_fixture() -> Fixture {
    let _prior_format = prior_format_startup();
    fixture()
}

/// A later serving owner of the same modeled predecessor, opened before it is
/// shaped and upgraded. Like `pre_recovery_fixture`, it publishes neither
/// baseline.
fn pre_recovery_open_serving(
    database: &std::path::Path,
    lock_root: &std::path::Path,
) -> Result<SqliteAuthorityStore, SqliteServingOwnerError> {
    let _prior_format = prior_format_startup();
    SqliteAuthorityStore::open_serving(database, lock_root)
}

fn prior_format_startup() -> (
    crate::admission_operation_store::PriorFormatHandleStartupGuard,
    crate::admission_operation_store::PriorFormatImportStartupGuard,
) {
    (
        crate::admission_operation_store::PriorFormatHandleStartupGuard::arm(),
        crate::admission_operation_store::PriorFormatImportStartupGuard::arm(),
    )
}

/// The first whole second no earlier than the authority's trusted time: the
/// commit-chain high water and the last recovery event, which the current
/// startup stamps with its own observation. A second-granular fixed clock
/// started here is never behind the history it is meant to extend.
fn clock_origin_ms(fixture: &Fixture) -> AnchoredTestResult<u64> {
    let high_water: i64 = fixture.store.connection()?.query_row(
        "SELECT max(
            (SELECT trusted_time_high_water_unix_ms FROM admission_operation_commit_meta
             WHERE singleton = 1),
            coalesce((SELECT observed_at FROM admission_operation_recovery_events
                      ORDER BY sequence DESC LIMIT 1), 0))",
        [],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(high_water)?
        .div_ceil(1_000)
        .saturating_mul(1_000)
        .max(now_ms() / 1_000 * 1_000))
}

/// Every global commit, every column, in chain order.
fn global_commit_rows(connection: &Connection) -> AnchoredTestResult<Vec<Vec<Value>>> {
    let mut statement =
        connection.prepare("SELECT * FROM authority_global_commits ORDER BY commit_sequence")?;
    let columns = statement.column_count();
    let rows = statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// The upgrade contract of a modeled pre-recovery predecessor once the current
/// binary serves it: every predecessor global commit is retained row for row,
/// the whole chain authenticates, and the serving owner's startup appends
/// exactly the handle-index baseline and then the import-manifest baseline.
/// Each appended commit names the first version of its retained recovery
/// record and that record's only event, and nothing else enters recovery
/// custody.
fn assert_predecessor_history_then_startup_baselines(
    connection: &Connection,
    predecessor: &[Vec<Value>],
    fence: &StoreMutationFence,
) -> AnchoredTestResult {
    assert_eq!(
        global_commit_rows(connection)?.get(..predecessor.len()),
        Some(predecessor),
        "predecessor global history is retained exactly"
    );
    crate::serving_owner::verify_authenticated_recovery_history(connection)?;
    let authority = sha256_hex(fence.store_uuid.as_bytes());
    let baselines = [
        format!("knowledge-handle-baseline:{authority}"),
        format!("knowledge-import-baseline:{authority}"),
    ];
    let expected = baselines
        .iter()
        .map(|key| {
            let event: String = connection.query_row(
                "SELECT event_digest FROM admission_operation_recovery_events
                 WHERE record_key = ?1 AND record_version = 1",
                [key],
                |row| row.get(0),
            )?;
            Ok((
                "recovery_transition".to_owned(),
                "recovery".to_owned(),
                key.clone(),
                1,
                event,
                fence.store_uuid.clone(),
                Some(fence.lease_id.clone()),
                i64::try_from(fence.owner_epoch)?,
            ))
        })
        .collect::<AnchoredTestResult<Vec<_>>>()?;
    let mut statement = connection.prepare(
        "SELECT mutation_kind, projection_kind, projection_key, projection_sequence,
                projection_reference_digest, store_uuid, store_lease_id, store_owner_epoch
         FROM authority_global_commits WHERE commit_sequence > ?1 ORDER BY commit_sequence",
    )?;
    let appended = statement
        .query_map([i64::try_from(predecessor.len())?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert_eq!(
        appended, expected,
        "the current startup appends exactly its two baselines under the serving owner"
    );
    let mut statement = connection.prepare(
        "SELECT record_key, version FROM admission_operation_recovery_records
         ORDER BY record_key",
    )?;
    let records = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert_eq!(
        records,
        baselines
            .iter()
            .map(|key| (key.clone(), 1))
            .collect::<Vec<_>>(),
        "recovery custody holds only the two baselines"
    );
    let mut statement = connection
        .prepare("SELECT record_key FROM admission_operation_recovery_events ORDER BY sequence")?;
    let events = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert_eq!(events, baselines, "each baseline has exactly one event");
    Ok(())
}

/// Tightens a fixture directory to owner-only access. Both `tempfile::tempdir` and
/// `fs::create_dir` inherit the process umask, and `validate_secure_directory`
/// refuses anything group or world writable.
fn secure_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("secure directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn create_lock_root(lock_root: &std::path::Path) {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(lock_root).expect("create lock root");
}

fn identifier(field: &'static str, value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new(field, value).expect("valid identifier")
}

fn digest(field: &'static str, byte: char) -> AdmissionDigest {
    AdmissionDigest::try_new(field, byte.to_string().repeat(64)).expect("valid digest")
}

fn prepared_operation(
    fence: &StoreMutationFence,
    kind: AdmissionOperationKind,
    request_id: &str,
    capability_id: &str,
) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "local-test-authority",
    ))
    .expect("namespace");
    let participant_requirements = match kind {
        AdmissionOperationKind::ToolDispatch => AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        },
        AdmissionOperationKind::GovernedActiveResponse => AdmissionParticipantRequirements {
            approval: true,
            ..AdmissionParticipantRequirements::NONE
        },
        AdmissionOperationKind::GovernedEconomicMutation => AdmissionParticipantRequirements::NONE,
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind,
        namespace,
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", capability_id),
        authorization_capability_hash: digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", 'b'),
            participant_requirements,
        )
        .expect("request binding"),
        policy_hash: digest("policy_hash", 'c'),
        effect_class: SideEffectClass::SideEffecting,
    })
    .expect("binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

fn prepared_payment_operation(
    fence: &StoreMutationFence,
    request_id: &str,
    capability_id: &str,
) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "local-test-authority",
    ))
    .expect("namespace");
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        payment: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", capability_id),
        authorization_capability_hash: digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", 'b'),
            requirements,
        )
        .expect("request binding"),
        policy_hash: digest("policy_hash", 'c'),
        effect_class: SideEffectClass::Monetary,
    })
    .expect("binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

fn provider_attempt(
    operation: &AdmissionOperationV1,
    attempt_id: &str,
) -> ProviderAttemptBindingV1 {
    ProviderAttemptBindingV1 {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        attempt_id: attempt_id.to_owned(),
        transport_id: "transport-test".to_owned(),
        transport_key_epoch: 1,
    }
}

fn now_ms() -> u64 {
    if let Some(fixed) = chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
        return fixed.checked_mul(1_000).expect("fixed millisecond clock");
    }
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("millisecond clock")
}

fn claim(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    claimant: &str,
    now: u64,
) -> AdmissionRecoveryLease {
    fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &identifier("claimant_id", claimant),
            now,
            now + 10_000,
            &fixture.fence,
        )
        .expect("claim recovery")
}

fn command(
    operation: &AdmissionOperationV1,
    lease: AdmissionRecoveryLease,
    attachments: Vec<AdmissionAttachment>,
    next_state: AdmissionOperationState,
    terminal_replay: Option<AdmissionTerminalReplay>,
) -> AdmissionOperationCommand {
    AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(next_state),
        terminal_replay,
        None,
    )
    .expect("command")
}

fn finalizing_tool_operation(
    fixture: &Fixture,
    request_id: &str,
    capability_id: &str,
    begun_at: u64,
) -> AdmissionOperationV1 {
    let mut operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        request_id,
        capability_id,
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin durable operation");
    let transitions = [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                &operation,
                "projection-attempt",
            ))],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "budget_hold_id",
                "projection-hold",
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, Vec::new()),
        (AdmissionOperationState::CapturePending, Vec::new()),
        (AdmissionOperationState::DispatchCommitted, Vec::new()),
        (
            AdmissionOperationState::Finalizing,
            vec![AdmissionAttachment::ToolOutcomeId(digest(
                "tool_outcome_id",
                'f',
            ))],
        ),
    ];
    for (index, (next_state, attachments)) in transitions.into_iter().enumerate() {
        let at = begun_at + 1 + u64::try_from(index).expect("transition index") * 2;
        let recovery = claim(fixture, &operation, "projection-worker", at);
        operation = fixture
            .store
            .compare_and_swap(
                &command(&operation, recovery, attachments, next_state, None),
                at + 1,
            )
            .expect("advance durable operation")
            .into_operation();
    }
    operation
}

#[test]
fn participant_replay_rejects_a_superseded_same_fence_recovery_lease() -> AnchoredTestResult {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::GovernedEconomicMutation,
        "superseded-participant-replay",
        "superseded-participant-capability",
    );
    let begun_at = now_ms();
    fixture.store.begin(&operation, &fixture.fence, begun_at)?;
    let first = claim(&fixture, &operation, "first-participant", begun_at + 1);
    let takeover_at = first.expires_at_unix_ms() + 1;
    let second = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant_id", "second-participant"),
        takeover_at,
        takeover_at + 5_000,
        &fixture.fence,
    )?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;

    assert!(matches!(
        verify_participant_recovery_tx(
            &transaction,
            &fixture.store.serving_owner,
            &operation,
            &first,
            takeover_at + 1,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    verify_participant_recovery_tx(
        &transaction,
        &fixture.store.serving_owner,
        &operation,
        &second,
        takeover_at + 1,
    )?;
    transaction.rollback()?;
    Ok(())
}

fn unknown_projection(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    incident_id: &str,
    incident_digest: char,
    at: u64,
) -> AdmissionTerminalProjection {
    let recovery = claim(fixture, operation, "projection-worker", at);
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: at + 1,
        coordinator_lease_id: recovery.coordinator_lease_id().clone(),
        coordinator_lease_epoch: recovery.coordinator_lease_epoch(),
        store_fence: recovery.store_fence().clone(),
    };
    let incident = AdmissionIncident::from_verified(
        operation,
        &context,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        identifier("incident_id", incident_id),
        digest("incident_digest", incident_digest),
    )
    .expect("bind durable incident");
    AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context,
        incident: Box::new(incident),
    }
}

fn unknown_projection_for_claimant(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    incident_id: &str,
    incident_digest: char,
    at: u64,
    claimant: &str,
) -> AdmissionTerminalProjection {
    let recovery = claim(fixture, operation, claimant, at);
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: at + 1,
        coordinator_lease_id: recovery.coordinator_lease_id().clone(),
        coordinator_lease_epoch: recovery.coordinator_lease_epoch(),
        store_fence: recovery.store_fence().clone(),
    };
    let incident = AdmissionIncident::from_verified(
        operation,
        &context,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        identifier("incident_id", incident_id),
        digest("incident_digest", incident_digest),
    )
    .expect("bind durable incident");
    AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context,
        incident: Box::new(incident),
    }
}

fn economic_digest(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn admission_commit_rows(connection: &Connection) -> rusqlite::Result<Vec<[Value; 13]>> {
    let mut statement = connection.prepare(
        r#"
        SELECT commit_sequence, operation_id, operation_version, mutation_kind,
               operation_digest, recovery_claim_digest, participant_digest,
               previous_chain_digest, chain_digest,
               store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
        FROM admission_operation_commits
        ORDER BY commit_sequence
        "#,
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok([
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
            ])
        })?
        .collect();
    rows
}

#[test]
fn begin_replays_exactly_conflicts_before_mutation_and_retains_rows() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-replay",
        "capability-a",
    );
    let begun_at = now_ms();
    assert!(matches!(
        fixture.store.begin(&operation, &fixture.fence, begun_at),
        Ok(AdmissionBeginResult::Created(_))
    ));
    assert!(matches!(
        fixture.store.begin(&operation, &fixture.fence, begun_at),
        Ok(AdmissionBeginResult::ExactReplay {
            terminal_replay: None,
            ..
        })
    ));

    let conflicting = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-replay",
        "capability-b",
    );
    assert!(matches!(
        fixture.store.begin(&conflicting, &fixture.fence, begun_at),
        Ok(AdmissionBeginResult::Conflict { .. })
    ));

    assert_eq!(
        fixture
            .store
            .load_terminal_replay(&operation.replay_key())
            .expect("terminal replay"),
        None
    );

    let connection = fixture.store.connection().expect("connection");
    assert!(connection
        .execute(
            "DELETE FROM admission_operations WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
        )
        .is_err());
}

#[test]
fn fresh_operation_epoch_must_match_the_active_serving_owner() {
    let fixture = fixture();
    let mut different_owner = fixture.fence.clone();
    different_owner.owner_epoch += 1;
    let operation = prepared_operation(
        &different_owner,
        AdmissionOperationKind::ToolDispatch,
        "request-wrong-coordinator-epoch",
        "capability-wrong-coordinator-epoch",
    );

    assert!(matches!(
        fixture.store.begin(&operation, &fixture.fence, now_ms()),
        Err(AdmissionOperationStoreError::Fenced)
    ));
}

#[test]
fn legal_transitions_round_trip_through_versioned_cas() {
    struct Case {
        kind: AdmissionOperationKind,
        state: AdmissionOperationState,
        attachments: Vec<AdmissionAttachment>,
    }

    let fixture = fixture();
    let cases = [
        Case {
            kind: AdmissionOperationKind::ToolDispatch,
            state: AdmissionOperationState::BrokerAttemptRegistered,
            attachments: Vec::new(),
        },
        Case {
            kind: AdmissionOperationKind::GovernedActiveResponse,
            state: AdmissionOperationState::ApprovalReserved,
            attachments: vec![
                AdmissionAttachment::ThresholdProposalHash(digest("threshold_proposal_hash", 'e')),
                AdmissionAttachment::ApprovalSetHash(digest("approval_set_hash", 'd')),
            ],
        },
        Case {
            kind: AdmissionOperationKind::GovernedEconomicMutation,
            state: AdmissionOperationState::MutationReady,
            attachments: Vec::new(),
        },
    ];
    let base_time = now_ms();
    let operations = cases
        .into_iter()
        .enumerate()
        .map(|(index, case)| {
            let operation = prepared_operation(
                &fixture.fence,
                case.kind,
                &format!("request-transition-{index}"),
                &format!("capability-transition-{index}"),
            );
            fixture
                .store
                .begin(&operation, &fixture.fence, base_time)
                .expect("begin");
            (index, case, operation)
        })
        .collect::<Vec<_>>();
    for (index, case, operation) in operations {
        let now = base_time + 1 + u64::try_from(index).expect("index") * 10;
        let lease = claim(&fixture, &operation, &format!("worker-{index}"), now);
        let attachments = if case.state == AdmissionOperationState::BrokerAttemptRegistered {
            vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                &operation,
                "attempt-table",
            ))]
        } else {
            case.attachments
        };
        let updated = fixture
            .store
            .compare_and_swap(
                &command(&operation, lease, attachments, case.state, None),
                now + 1,
            )
            .expect("CAS")
            .into_operation();
        let loaded = fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load")
            .expect("operation");
        assert_eq!(updated, loaded);
        assert_eq!(loaded.state(), case.state);
        assert_eq!(loaded.version(), 2);
    }
}

#[test]
fn terminal_projection_is_atomic_replayable_and_retained() {
    let fixture = fixture();
    let begun_at = now_ms();
    let first = finalizing_tool_operation(
        &fixture,
        "request-projection-first",
        "capability-projection-first",
        begun_at,
    );
    let first_projection = unknown_projection(
        &fixture,
        &first,
        "projection-shared-incident",
        'c',
        begun_at + 20,
    );
    let committed = fixture
        .store
        .commit_terminal_projection(&first_projection)
        .expect("commit terminal projection");
    assert_eq!(
        committed.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(
        fixture
            .store
            .commit_terminal_projection(&first_projection)
            .expect("replay identical projection"),
        committed
    );
    assert_eq!(
        fixture
            .store
            .load_terminal_replay(&first.replay_key())
            .expect("load terminal replay"),
        Some(committed.replay.clone())
    );

    let second = finalizing_tool_operation(
        &fixture,
        "request-projection-second",
        "capability-projection-second",
        begun_at + 30,
    );
    let conflicting = unknown_projection(
        &fixture,
        &second,
        "projection-shared-incident",
        'd',
        begun_at + 50,
    );
    assert!(fixture
        .store
        .commit_terminal_projection(&conflicting)
        .is_err());
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(second.binding().operation_id())
            .expect("load operation after rollback"),
        Some(second.clone())
    );

    let retry = AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context: conflicting.context().clone(),
        incident: Box::new(
            AdmissionIncident::from_verified(
                &second,
                conflicting.context(),
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                identifier("incident_id", "projection-second-incident"),
                digest("incident_digest", 'd'),
            )
            .expect("bind retry incident"),
        ),
    };
    fixture
        .store
        .commit_terminal_projection(&retry)
        .expect("retry clean terminal projection");

    let replay_key = first.replay_key();
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
    let reopened =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("reopen authority");
    assert!(reopened
        .admission_operation_store()
        .load_terminal_replay(&replay_key)
        .expect("load retained replay")
        .is_some());
    drop(reopened);
    drop(_temp);
}

#[test]
fn signed_terminal_projection_is_bound_to_the_durable_kernel_claimant() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-signed-projection",
        "capability-signed-projection",
        begun_at,
    );
    let signer = Keypair::generate();
    let claimant = format!("kernel:{}", signer.public_key().to_hex());
    let projection = unknown_projection_for_claimant(
        &fixture,
        &operation,
        "signed-projection-incident",
        'e',
        begun_at + 20_000,
        &claimant,
    );
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &fixture.store.admission_projection_capabilities(),
        &signer,
    )
    .expect("projection envelope");
    let signed_bytes = envelope
        .verify()
        .expect("verified envelope")
        .projection_json()
        .to_vec();
    let interleaved = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-interleaved-projection",
        "capability-interleaved-projection",
    );
    fixture
        .store
        .begin(&interleaved, &fixture.fence, begun_at + 21_000)
        .expect("later independent decision arrives before this signed projection");
    let committed = fixture
        .store
        .commit_signed_terminal_projection(&envelope)
        .expect("commit signed terminal projection");
    assert_eq!(
        committed.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(
        fixture
            .store
            .commit_signed_terminal_projection(&envelope)
            .expect("exact signed replay"),
        committed
    );
    let retained_bytes: Vec<u8> = fixture.store.connection().expect("connection")
        .query_row("SELECT projection_json FROM admission_operation_terminal_projections WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()], |row| row.get(0))
        .expect("retained signed projection");
    assert_eq!(
        retained_bytes, signed_bytes,
        "authority must not restamp signed evidence"
    );

    let second_begun_at = begun_at + 30_000;
    let second = finalizing_tool_operation(
        &fixture,
        "request-signer-substitution",
        "capability-signer-substitution",
        second_begun_at,
    );
    let authorized = Keypair::generate();
    let authorized_claimant = format!("kernel:{}", authorized.public_key().to_hex());
    let second_projection = unknown_projection_for_claimant(
        &fixture,
        &second,
        "signer-substitution-incident",
        'd',
        second_begun_at + 20_000,
        &authorized_claimant,
    );
    let substituted = SignedAdmissionTerminalProjectionV1::from_verified(
        &second,
        &second_projection,
        &fixture.store.admission_projection_capabilities(),
        &Keypair::generate(),
    )
    .expect("structurally valid substituted envelope");
    assert!(matches!(
        fixture
            .store
            .commit_signed_terminal_projection(&substituted),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(second.binding().operation_id())
            .expect("load after signer rejection"),
        Some(second)
    );
}

#[path = "admission_operation_store_tests/connection_recovery.rs"]
mod connection_recovery;
