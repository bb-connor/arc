use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::admission_operation::{
    AdmissionAttachment, AdmissionBeginResult, AdmissionDigest, AdmissionIdentifier,
    AdmissionIncident, AdmissionOperationBindingInputV1, AdmissionOperationBindingV1,
    AdmissionOperationCommand, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore, AdmissionOperationStoreError, AdmissionOperationV1,
    AdmissionParticipantRequirements, AdmissionProjectionContext, AdmissionRecoveryLease,
    AdmissionRequestBindingV1, AdmissionTerminalProjection, AdmissionTerminalReplay,
    AuthenticatedRequestNamespace, ProviderAttemptBindingV1, QualifiedAdmissionOperationStoreExt,
    SideEffectClass, UntrustedAdmissionRecoveryClaim,
};
use chio_kernel::receipt_store::{ReceiptStore, ReceiptStoreError};
use rusqlite::{params, Connection};
use tempfile::TempDir;

use super::*;
use crate::{SqliteAuthorityStore, SqliteServingOwnerError};

struct Fixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
    authority: SqliteAuthorityStore,
    store: SqliteAdmissionOperationStore,
    fence: StoreMutationFence,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
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

#[test]
fn fresh_provision_creates_the_operation_schema_after_serving_lease_schema() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    let (version, head, high_water, lease_table): (i64, i64, i64, bool) = connection
        .query_row(
            r#"
            SELECT
                (SELECT version FROM chio_store_schema_versions
                 WHERE store_key = 'admission_operation'),
                (SELECT head_sequence FROM admission_operation_commit_meta
                 WHERE singleton = 1),
                (SELECT trusted_time_high_water_unix_ms
                 FROM admission_operation_commit_meta WHERE singleton = 1),
                EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'chio_serving_leases'
                )
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("schema projection");
    assert_eq!(
        version,
        i64::from(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    assert_eq!(head, 0);
    assert_eq!(high_water, 0);
    assert!(lease_table);
    verify_admission_operation_invariants(&connection).expect("fresh invariants");
}

#[test]
fn provision_migrates_v1_operation_state_without_losing_replay_identity() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-v1-migration",
        "capability-v1-migration",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now_ms())
        .expect("persist v1 operation");

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

    let connection = Connection::open(&database).expect("open offline database");
    connection
        .execute_batch(
            r#"
            DROP TABLE admission_operation_observer_attempts;
            DROP TABLE admission_operation_authorization_consumptions;
            DROP TABLE admission_operation_terminal_records;
            DROP TABLE admission_operation_terminal_projections;
            UPDATE chio_store_schema_versions
            SET version = 1
            WHERE store_key = 'admission_operation';
            "#,
        )
        .expect("shape database as v1");
    drop(connection);

    SqliteAuthorityStore::provision(&database, &lock_root).expect("migrate v1 authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open migrated authority");
    let store = authority.admission_operation_store();
    assert_eq!(
        store
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load preserved operation"),
        Some(operation)
    );
    let connection = store.connection().expect("migrated connection");
    verify_admission_operation_invariants(&connection).expect("migrated invariants");
    drop(_temp);
}

#[test]
fn provision_migrates_v2_commit_chain_across_closed_serving_epochs() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-v2-chain-migration",
        "capability-v2-chain-migration",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now_ms())
        .expect("persist v2 operation");
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

    let replacement =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("rotate serving owner");
    drop(replacement);

    let connection = Connection::open(&database).expect("open offline database");
    let closed_epochs: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM admission_operation_commits AS commits
            JOIN chio_serving_leases AS leases
              ON leases.store_uuid = commits.store_uuid
             AND leases.owner_epoch = commits.store_owner_epoch
            WHERE leases.end_head_index IS NOT NULL
            "#,
            [],
            |row| row.get(0),
        )
        .expect("closed commit epochs");
    assert!(closed_epochs > 0);
    connection
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v3;

            CREATE TABLE admission_operation_commits (
                commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
                operation_id TEXT NOT NULL,
                operation_version INTEGER NOT NULL CHECK (operation_version > 0),
                mutation_kind TEXT NOT NULL CHECK (
                    mutation_kind IN ('begin', 'compare_and_swap', 'recovery_claim')
                ),
                operation_digest TEXT NOT NULL CHECK (
                    length(operation_digest) = 64
                    AND operation_digest NOT GLOB '*[^0-9a-f]*'
                ),
                recovery_claim_digest TEXT CHECK (
                    recovery_claim_digest IS NULL
                    OR (length(recovery_claim_digest) = 64
                        AND recovery_claim_digest NOT GLOB '*[^0-9a-f]*')
                ),
                previous_chain_digest TEXT NOT NULL CHECK (
                    length(previous_chain_digest) = 64
                    AND previous_chain_digest NOT GLOB '*[^0-9a-f]*'
                ),
                chain_digest TEXT NOT NULL CHECK (
                    length(chain_digest) = 64
                    AND chain_digest NOT GLOB '*[^0-9a-f]*'
                ),
                store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
                store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
                store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
                recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
                FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
                FOREIGN KEY (store_uuid, store_owner_epoch)
                    REFERENCES chio_serving_leases(store_uuid, owner_epoch),
                CHECK (
                    (mutation_kind = 'begin' AND recovery_claim_digest IS NULL)
                    OR (mutation_kind IN ('compare_and_swap', 'recovery_claim')
                        AND recovery_claim_digest IS NOT NULL)
                )
            );
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, previous_chain_digest,
                chain_digest, store_uuid, store_lease_id, store_owner_epoch,
                recorded_at_unix_ms
            )
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, previous_chain_digest,
                   chain_digest, store_uuid, store_lease_id, store_owner_epoch,
                   recorded_at_unix_ms
            FROM admission_operation_commits_v3;
            DROP TABLE admission_operation_commits_v3;
            CREATE INDEX admission_operation_commits_operation
                ON admission_operation_commits(operation_id, commit_sequence);
            CREATE TRIGGER admission_operation_commits_exact_lease
            BEFORE INSERT ON admission_operation_commits
            WHEN NOT EXISTS (
                SELECT 1 FROM chio_serving_leases
                WHERE store_uuid = NEW.store_uuid
                  AND owner_epoch = NEW.store_owner_epoch
                  AND lease_id = NEW.store_lease_id
                  AND end_head_index IS NULL
            )
            BEGIN
                SELECT RAISE(ABORT, 'admission operation commit has no exact serving lease');
            END;
            CREATE TRIGGER admission_operation_commits_immutable
            BEFORE UPDATE ON admission_operation_commits
            BEGIN
                SELECT RAISE(ABORT, 'admission operation commit is immutable');
            END;
            CREATE TRIGGER admission_operation_commits_no_delete
            BEFORE DELETE ON admission_operation_commits
            BEGIN
                SELECT RAISE(ABORT, 'admission operation commit is immutable');
            END;
            UPDATE chio_store_schema_versions
            SET version = 2
            WHERE store_key = 'admission_operation';
            "#,
        )
        .expect("shape database as v2");
    drop(connection);

    SqliteAuthorityStore::provision(&database, &lock_root).expect("migrate v2 authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open migrated authority");
    let store = authority.admission_operation_store();
    assert_eq!(
        store
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load preserved operation"),
        Some(operation)
    );
    let connection = store.connection().expect("migrated connection");
    let (version, null_participants): (i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT version FROM chio_store_schema_versions
                 WHERE store_key = 'admission_operation'),
                (SELECT COUNT(*) FROM admission_operation_commits
                 WHERE participant_digest IS NULL)
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("migrated commit schema");
    assert_eq!(
        version,
        i64::from(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    assert!(null_participants > 0);
    verify_admission_operation_invariants(&connection).expect("migrated invariants");
    drop(_temp);
}

#[test]
fn canonical_schema_rejects_a_same_name_no_op_trigger() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER admission_operations_no_delete;
            CREATE TRIGGER admission_operations_no_delete
            BEFORE DELETE ON admission_operations
            BEGIN
                SELECT 1;
            END;
            "#,
        )
        .expect("replace trigger");

    assert!(matches!(
        verify_admission_operation_invariants(&connection),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn canonical_schema_rejects_an_unexpected_trigger_with_an_unrelated_name() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    connection
        .execute_batch(
            r#"
            CREATE TRIGGER unexpected_delete_hook
            BEFORE DELETE ON admission_operations
            BEGIN
                SELECT 1;
            END;
            "#,
        )
        .expect("add trigger");

    assert!(matches!(
        verify_admission_operation_invariants(&connection),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn canonical_schema_rejects_a_weakened_table_definition() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    connection
        .execute_batch("PRAGMA writable_schema = ON")
        .expect("enable schema repair mode");
    let changed = connection
        .execute(
            r#"
            UPDATE sqlite_schema
            SET sql = 'CREATE TABLE admission_operations (operation_id TEXT PRIMARY KEY)'
            WHERE type = 'table' AND name = 'admission_operations'
            "#,
            [],
        )
        .expect("weaken table definition");
    connection
        .execute_batch("PRAGMA writable_schema = OFF")
        .expect("disable schema repair mode");
    assert_eq!(changed, 1);

    assert!(matches!(
        verify_admission_operation_invariants(&connection),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn persisted_operations_use_rfc_8785_bytes() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-canonical-雪",
        "capability-canonical",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now_ms())
        .expect("begin operation");

    let stored = fixture
        .store
        .connection()
        .expect("connection")
        .query_row(
            "SELECT operation_json FROM admission_operations WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .expect("stored operation bytes");
    let expected = canonical_json_bytes(&operation.to_persisted()).expect("canonical operation");
    let serde_order = serde_json::to_vec(&operation.to_persisted()).expect("serde operation");

    assert_eq!(stored, expected);
    assert_ne!(stored, serde_order);
    assert!(std::str::from_utf8(&stored)
        .expect("UTF-8 operation")
        .contains('雪'));
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
fn receipt_lookup_rejects_records_outside_the_terminal_manifest() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-forged-receipt",
        "capability-forged-receipt",
        begun_at,
    );
    fixture
        .store
        .commit_terminal_projection(&unknown_projection(
            &fixture,
            &operation,
            "projection-forged-receipt-incident",
            'e',
            begun_at + 20,
        ))
        .expect("commit terminal projection");

    let connection = fixture.store.connection().expect("connection");
    connection
        .execute(
            r#"
            INSERT INTO admission_operation_terminal_records (
                operation_id, record_kind, record_id, record_digest, record_json
            ) VALUES (?1, 'receipt', 'forged-receipt', ?2, X'7B7D')
            "#,
            params![operation.binding().operation_id().as_str(), "a".repeat(64),],
        )
        .expect("inject out-of-manifest record");
    drop(connection);

    assert!(matches!(
        fixture.store.load_chio_receipt("forged-receipt"),
        Err(ReceiptStoreError::Conflict(detail))
            if detail.contains("record count differs from its manifest")
    ));
}

#[test]
fn recovery_claims_are_bounded_fenced_and_time_monotonic() {
    let fixture = fixture();
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-recovery-a",
        "capability-recovery-a",
    );
    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-recovery-b",
        "capability-recovery-b",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&first, &fixture.fence, begun_at)
        .expect("begin");
    fixture
        .store
        .begin(&second, &fixture.fence, begun_at)
        .expect("begin");
    let now = begun_at + 1;
    fixture
        .store
        .claim_recovery(
            first.binding().operation_id(),
            1,
            &identifier("claimant_id", "worker-active"),
            now,
            now + 1_000,
            &fixture.fence,
        )
        .expect("claim");
    let recoverable = fixture
        .store
        .list_recoverable(now, 10)
        .expect("recoverable");
    assert_eq!(recoverable, vec![second.clone()]);
    assert_eq!(
        fixture
            .store
            .list_recoverable(now + 1_000, 10)
            .expect("expired claim scan")
            .len(),
        2
    );
    assert!(matches!(
        fixture.store.list_recoverable(now, 257),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));

    let mut forged = fixture.fence.clone();
    forged.owner_epoch += 1;
    assert!(matches!(
        fixture.store.claim_recovery(
            second.binding().operation_id(),
            1,
            &identifier("claimant_id", "worker-forged"),
            now,
            now + 1_000,
            &forged,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert!(matches!(
        fixture.store.claim_recovery(
            second.binding().operation_id(),
            1,
            &identifier("claimant_id", "worker-old-time"),
            1,
            now + 1_000,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn recovery_claim_retry_returns_the_persisted_lease_when_expiry_changes() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-recovery-retry",
        "capability-recovery-retry",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    let claimant = identifier("claimant_id", "worker-retry");
    let first = fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &claimant,
            begun_at + 1,
            begun_at + 10_000,
            &fixture.fence,
        )
        .expect("first claim");
    let retried = fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &claimant,
            begun_at + 2,
            begun_at + 20_000,
            &fixture.fence,
        )
        .expect("retry claim");

    assert_eq!(retried, first);
    let claim_commits: i64 = fixture
        .store
        .connection()
        .expect("connection")
        .query_row(
            "SELECT COUNT(*) FROM admission_operation_commits WHERE mutation_kind = 'recovery_claim'",
            [],
            |row| row.get(0),
        )
        .expect("claim commits");
    assert_eq!(claim_commits, 1);
}

#[test]
fn qualified_recovery_rechecks_history_version_fence_and_expiry() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-qualified-recovery",
        "capability-qualified-recovery",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    let now = begun_at + 1;
    let expires_at = now + 100;
    let lease = fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &identifier("claimant_id", "qualified-worker"),
            now,
            expires_at,
            &fixture.fence,
        )
        .expect("qualified claim");
    fixture
        .store
        .revalidate_recovery_claim(&operation, lease.untrusted_claim(), now + 1, &fixture.fence)
        .expect("exact durable claim must revalidate");

    let forged =
        |coordinator_lease_id: &str, claimed_version: u64, store_fence: StoreMutationFence| {
            UntrustedAdmissionRecoveryClaim::new(
                operation.binding().operation_id().clone(),
                identifier("claimant_id", "qualified-worker"),
                identifier("coordinator_lease_id", coordinator_lease_id),
                operation.coordinator_lease_epoch(),
                claimed_version,
                expires_at,
                store_fence,
            )
            .expect("forged raw claim remains structurally valid")
        };
    let wrong_history = forged(
        "different-coordinator-lease",
        operation.version(),
        fixture.fence.clone(),
    );
    assert!(matches!(
        fixture.store.revalidate_recovery_claim(
            &operation,
            &wrong_history,
            now + 1,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let wrong_version = forged(
        lease.coordinator_lease_id().as_str(),
        operation.version() + 1,
        fixture.fence.clone(),
    );
    assert!(matches!(
        fixture.store.revalidate_recovery_claim(
            &operation,
            &wrong_version,
            now + 1,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let mut stale_fence = fixture.fence.clone();
    stale_fence.lease_id = "stale-serving-lease".to_string();
    let wrong_fence = forged(
        lease.coordinator_lease_id().as_str(),
        operation.version(),
        stale_fence,
    );
    assert!(matches!(
        fixture
            .store
            .revalidate_recovery_claim(&operation, &wrong_fence, now + 1, &fixture.fence,),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert_eq!(
        fixture.store.revalidate_recovery_claim(
            &operation,
            lease.untrusted_claim(),
            expires_at,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Operation(
            AdmissionOperationError::LeaseExpired
        ))
    );
}

#[test]
fn recovery_claim_rolls_forward_only_for_the_same_claimant() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-recovery-roll-forward",
        "capability-recovery-roll-forward",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    let claimant = identifier("claimant_id", "worker-owner");
    let first = fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &claimant,
            begun_at + 1,
            begun_at + 10_000,
            &fixture.fence,
        )
        .expect("first claim");
    let updated = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                first,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "attempt-recovery-roll-forward",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            begun_at + 2,
        )
        .expect("advance operation")
        .into_operation();

    assert!(matches!(
        fixture.store.claim_recovery(
            updated.binding().operation_id(),
            2,
            &identifier("claimant_id", "worker-other"),
            begun_at + 3,
            begun_at + 20_000,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let rolled_forward = fixture
        .store
        .claim_recovery(
            updated.binding().operation_id(),
            2,
            &claimant,
            begun_at + 3,
            begun_at + 20_000,
            &fixture.fence,
        )
        .expect("roll claim forward");
    assert_eq!(rolled_forward.claimed_version(), 2);
    assert_eq!(rolled_forward.expires_at_unix_ms(), begun_at + 20_000);
}

#[test]
fn trusted_time_high_water_rejects_regression_across_operations() {
    let fixture = fixture();
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-time-a",
        "capability-time-a",
    );
    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-time-b",
        "capability-time-b",
    );
    let third = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-time-c",
        "capability-time-c",
    );
    let begun_at = now_ms();
    assert!(matches!(
        fixture.store.begin(&first, &fixture.fence, 0),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        fixture
            .store
            .begin(&first, &fixture.fence, MAX_TRUSTED_UNIX_MS + 1),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        fixture
            .store
            .begin(&first, &fixture.fence, MAX_TRUSTED_UNIX_MS),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    fixture
        .store
        .begin(&first, &fixture.fence, begun_at)
        .expect("first begin");
    assert!(matches!(
        fixture.store.claim_recovery(
            first.binding().operation_id(),
            1,
            &identifier("claimant_id", "long-lease-worker"),
            begun_at + 1,
            begun_at + 1 + MAX_RECOVERY_LEASE_DURATION_MS + 1,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        fixture.store.claim_recovery(
            first.binding().operation_id(),
            1,
            &identifier("claimant_id", "zero-time-worker"),
            0,
            begun_at + 10_000,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    fixture
        .store
        .claim_recovery(
            first.binding().operation_id(),
            1,
            &identifier("claimant_id", "time-worker-a"),
            begun_at + 2,
            begun_at + 10_000,
            &fixture.fence,
        )
        .expect("advance time high-water");
    assert!(matches!(
        fixture.store.begin(&second, &fixture.fence, begun_at + 1),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(fixture
        .store
        .load_by_operation_id(second.binding().operation_id())
        .expect("load")
        .is_none());
    fixture
        .store
        .begin(&second, &fixture.fence, begun_at + 2)
        .expect("non-regressing begin");
    let lease = fixture
        .store
        .claim_recovery(
            second.binding().operation_id(),
            1,
            &identifier("claimant_id", "time-worker-b"),
            begun_at + 3,
            begun_at + 10_000,
            &fixture.fence,
        )
        .expect("second claim");
    assert!(matches!(
        fixture.store.compare_and_swap(
            &command(
                &second,
                lease.clone(),
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &second,
                    "attempt-time",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            0,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    fixture
        .store
        .compare_and_swap(
            &command(
                &second,
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &second,
                    "attempt-time",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            begun_at + 4,
        )
        .expect("advance high-water by CAS");
    assert!(matches!(
        fixture.store.begin(&third, &fixture.fence, begun_at + 3),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn scoped_runtime_clock_qualifies_deterministic_admission_time() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-fixed-runtime-time",
        "capability-fixed-runtime-time",
    );
    let fixed_now_unix_ms = 1_700_000_001_000;
    let _scope = chio_kernel::scope_fixed_runtime_for_current_thread(
        fixed_now_unix_ms / 1_000,
        std::iter::empty(),
    );

    fixture
        .store
        .begin(&operation, &fixture.fence, fixed_now_unix_ms)
        .expect("fixed runtime clock");
}

#[test]
fn post_open_tampering_is_rejected_by_every_read_path_and_rows_cannot_be_deleted() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-read-integrity",
        "capability-read-integrity",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    {
        let connection = fixture.store.connection().expect("connection");
        assert!(connection
            .execute(
                "DELETE FROM admission_operations WHERE operation_id = ?1",
                [operation.binding().operation_id().as_str()],
            )
            .is_err());
        connection
            .execute(
                r#"
                UPDATE admission_operations
                SET updated_at_unix_ms = updated_at_unix_ms + 1
                WHERE operation_id = ?1
                "#,
                [operation.binding().operation_id().as_str()],
            )
            .expect("tamper row after open");
    }
    for result in [
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .map(|_| ()),
        fixture
            .store
            .load_by_replay_key(&operation.replay_key())
            .map(|_| ()),
        fixture.store.list_recoverable(begun_at, 10).map(|_| ()),
        fixture
            .store
            .load_terminal_replay(&operation.replay_key())
            .map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(AdmissionOperationStoreError::Invariant(_))
        ));
    }
}

#[test]
fn stale_owner_fences_reads_and_mutations() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-fence",
        "capability-fence",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now_ms())
        .expect("begin");

    let connection = Connection::open(&fixture.database).expect("tamper connection");
    connection
        .execute(
            r#"
            UPDATE chio_serving_owner
            SET owner_epoch = ?1, lease_id = 'replacement-lease'
            WHERE singleton = 1
            "#,
            params![i64::try_from(fixture.fence.owner_epoch + 1).expect("epoch")],
        )
        .expect("advance owner");
    assert!(matches!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id()),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert!(matches!(
        fixture.store.begin(&operation, &fixture.fence, now_ms()),
        Err(AdmissionOperationStoreError::Fenced)
    ));
}

#[test]
fn a_new_serving_epoch_reclaims_an_unexpired_stale_owner_lease() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let first = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    let first_fence = first.mutation_fence();
    let first_store = first.admission_operation_store();
    let operation = prepared_operation(
        &first_fence,
        AdmissionOperationKind::ToolDispatch,
        "request-owner-rotation",
        "capability-owner-rotation",
    );
    let begun_at = now_ms();
    first_store
        .begin(&operation, &first_fence, begun_at)
        .expect("begin");
    let now = begun_at + 1;
    first_store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &identifier("claimant_id", "old-worker"),
            now,
            now + 100_000,
            &first_fence,
        )
        .expect("old claim");
    drop(first_store);
    drop(first);

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("second owner");
    let second_fence = second.mutation_fence();
    let second_store = second.admission_operation_store();
    assert_eq!(
        second_store
            .list_recoverable(now + 1, 10)
            .expect("recover stale owner"),
        vec![operation.clone()]
    );
    let lease = second_store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &identifier("claimant_id", "new-worker"),
            now + 1,
            now + 10_000,
            &second_fence,
        )
        .expect("new claim");
    assert_eq!(lease.store_fence(), &second_fence);
    assert_eq!(lease.coordinator_lease_id().as_str(), first_fence.lease_id);
    assert_eq!(lease.coordinator_lease_epoch(), first_fence.owner_epoch);

    let advance = |current: &AdmissionOperationV1,
                   state: AdmissionOperationState,
                   attachments: Vec<AdmissionAttachment>,
                   time: u64| {
        let lease = second_store
            .claim_recovery(
                current.binding().operation_id(),
                current.version(),
                &identifier("claimant_id", "new-worker"),
                time,
                time + 10_000,
                &second_fence,
            )
            .expect("claim next version");
        assert_eq!(lease.coordinator_lease_id().as_str(), first_fence.lease_id);
        assert_eq!(lease.coordinator_lease_epoch(), first_fence.owner_epoch);
        second_store
            .compare_and_swap(&command(current, lease, attachments, state, None), time + 1)
            .expect("advance recovered operation")
            .into_operation()
    };
    let broker_registered = advance(
        &operation,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
            &operation,
            "attempt-rotated-owner",
        ))],
        now + 2,
    );
    let budget_authorized = advance(
        &broker_registered,
        AdmissionOperationState::BudgetAuthorized,
        vec![AdmissionAttachment::BudgetHoldId(identifier(
            "budget_hold_id",
            "rotated-owner-hold",
        ))],
        now + 4,
    );
    let ready = advance(
        &budget_authorized,
        AdmissionOperationState::ReadyToDispatch,
        Vec::new(),
        now + 6,
    );
    let capture_pending = advance(
        &ready,
        AdmissionOperationState::CapturePending,
        Vec::new(),
        now + 8,
    );
    let dispatched = advance(
        &capture_pending,
        AdmissionOperationState::DispatchCommitted,
        Vec::new(),
        now + 10,
    );
    let finalizing = advance(
        &dispatched,
        AdmissionOperationState::Finalizing,
        vec![AdmissionAttachment::ToolOutcomeId(digest(
            "tool_outcome_id",
            'f',
        ))],
        now + 12,
    );
    let dispatch_commit = finalizing.dispatch_commit().expect("dispatch commit");
    assert_eq!(
        dispatch_commit.coordinator_lease_id.as_str(),
        first_fence.lease_id
    );
    assert_eq!(
        dispatch_commit.coordinator_lease_epoch,
        first_fence.owner_epoch
    );
    assert_eq!(&dispatch_commit.store_fence, &second_fence);
}

#[test]
fn transaction_failures_leave_no_partial_begin_or_cas_commit() {
    let fixture = fixture();
    let begun_at = now_ms();
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-rollback-begin",
        "capability-rollback-begin",
    );
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch(
                r#"
                CREATE TEMP TRIGGER fail_admission_begin
                BEFORE UPDATE ON admission_operation_commit_meta
                BEGIN
                    SELECT RAISE(ROLLBACK, 'injected begin rollback');
                END;
                "#,
            )
            .expect("install failure");
    }
    assert!(fixture
        .store
        .begin(&first, &fixture.fence, begun_at)
        .is_err());
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch("DROP TRIGGER fail_admission_begin")
            .expect("drop failure");
    }
    assert!(fixture
        .store
        .load_by_operation_id(first.binding().operation_id())
        .expect("load")
        .is_none());

    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-rollback-cas",
        "capability-rollback-cas",
    );
    fixture
        .store
        .begin(&second, &fixture.fence, begun_at)
        .expect("begin second");
    let now = begun_at + 1;
    let lease = claim(&fixture, &second, "worker-rollback", now);
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch(
                r#"
                CREATE TEMP TRIGGER fail_admission_cas
                BEFORE UPDATE ON admission_operation_commit_meta
                BEGIN
                    SELECT RAISE(ROLLBACK, 'injected CAS rollback');
                END;
                "#,
            )
            .expect("install failure");
    }
    assert!(fixture
        .store
        .compare_and_swap(
            &command(
                &second,
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &second,
                    "attempt-rollback",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now + 1,
        )
        .is_err());
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch("DROP TRIGGER fail_admission_cas")
            .expect("drop failure");
        verify_admission_operation_invariants(&connection).expect("valid projection");
    }
    let loaded = fixture
        .store
        .load_by_operation_id(second.binding().operation_id())
        .expect("load")
        .expect("operation");
    assert_eq!(loaded.state(), AdmissionOperationState::Prepared);
    assert_eq!(loaded.version(), 1);
}

#[test]
fn commit_log_binds_each_mutation_to_the_active_serving_lease() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-commit-log",
        "capability-commit-log",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    let now = begun_at + 1;
    let lease = claim(&fixture, &operation, "worker-log", now);
    assert!(matches!(
        fixture.store.compare_and_swap(
            &command(
                &operation,
                lease.clone(),
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "attempt-log",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now - 1,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "attempt-log",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now + 1,
        )
        .expect("CAS");

    let connection = fixture.store.connection().expect("connection");
    let mut statement = connection
        .prepare(
            r#"
            SELECT mutation_kind, operation_version, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM admission_operation_commits
            WHERE operation_id = ?1
            ORDER BY commit_sequence
            "#,
        )
        .expect("prepare");
    let commits = statement
        .query_map([operation.binding().operation_id().as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("commits");
    assert_eq!(
        commits
            .iter()
            .map(|commit| (commit.0.as_str(), commit.1))
            .collect::<Vec<_>>(),
        vec![("begin", 1), ("recovery_claim", 1), ("compare_and_swap", 2)]
    );
    assert!(commits.iter().all(|commit| {
        commit.2 == fixture.fence.store_uuid
            && commit.3 == fixture.fence.lease_id
            && u64::try_from(commit.4).ok() == Some(fixture.fence.owner_epoch)
    }));
}

#[test]
fn corrupt_rows_and_partial_current_schema_fail_closed() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-corrupt",
        "capability-corrupt",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute(
                "UPDATE admission_operations SET operation_json = X'7b', version = version + 1 WHERE operation_id = ?1",
                [operation.binding().operation_id().as_str()],
            )
            .expect("inject corrupt row");
    }
    assert!(matches!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id()),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(verify_admission_operation_invariants(
        &fixture.store.connection().expect("connection")
    )
    .is_err());

    let clean = self::fixture();
    {
        let connection = clean.store.connection().expect("connection");
        connection
            .execute_batch("DROP INDEX admission_operation_commits_operation")
            .expect("drop index");
    }
    assert!(
        verify_admission_operation_invariants(&clean.store.connection().expect("connection"))
            .is_err()
    );
    let database = clean.database.clone();
    let lock_root = clean.lock_root.clone();
    drop(clean.store);
    drop(clean.authority);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(database, lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}
