//! The stop chain survives restart, refuses stale resumes, and fails closed
//! on tampering.
use chio_kernel::stop::{
    DecisionTime, DurableStopError, DurableStopStore, StopAuthorizer, StopEpochId, StopRequestPath,
    StopScope, StopState, StopTransition, StopTransitionRequest,
};

use super::*;

fn request(
    transition: StopTransition,
    expected_epoch: Option<StopEpochId>,
) -> StopTransitionRequest {
    StopTransitionRequest {
        scope: StopScope::Kernel,
        transition,
        expected_epoch,
        reason: "incident 42".to_owned(),
        authorizer: StopAuthorizer::shared_credential("test-route"),
        requested_via: StopRequestPath::Route {
            host_id: "edge-1".to_owned(),
        },
        allow_containment: true,
    }
}

fn reopen(fixture: Fixture) -> (TempDir, SqliteAdmissionOperationStore) {
    let Closed {
        _temp,
        database,
        lock_root,
        fence: _fence,
        _clock,
    } = fixture.close();
    let authority = crate::test_authority::open_serving(&database, &lock_root).expect("reopen");
    (_temp, authority.admission_operation_store())
}

const EPOCH_ONE: StopEpochId = StopEpochId {
    chain_generation: 1,
    epoch: 1,
};

#[test]
fn a_stop_persists_across_restart_and_a_resume_clears_it() {
    let fixture = fixture();
    assert_eq!(
        fixture.store.load_stop_head(StopScope::Kernel).unwrap(),
        None
    );
    let stopped = fixture
        .store
        .append_stop_transition(&request(StopTransition::Stop, None), &fixture.fence)
        .unwrap()
        .unwrap();
    assert_eq!(stopped.id(), EPOCH_ONE);
    assert_eq!(stopped.state, StopState::Stopped);
    assert_eq!(stopped.authority_id, fixture.fence.store_uuid);
    assert!(matches!(stopped.decided_at, DecisionTime::Observed(_)));

    let (_temp, store) = reopen(fixture);
    let head = store.load_stop_head(StopScope::Kernel).unwrap().unwrap();
    assert_eq!(head, stopped);

    let fence = store.serving_owner.fence.clone();
    let resumed = store
        .append_stop_transition(&request(StopTransition::Resume, Some(EPOCH_ONE)), &fence)
        .unwrap()
        .unwrap();
    assert_eq!(resumed.state, StopState::Running);
    assert_eq!(resumed.expected_epoch, EPOCH_ONE);
    assert_eq!(resumed.previous, stopped.digest().unwrap());
    assert_eq!(
        store.load_stop_head(StopScope::Kernel).unwrap(),
        Some(resumed)
    );
}

#[test]
fn a_repeated_stop_appends_nothing_and_a_stale_resume_is_refused() {
    let fixture = fixture();
    let first = fixture
        .store
        .append_stop_transition(&request(StopTransition::Stop, None), &fixture.fence)
        .unwrap();
    let again = fixture
        .store
        .append_stop_transition(&request(StopTransition::Stop, None), &fixture.fence)
        .unwrap();
    assert_eq!(first, again);
    for stale in [None, Some(StopEpochId::GENESIS)] {
        assert!(matches!(
            fixture
                .store
                .append_stop_transition(&request(StopTransition::Resume, stale), &fixture.fence),
            Err(DurableStopError::HeadMoved {
                head: Some(EPOCH_ONE)
            })
        ));
    }
    let rows: i64 = Connection::open(&fixture.database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM admission_operation_stop_epochs",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn a_resume_over_a_running_head_is_a_no_op() {
    let fixture = fixture();
    assert_eq!(
        fixture
            .store
            .append_stop_transition(&request(StopTransition::Resume, None), &fixture.fence)
            .unwrap(),
        None
    );
}

#[test]
fn a_stale_fence_cannot_append() {
    let fixture = fixture();
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert!(fixture
        .store
        .append_stop_transition(&request(StopTransition::Stop, None), &stale)
        .is_err());
    assert_eq!(
        fixture.store.load_stop_head(StopScope::Kernel).unwrap(),
        None
    );
}

#[test]
fn stop_records_are_append_only_and_covered_by_the_global_chain() {
    let fixture = fixture();
    let record = fixture
        .store
        .append_stop_transition(&request(StopTransition::Stop, None), &fixture.fence)
        .unwrap()
        .unwrap();
    let connection = Connection::open(&fixture.database).unwrap();
    assert!(connection
        .execute("UPDATE admission_operation_stop_epochs SET epoch = 2", [])
        .is_err());
    assert!(connection
        .execute("DELETE FROM admission_operation_stop_epochs", [])
        .is_err());
    let (kind, key, sequence, reference): (String, String, i64, String) = connection
        .query_row(
            "SELECT projection_kind, projection_key, projection_sequence, projection_reference_digest
             FROM authority_global_commits ORDER BY commit_sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (kind.as_str(), key.as_str(), sequence),
        ("stop_epoch", "kernel:1", 1)
    );
    assert_eq!(reference, record.digest().unwrap());
    let (salt, text): (String, String) = connection
        .query_row(
            "SELECT salt, redacted_text FROM admission_operation_stop_notes",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(text, "incident 42");
    assert_eq!(
        record.reason_commitment,
        chio_kernel::stop::stop_reason_commitment(&hex::decode(salt).unwrap(), "incident 42")
    );
}

#[test]
fn a_tampered_stop_record_fails_closed() {
    let fixture = fixture();
    fixture
        .store
        .append_stop_transition(&request(StopTransition::Stop, None), &fixture.fence)
        .unwrap();
    let database = fixture.database.clone();
    let Fixture {
        _temp,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER admission_operation_stop_epochs_immutable;
             UPDATE admission_operation_stop_epochs
                SET payload = CAST(replace(CAST(payload AS TEXT), '\"stopped\"', '\"running\"') AS BLOB);
             CREATE TRIGGER admission_operation_stop_epochs_immutable
             BEFORE UPDATE ON admission_operation_stop_epochs
             BEGIN
                 SELECT RAISE(ABORT, 'stop epoch record is immutable');
             END;",
        )
        .unwrap();
    drop(connection);
    let refused = match crate::test_authority::open_serving(&database, &lock_root) {
        Err(_) => true,
        Ok(authority) => authority
            .admission_operation_store()
            .load_stop_head(StopScope::Kernel)
            .is_err(),
    };
    assert!(
        refused,
        "a tampered stop record must not load as a verified head"
    );
}

#[test]
fn stopped_terminal_transaction_retains_finalizing_until_resume() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "stopped-terminal",
        "stopped-terminal-capability",
        begun_at,
    );
    let projection = unknown_projection(
        &fixture,
        &operation,
        "stopped-terminal-incident",
        'c',
        begun_at + 20,
    );
    fixture
        .store
        .append_stop_transition(&request(StopTransition::Stop, None), &fixture.fence)
        .unwrap();
    assert_eq!(
        fixture.store.commit_terminal_projection(&projection),
        Err(AdmissionOperationStoreError::KernelStopped)
    );
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .unwrap(),
        Some(operation.clone())
    );
    assert_eq!(
        fixture
            .store
            .load_terminal_replay(&operation.replay_key())
            .unwrap(),
        None
    );
    fixture
        .store
        .append_stop_transition(
            &request(StopTransition::Resume, Some(EPOCH_ONE)),
            &fixture.fence,
        )
        .unwrap();
    let terminal = fixture
        .store
        .commit_terminal_projection(&projection)
        .unwrap();
    assert_eq!(
        terminal.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
}
