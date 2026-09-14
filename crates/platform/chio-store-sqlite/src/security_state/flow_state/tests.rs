use super::*;

#[cfg(unix)]
mod declassification;
mod egress_history;
mod isolation;
#[cfg(unix)]
mod native_scope;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn request(transition_id: &str) -> TestResult<FlowJoinRequest> {
    use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId};
    Ok(FlowJoinRequest {
        key: FlowStateKey {
            tenant_id: TenantId::new("tenant")?,
            principal_id: chio_security_types::PrincipalId::new("principal")?,
            lineage_id: LineageId::new("lineage")?,
            session_id: SessionId::new("session")?,
            isolation_epoch_id: IsolationEpochId::new("epoch")?,
        },
        principal_join: InformationLabel::bottom(),
        lineage_join: InformationLabel::bottom(),
        session_join: InformationLabel::bottom(),
        transition_id: RecordId::new(transition_id)?,
    })
}

#[test]
fn join_and_fence_wait_for_the_outer_commit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = SqliteSecurityStateStore::open(&path)?;
    let observer = Connection::open(&path)?;
    let join = request("join")?;
    let mut connection = store.connection()?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    record_transition(&tx, "tenant", "outer-transition", "outer", &[1; 32])?;
    let (owner, snapshot) = SecurityStateWriteTransaction::new(tx)?.join(&join)?;
    let (owner, fence) = owner.acquire_egress_fence(
        &EgressFenceRequest {
            key: join.key.clone(),
            request_id: chio_security_types::ports::RequestId::new("request")?,
            request_hash: Digest32::new([2; 32]),
            expected_context_generation: snapshot.context_generation,
            expires_at_unix_ms: i64::MAX as u64,
        },
        &SystemSecurityStateClock,
    )?;
    assert!(load_flow_snapshot(&observer, &join.key)?.is_none());
    assert!(!transition_status(
        &observer,
        "tenant",
        "outer-transition",
        "outer",
        &[1; 32]
    )?);
    let (owner, committed) = owner.commit_egress_fence(
        &EgressFenceCommit {
            fence: fence.clone(),
            dispatch_commitment_id: RecordId::new("dispatch")?,
            committed_at_unix_ms: SystemSecurityStateClock.now_unix_ms()?,
        },
        &SystemSecurityStateClock,
    )?;
    assert!(load_flow_snapshot(&observer, &join.key)?.is_none());
    owner.into_transaction().commit()?;
    assert_eq!(load_flow_snapshot(&observer, &join.key)?, Some(snapshot));
    assert!(transition_status(
        &observer,
        "tenant",
        "outer-transition",
        "outer",
        &[1; 32]
    )?);
    assert_eq!(committed.fence_id, fence.fence_id);
    Ok(())
}

#[test]
fn dropping_successful_flow_owner_rolls_back_earlier_outer_writes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteSecurityStateStore::open(directory.path().join("security.db"))?;
    let join = request("join")?;
    let mut connection = store.connection()?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    record_transition(&tx, "tenant", "outer-transition", "outer", &[1; 32])?;
    let (owner, _) = SecurityStateWriteTransaction::new(tx)?.join(&join)?;
    drop(owner);
    assert!(connection.is_autocommit());
    assert!(load_flow_snapshot(&connection, &join.key)?.is_none());
    assert!(!transition_status(
        &connection,
        "tenant",
        "outer-transition",
        "outer",
        &[1; 32]
    )?);
    Ok(())
}

#[test]
fn late_flow_error_rolls_back_even_if_caller_requested_commit_on_drop() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteSecurityStateStore::open(directory.path().join("security.db"))?;
    let join = request("join")?;
    let mut connection = store.connection()?;
    connection.execute_batch(
        "CREATE TRIGGER reject_context BEFORE INSERT ON security_flow_contexts
         BEGIN SELECT RAISE(ABORT, 'injected late flow failure'); END;",
    )?;
    let mut tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.set_drop_behavior(rusqlite::DropBehavior::Commit);
    record_transition(&tx, "tenant", "outer-transition", "outer", &[1; 32])?;
    assert!(SecurityStateWriteTransaction::new(tx)?.join(&join).is_err());
    assert!(connection.is_autocommit());
    assert!(load_flow_snapshot(&connection, &join.key)?.is_none());
    assert!(!transition_status(
        &connection,
        "tenant",
        "outer-transition",
        "outer",
        &[1; 32]
    )?);
    let generations: i64 =
        connection.query_row("SELECT count(*) FROM security_flow_sequences", [], |row| {
            row.get(0)
        })?;
    assert_eq!(generations, 0);
    Ok(())
}

#[test]
fn flow_owner_rejects_an_unacquired_or_read_only_transaction() -> TestResult {
    for read in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = SqliteSecurityStateStore::open(directory.path().join("security.db"))?;
        let mut connection = store.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        if read {
            participant_source::ensure_legacy_writable(&tx)?;
        }
        let error = match SecurityStateWriteTransaction::new(tx) {
            Err(error) => error,
            Ok(_) => panic!("non-write transaction acquired mutation ownership"),
        };
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::InvalidData
        );
        assert!(connection.is_autocommit());
    }
    Ok(())
}
