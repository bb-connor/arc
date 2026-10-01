use super::*;

struct Clock;

impl SecurityStateClock for Clock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(1_000)
    }
}

fn prepare(store: &SqliteSecurityStateStore) -> TestResult<EgressFenceRequest> {
    let join = request("join")?;
    let snapshot = store.join(&join)?;
    Ok(EgressFenceRequest {
        key: join.key,
        request_id: chio_security_types::ports::RequestId::new("request")?,
        request_hash: Digest32::new([4; 32]),
        expected_context_generation: snapshot.context_generation,
        expires_at_unix_ms: 2_000,
    })
}

#[test]
fn acquisition_replay_rejects_partial_or_impossible_commitment_history() -> TestResult {
    for mutation in [
        "UPDATE security_egress_fences SET committed_at = 1000",
        "UPDATE security_egress_fences SET dispatch_commitment_id = 'dispatch'",
        "UPDATE security_egress_fences SET dispatch_commitment_id = '', committed_at = 1000",
        "UPDATE security_egress_fences SET dispatch_commitment_id = 'dispatch', committed_at = -1",
        "UPDATE security_egress_fences SET dispatch_commitment_id = 'dispatch', committed_at = 2001",
        "UPDATE security_egress_fences SET principal_id = 'another-principal'",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let store = SqliteSecurityStateStore::open_with_trusted_clock(&path, Arc::new(Clock))?;
        let request = prepare(&store)?;
        store.acquire_egress_fence(&request)?;
        Connection::open(&path)?.execute_batch(mutation)?;
        assert!(store.acquire_egress_fence(&request).is_err(), "{mutation}");
    }
    Ok(())
}

#[test]
fn live_fence_validation_rejects_partial_commitment_history() -> TestResult {
    for mutation in [
        "UPDATE security_egress_fences SET committed_at = 1000",
        "UPDATE security_egress_fences SET dispatch_commitment_id = 'dispatch'",
        "UPDATE security_egress_fences SET dispatch_commitment_id = 'dispatch', committed_at = 2001",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let store = SqliteSecurityStateStore::open_with_trusted_clock(&path, Arc::new(Clock))?;
        let fence = store.acquire_egress_fence(&prepare(&store)?)?;
        Connection::open(&path)?.execute_batch(mutation)?;
        assert!(store.validate_egress_fence(&fence).is_err(), "{mutation}");
    }
    Ok(())
}

#[test]
fn historical_commit_rejects_noncanonical_fence_identity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = SqliteSecurityStateStore::open_with_trusted_clock(&path, Arc::new(Clock))?;
    let fence = store.acquire_egress_fence(&prepare(&store)?)?;
    let mut commitment = EgressFenceCommit {
        fence,
        dispatch_commitment_id: RecordId::new("dispatch")?,
        committed_at_unix_ms: 1_000,
    };
    store.commit_egress_fence(&commitment)?;
    Connection::open(&path)?
        .execute_batch("UPDATE security_egress_fences SET fence_id = 'substituted-history'")?;
    commitment.fence.fence_id = RecordId::new("substituted-history")?;
    assert!(store.commit_egress_fence(&commitment).is_err());
    assert!(store.validate_egress_fence(&commitment.fence).is_err());
    Ok(())
}
