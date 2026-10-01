use super::super::super::egress_history::{Lookup, RetainedEgressFence};
use super::*;

pub(super) fn fence_request(snapshot: &FlowStateSnapshot) -> TestResult<EgressFenceRequest> {
    Ok(EgressFenceRequest {
        key: snapshot.key.clone(),
        request_id: RequestId::new("same-request")?,
        request_hash: Digest32::new([9; 32]),
        expected_context_generation: snapshot.context_generation,
        expires_at_unix_ms: 2_000,
    })
}

#[test]
fn colliding_fences_have_independent_commitments_and_historical_replay() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let a = FlowMutation::native_for_test(&tx, A);
        let b = FlowMutation::native_for_test(&tx, B);
        let join = request("initial")?;
        let snapshot = a.join(&join)?;
        b.join(&join)?;
        let requested = fence_request(&snapshot)?;
        let fence = a.acquire_egress_fence(&requested, || Ok(1_000))?;
        assert_eq!(b.acquire_egress_fence(&requested, || Ok(1_000))?, fence);
        let commitment = EgressFenceCommit {
            fence: fence.clone(),
            dispatch_commitment_id: RecordId::new("dispatch-a")?,
            committed_at_unix_ms: 1_001,
        };
        let committed = a.commit_egress_fence(&commitment, || Ok(1_001))?;
        assert!(RetainedEgressFence::load(
            b.reader(),
            &fence.key.tenant_id,
            Lookup::Fence(&fence.fence_id)
        )?
        .ok_or("missing b fence")?
        .commitment
        .is_none());
        assert_eq!(
            a.commit_egress_fence(&commitment, || Err(PortError::unavailable()))?,
            committed
        );
        assert!(b.commit_egress_fence(&commitment, || Ok(2_000)).is_err());
        assert!(a.acquire_egress_fence(&requested, || Ok(2_000)).is_err());
        let mut b_commitment = commitment.clone();
        b_commitment.dispatch_commitment_id = RecordId::new("dispatch-b")?;
        assert!(a.commit_egress_fence(&b_commitment, || Ok(1_001)).is_err());
        let b_committed = b.commit_egress_fence(&b_commitment, || Ok(1_001))?;
        assert_ne!(
            committed.dispatch_commitment_id,
            b_committed.dispatch_commitment_id
        );
        verify_native_flow_state(&tx, A)?;
        verify_native_flow_state(&tx, B)?;
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn taint_invalidates_only_its_authority_fence() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let a = FlowMutation::native_for_test(&tx, A);
        let b = FlowMutation::native_for_test(&tx, B);
        let mut join = request("initial")?;
        let snapshot = a.join(&join)?;
        b.join(&join)?;
        let requested = fence_request(&snapshot)?;
        let fence = a.acquire_egress_fence(&requested, || Ok(1_000))?;
        b.acquire_egress_fence(&requested, || Ok(1_000))?;
        join.transition_id = RecordId::new("taint")?;
        join.lineage_join = label("restricted")?;
        a.join(&join)?;
        assert!(validate_fence(a.reader(), &fence, 1_001).is_err());
        validate_fence(b.reader(), &fence, 1_001)?;
        let commitment = EgressFenceCommit {
            fence,
            dispatch_commitment_id: RecordId::new("dispatch")?,
            committed_at_unix_ms: 1_001,
        };
        assert!(a.commit_egress_fence(&commitment, || Ok(1_001)).is_err());
        b.commit_egress_fence(&commitment, || Ok(1_001))?;
        verify_native_flow_state(&tx, A)?;
        verify_native_flow_state(&tx, B)?;
        tx.rollback()?;
        Ok(())
    })
}
