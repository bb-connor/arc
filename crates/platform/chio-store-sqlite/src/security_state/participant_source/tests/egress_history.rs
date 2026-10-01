use super::*;

#[test]
fn migration_refuses_malformed_egress_history_without_retiring_the_source() -> TestResult {
    for mutation in [
        "UPDATE security_egress_fences SET committed_at = 1000",
        "UPDATE security_egress_fences SET dispatch_commitment_id = 'dispatch'",
        "UPDATE security_egress_fences SET dispatch_commitment_id = '', committed_at = 1000",
        "UPDATE security_egress_fences SET dispatch_commitment_id = 'dispatch', committed_at = -1",
        "UPDATE security_egress_fences SET fence_id = 'noncanonical'",
        "UPDATE security_egress_fences SET context_generation = 0",
        "UPDATE security_egress_fences SET request_id = ''",
        "UPDATE security_flow_sequences SET last_generation = X'31'",
        "UPDATE security_egress_fences SET dispatch_commitment_id = 'dispatch', committed_at = 'invalid-time'",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let _store = seed(&path)?;
        let source = SqliteSecurityParticipantSource::open(&path)?;
        let expected = source.preview(&binding()?)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(mutation)?;
        assert!(source.preview(&binding()?).is_err(), "{mutation}");
        assert!(SqliteSecurityParticipantSource::open(&path).is_err(), "{mutation}");
        assert!(source.seal_exact(&expected).is_err(), "{mutation}");
        assert!(!schema::has_evidence(&connection)?);
    }
    Ok(())
}

#[test]
fn historical_fences_cannot_reference_missing_or_regressed_flow_state() -> TestResult {
    for mutation in [
        "DELETE FROM security_flow_contexts",
        "UPDATE security_flow_contexts SET generation = 1;
         UPDATE security_principal_flow_state SET generation = 1;
         UPDATE security_lineage_flow_state SET generation = 1;
         UPDATE security_session_flow_state SET generation = 1;",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let store = seed(&path)?;
        let snapshot = store.join(&join_request("second-join")?)?;
        store.acquire_egress_fence(&EgressFenceRequest {
            key: key()?,
            request_id: RequestId::new("second-request")?,
            request_hash: Digest32::new([2; 32]),
            expected_context_generation: snapshot.context_generation,
            expires_at_unix_ms: 2_000,
        })?;
        let source = SqliteSecurityParticipantSource::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(mutation)?;
        assert!(source.preview(&binding()?).is_err(), "{mutation}");
        assert!(
            SqliteSecurityParticipantSource::open(&path).is_err(),
            "{mutation}"
        );
        assert!(!schema::has_evidence(&connection)?);
    }
    Ok(())
}

#[test]
fn expired_stale_and_committed_fences_remain_exact_migratable_history() -> TestResult {
    use chio_security_types::ports::EgressFenceCommit;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    struct Clock(AtomicU64);
    impl crate::security_state::SecurityStateClock for Clock {
        fn now_unix_ms(&self) -> chio_security_types::ports::PortResult<u64> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = SqliteSecurityStateStore::open_with_trusted_clock(&path, clock.clone())?;
    let snapshot = store.join(&join_request("initial")?)?;
    let request = EgressFenceRequest {
        key: key()?,
        request_id: RequestId::new("committed")?,
        request_hash: Digest32::new([2; 32]),
        expected_context_generation: snapshot.context_generation,
        expires_at_unix_ms: 2_000,
    };
    let fence = store.acquire_egress_fence(&request)?;
    let pending = store.acquire_egress_fence(&EgressFenceRequest {
        request_id: RequestId::new("pending")?,
        ..request
    })?;
    let commitment = EgressFenceCommit {
        fence: fence.clone(),
        dispatch_commitment_id: RecordId::new("dispatch")?,
        // Preserve the qualified receipt-time boundary; observed time is live.
        committed_at_unix_ms: 2_000,
    };
    let committed = store.commit_egress_fence(&commitment)?;
    store.join(&join_request("later-join")?)?;
    clock.0.store(3_000, Ordering::Release);
    assert!(store.validate_egress_fence(&fence).is_err());
    assert!(store.validate_egress_fence(&pending).is_err());
    assert_eq!(store.commit_egress_fence(&commitment)?, committed);
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    let retained = source.read_sealed_rows(&expected)?;
    let (_, fences) = retained
        .tables
        .iter()
        .find(|(name, _)| *name == "security_egress_fences")
        .ok_or("fence table absent")?;
    assert_eq!(fences.len(), 2);
    source.verify_seal(&expected)?;
    assert_eq!(
        source.load_seal()?.ok_or("seal absent")?.snapshot(),
        &expected
    );
    Ok(())
}
