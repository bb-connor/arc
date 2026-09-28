use super::*;
use crate::admission_operation::AdmissionIdentifier;
use crate::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
use chio_core::capability::{scope::ChioScope, token::CapabilityTokenBody};

use crate::replay_retention::tests::TestClock;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_accounting_error<T: std::fmt::Debug>(result: Result<T, KernelError>) {
    assert!(
        matches!(result, Err(KernelError::Dpop(DpopError::Accounting))),
        "{result:?}"
    );
}

#[test]
fn prune_checks_the_entire_release_before_deleting_any_marker() -> TestResult {
    let clock = Arc::new(TestClock::new(100));
    let store = clock_tests::store(clock.clone(), 8);
    for nonce in ["a", "b"] {
        assert!(store.check_and_insert_entry(
            nonce,
            "cap",
            ReplayHorizon::Local(Duration::from_secs(10)),
            None,
        )?);
    }
    let charged = store.identity_byte_utilization()?.0;
    // Corrupt the second release's accounting to prove the first stays intact.
    store
        .inner
        .lock()
        .map_err(|_| "lock poisoned")?
        .capability_counts
        .insert("cap".into(), 1);
    clock.set(111, 11);
    assert_accounting_error(store.check_and_insert_entry(
        "new",
        "cap",
        ReplayHorizon::Local(Duration::from_secs(10)),
        None,
    ));
    assert_eq!(store.utilization()?.0, 2);
    assert_eq!(store.identity_byte_utilization()?.0, charged);
    {
        let state = store.inner.lock().map_err(|_| "lock poisoned")?;
        for nonce in ["a", "b"] {
            assert!(state.cache.peek(&(nonce.into(), "cap".into())).is_some());
        }
        assert_eq!(state.capability_counts.get("cap"), Some(&1));
    }
    assert_accounting_error(store.check_and_insert("later", "different-cap"));
    assert_accounting_error(store.preview_unsealed(&DpopReplaySourceBinding {
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "dpop")?,
        destination_authority_id: AdmissionIdentifier::try_new("destination", "admission")?,
    }));
    Ok(())
}

#[test]
fn owned_rollback_preserves_marker_on_byte_underflow_and_latches_refusal() -> TestResult {
    let store = DpopNonceStore::new(8, Duration::from_secs(60));
    assert!(store.reserve_for_dispatch_until("nonce", "cap", u64::MAX, "owner")?);
    store
        .inner
        .lock()
        .map_err(|_| "lock poisoned")?
        .identity_bytes = 0;
    assert!(!store.rollback_dispatch_reservation("nonce", "cap", "other")?);
    assert_accounting_error(store.rollback_dispatch_reservation("nonce", "cap", "owner"));
    {
        let state = store.inner.lock().map_err(|_| "lock poisoned")?;
        assert_eq!(state.cache.len(), 1);
        assert_eq!(state.capability_counts.get("cap"), Some(&1));
        assert_eq!(state.identity_bytes, 0);
    }
    assert_accounting_error(store.rollback_dispatch_reservation("nonce", "cap", "owner"));
    Ok(())
}

#[test]
fn successful_prune_and_cancel_leave_exact_capacity_for_live_replay_markers() -> TestResult {
    let clock = Arc::new(TestClock::new(100));
    let store = clock_tests::store(clock.clone(), 3);
    for nonce in ["a", "b"] {
        assert!(store.check_and_insert_entry(
            nonce,
            "expired",
            ReplayHorizon::Local(Duration::from_secs(10)),
            None,
        )?);
    }
    assert!(store.check_and_insert_entry(
        "live",
        "live-cap",
        ReplayHorizon::Local(Duration::from_secs(100)),
        Some("owner"),
    )?);
    clock.set(111, 11);
    assert!(store.check_and_insert_entry(
        "fresh",
        "fresh-cap",
        ReplayHorizon::Local(Duration::from_secs(100)),
        None,
    )?);
    assert!(!store.check_and_insert_entry(
        "live",
        "live-cap",
        ReplayHorizon::Local(Duration::from_secs(100)),
        None,
    )?);
    assert!(!store.rollback_dispatch_reservation("live", "live-cap", "wrong-owner")?);
    assert!(store.rollback_dispatch_reservation("live", "live-cap", "owner")?);
    let state = store.inner.lock().map_err(|_| "lock poisoned")?;
    assert_eq!(state.cache.len(), 1);
    assert_eq!(
        state.capability_counts,
        HashMap::from([("fresh-cap".into(), 1)])
    );
    assert_eq!(
        state.identity_bytes,
        identity::retained_bytes("fresh", "fresh-cap", None)?
    );
    Ok(())
}

#[test]
fn proof_deadline_overflow_is_rejected_before_nonce_reservation() -> TestResult {
    let key = Keypair::generate();
    let cap = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap".into(),
            issuer: key.public_key(),
            subject: key.public_key(),
            scope: ChioScope::default(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &key,
    )?;
    let proof = DpopProof::sign(
        DpopProofBody {
            schema: DPOP_SCHEMA.into(),
            replay_authority: None,
            capability_id: cap.id.clone(),
            tool_server: "server".into(),
            tool_name: "tool".into(),
            action_hash: "hash".into(),
            nonce: "nonce".into(),
            issued_at: 1,
            agent_key: key.public_key(),
        },
        &key,
    )?;
    let config = DpopConfig {
        proof_ttl_secs: u64::MAX,
        ..Default::default()
    };
    let store = DpopNonceStore::new(8, Duration::from_secs(60));
    for result in [
        verify_dpop_proof_stateless(
            &proof,
            &cap,
            "server",
            "tool",
            "hash",
            &config,
            store.trusted_now()?,
        ),
        verify_dpop_proof(&proof, &cap, "server", "tool", "hash", &store, &config),
    ] {
        assert!(
            matches!(result, Err(KernelError::Dpop(DpopError::WindowOverflow))),
            "{result:?}"
        );
    }
    assert_eq!(store.utilization()?.0, 0);
    assert_eq!(store.identity_byte_utilization()?.0, 0);
    assert!(store.check_and_insert("nonce", "cap")?);
    assert!(dpop_freshness_admits(u64::MAX, 0, &config));
    assert!(!dpop_freshness_admits(u64::MAX, 1, &config));
    Ok(())
}
