use super::*;
use crate::replay_retention::tests::TestClock;
use std::sync::{Arc, Barrier};

fn binding(destination: &str) -> DpopReplaySourceBinding {
    DpopReplaySourceBinding {
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "dpop-authority").unwrap(),
        destination_authority_id: AdmissionIdentifier::try_new("destination", destination).unwrap(),
    }
}

fn store() -> DpopNonceStore {
    DpopNonceStore::new_with_per_capability_capacity(16, 8, Duration::from_secs(60))
        .expect("positive replay store test capacities")
}

fn preview(store: &DpopNonceStore) -> DpopReplaySourceSnapshot {
    store.preview_unsealed(&binding("destination")).unwrap()
}

#[test]
fn inventory_preserves_every_retention_kind_and_inclusive_horizon() {
    let store = crate::dpop::clock_tests::store(Arc::new(TestClock::new(100)), 16);
    let through = 700;
    assert!(store.check_and_insert("private-local", "cap-a").unwrap());
    assert!(store
        .check_and_insert_through("signed", "cap-a", through)
        .unwrap());
    assert!(store
        .check_and_insert_through("indefinite", "cap-c", u64::MAX)
        .unwrap());
    let snapshot = preview(&store);
    assert_eq!(snapshot.markers().len(), 3);
    let bytes = snapshot.canonical_bytes().unwrap();
    assert_eq!(
        DpopReplaySourceSnapshot::from_canonical_bytes(&bytes).unwrap(),
        snapshot
    );
    assert!(matches!(
        snapshot.markers()[0].retention,
        DpopReplaySourceRetention::Local { .. }
    ));
    match &snapshot.markers()[1].retention {
        DpopReplaySourceRetention::Signed {
            exclusive_unix_ns,
            monotonic_deadline_offset_ns,
        } => {
            assert_eq!(
                exclusive_unix_ns.as_deref(),
                Some(((u128::from(through) + 1) * 1_000_000_000).to_string()).as_deref()
            );
            assert!(monotonic_deadline_offset_ns.is_some());
        }
        _ => panic!("signed marker lost its retention kind"),
    }
    assert!(matches!(
        &snapshot.markers()[2].retention,
        DpopReplaySourceRetention::Signed {
            exclusive_unix_ns: None,
            monotonic_deadline_offset_ns: None
        }
    ));
    assert!(!format!("{snapshot:?}").contains("private-local"));
    assert!(matches!(
        store.verify_exact(&snapshot),
        Err(KernelError::DpopVerificationFailed(reason))
            if reason == "DPoP replay source: live source seal or retained inventory does not match"
    ));
    assert_eq!(snapshot, preview(&store));
    store.seal_exact(&snapshot).unwrap();
    store.verify_exact(&snapshot).unwrap();
}

#[test]
fn sealing_blocks_every_source_mutator_and_exact_retry_is_read_only() {
    let store = store();
    assert!(store
        .check_and_insert_through("retained", "cap", u64::MAX)
        .unwrap());
    let snapshot = preview(&store);
    store.seal_exact(&snapshot).unwrap();
    for result in [
        store.check_and_insert("local", "cap"),
        store.check_and_insert_until("until", "cap", u64::MAX),
        store.check_and_insert_through("through", "cap", u64::MAX),
    ] {
        assert!(matches!(
            result,
            Err(KernelError::DpopVerificationFailed(reason))
                if reason == "DPoP replay source: source is retired; replay mutations are forbidden"
        ));
    }
    assert!(matches!(
        store.ensure_unsealed(),
        Err(KernelError::DpopVerificationFailed(reason))
            if reason == "DPoP replay source: source is retired; replay mutations are forbidden"
    ));
    assert!(matches!(
        store.preview_unsealed(&binding("destination")),
        Err(KernelError::DpopVerificationFailed(reason))
            if reason == "DPoP replay source: source is retired; replay mutations are forbidden"
    ));
    assert_eq!(store.utilization().unwrap(), (1, 16));
    store.seal_exact(&snapshot).unwrap();
    store.verify_exact(&snapshot).unwrap();
}

#[test]
fn a_fresh_empty_store_cannot_replace_a_lost_source_even_with_copied_data() {
    let original = store();
    let snapshot = preview(&original);
    original.seal_exact(&snapshot).unwrap();
    let data = snapshot.canonical_bytes().unwrap();
    drop(original);
    let replacement = store();
    let decoded = DpopReplaySourceSnapshot::from_canonical_bytes(&data).unwrap();
    assert!(replacement.verify_exact(&decoded).is_err());
    assert!(replacement.seal_exact(&decoded).is_err());
    let own = preview(&replacement);
    assert_ne!(own.instance_id(), decoded.instance_id());
    replacement.seal_exact(&own).unwrap();
    assert!(replacement.verify_exact(&decoded).is_err());
    replacement.verify_exact(&own).unwrap();
}

#[test]
fn changed_destination_cannot_rebind_a_seal_and_failure_does_not_unseal() {
    let store = store();
    let first = preview(&store);
    let other = store
        .preview_unsealed(&binding("other-destination"))
        .unwrap();
    store.seal_exact(&first).unwrap();
    assert!(store.seal_exact(&other).is_err());
    assert!(store.verify_exact(&other).is_err());
    store.verify_exact(&first).unwrap();
    assert!(store.check_and_insert("nonce", "cap").is_err());
}

#[test]
fn a_replay_attempt_invalidates_the_exact_preview() {
    let store = crate::dpop::clock_tests::store(Arc::new(TestClock::new(100)), 16);
    assert!(store
        .check_and_insert_through("nonce", "cap", u64::MAX)
        .unwrap());
    let old = preview(&store);
    assert!(!store
        .check_and_insert_through("nonce", "cap", u64::MAX)
        .unwrap());
    assert_eq!(store.utilization().unwrap().0, 1);
    assert!(matches!(
        store.seal_exact(&old),
        Err(KernelError::DpopVerificationFailed(reason))
            if reason == "DPoP replay source: source no longer matches the pinned instance and inventory"
    ));
    store.ensure_unsealed().unwrap();
    let current = preview(&store);
    assert_eq!(old.instance_id(), current.instance_id());
    assert!(old.markers() == current.markers());
    assert_ne!(old.inventory_sha256(), current.inventory_sha256());
    store.seal_exact(&current).unwrap();
}

#[test]
fn insertion_and_retirement_share_one_linearization_boundary() {
    for _ in 0..16 {
        let store = Arc::new(store());
        let snapshot = preview(&store);
        let barrier = Arc::new(Barrier::new(2));
        let writer = {
            let (store, barrier) = (store.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                store.check_and_insert_through("race", "cap", u64::MAX)
            })
        };
        barrier.wait();
        let seal = store.seal_exact(&snapshot);
        let insertion = writer.join().unwrap();
        assert_ne!(seal.is_ok(), insertion.is_ok());
        if seal.is_ok() {
            store.verify_exact(&snapshot).unwrap();
            assert_eq!(store.utilization().unwrap().0, 0);
        } else {
            assert!(insertion.unwrap());
            assert_eq!(preview(&store).markers().len(), 1);
        }
    }
}

#[test]
fn pruning_and_retirement_share_one_linearization_boundary() {
    for _ in 0..16 {
        let clock = Arc::new(TestClock::new(100));
        let store = Arc::new(crate::dpop::clock_tests::store(clock.clone(), 16));
        assert!(store.check_and_insert_until("expired", "cap", 110).unwrap());
        let snapshot = preview(&store);
        clock.set(110, 10);
        let barrier = Arc::new(Barrier::new(2));
        let writer = {
            let (store, barrier) = (store.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                store.check_and_insert_until("fresh", "cap", 120)
            })
        };
        barrier.wait();
        let seal = store.seal_exact(&snapshot);
        let insertion = writer.join().unwrap();
        assert_ne!(seal.is_ok(), insertion.is_ok());
        if seal.is_ok() {
            store.verify_exact(&snapshot).unwrap();
            assert_eq!(store.utilization().unwrap().0, 1);
            assert!(matches!(
                insertion,
                Err(KernelError::DpopVerificationFailed(reason))
                    if reason == "DPoP replay source: source is retired; replay mutations are forbidden"
            ));
        } else {
            assert!(insertion.unwrap());
            assert!(matches!(
                seal,
                Err(KernelError::DpopVerificationFailed(reason))
                    if reason == "DPoP replay source: source no longer matches the pinned instance and inventory"
            ));
            let current = preview(&store);
            assert_eq!(current.markers().len(), 1);
            assert_eq!(current.markers()[0].nonce, "fresh");
            store.seal_exact(&current).unwrap();
            store.verify_exact(&current).unwrap();
        }
    }
}

#[test]
fn previews_do_not_prune_and_real_pruning_is_retained_in_inventory() {
    let store =
        DpopNonceStore::new(4, Duration::ZERO).expect("positive replay store test capacities");
    store.check_and_insert("elapsed", "cap").unwrap();
    let old = preview(&store);
    assert_eq!(old.markers().len(), 1);
    let old_data: serde_json::Value =
        serde_json::from_slice(&old.canonical_bytes().unwrap()).unwrap();
    assert!(old_data["body"]["inventory"]["pruned_through_unix_ns"].is_null());
    store
        .check_and_insert_through("live", "cap", u64::MAX)
        .unwrap();
    let current = preview(&store);
    assert_eq!(current.markers().len(), 1);
    let current_data: serde_json::Value =
        serde_json::from_slice(&current.canonical_bytes().unwrap()).unwrap();
    assert!(current_data["body"]["inventory"]["pruned_through_unix_ns"].is_string());
    assert!(store.seal_exact(&old).is_err());
    store.seal_exact(&current).unwrap();
}

#[test]
fn unrepresentable_inventory_is_refused_without_reset_or_retirement() {
    let clock = Arc::new(TestClock::new(100));
    let store = crate::dpop::clock_tests::store(clock.clone(), 16);
    let oversized = "n".repeat(snapshot::MAX_KEY_BYTES + 1);
    // Model retained identity corruption without admitting it through a writer.
    {
        let mut state = store.inner.lock().unwrap();
        state.identity_bytes = identity::retained_bytes(&oversized, "cap").unwrap();
        state.cache.put(
            (oversized.clone(), "cap".to_owned()),
            DpopNonceEntry {
                retention: ReplayHorizon::Through(u64::MAX).project(clock.read().unwrap()),
            },
        );
        state.capability_counts.insert("cap".to_owned(), 1);
    }
    assert!(store.preview_unsealed(&binding("destination")).is_err());
    assert_eq!(store.utilization().unwrap().0, 1);
    store.ensure_unsealed().unwrap();
    assert!(matches!(
        store.check_and_insert_through(&oversized, "cap", u64::MAX),
        Err(KernelError::Dpop(DpopError::IdentityLimit))
    ));
    assert_eq!(store.utilization().unwrap().0, 1);
    assert!(store.preview_unsealed(&binding("destination")).is_err());
}

#[test]
fn source_clock_anomaly_and_poisoned_mutex_refuse_without_repair() {
    let store = store();
    let snapshot = preview(&store);
    {
        let mut state = store.inner.lock().unwrap();
        let now = SystemClock.read().unwrap();
        state.replay_clock = ReplayClock::default();
        state
            .replay_clock
            .observe(
                "dpop_nonce",
                ClockReading::new(
                    now.unix_millis().checked_add(3_600_000).unwrap(),
                    now.monotonic(),
                ),
            )
            .unwrap();
    }
    assert!(store.preview_unsealed(&binding("destination")).is_err());
    assert!(store.seal_exact(&snapshot).is_err());
    assert!(store.inner.lock().unwrap().source.sealed.is_none());
    let store = Arc::new(store);
    let poisoned = store.clone();
    assert!(std::thread::spawn(move || {
        let _guard = poisoned.inner.lock().unwrap();
        panic!("poison source lock");
    })
    .join()
    .is_err());
    assert!(store.preview_unsealed(&binding("destination")).is_err());
    assert!(store.verify_exact(&snapshot).is_err());
    assert!(store.check_and_insert("nonce", "cap").is_err());
}

#[test]
fn revision_exhaustion_denies_before_replay_mutation() {
    let store = store();
    store.inner.lock().unwrap().source.revision = u64::MAX;
    let snapshot = preview(&store);
    assert!(store.check_and_insert("nonce", "cap").is_err());
    assert_eq!(store.utilization().unwrap().0, 0);
    assert_eq!(preview(&store), snapshot);
    store.seal_exact(&snapshot).unwrap();
}
