use super::*;
use std::sync::{Arc, Barrier};

fn binding(destination: &str) -> DpopReplaySourceBinding {
    DpopReplaySourceBinding {
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "dpop-authority").unwrap(),
        destination_authority_id: AdmissionIdentifier::try_new("destination", destination).unwrap(),
    }
}

fn store() -> DpopNonceStore {
    DpopNonceStore::new_with_per_capability_capacity(16, 8, Duration::from_secs(60))
}

fn preview(store: &DpopNonceStore) -> DpopReplaySourceSnapshot {
    store.preview_unsealed(&binding("destination")).unwrap()
}

#[test]
fn inventory_preserves_every_retention_kind_owner_and_inclusive_horizon() {
    let store = store();
    let through = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    assert!(store.check_and_insert("local", "cap-a").unwrap());
    assert!(store
        .check_and_insert_through("signed", "cap-a", through)
        .unwrap());
    assert!(store
        .reserve_for_dispatch_through("owned", "cap-b", through, "private-owner")
        .unwrap());
    assert!(store
        .check_and_insert_through("indefinite", "cap-c", u64::MAX)
        .unwrap());
    let snapshot = preview(&store);
    assert_eq!(snapshot.markers().len(), 4);
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
    assert_eq!(
        snapshot.markers()[2].dispatch_reservation_id.as_deref(),
        Some("private-owner")
    );
    assert!(matches!(
        &snapshot.markers()[3].retention,
        DpopReplaySourceRetention::Signed {
            exclusive_unix_ns: None,
            monotonic_deadline_offset_ns: None
        }
    ));
    assert!(!format!("{snapshot:?}").contains("private-owner"));
    assert!(store.verify_exact(&snapshot).is_err());
    assert_eq!(snapshot, preview(&store));
    store.seal_exact(&snapshot).unwrap();
    store.verify_exact(&snapshot).unwrap();
}

#[test]
fn sealing_blocks_every_legacy_mutator_and_exact_retry_is_read_only() {
    let store = store();
    assert!(store
        .reserve_for_dispatch_through("owned", "cap", u64::MAX, "owner")
        .unwrap());
    let snapshot = preview(&store);
    store.seal_exact(&snapshot).unwrap();
    for result in [
        store.check_and_insert("local", "cap"),
        store.check_and_insert_until("until", "cap", u64::MAX),
        store.check_and_insert_through("through", "cap", u64::MAX),
        store.reserve_for_dispatch_through("reserve", "cap", u64::MAX, "owner"),
        store.reserve_for_dispatch_until("reserve-until", "cap", u64::MAX, "owner"),
        store.rollback_dispatch_reservation("owned", "cap", "owner"),
        store.rollback_dispatch_reservation("owned", "cap", "wrong-owner"),
    ] {
        assert!(result.is_err());
    }
    assert!(store.ensure_accepting_proofs().is_err());
    assert!(store.preview_unsealed(&binding("destination")).is_err());
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
fn an_insert_rollback_cycle_invalidates_the_exact_preview() {
    let store = store();
    let old = preview(&store);
    assert!(store
        .reserve_for_dispatch_through("nonce", "cap", u64::MAX, "owner")
        .unwrap());
    assert!(store
        .rollback_dispatch_reservation("nonce", "cap", "owner")
        .unwrap());
    assert_eq!(store.utilization().unwrap().0, 0);
    assert!(store.seal_exact(&old).is_err());
    store.ensure_accepting_proofs().unwrap();
    let current = preview(&store);
    assert_eq!(old.instance_id(), current.instance_id());
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
fn rollback_and_retirement_cannot_omit_an_outstanding_reservation() {
    for _ in 0..16 {
        let store = Arc::new(store());
        store
            .reserve_for_dispatch_through("race", "cap", u64::MAX, "owner")
            .unwrap();
        let snapshot = preview(&store);
        let barrier = Arc::new(Barrier::new(2));
        let rollback = {
            let (store, barrier) = (store.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                store.rollback_dispatch_reservation("race", "cap", "owner")
            })
        };
        barrier.wait();
        let seal = store.seal_exact(&snapshot);
        let release = rollback.join().unwrap();
        assert_ne!(seal.is_ok(), release.is_ok());
        if seal.is_ok() {
            store.verify_exact(&snapshot).unwrap();
            assert_eq!(store.utilization().unwrap().0, 1);
        } else {
            assert!(release.unwrap());
        }
    }
}

#[test]
fn previews_do_not_prune_and_real_pruning_is_retained_in_inventory() {
    let store = DpopNonceStore::new(4, Duration::ZERO);
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
    let store = store();
    let oversized = "n".repeat(snapshot::MAX_KEY_BYTES + 1);
    // Model physically retained history from a writer predating byte bounds.
    // New runtime admission must not provide a bypass to manufacture it.
    {
        let mut state = store.inner.lock().unwrap();
        state.identity_bytes = identity::retained_bytes(&oversized, "cap", Some("owner")).unwrap();
        state.cache.put(
            (oversized.clone(), "cap".to_owned()),
            DpopNonceEntry {
                retention: ReplayRetention::signed_through_unix_secs(u64::MAX),
                dispatch_reservation_id: Some("owner".to_owned()),
            },
        );
        state.capability_counts.insert("cap".to_owned(), 1);
    }
    assert!(store.preview_unsealed(&binding("destination")).is_err());
    assert_eq!(store.utilization().unwrap().0, 1);
    store.ensure_accepting_proofs().unwrap();
    assert!(store
        .rollback_dispatch_reservation(&oversized, "cap", "owner")
        .is_err());
    assert_eq!(store.utilization().unwrap().0, 1);
    assert!(store.preview_unsealed(&binding("destination")).is_err());
}

#[test]
fn source_clock_anomaly_and_poisoned_mutex_refuse_without_repair() {
    let store = store();
    let snapshot = preview(&store);
    {
        let mut state = store.inner.lock().unwrap();
        state.wall_clock_high_water = SystemTime::now() + Duration::from_secs(3600);
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
