use super::*;
use crate::admission_operation::AdmissionIdentifier;
use crate::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
use crate::dpop::*;
use std::sync::{Arc, Barrier};
use std::time::Duration;

fn snapshot(store: &DpopNonceStore) -> replay_source::DpopReplaySourceSnapshot {
    store
        .preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: AdmissionIdentifier::try_new("authority", "dpop").unwrap(),
            destination_authority_id: AdmissionIdentifier::try_new("destination", "admission")
                .unwrap(),
        })
        .unwrap()
}

#[test]
fn oversized_identity_is_rejected_by_every_writer_before_any_state_change() {
    let oversized = "secret-identity-".repeat(300);
    assert!(oversized.len() > MAX_DPOP_REPLAY_IDENTITY_PART_BYTES);
    for bad_part in 0..3 {
        let store = DpopNonceStore::new(8, Duration::ZERO);
        let before = snapshot(&store);
        let nonce = if bad_part == 0 {
            oversized.as_str()
        } else {
            "nonce"
        };
        let cap = if bad_part == 1 {
            oversized.as_str()
        } else {
            "cap"
        };
        let owner = if bad_part == 2 {
            oversized.as_str()
        } else {
            "owner"
        };
        let mut results = vec![
            store.reserve_for_dispatch_through(nonce, cap, u64::MAX, owner),
            store.reserve_for_dispatch_until(nonce, cap, u64::MAX, owner),
            store.rollback_dispatch_reservation(nonce, cap, owner),
        ];
        if bad_part < 2 {
            results.extend([
                store.check_and_insert(nonce, cap),
                store.check_and_insert_until(nonce, cap, u64::MAX),
                store.check_and_insert_through(nonce, cap, u64::MAX),
            ]);
        }
        for result in results {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("4096-byte limit"));
            assert!(!error.contains("secret-identity"));
        }
        assert_eq!(snapshot(&store), before);
        assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
    }
}

#[test]
fn limits_measure_utf8_bytes_and_keep_identity_text_exact() {
    let store = DpopNonceStore::new(8, Duration::from_secs(60));
    let boundary = "é".repeat(MAX_DPOP_REPLAY_IDENTITY_PART_BYTES / 2);
    assert!(store
        .reserve_for_dispatch_through(&boundary, "cap", u64::MAX, "owner")
        .unwrap());
    assert!(!store
        .reserve_for_dispatch_through(&boundary, "cap", u64::MAX, "other")
        .unwrap());
    assert!(store
        .check_and_insert_through(&(boundary.clone() + "é"), "cap", u64::MAX)
        .is_err());
    assert!(!store
        .rollback_dispatch_reservation(&boundary, "cap", "other")
        .unwrap());
    assert!(store
        .rollback_dispatch_reservation(&boundary, "cap", "owner")
        .unwrap());
    assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
    assert!(store
        .check_and_insert_through("é", "cap", u64::MAX)
        .unwrap());
    assert!(store
        .check_and_insert_through("e\u{301}", "cap", u64::MAX)
        .unwrap());
    assert!(store
        .check_and_insert_through(" é ", "cap", u64::MAX)
        .unwrap());
    assert_eq!(store.utilization().unwrap().0, 3);
}

#[test]
fn byte_pressure_never_evicts_a_live_or_reserved_marker() {
    for owned in [false, true] {
        let owner = owned.then_some("owner");
        let capacity = retained_bytes("nonce", "cap", owner).unwrap();
        let store = DpopNonceStore::new_with_identity_byte_capacity(
            8,
            8,
            capacity,
            Duration::from_secs(60),
        );
        if owned {
            assert!(store
                .reserve_for_dispatch_through("nonce", "cap", u64::MAX, "owner")
                .unwrap());
        } else {
            assert!(store
                .check_and_insert_through("nonce", "cap", u64::MAX)
                .unwrap());
        }
        assert_eq!(
            store.identity_byte_utilization().unwrap(),
            (capacity, capacity)
        );
        assert!(store
            .check_and_insert_through("other", "cap", u64::MAX)
            .is_err());
        assert!(!store
            .check_and_insert_through("nonce", "cap", u64::MAX)
            .unwrap());
        assert_eq!(store.utilization().unwrap().0, 1);
        assert_eq!(store.identity_byte_utilization().unwrap().0, capacity);
        if owned {
            assert!(!store
                .rollback_dispatch_reservation("nonce", "cap", "wrong")
                .unwrap());
            assert!(store
                .rollback_dispatch_reservation("nonce", "cap", "owner")
                .unwrap());
            assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
            assert!(store
                .check_and_insert_through("other", "cap", u64::MAX)
                .unwrap());
        }
    }
}

#[test]
fn expired_reclamation_and_shared_capability_cleanup_return_the_exact_charge() {
    let store = DpopNonceStore::new_with_identity_byte_capacity(8, 8, 100, Duration::ZERO);
    store.check_and_insert("expired", "cap").unwrap();
    assert_eq!(store.identity_byte_utilization().unwrap().0, 13);
    store
        .reserve_for_dispatch_through("a", "cap", u64::MAX, "owner")
        .unwrap();
    assert_eq!(store.identity_byte_utilization().unwrap().0, 12);
    store
        .reserve_for_dispatch_through("b", "cap", u64::MAX, "owner")
        .unwrap();
    assert_eq!(store.identity_byte_utilization().unwrap().0, 24);
    store
        .rollback_dispatch_reservation("a", "cap", "owner")
        .unwrap();
    assert_eq!(store.identity_byte_utilization().unwrap().0, 12);
    assert_eq!(
        store.inner.lock().unwrap().capability_counts.get("cap"),
        Some(&1)
    );
    store
        .rollback_dispatch_reservation("b", "cap", "owner")
        .unwrap();
    assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
    assert!(store.inner.lock().unwrap().capability_counts.is_empty());
}

#[test]
fn concurrent_reservations_cannot_oversubscribe_the_byte_budget() {
    let store = Arc::new(DpopNonceStore::new_with_identity_byte_capacity(
        8,
        8,
        8,
        Duration::from_secs(60),
    ));
    let barrier = Arc::new(Barrier::new(8));
    let writers = (0..8)
        .map(|index| {
            let (store, barrier) = (store.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .check_and_insert_through(&index.to_string(), "cap", u64::MAX)
                    .is_ok()
            })
        })
        .collect::<Vec<_>>();
    let winners = writers
        .into_iter()
        .map(|writer| usize::from(writer.join().unwrap()))
        .sum::<usize>();
    assert_eq!(winners, 1);
    assert_eq!(store.utilization().unwrap().0, 1);
    assert_eq!(store.identity_byte_utilization().unwrap(), (7, 8));
}

#[test]
fn retirement_binds_byte_limits_and_detects_accounting_substitution() {
    let store = DpopNonceStore::new_with_identity_byte_capacity(8, 8, 100, Duration::from_secs(60));
    store
        .check_and_insert_through("nonce", "cap", u64::MAX)
        .unwrap();
    let sealed = snapshot(&store);
    store.seal_exact(&sealed).unwrap();
    let usage = store.identity_byte_utilization().unwrap();
    assert!(store
        .check_and_insert_through("other", "cap", u64::MAX)
        .is_err());
    assert_eq!(store.identity_byte_utilization().unwrap(), usage);
    store.inner.lock().unwrap().identity_byte_capacity += 1;
    assert!(store.verify_exact(&sealed).is_err());
    store.inner.lock().unwrap().identity_byte_capacity -= 1;
    store.inner.lock().unwrap().identity_bytes -= 1;
    assert!(store.verify_exact(&sealed).is_err());
}

#[test]
#[should_panic(expected = "identity byte capacity must be greater than zero")]
fn zero_identity_byte_capacity_is_rejected() {
    let _ = DpopNonceStore::new_with_identity_byte_capacity(1, 1, 0, Duration::ZERO);
}
