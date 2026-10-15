use super::*;
use crate::admission_operation::AdmissionIdentifier;
use crate::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
use crate::dpop::*;
use crate::replay_retention::tests::TestClock;
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
    for bad_part in 0..2 {
        let store =
            DpopNonceStore::new(8, Duration::ZERO).expect("positive replay store test capacities");
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
        for result in [
            store.check_and_insert(nonce, cap),
            store.check_and_insert_until(nonce, cap, u64::MAX),
            store.check_and_insert_through(nonce, cap, u64::MAX),
        ] {
            let error = result.unwrap_err();
            assert!(matches!(error, KernelError::Dpop(DpopError::IdentityLimit)));
            assert!(!error.to_string().contains("secret-identity"));
        }
        assert_eq!(snapshot(&store), before);
        assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
    }
}

#[test]
fn limits_measure_utf8_bytes_and_keep_identity_text_exact() {
    let store = DpopNonceStore::new(8, Duration::from_secs(60))
        .expect("positive replay store test capacities");
    let boundary = "é".repeat(MAX_DPOP_REPLAY_IDENTITY_PART_BYTES / 2);
    assert!(store
        .check_and_insert_through(&boundary, "cap", u64::MAX)
        .unwrap());
    assert!(!store
        .check_and_insert_through(&boundary, "cap", u64::MAX)
        .unwrap());
    assert!(matches!(
        store.check_and_insert_through(&(boundary.clone() + "é"), "cap", u64::MAX),
        Err(KernelError::Dpop(DpopError::IdentityLimit))
    ));
    assert_eq!(
        store.identity_byte_utilization().unwrap().0,
        boundary.len() + 6
    );
    assert!(store
        .check_and_insert_through("é", "cap", u64::MAX)
        .unwrap());
    assert!(store
        .check_and_insert_through("e\u{301}", "cap", u64::MAX)
        .unwrap());
    assert!(store
        .check_and_insert_through(" é ", "cap", u64::MAX)
        .unwrap());
    assert_eq!(store.utilization().unwrap().0, 4);
}

#[test]
fn byte_pressure_never_evicts_a_live_marker() {
    let capacity = retained_bytes("nonce", "cap").unwrap();
    let store =
        DpopNonceStore::new_with_identity_byte_capacity(8, 8, capacity, Duration::from_secs(60))
            .expect("positive replay store test capacities");
    assert!(store
        .check_and_insert_through("nonce", "cap", u64::MAX)
        .unwrap());
    assert_eq!(
        store.identity_byte_utilization().unwrap(),
        (capacity, capacity)
    );
    assert!(matches!(
        store.check_and_insert_through("other", "cap", u64::MAX),
        Err(KernelError::Dpop(DpopError::IdentityCapacity))
    ));
    assert!(!store
        .check_and_insert_through("nonce", "cap", u64::MAX)
        .unwrap());
    assert_eq!(store.utilization().unwrap().0, 1);
    assert_eq!(store.identity_byte_utilization().unwrap().0, capacity);
}

#[test]
fn expired_reclamation_and_shared_capability_cleanup_return_the_exact_charge() {
    let clock = Arc::new(TestClock::new(100));
    let store = DpopNonceStore::with_clock(8, 8, 100, Duration::from_secs(10), clock.clone())
        .expect("positive replay store test capacities");
    store.check_and_insert("expired", "cap").unwrap();
    assert_eq!(store.identity_byte_utilization().unwrap().0, 13);
    clock.set(110, 10);
    assert!(store.check_and_insert_until("a", "cap", 120).unwrap());
    assert_eq!(store.identity_byte_utilization().unwrap().0, 7);
    assert!(store.check_and_insert_until("b", "cap", 130).unwrap());
    assert_eq!(store.identity_byte_utilization().unwrap().0, 14);
    clock.set(120, 20);
    assert!(matches!(
        store.check_and_insert_until("elapsed", "trigger", 120),
        Err(KernelError::Dpop(DpopError::Expired))
    ));
    assert_eq!(store.identity_byte_utilization().unwrap().0, 7);
    assert_eq!(
        store.inner.lock().unwrap().capability_counts.get("cap"),
        Some(&1)
    );
    clock.set(130, 30);
    assert!(matches!(
        store.check_and_insert_until("elapsed", "trigger", 130),
        Err(KernelError::Dpop(DpopError::Expired))
    ));
    assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
    assert!(store.inner.lock().unwrap().capability_counts.is_empty());
}

#[test]
fn concurrent_insertions_cannot_oversubscribe_the_byte_budget() {
    let store = Arc::new(
        DpopNonceStore::new_with_identity_byte_capacity(8, 8, 8, Duration::from_secs(60))
            .expect("positive replay store test capacities"),
    );
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
    let store = DpopNonceStore::new_with_identity_byte_capacity(8, 8, 100, Duration::from_secs(60))
        .expect("positive replay store test capacities");
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
fn zero_identity_byte_capacity_is_rejected() {
    assert!(matches!(
        DpopNonceStore::new_with_identity_byte_capacity(1, 1, 0, Duration::ZERO),
        Err(DpopError::InvalidCapacity(_))
    ));
}
