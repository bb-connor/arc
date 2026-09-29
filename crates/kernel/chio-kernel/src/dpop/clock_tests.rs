use super::*;
use crate::admission_operation::AdmissionIdentifier;
use crate::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
use crate::replay_retention::tests::TestClock;
use chio_security_types::clock::ClockError;

pub(super) fn store(clock: Arc<TestClock>, capacity: usize) -> DpopNonceStore {
    DpopNonceStore::with_clock(
        capacity,
        capacity,
        DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
        Duration::from_secs(10),
        clock,
    )
    .expect("positive replay store test capacities")
}
#[test]
fn injected_time_preserves_inclusive_horizon_and_retry_window() {
    let clock = Arc::new(TestClock::new(100));
    let store = store(clock.clone(), 1);
    assert!(store.check_and_insert_through("nonce", "cap", 110).unwrap());
    clock.set(110, 10);
    assert!(!store.check_and_insert_through("nonce", "cap", 999).unwrap());
    assert!(matches!(
        store.check_and_insert_through("other", "cap", 120),
        Err(KernelError::Dpop(DpopError::Capacity))
    ));
    clock.set(111, 11);
    assert!(store.check_and_insert_through("other", "cap", 120).unwrap());
    assert_eq!(store.utilization().unwrap().0, 1);
}
#[test]
fn failure_and_regression_preserve_custody_and_exact_owner_cleanup() {
    let clock = Arc::new(TestClock::new(100));
    let store = store(clock.clone(), 2);
    assert!(store
        .reserve_for_dispatch_through("nonce", "cap", 110, "owner")
        .unwrap());
    clock.fail();
    assert!(matches!(
        store.check_and_insert_through("other", "cap", 110),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert!(!store
        .rollback_dispatch_reservation("nonce", "cap", "other")
        .unwrap());
    assert_eq!(store.utilization().unwrap().0, 1);
    clock.set(99, 1);
    assert!(matches!(
        store.check_and_insert_through("other", "cap", 110),
        Err(KernelError::Clock(ClockError::WallClockRegression))
    ));
    clock.fail();
    assert!(store
        .rollback_dispatch_reservation("nonce", "cap", "owner")
        .unwrap());
    assert_eq!(store.utilization().unwrap().0, 0);
}
#[test]
fn first_clock_failure_does_not_publish_a_source_or_marker() {
    let clock = Arc::new(TestClock::new(100));
    clock.fail();
    let store = store(clock.clone(), 1);
    assert!(matches!(
        store.check_and_insert("nonce", "cap"),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(store.utilization().unwrap().0, 0);
    clock.set(100, 0);
    assert!(store.check_and_insert("nonce", "cap").unwrap());
}
#[test]
fn source_seal_uses_injected_clock_without_repair_or_history_loss() {
    let clock = Arc::new(TestClock::new(100));
    let store = store(clock.clone(), 1);
    let binding = DpopReplaySourceBinding {
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "dpop").unwrap(),
        destination_authority_id: AdmissionIdentifier::try_new("destination", "kernel").unwrap(),
    };
    assert!(store.check_and_insert_through("nonce", "cap", 110).unwrap());
    let snapshot = store.preview_unsealed(&binding).unwrap();
    clock.fail();
    assert!(matches!(
        store.seal_exact(&snapshot),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    clock.set(99, 1);
    assert!(matches!(
        store.preview_unsealed(&binding),
        Err(KernelError::Clock(ClockError::WallClockRegression))
    ));
    clock.set(101, 1);
    store.seal_exact(&snapshot).unwrap();
    store.verify_exact(&snapshot).unwrap();
    assert_eq!(store.utilization().unwrap().0, 1);
}
#[test]
fn clock_is_sampled_after_waiting_for_the_reservation_lock() {
    let clock = Arc::new(TestClock::new(100));
    let store = Arc::new(store(clock.clone(), 1));
    let lock = store.inner.lock().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = {
        let store = store.clone();
        std::thread::spawn(move || {
            tx.send(()).unwrap();
            store.check_and_insert_until("nonce", "cap", 101)
        })
    };
    rx.recv().unwrap();
    clock.set(101, 1);
    drop(lock);
    assert!(matches!(
        worker.join().unwrap(),
        Err(KernelError::Dpop(DpopError::Expired))
    ));
    assert_eq!(store.utilization().unwrap().0, 0);
}
#[test]
fn suspend_rebaseline_cannot_reopen_a_live_marker() {
    let clock = Arc::new(TestClock::new(100));
    let store = store(clock.clone(), 3);
    assert!(store.check_and_insert_until("nonce", "cap", 10000).unwrap());
    clock.set(3700, 1);
    assert!(matches!(
        store.check_and_insert("probe", "cap"),
        Err(KernelError::ReplayClockAnomaly { .. })
    ));
    clock.set(3701, 2);
    assert!(store.check_and_insert("probe", "cap").unwrap());
    assert!(!store.check_and_insert_until("nonce", "cap", 10000).unwrap());
}

#[test]
fn commit_disables_owner_rollback_without_sampling_an_unavailable_clock() {
    let clock = Arc::new(TestClock::new(100));
    let store = store(clock.clone(), 1);
    assert!(store
        .reserve_for_dispatch_through("nonce", "cap", 110, "owner")
        .unwrap());
    let bytes = store.identity_byte_utilization().unwrap().0;
    clock.fail();
    assert!(!store
        .commit_dispatch_reservation("nonce", "cap", "wrong")
        .unwrap());
    assert!(store
        .commit_dispatch_reservation("nonce", "cap", "owner")
        .unwrap());
    assert!(!store
        .rollback_dispatch_reservation("nonce", "cap", "owner")
        .unwrap());
    assert_eq!(
        store.identity_byte_utilization().unwrap().0,
        bytes - "owner".len()
    );
    clock.set(101, 1);
    assert!(!store.check_and_insert_through("nonce", "cap", 120).unwrap());
}
