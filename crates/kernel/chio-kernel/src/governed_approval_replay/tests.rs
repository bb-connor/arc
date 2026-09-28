use crate::replay_retention::tests::TestClock;
use chio_security_types::clock::ClockError;

use super::*;

#[test]
#[should_panic(expected = "governed approval replay capacity must be greater than zero")]
fn zero_capacity_is_rejected() {
    let _store = InMemoryGovernedApprovalReplayStore::new(0);
}

#[test]
fn commit_retains_marker_and_disables_owner_rollback() {
    let store = InMemoryGovernedApprovalReplayStore::with_clock(2, Arc::new(TestClock::new(100)));
    let expires_at = 160;
    assert!(store
        .reserve_for_dispatch("subject", "request", "intent", expires_at, "owner")
        .unwrap_or(false));
    assert!(store
        .commit_dispatch_reservation("subject", "request", "intent", "owner")
        .unwrap_or(false));
    assert!(!store
        .rollback_dispatch_reservation("subject", "request", "intent", "owner")
        .unwrap_or(true));
    assert!(!store
        .reserve_for_dispatch("subject", "request", "intent", expires_at, "other")
        .unwrap_or(true));
}

#[test]
fn rollback_is_owner_qualified() {
    let store = InMemoryGovernedApprovalReplayStore::with_clock(2, Arc::new(TestClock::new(100)));
    let expires_at = 160;
    assert!(store
        .reserve_for_dispatch("subject", "request", "intent", expires_at, "owner")
        .unwrap_or(false));
    assert!(!store
        .rollback_dispatch_reservation("subject", "request", "intent", "other")
        .unwrap_or(true));
    assert!(store
        .rollback_dispatch_reservation("subject", "request", "intent", "owner")
        .unwrap_or(false));
}

#[test]
fn live_capacity_is_not_evicted() {
    let clock = Arc::new(TestClock::new(100));
    let store = InMemoryGovernedApprovalReplayStore::with_clock(1, clock);
    let expires_at = 160;
    assert!(store
        .reserve("subject", "request-a", "intent-a", expires_at, "owner-a")
        .unwrap());
    assert!(matches!(
        store.reserve("subject", "request-b", "intent-b", expires_at, "owner-b",),
        Err(KernelError::ApprovalReplay(ApprovalReplayError::Capacity))
    ));
    assert!(!store
        .reserve_for_dispatch("subject", "request-a", "intent-a", expires_at, "other",)
        .unwrap_or(true));
}

#[test]
fn identical_request_and_intent_are_scoped_by_subject() {
    let store = InMemoryGovernedApprovalReplayStore::with_clock(2, Arc::new(TestClock::new(100)));
    let expires_at = 160;
    assert!(store
        .reserve_for_dispatch("subject-a", "request", "intent", expires_at, "owner-a")
        .unwrap_or(false));
    assert!(store
        .reserve_for_dispatch("subject-b", "request", "intent", expires_at, "owner-b")
        .unwrap_or(false));
}

#[test]
fn clock_faults_and_commit_preserve_marker_custody() {
    let clock = Arc::new(TestClock::new(100));
    let store = InMemoryGovernedApprovalReplayStore::with_clock(2, clock.clone());
    assert!(store
        .reserve_for_dispatch("s", "r", "i", 110, "owner")
        .unwrap());
    clock.fail();
    assert!(matches!(
        store.reserve_for_dispatch("s", "r2", "i", 110, "owner"),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert!(store
        .commit_dispatch_reservation("s", "r", "i", "owner")
        .unwrap());
    assert!(!store
        .rollback_dispatch_reservation("s", "r", "i", "owner")
        .unwrap());
    clock.set(99, 1);
    assert!(matches!(
        store.reserve_for_dispatch("s", "r2", "i", 110, "owner"),
        Err(KernelError::Clock(ClockError::WallClockRegression))
    ));
    clock.set(109, 9);
    assert!(!store
        .reserve_for_dispatch("s", "r", "i", 999, "owner")
        .unwrap());
    clock.set(110, 10);
    assert!(store
        .reserve_for_dispatch("s", "r2", "i", 120, "owner")
        .unwrap());
    clock.fail();
    assert!(store
        .rollback_dispatch_reservation("s", "r2", "i", "owner")
        .unwrap());
}
