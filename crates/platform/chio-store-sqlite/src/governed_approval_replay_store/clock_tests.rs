#![allow(
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
use super::*;
use crate::replay_clock::tests::ManualClock;

#[test]
fn expiry_between_initial_sample_and_writer_lock_keeps_database_unchanged() {
    let clock = crate::replay_clock::tests::StepClock::new(10_000);
    let store =
        SqliteGovernedApprovalReplayStore::open_in_memory_with_clock(4, clock.clone()).unwrap();
    let snapshot = || {
        store
            .pool
            .get()
            .unwrap()
            .query_row(
                "SELECT wall_clock_high_water, pruned_through,
        (SELECT count(*) FROM chio_governed_approval_replay_entries)
        FROM chio_governed_approval_replay_clock",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    let before = snapshot();
    clock.advance_after_reads(1, 10_030, 30);
    assert!(matches!(
        store.reserve_for_dispatch("s", "r", "i", 10_030, "owner"),
        Err(KernelError::Clock(ClockError::Expired))
    ));
    assert_eq!(snapshot(), before);
    assert!(store
        .reserve_for_dispatch("s", "r", "i", 10_031, "owner")
        .unwrap());
}

#[test]
fn injected_clock_faults_preserve_approval_owner_and_retry_window() {
    let clock = ManualClock::new(10_000);
    let store =
        SqliteGovernedApprovalReplayStore::open_in_memory_with_clock(4, clock.clone()).unwrap();
    assert!(store
        .reserve_for_dispatch("s", "r", "i", 10_030, "owner")
        .unwrap());
    clock.fail(ClockError::Unavailable);
    assert!(matches!(
        store.reserve_for_dispatch("s", "r", "i", 10_300, "other"),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    clock.set(9_999, 1);
    assert!(matches!(
        store.reserve_for_dispatch("s", "r2", "i", 10_300, "other"),
        Err(KernelError::Clock(ClockError::WallClockRegression))
    ));
    clock.set(10_001, 2);
    assert!(!store
        .reserve_for_dispatch("s", "r", "i", 10_300, "other")
        .unwrap());
    let expiry: i64 = store
        .pool
        .get()
        .unwrap()
        .query_row(
            "SELECT expires_at FROM chio_governed_approval_replay_entries",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expiry, 10_030);
    assert!(!store
        .rollback_dispatch_reservation("s", "r", "i", "other")
        .unwrap());
    clock.fail(ClockError::Unavailable);
    assert!(store
        .rollback_dispatch_reservation("s", "r", "i", "owner")
        .unwrap());
}

#[test]
fn restart_keeps_approval_consumed_and_checks_durable_clock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approval.sqlite");
    let clock = ManualClock::new(10_000);
    let store =
        SqliteGovernedApprovalReplayStore::open_with_clock(&path, 4, clock.clone()).unwrap();
    assert!(store
        .reserve_for_dispatch("s", "r", "i", 10_030, "owner")
        .unwrap());
    assert!(store
        .commit_dispatch_reservation("s", "r", "i", "owner")
        .unwrap());
    drop(store);
    let store = SqliteGovernedApprovalReplayStore::open_with_clock(&path, 4, clock).unwrap();
    assert!(!store
        .reserve_for_dispatch("s", "r", "i", 10_300, "other")
        .unwrap());
    drop(store);
    assert!(matches!(
        SqliteGovernedApprovalReplayStore::open_with_clock(&path, 4, ManualClock::new(9_000)),
        Err(SqliteGovernedApprovalReplayStoreError::ClockAnomaly {
            direction: ReplayClockDirection::Rollback,
            ..
        })
    ));
}
