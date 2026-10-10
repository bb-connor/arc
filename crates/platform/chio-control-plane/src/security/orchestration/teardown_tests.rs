use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use super::{ActiveDefenseTeardownSupervisor, RetainedActiveDefenseCleanupWork};

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "retained teardown did not complete"
        );
        std::thread::yield_now();
    }
}

#[test]
fn injected_service_spawn_failure_retains_and_completes_the_only_cleanup() {
    let supervisor = Arc::new(ActiveDefenseTeardownSupervisor::new());
    supervisor.fail_next_spawn();
    let permit = supervisor
        .acquire()
        .unwrap_or_else(|error| panic!("acquire retained teardown permit: {error}"));
    let completed = Arc::new(AtomicU64::new(0));
    let completed_for_job = Arc::clone(&completed);
    permit.enqueue(RetainedActiveDefenseCleanupWork::Test(Box::new(
        move || {
            completed_for_job.fetch_add(1, Ordering::AcqRel);
        },
    )));

    wait_until(|| completed.load(Ordering::Acquire) == 1);
    wait_until(|| supervisor.lock_state().retained_owners == 0);
}

#[test]
fn panic_and_replacement_spawn_failure_retain_the_only_cleanup() {
    let supervisor = Arc::new(ActiveDefenseTeardownSupervisor::new());
    let permit = supervisor
        .acquire()
        .unwrap_or_else(|error| panic!("acquire retained teardown permit: {error}"));
    supervisor.panic_next_service_attempt();
    supervisor.fail_next_spawn();
    let completed = Arc::new(AtomicU64::new(0));
    let completed_for_job = Arc::clone(&completed);
    permit.enqueue(RetainedActiveDefenseCleanupWork::Test(Box::new(
        move || {
            completed_for_job.fetch_add(1, Ordering::AcqRel);
        },
    )));

    wait_until(|| completed.load(Ordering::Acquire) == 1);
    wait_until(|| supervisor.lock_state().retained_owners == 0);
}

#[test]
fn concurrent_acquire_never_observes_running_before_spawn_succeeds() {
    let supervisor = Arc::new(ActiveDefenseTeardownSupervisor::new());
    supervisor.fail_next_spawn();
    let start = Arc::new(Barrier::new(3));
    let acquired = Arc::new(Barrier::new(3));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let mut joins = Vec::new();
    for _ in 0..2 {
        let supervisor_for_thread = Arc::clone(&supervisor);
        let start_for_thread = Arc::clone(&start);
        let acquired_for_thread = Arc::clone(&acquired);
        let observations_for_thread = Arc::clone(&observations);
        joins.push(std::thread::spawn(move || {
            start_for_thread.wait();
            let permit = supervisor_for_thread
                .acquire()
                .unwrap_or_else(|error| panic!("concurrent permit acquisition: {error}"));
            let running = supervisor_for_thread.lock_state().service_running;
            observations_for_thread
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(running);
            acquired_for_thread.wait();
            drop(permit);
        }));
    }
    start.wait();
    acquired.wait();
    for join in joins {
        join.join()
            .unwrap_or_else(|_| panic!("concurrent permit acquisition thread panicked"));
    }

    let observations = observations
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(observations.as_slice(), &[true, true]);
}
