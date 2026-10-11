use super::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use chio_test_support::prelude::*;

const HANG_GUARD: Duration = Duration::from_secs(30);
const SHORT_BUDGET: Duration = Duration::from_millis(250);

/// Occupy the pool's only worker with a job parked until the returned sender
/// fires, returning once that job has started.
pub(crate) fn park_the_worker(
    pool: &Arc<BoundedWorkerPool>,
) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let parked = Arc::clone(pool);
    let caller = std::thread::spawn(move || {
        parked
            .run_within_budget(HANG_GUARD, move || {
                entered_tx.send(()).test_unwrap();
                release_rx.recv_timeout(HANG_GUARD).test_unwrap();
            })
            .test_unwrap();
    });
    entered_rx.recv_timeout(HANG_GUARD).test_unwrap();
    (release_tx, caller)
}

/// Returns once every job queued before this call has been dequeued by the
/// pool's single worker.
pub(crate) fn drain(pool: &BoundedWorkerPool) {
    pool.run_within_budget(HANG_GUARD, || ()).test_unwrap();
}

#[test]
fn healthy_job_answers_within_its_budget() {
    let pool = BoundedWorkerPool::new(1, 1);
    assert_eq!(pool.run_within_budget(HANG_GUARD, || 7u32), Ok(7));
}

#[test]
fn empty_budget_is_refused_without_running_the_job() {
    let pool = BoundedWorkerPool::new(1, 1);
    let ran = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&ran);
    let outcome = pool.run_within_budget(Duration::ZERO, move || {
        observed.store(true, Ordering::SeqCst)
    });
    assert_eq!(outcome, Err(BudgetElapsed));
    drain(&pool);
    assert!(!ran.load(Ordering::SeqCst));
}

#[test]
fn queued_job_is_skipped_after_its_deadline() {
    let pool = Arc::new(BoundedWorkerPool::new(1, 1));
    let (release, caller) = park_the_worker(&pool);
    let ran = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&ran);

    let outcome =
        pool.run_within_budget(SHORT_BUDGET, move || observed.store(true, Ordering::SeqCst));
    assert_eq!(outcome, Err(BudgetElapsed));

    release.send(()).test_unwrap();
    caller.join().test_unwrap();
    drain(&pool);
    assert!(
        !ran.load(Ordering::SeqCst),
        "a job dequeued after its deadline must not run"
    );
}

#[test]
fn started_job_runs_to_completion_after_its_caller_fails_closed() {
    let pool = BoundedWorkerPool::new(1, 1);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let completed = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&completed);

    let outcome = pool.run_within_budget(SHORT_BUDGET, move || {
        entered_tx.send(()).test_unwrap();
        release_rx.recv_timeout(HANG_GUARD).test_unwrap();
        observed.store(true, Ordering::SeqCst);
    });
    assert_eq!(outcome, Err(BudgetElapsed));

    entered_rx.recv_timeout(HANG_GUARD).test_unwrap();
    release_tx.send(()).test_unwrap();
    drain(&pool);
    assert!(
        completed.load(Ordering::SeqCst),
        "a started job must run to completion"
    );
}
