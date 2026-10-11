use super::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use chio_test_support::prelude::*;

const HANG_GUARD: Duration = Duration::from_secs(30);
const QUEUED_BUDGET: Duration = Duration::from_millis(250);
/// Long enough that an idle worker always starts the job before the deadline.
const STARTED_BUDGET: Duration = Duration::from_secs(2);

fn deadline_in(budget: Duration) -> Instant {
    Instant::now().checked_add(budget).test_unwrap()
}

/// One worker runs jobs in submission order, and the spare queue slot lets
/// [`drain`] queue behind a job left in the queue, so a completed drain proves
/// that job was dequeued.
pub(crate) fn single_worker_pool() -> BoundedWorkerPool {
    BoundedWorkerPool::new(1, 2)
}

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
            .run_until(deadline_in(HANG_GUARD), move || {
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
    pool.run_until(deadline_in(HANG_GUARD), || ()).test_unwrap();
}

#[test]
fn healthy_job_answers_before_its_deadline() {
    let pool = BoundedWorkerPool::new(1, 1);
    assert_eq!(pool.run_until(deadline_in(HANG_GUARD), || 7u32), Ok(7));
}

#[test]
fn passed_deadline_is_refused_without_running_the_job() {
    let pool = BoundedWorkerPool::new(1, 1);
    let ran = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&ran);
    let outcome = pool.run_until(Instant::now(), move || {
        observed.store(true, Ordering::SeqCst)
    });
    assert_eq!(outcome, Err(DeadlinePassed));
    drain(&pool);
    assert!(!ran.load(Ordering::SeqCst));
}

#[test]
fn ready_outcome_observed_at_the_deadline_is_refused() {
    assert_eq!(observed_before(Instant::now(), 7u32), Err(DeadlinePassed));
    assert_eq!(observed_before(deadline_in(HANG_GUARD), 7u32), Ok(7));
}

#[test]
fn queued_job_is_skipped_after_its_deadline() {
    let pool = Arc::new(single_worker_pool());
    let (release, caller) = park_the_worker(&pool);
    let ran = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&ran);

    let outcome = pool.run_until(deadline_in(QUEUED_BUDGET), move || {
        observed.store(true, Ordering::SeqCst)
    });
    assert_eq!(outcome, Err(DeadlinePassed));

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

    let outcome = pool.run_until(deadline_in(STARTED_BUDGET), move || {
        entered_tx.send(()).test_unwrap();
        release_rx.recv_timeout(HANG_GUARD).test_unwrap();
        observed.store(true, Ordering::SeqCst);
    });
    assert_eq!(outcome, Err(DeadlinePassed));

    entered_rx.recv_timeout(HANG_GUARD).test_unwrap();
    release_tx.send(()).test_unwrap();
    drain(&pool);
    assert!(
        completed.load(Ordering::SeqCst),
        "a started job must run to completion"
    );
}
