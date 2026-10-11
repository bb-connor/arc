//! A fixed pool of persistent worker threads that runs blocking jobs under a
//! wall-clock budget.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// A job did not produce its outcome within the caller's budget, or the pool
/// refused it at once because it was saturated or the budget was empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BudgetElapsed;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// A fixed-size pool of persistent worker threads for blocking jobs that must
/// answer within a budget.
///
/// Running each job on a fresh detached thread would let sustained traffic
/// against a stalled dependency accumulate one parked thread per job and
/// eventually exhaust process threads. This pool caps the number of
/// concurrently parked jobs at a fixed worker count: once every worker is
/// parked and the small queue is full, further submissions fail closed instead
/// of spawning more threads. A job still queued at its deadline is dropped
/// unrun. A job that started before its deadline runs to completion on its
/// worker, and its result is discarded once the caller has failed closed.
pub(crate) struct BoundedWorkerPool {
    submit: SyncSender<Job>,
}

impl BoundedWorkerPool {
    pub(crate) fn new(workers: usize, queue_depth: usize) -> Self {
        let (submit, receive) = sync_channel::<Job>(queue_depth);
        let receive = Arc::new(Mutex::new(receive));
        for _ in 0..workers.max(1) {
            let receive = Arc::clone(&receive);
            std::thread::spawn(move || Self::run_worker(&receive));
        }
        Self { submit }
    }

    fn run_worker(receive: &Mutex<Receiver<Job>>) {
        loop {
            // Hold the lock only to dequeue, never while running the job, so a
            // worker parked on a stalled job does not block its peers from
            // dequeuing the next one.
            let job = {
                let guard = receive.lock().unwrap_or_else(PoisonError::into_inner);
                guard.recv()
            };
            match job {
                Ok(job) => job(),
                // Every submitter has dropped: the pool is gone, so exit.
                Err(_) => break,
            }
        }
    }

    /// Run `job` under `budget`, returning its outcome or [`BudgetElapsed`].
    /// The budget becomes one absolute deadline at submission: the job starts
    /// only before it and the caller waits only until it. Fails closed
    /// immediately for an empty budget, or when every worker is parked and the
    /// queue is full, so a stalled dependency can never grow the pool past its
    /// fixed worker count.
    pub(crate) fn run_within_budget<F, T>(
        &self,
        budget: Duration,
        job: F,
    ) -> Result<T, BudgetElapsed>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        if budget.is_zero() {
            return Err(BudgetElapsed);
        }
        let deadline = Instant::now().checked_add(budget).ok_or(BudgetElapsed)?;
        let (done, outcome) = sync_channel::<T>(1);
        let job: Job = Box::new(move || {
            if Instant::now() >= deadline {
                return;
            }
            // The caller may have already failed closed and dropped `outcome`;
            // the send then fails and the completed job is simply discarded.
            let _ = done.send(job());
        });
        self.submit.try_send(job).map_err(|_| BudgetElapsed)?;
        outcome
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| BudgetElapsed)
    }
}

#[cfg(test)]
#[path = "bounded_worker_pool_tests.rs"]
pub(crate) mod tests;
