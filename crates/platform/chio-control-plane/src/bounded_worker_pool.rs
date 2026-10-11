//! A fixed pool of persistent worker threads that runs blocking jobs under a
//! wall-clock budget.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// A job did not produce its outcome within the caller's budget, or the pool
/// was saturated and refused it at once.
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
/// of spawning more threads. A job that outlives the caller's budget still runs
/// to completion on its worker with its result discarded, since the caller has
/// already failed closed.
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
    /// Fails closed immediately when every worker is parked and the queue is
    /// full, so a stalled dependency can never grow the pool past its fixed
    /// worker count.
    pub(crate) fn run_within_budget<F, T>(
        &self,
        budget: Duration,
        job: F,
    ) -> Result<T, BudgetElapsed>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let (done, outcome) = sync_channel::<T>(1);
        let job: Job = Box::new(move || {
            // The caller may have already failed closed and dropped `outcome`;
            // the send then fails and the completed job is simply discarded.
            let _ = done.send(job());
        });
        self.submit.try_send(job).map_err(|_| BudgetElapsed)?;
        outcome.recv_timeout(budget).map_err(|_| BudgetElapsed)
    }
}
