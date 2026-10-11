//! A fixed pool of persistent worker threads that runs blocking jobs against
//! an absolute deadline.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

/// A job produced no outcome observed before its deadline, or the pool refused
/// it at once because it was saturated or the deadline had already passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeadlinePassed;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// A fixed-size pool of persistent worker threads for blocking jobs that must
/// answer before a deadline.
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

    /// Run `job` against `deadline`, returning its outcome or
    /// [`DeadlinePassed`]. The job starts only before the deadline, the caller
    /// waits only until it, and an outcome is accepted only when observed
    /// before it. Fails closed immediately for a passed deadline, or when every
    /// worker is parked and the queue is full, so a stalled dependency can
    /// never grow the pool past its fixed worker count.
    pub(crate) fn run_until<F, T>(&self, deadline: Instant, job: F) -> Result<T, DeadlinePassed>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        observed_before(deadline, ())?;
        let (done, outcome) = sync_channel::<T>(1);
        let job: Job = Box::new(move || {
            if observed_before(deadline, ()).is_err() {
                return;
            }
            // The caller may have already failed closed and dropped `outcome`;
            // the send then fails and the completed job is simply discarded.
            let _ = done.send(job());
        });
        self.submit.try_send(job).map_err(|_| DeadlinePassed)?;
        let outcome = outcome
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| DeadlinePassed)?;
        observed_before(deadline, outcome)
    }
}

/// Accept `outcome` only when it is observed strictly before `deadline`.
fn observed_before<T>(deadline: Instant, outcome: T) -> Result<T, DeadlinePassed> {
    if Instant::now() < deadline {
        Ok(outcome)
    } else {
        Err(DeadlinePassed)
    }
}

#[cfg(test)]
#[path = "bounded_worker_pool_tests.rs"]
pub(crate) mod tests;
