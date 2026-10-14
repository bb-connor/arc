//! Settlement workers are owned independently of Tokio intake blocking capacity.
use super::RecoveryRuntimeError;
use chio_kernel::recovery::RecoveryCommandResponseV1;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{mpsc, Arc, Mutex},
    thread,
};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

type Result = std::result::Result<RecoveryCommandResponseV1, RecoveryRuntimeError>;
type Work = Box<dyn FnOnce() -> Result + Send>;
type Routine = Box<dyn FnOnce() + Send>;
struct Job {
    work: Work,
    reply: oneshot::Sender<Result>,
    _permit: OwnedSemaphorePermit,
}
/// Two outstanding jobs include active work, queued work and disconnected work.
/// Closing stops intake; accepted reconciliation finishes without resubmission.
pub(super) struct SettlementExecutor {
    sender: Mutex<Option<mpsc::SyncSender<Job>>>,
    capacity: Arc<Semaphore>,
    workers: Vec<thread::JoinHandle<()>>,
}
impl SettlementExecutor {
    pub(super) fn new() -> std::result::Result<Self, RecoveryRuntimeError> {
        Self::start_with(|index, routine| {
            thread::Builder::new()
                .name(format!("chio-recovery-settle-{index}"))
                .spawn(routine)
        })
    }
    fn start_with(
        mut start: impl FnMut(usize, Routine) -> std::io::Result<thread::JoinHandle<()>>,
    ) -> std::result::Result<Self, RecoveryRuntimeError> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(2);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(2);
        for index in 0..2 {
            let receiver = receiver.clone();
            match start(index, Box::new(move || worker(receiver))) {
                Ok(handle) => workers.push(handle),
                Err(_) => {
                    drop(sender);
                    // No job can have been submitted during construction.
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(RecoveryRuntimeError::Unavailable);
                }
            }
        }
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            capacity: Arc::new(Semaphore::new(2)),
            workers,
        })
    }
    pub(super) fn try_submit(
        &self,
        work: Work,
    ) -> std::result::Result<oneshot::Receiver<Result>, RecoveryRuntimeError> {
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        let (reply, response) = oneshot::channel();
        let sender = self
            .sender
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        sender
            .as_ref()
            .ok_or(RecoveryRuntimeError::Unavailable)?
            .try_send(Job {
                work,
                reply,
                _permit: permit,
            })
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        Ok(response)
    }
    fn close(&self) -> std::result::Result<(), RecoveryRuntimeError> {
        self.sender
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?
            .take();
        Ok(())
    }
}
impl Drop for SettlementExecutor {
    fn drop(&mut self) {
        let _ = self.close();
        // Do not block a disconnected HTTP task or cancel accepted native work.
        // Channel closure makes both workers exit after at most two owned jobs.
        // Each native job retains its permit and result sender independently.
        for worker in self.workers.drain(..) {
            drop(worker);
        }
    }
}
fn worker(receiver: Arc<Mutex<mpsc::Receiver<Job>>>) {
    loop {
        let job = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => return,
        };
        let Ok(job) = job else {
            return;
        };
        let Job {
            work,
            reply,
            _permit,
        } = job;
        // No intake, native store or receiver mutex spans reconciliation.
        let result =
            catch_unwind(AssertUnwindSafe(work)).unwrap_or(Err(RecoveryRuntimeError::Unavailable));
        let _ = reply.send(result);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn reserved_disconnect_and_shutdown_preserve_two_owned_jobs(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let executor = SettlementExecutor::new()?;
        let (started, observations) = mpsc::channel();
        let mut releases = Vec::new();
        for _ in 0..2 {
            let started = started.clone();
            let (release, wait) = mpsc::channel();
            releases.push(release);
            let response = executor.try_submit(Box::new(move || {
                let _ = started.send(());
                let _ = wait.recv();
                Err(RecoveryRuntimeError::AuthorityDenied)
            }))?;
            drop(response);
        }
        observations.recv_timeout(Duration::from_secs(2))?;
        observations.recv_timeout(Duration::from_secs(2))?;
        assert!(executor
            .try_submit(Box::new(|| Err(RecoveryRuntimeError::Conflict)))
            .is_err());
        assert_eq!(executor.capacity.available_permits(), 0);
        executor.close()?;
        assert!(executor
            .try_submit(Box::new(|| Err(RecoveryRuntimeError::Conflict)))
            .is_err());
        for release in releases {
            release.send(())?;
        }
        let start = std::time::Instant::now();
        while executor.capacity.available_permits() != 2 && start.elapsed() < Duration::from_secs(2)
        {
            std::thread::yield_now();
        }
        assert_eq!(executor.capacity.available_permits(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn reserved_panic_refuses_and_does_not_destroy_the_worker(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let executor = SettlementExecutor::new()?;
        let response = executor.try_submit(Box::new(|| panic!("reserved worker panic")))?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), response)
                .await??
                .err(),
            Some(RecoveryRuntimeError::Unavailable)
        );
        let response =
            executor.try_submit(Box::new(|| Err(RecoveryRuntimeError::InvalidCommand)))?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), response)
                .await??
                .err(),
            Some(RecoveryRuntimeError::InvalidCommand)
        );
        Ok(())
    }

    #[test]
    fn reserved_partial_startup_failure_reaps_the_first_worker(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (ended, observation) = mpsc::channel();
        let result = SettlementExecutor::start_with(|index, routine| {
            if index == 1 {
                return Err(std::io::Error::other("task startup failure"));
            }
            let ended = ended.clone();
            std::thread::Builder::new().spawn(move || {
                routine();
                let _ = ended.send(());
            })
        });
        assert!(result.is_err());
        observation.recv_timeout(Duration::from_secs(2))?;
        Ok(())
    }
}
