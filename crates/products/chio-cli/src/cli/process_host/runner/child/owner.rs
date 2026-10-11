//! The thread that forks a worker is the thread that reaps it.
//!
//! Linux sends a child's parent-death signal when the thread that forked it
//! exits, not when its process exits. A pooled runtime thread can retire while
//! a child it forked is still live, so every worker is forked by a dedicated
//! owner thread that returns only after reaping that worker. Death of the
//! runner process ends every owner thread, so the kernel still kills each live
//! worker.

use std::io;
use std::sync::mpsc;

use tokio::sync::{oneshot, Semaphore};

use super::{launch_failure, Guard, Observation, Outcome, Spawned, Started};

/// Owner threads in this process. Each keeps its permit until its worker is
/// reaped. The plan's parallelism ceiling keeps runs well below this bound.
pub(super) static OWNERS: Semaphore = Semaphore::const_new(64);

type Arm = (Option<u64>, oneshot::Sender<io::Result<Outcome>>);

/// Releases a worker's owner thread to reap it. Dropped unarmed, it releases
/// the owner without a resident ceiling; the guard has killed the worker.
pub(super) struct Reaper(mpsc::Sender<Arm>);

impl Reaper {
    /// The owner publishes the outcome to the worker's observation before it
    /// replies, so dropping the receiver cannot lose the outcome.
    pub(super) fn reap(
        self,
        resident_ceiling: Option<u64>,
    ) -> oneshot::Receiver<io::Result<Outcome>> {
        let (reply, reaped) = oneshot::channel();
        // A failed send drops the reply, which reports the lost owner.
        let _ = self.0.send((resident_ceiling, reply));
        reaped
    }
}

/// Reserve capacity, then start an owner thread that runs `start` and hands
/// the supervised worker to the returned receiver.
pub(super) fn launch(
    capacity: &'static Semaphore,
    start: impl FnOnce() -> io::Result<Started> + Send + 'static,
) -> io::Result<mpsc::Receiver<io::Result<Spawned>>> {
    let permit = capacity
        .try_acquire()
        .map_err(|_| launch_failure(io::Error::other("worker owner capacity exhausted"), true))?;
    let (handover, launched) = mpsc::channel();
    std::thread::Builder::new()
        .name("chio-run-owner".into())
        .spawn(move || {
            let _permit = permit;
            own(start, handover);
        })
        .map_err(|failure| launch_failure(failure, true))?;
    Ok(launched)
}

fn own(start: impl FnOnce() -> io::Result<Started>, handover: mpsc::Sender<io::Result<Spawned>>) {
    let Started {
        pid,
        child,
        process,
        resident,
    } = match start() {
        Ok(started) => started,
        Err(failure) => {
            let _ = handover.send(Err(failure));
            return;
        }
    };
    let observation = Observation::new();
    let (arm, armed) = mpsc::channel();
    let spawned = Spawned {
        guard: Guard {
            process,
            observation: observation.clone(),
            reaped: false,
        },
        child,
        resident,
        reaper: Reaper(arm),
    };
    if let Err(undelivered) = handover.send(Ok(spawned)) {
        // Nobody took the worker: this kills it and releases the wait below.
        drop(undelivered);
    }
    let (resident_ceiling, reply) = match armed.recv() {
        Ok((resident_ceiling, reply)) => (resident_ceiling, Some(reply)),
        Err(_) => (None, None),
    };
    let reaped = observation.reap(pid, resident_ceiling);
    if let Some(reply) = reply {
        let _ = reply.send(reaped);
    }
}
