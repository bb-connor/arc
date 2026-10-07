//! Fixed owned command capacity independent of the caller's async executor.
use super::RecoveryRuntimeError;
use std::{
    collections::BTreeMap,
    future::Future,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{mpsc, Arc, Mutex, OnceLock},
    thread,
};
use tokio::{
    runtime::Runtime,
    sync::{oneshot, watch, OwnedSemaphorePermit, Semaphore},
};

const WORKERS: usize = 4;
const PER_PRINCIPAL: usize = 2;
type Work = Box<dyn FnOnce(&Runtime) + Send + 'static>;
#[cfg(test)]
type PrincipalRefusalObserver = dyn Fn(&str) + Send + Sync + 'static;

struct Job {
    work: Work,
    _permit: PrincipalPermit,
}

struct PrincipalPermit {
    principal: String,
    principals: Arc<Mutex<BTreeMap<String, usize>>>,
    _capacity: OwnedSemaphorePermit,
}

impl Drop for PrincipalPermit {
    fn drop(&mut self) {
        if let Ok(mut principals) = self.principals.lock() {
            if let Some(count) = principals.get_mut(&self.principal) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    principals.remove(&self.principal);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct WorkerState {
    ready: usize,
    exited: usize,
    failed: bool,
}

struct WorkerLifecycle {
    state: watch::Sender<WorkerState>,
    sender: Arc<Mutex<Option<mpsc::SyncSender<Job>>>>,
}

impl WorkerLifecycle {
    fn fail(&self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        self.state.send_modify(|state| state.failed = true);
    }
    fn ready(&self) {
        self.state.send_modify(|state| state.ready += 1);
    }
}

struct WorkerExit(Arc<WorkerLifecycle>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.fail();
        self.0.state.send_modify(|state| state.exited += 1);
    }
}

pub(super) struct CommandExecutor {
    sender: Arc<Mutex<Option<mpsc::SyncSender<Job>>>>,
    lifecycle: Arc<WorkerLifecycle>,
    state: watch::Receiver<WorkerState>,
    capacity: Arc<Semaphore>,
    principals: Arc<Mutex<BTreeMap<String, usize>>>,
    _workers: Vec<thread::JoinHandle<()>>,
    #[cfg(test)]
    principal_refusal_observer: Mutex<Option<Arc<PrincipalRefusalObserver>>>,
}

impl CommandExecutor {
    /// Initialization is retained process-wide even if its first waiter is
    /// cancelled. No caller cancellation can spawn another partial pool.
    pub(super) async fn shared() -> Result<&'static Self, RecoveryRuntimeError> {
        static EXECUTOR: OnceLock<CommandExecutor> = OnceLock::new();
        let executor = EXECUTOR.get_or_init(Self::new);
        executor.ready().await?;
        Ok(executor)
    }

    fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Job>(WORKERS);
        let sender = Arc::new(Mutex::new(Some(sender)));
        let receiver = Arc::new(Mutex::new(receiver));
        let (state, observed) = watch::channel(WorkerState::default());
        let lifecycle = Arc::new(WorkerLifecycle {
            state,
            sender: sender.clone(),
        });
        let mut workers = Vec::with_capacity(WORKERS);
        for index in 0..WORKERS {
            let receiver = receiver.clone();
            let lifecycle = lifecycle.clone();
            let worker_lifecycle = lifecycle.clone();
            match thread::Builder::new()
                .name(format!("chio-recovery-command-{index}"))
                .spawn(move || {
                    let _exit = WorkerExit(worker_lifecycle.clone());
                    // Construct and drop the Tokio driver on its owned OS
                    // thread, including every failed-startup path.
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(_) => return,
                    };
                    worker_lifecycle.ready();
                    worker(receiver, runtime);
                }) {
                Ok(handle) => workers.push(handle),
                Err(_) => {
                    lifecycle.fail();
                    break;
                }
            }
        }
        Self {
            sender,
            lifecycle,
            state: observed,
            capacity: Arc::new(Semaphore::new(WORKERS)),
            principals: Arc::new(Mutex::new(BTreeMap::new())),
            _workers: workers,
            #[cfg(test)]
            principal_refusal_observer: Mutex::new(None),
        }
    }

    async fn ready(&self) -> Result<(), RecoveryRuntimeError> {
        let mut observed = self.state.clone();
        loop {
            let state = *observed.borrow();
            if state.failed {
                // A failed pool never accepts work. All partial workers leave
                // after channel closure; no native command has been queued.
                if state.exited == self._workers.len() {
                    return Err(RecoveryRuntimeError::Unavailable);
                }
            } else if state.ready == WORKERS {
                return Ok(());
            }
            observed
                .changed()
                .await
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        }
    }

    #[cfg(test)]
    fn observe_principal_refusal_for_test(&self, principal: &str) {
        let observer = self
            .principal_refusal_observer
            .lock()
            .ok()
            .and_then(|observer| observer.clone());
        if let Some(observer) = observer {
            observer(principal);
        }
    }

    /// At most four accepted jobs and two per checked authority/subject.
    /// Capacity includes queued, running and disconnected work through completion.
    pub(super) fn try_submit<T: Send + 'static>(
        &self,
        principal: String,
        fixed_time: Option<u64>,
        future: impl Future<Output = Result<T, RecoveryRuntimeError>> + Send + 'static,
    ) -> Result<oneshot::Receiver<Result<T, RecoveryRuntimeError>>, RecoveryRuntimeError> {
        if self.state.borrow().failed {
            return Err(RecoveryRuntimeError::Unavailable);
        }
        let capacity = {
            let mut principals = self
                .principals
                .lock()
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
            let count = principals.get(&principal).copied().unwrap_or_default();
            if count >= PER_PRINCIPAL {
                // Pause only a real principal refusal in the default-off test
                // bridge. No principal lock spans the observer.
                drop(principals);
                #[cfg(test)]
                self.observe_principal_refusal_for_test(&principal);
                return Err(RecoveryRuntimeError::Unavailable);
            }
            // Refused work neither owns global capacity nor inserts an idle
            // principal. Both reservations are made under this bounded lock.
            let capacity = self
                .capacity
                .clone()
                .try_acquire_owned()
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
            principals.insert(principal.clone(), count + 1);
            capacity
        };
        let permit = PrincipalPermit {
            principal,
            principals: self.principals.clone(),
            _capacity: capacity,
        };
        let (reply, response) = oneshot::channel();
        // The owning job moves only its pinned pointer through unwind and
        // runtime frames. Large native command futures stay on the heap.
        let future = Box::pin(future);
        let work = Box::new(move |runtime: &Runtime| {
            let _clock = fixed_time.map(chio_kernel::scope_fixed_runtime_clock_for_current_thread);
            let result = catch_unwind(AssertUnwindSafe(|| runtime.block_on(future)))
                .unwrap_or(Err(RecoveryRuntimeError::Unavailable));
            let _ = reply.send(result);
        });
        self.sender
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?
            .as_ref()
            .ok_or(RecoveryRuntimeError::Unavailable)?
            .try_send(Job {
                work,
                _permit: permit,
            })
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        Ok(response)
    }
}

impl Drop for CommandExecutor {
    fn drop(&mut self) {
        self.lifecycle.fail();
        // Accepted jobs retain their own permits and completion senders.
        // Closing this bounded channel cannot cancel or resubmit them.
    }
}

fn worker(receiver: Arc<Mutex<mpsc::Receiver<Job>>>, runtime: Runtime) {
    loop {
        let job = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => return,
        };
        let Ok(Job { work, _permit }) = job else {
            return;
        };
        // No queue or principal mutex spans native work. Contained failures
        // finish this exact job; they never create another admission attempt.
        let _ = catch_unwind(AssertUnwindSafe(|| work(&runtime)));
    }
}

#[cfg(test)]
mod tests;
