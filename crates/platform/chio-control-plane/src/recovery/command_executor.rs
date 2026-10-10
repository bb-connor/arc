//! Finite native work domains independent of the caller's async executor.
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
#[derive(Clone, Copy)]
enum ExecutionDomain {
    Command,
    ProviderFinality,
}
impl ExecutionDomain {
    const fn workers(self) -> usize {
        match self {
            Self::Command => WORKERS,
            Self::ProviderFinality => 2,
        }
    }
    const fn per_principal(self) -> usize {
        match self {
            Self::Command => PER_PRINCIPAL,
            Self::ProviderFinality => 1,
        }
    }
    const fn thread_prefix(self) -> &'static str {
        match self {
            Self::Command => "chio-recovery-command",
            Self::ProviderFinality => "chio-recovery-finality",
        }
    }
}
type Work = Box<dyn FnOnce(&Runtime, PrincipalPermit) + Send + 'static>;
#[cfg(test)]
type PrincipalRefusalObserver = dyn Fn(&str) + Send + Sync + 'static;
#[cfg(test)]
type ReplyPublicationObserver = dyn Fn(&str) + Send + Sync + 'static;

struct Job {
    work: Work,
    permit: PrincipalPermit,
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
    domain: ExecutionDomain,
    sender: Arc<Mutex<Option<mpsc::SyncSender<Job>>>>,
    lifecycle: Arc<WorkerLifecycle>,
    state: watch::Receiver<WorkerState>,
    capacity: Arc<Semaphore>,
    principals: Arc<Mutex<BTreeMap<String, usize>>>,
    _workers: Vec<thread::JoinHandle<()>>,
    #[cfg(test)]
    principal_refusal_observer: Mutex<Option<Arc<PrincipalRefusalObserver>>>,
    #[cfg(test)]
    reply_publication_observer: Mutex<Option<Arc<ReplyPublicationObserver>>>,
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

    /// Two retained finality workers are independent of all command capacity.
    /// One outstanding native phase per checked authority/subject leaves the
    /// other slot available to another settlement principal.
    pub(super) async fn shared_provider_finality() -> Result<&'static Self, RecoveryRuntimeError> {
        static EXECUTOR: OnceLock<CommandExecutor> = OnceLock::new();
        let executor =
            EXECUTOR.get_or_init(|| Self::new_in_domain(ExecutionDomain::ProviderFinality));
        executor.ready().await?;
        Ok(executor)
    }

    fn new() -> Self {
        Self::new_in_domain(ExecutionDomain::Command)
    }

    fn new_in_domain(domain: ExecutionDomain) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Job>(domain.workers());
        let sender = Arc::new(Mutex::new(Some(sender)));
        let receiver = Arc::new(Mutex::new(receiver));
        let (state, observed) = watch::channel(WorkerState::default());
        let lifecycle = Arc::new(WorkerLifecycle {
            state,
            sender: sender.clone(),
        });
        let mut workers = Vec::with_capacity(domain.workers());
        for index in 0..domain.workers() {
            let receiver = receiver.clone();
            let lifecycle = lifecycle.clone();
            let worker_lifecycle = lifecycle.clone();
            match thread::Builder::new()
                .name(format!("{}-{index}", domain.thread_prefix()))
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
            domain,
            sender,
            lifecycle,
            state: observed,
            capacity: Arc::new(Semaphore::new(domain.workers())),
            principals: Arc::new(Mutex::new(BTreeMap::new())),
            _workers: workers,
            #[cfg(test)]
            principal_refusal_observer: Mutex::new(None),
            #[cfg(test)]
            reply_publication_observer: Mutex::new(None),
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
            } else if state.ready == self.domain.workers() {
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

    /// Commands admit four jobs and two per checked authority/subject. Provider
    /// finality admits two jobs and one per checked authority/subject.
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
            if count >= self.domain.per_principal() {
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
        #[cfg(test)]
        let reply_observer = self
            .reply_publication_observer
            .lock()
            .ok()
            .and_then(|observer| observer.clone());
        #[cfg(test)]
        let observed_principal = permit.principal.clone();
        // The owning job moves only its pinned pointer through unwind and
        // runtime frames. Large native command futures stay on the heap.
        let future = Box::pin(future);
        let work = Box::new(move |runtime: &Runtime, permit: PrincipalPermit| {
            let _clock = fixed_time.map(chio_kernel::scope_fixed_runtime_clock_for_current_thread);
            let result = catch_unwind(AssertUnwindSafe(|| runtime.block_on(future)))
                .unwrap_or(Err(RecoveryRuntimeError::Unavailable));
            // Completion and unwind retain this exact permit. Release it before
            // waking a caller that may immediately submit its next native phase.
            drop(permit);
            let _ = reply.send(result);
            #[cfg(test)]
            if let Some(observer) = reply_observer {
                // Observe a real published reply outside queue/principal locks.
                // The default-off bridge grants no native execution authority.
                observer(&observed_principal);
            }
        });
        self.sender
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?
            .as_ref()
            .ok_or(RecoveryRuntimeError::Unavailable)?
            .try_send(Job { work, permit })
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
        let Ok(Job { work, permit }) = job else {
            return;
        };
        // No queue or principal mutex spans native work. Contained failures
        // finish this exact job; they never create another admission attempt.
        let _ = catch_unwind(AssertUnwindSafe(|| work(&runtime, permit)));
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod finality_tests;
