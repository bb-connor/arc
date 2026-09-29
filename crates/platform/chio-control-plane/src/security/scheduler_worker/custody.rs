use super::*;

pub(super) const MAX_RESPONSE_WORKER_JOIN_OWNERS: usize = 64;
pub(super) const RESPONSE_WORKER_REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) struct ResponseWorkerJoinPermit {
    registry: Arc<ResponseWorkerReaperRegistry>,
}

pub(super) struct ResponseWorkerJoinJob {
    join: std::thread::JoinHandle<Result<(), ResponseWorkerTickError>>,
    worker: Arc<ProductionResponseWorker>,
    _permit: ResponseWorkerJoinPermit,
}

pub(super) struct ResponseWorkerReaperState {
    join_owners: usize,
    jobs: VecDeque<ResponseWorkerJoinJob>,
    reaper: Option<std::thread::JoinHandle<()>>,
}

pub(super) struct ResponseWorkerReaperRegistry {
    state: Mutex<ResponseWorkerReaperState>,
    wake: Condvar,
    #[cfg(test)]
    fail_next_spawn: AtomicBool,
}

pub(super) static RESPONSE_WORKER_REAPER_REGISTRY: OnceLock<Arc<ResponseWorkerReaperRegistry>> =
    OnceLock::new();

impl ResponseWorkerReaperRegistry {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(ResponseWorkerReaperState {
                join_owners: 0,
                jobs: VecDeque::new(),
                reaper: None,
            }),
            wake: Condvar::new(),
            #[cfg(test)]
            fail_next_spawn: AtomicBool::new(false),
        }
    }

    pub(super) fn lock_state(&self) -> std::sync::MutexGuard<'_, ResponseWorkerReaperState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn ensure_service(self: &Arc<Self>) -> Result<(), ResponseWorkerTickError> {
        let mut state = self.lock_state();
        if state
            .reaper
            .as_ref()
            .is_some_and(|reaper| !reaper.is_finished())
        {
            return Ok(());
        }
        if let Some(reaper) = state.reaper.take() {
            let _ = reaper.join();
        }
        #[cfg(test)]
        if self.fail_next_spawn.swap(false, Ordering::AcqRel) {
            return Err(ResponseWorkerTickError::WorkerReaper(
                "injected service spawn failure".to_string(),
            ));
        }
        let registry = Arc::clone(self);
        let reaper = std::thread::Builder::new()
            .name("chio-response-worker-reaper".to_string())
            .spawn(move || registry.run())
            .map_err(|error| ResponseWorkerTickError::WorkerReaper(error.to_string()))?;
        state.reaper = Some(reaper);
        Ok(())
    }

    fn acquire(self: &Arc<Self>) -> Result<ResponseWorkerJoinPermit, ResponseWorkerTickError> {
        self.ensure_service()?;
        let mut state = self.lock_state();
        if state.join_owners >= MAX_RESPONSE_WORKER_JOIN_OWNERS {
            return Err(ResponseWorkerTickError::WorkerReaperCapacity);
        }
        state.join_owners = state.join_owners.saturating_add(1);
        Ok(ResponseWorkerJoinPermit {
            registry: Arc::clone(self),
        })
    }

    pub(super) fn enqueue(self: &Arc<Self>, job: ResponseWorkerJoinJob) {
        {
            let mut state = self.lock_state();
            state.jobs.push_back(job);
            if state.jobs.len() > MAX_RESPONSE_WORKER_JOIN_OWNERS {
                tracing::error!(
                    retained_joins = state.jobs.len(),
                    audit_fault = "response_worker_reaper_capacity_invariant",
                    "response worker join registry exceeded its reserved capacity"
                );
            }
        }
        self.wake.notify_one();
        if let Err(error) = self.ensure_service() {
            tracing::error!(
                error = %error,
                audit_fault = "response_worker_reaper_unavailable",
                "response worker join ownership remains retained for a later reaper restart"
            );
        }
    }

    fn take_ready_job(&self) -> ResponseWorkerJoinJob {
        let mut state = self.lock_state();
        loop {
            while state.jobs.is_empty() {
                state = match self.wake.wait(state) {
                    Ok(state) => state,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            if let Some(index) = state.jobs.iter().position(|job| job.join.is_finished()) {
                if let Some(job) = state.jobs.remove(index) {
                    return job;
                }
            }
            state = match self
                .wake
                .wait_timeout(state, RESPONSE_WORKER_REAPER_POLL_INTERVAL)
            {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    fn run(self: Arc<Self>) {
        loop {
            let ResponseWorkerJoinJob {
                join,
                worker,
                _permit,
            } = self.take_ready_job();
            let joined = catch_unwind(AssertUnwindSafe(|| {
                join_response_worker_thread(join, &worker)
            }));
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(
                        error = %error,
                        audit_fault = "response_worker_drop_join_failed",
                        "response worker stopped after its handle was dropped but did not shut down cleanly"
                    );
                }
                Err(_) => {
                    worker.thread_joined.store(true, Ordering::Release);
                    tracing::error!(
                        audit_fault = "response_worker_reaper_join_panicked",
                        "response worker reaper contained a panic while finalizing a joined worker"
                    );
                }
            }
            drop(_permit);
        }
    }

    fn release_join_owner(&self) {
        let mut state = self.lock_state();
        if state.join_owners == 0 {
            tracing::error!(
                audit_fault = "response_worker_reaper_permit_underflow",
                "response worker join registry observed a permit underflow"
            );
            return;
        }
        state.join_owners -= 1;
    }

    #[cfg(test)]
    pub(super) fn acquire_without_service_for_test(
        self: &Arc<Self>,
    ) -> Result<ResponseWorkerJoinPermit, ResponseWorkerTickError> {
        let mut state = self.lock_state();
        if state.join_owners >= MAX_RESPONSE_WORKER_JOIN_OWNERS {
            return Err(ResponseWorkerTickError::WorkerReaperCapacity);
        }
        state.join_owners = state.join_owners.saturating_add(1);
        Ok(ResponseWorkerJoinPermit {
            registry: Arc::clone(self),
        })
    }

    #[cfg(test)]
    pub(super) fn take_retained_job_for_test(&self) -> Option<ResponseWorkerJoinJob> {
        self.lock_state().jobs.pop_front()
    }
}

impl ResponseWorkerJoinPermit {
    fn transfer(
        self,
        join: std::thread::JoinHandle<Result<(), ResponseWorkerTickError>>,
        worker: Arc<ProductionResponseWorker>,
    ) {
        let registry = Arc::clone(&self.registry);
        registry.enqueue(ResponseWorkerJoinJob {
            join,
            worker,
            _permit: self,
        });
    }
}

impl Drop for ResponseWorkerJoinPermit {
    fn drop(&mut self) {
        self.registry.release_join_owner();
    }
}

pub(super) fn acquire_response_worker_join_permit() -> Result<ResponseWorkerJoinPermit, ResponseWorkerTickError>
{
    let registry = Arc::clone(
        RESPONSE_WORKER_REAPER_REGISTRY
            .get_or_init(|| Arc::new(ResponseWorkerReaperRegistry::new())),
    );
    registry.acquire()
}

pub(super) fn join_response_worker_thread(
    join: std::thread::JoinHandle<Result<(), ResponseWorkerTickError>>,
    worker: &ProductionResponseWorker,
) -> Result<(), ResponseWorkerTickError> {
    let result = match join.join() {
        Ok(result) => result,
        Err(_) => match worker.complete_shutdown_after_loop() {
            Ok(()) => Err(worker_task_crash_error()),
            Err(error) => Err(error),
        },
    };
    worker.thread_joined.store(true, Ordering::Release);
    result
}

impl ResponseWorkerStartupGuard {
    pub(super) fn take_join(&mut self) -> Result<ResponseWorkerJoinOwnership, ResponseWorkerTickError> {
        let join = self.join.take().ok_or_else(worker_task_crash_error)?;
        self.active = false;
        Ok(join)
    }
}

impl Drop for ResponseWorkerStartupGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = self.shutdown.send(true);
        if let Some(ResponseWorkerJoinOwnership { join, permit }) = self.join.take() {
            let _ = join_response_worker_thread(join, &self.worker);
            drop(permit);
        }
    }
}

pub(super) struct ResponseWorkerTaskLiveness {
    worker: Arc<ProductionResponseWorker>,
}

impl Drop for ResponseWorkerThreadCompletion {
    fn drop(&mut self) {
        let _ = self.completion.send_replace(true);
    }
}

impl ResponseWorkerTaskLiveness {
    pub(super) fn begin(worker: Arc<ProductionResponseWorker>) -> Self {
        worker.task_live.store(true, Ordering::Release);
        Self { worker }
    }
}

impl Drop for ResponseWorkerTaskLiveness {
    fn drop(&mut self) {
        self.worker.task_live.store(false, Ordering::Release);
        if !self.worker.shutdown_requested.load(Ordering::Acquire)
            && !self.worker.shutdown_completed.load(Ordering::Acquire)
        {
            self.worker.mark_failed(&worker_task_crash_error());
        }
    }
}

impl ProductionResponseWorkerHandle {
    #[must_use]
    pub(in crate::security) fn is_running(&self) -> bool {
        self.publication_released
            && self.publication_ready
            && self.worker.task_live.load(Ordering::Acquire)
            && self
                .join
                .as_ref()
                .is_some_and(|ownership| !ownership.join.is_finished())
    }

    pub(in crate::security) async fn arm(&mut self) -> Result<(), ResponseWorkerTickError> {
        let arm = self
            .arm
            .take()
            .ok_or(ResponseWorkerTickError::WorkerArmHandshake)?;
        arm.send(())
            .map_err(|_| ResponseWorkerTickError::WorkerArmHandshake)?;
        self.armed
            .take()
            .ok_or(ResponseWorkerTickError::WorkerArmHandshake)?
            .await
            .map_err(|_| ResponseWorkerTickError::WorkerArmHandshake)
    }

    pub(in crate::security) fn release_publication(&mut self) -> Result<(), ResponseWorkerTickError> {
        let publication_gate = self
            .publication_gate
            .take()
            .ok_or(ResponseWorkerTickError::WorkerPublicationGate)?;
        self.worker.mark_publication_released()?;
        publication_gate.send(()).map_err(|_| {
            self.worker
                .mark_failed(&ResponseWorkerTickError::WorkerPublicationGate);
            ResponseWorkerTickError::WorkerPublicationGate
        })?;
        self.publication_released = true;
        Ok(())
    }

    pub(in crate::security) async fn wait_for_publication_readiness(
        &mut self,
    ) -> Result<(), ResponseWorkerTickError> {
        if !self.publication_released {
            return Err(ResponseWorkerTickError::WorkerPublicationGate);
        }
        self.publication_readiness
            .take()
            .ok_or(ResponseWorkerTickError::WorkerPublicationGate)?
            .await
            .map_err(|_| ResponseWorkerTickError::WorkerPublicationGate)?
            .map_err(ResponseWorkerTickError::WorkerInitialTick)?;
        self.publication_ready = true;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<(), ResponseWorkerTickError> {
        if self.clean_shutdown {
            return Ok(());
        }
        self.worker.request_stop();
        let _ = self.shutdown.send(true);
        let result = if self.join.is_some() {
            if !*self.thread_completion.borrow() {
                while self.thread_completion.changed().await.is_ok() {
                    if *self.thread_completion.borrow() {
                        break;
                    }
                }
            }
            while self
                .join
                .as_ref()
                .is_some_and(|ownership| !ownership.join.is_finished())
            {
                tokio::task::yield_now().await;
            }
            let ResponseWorkerJoinOwnership { join, permit } =
                self.join.take().ok_or_else(worker_task_crash_error)?;
            let result = join_response_worker_thread(join, &self.worker);
            drop(permit);
            result
        } else {
            if self.worker.task_live.load(Ordering::Acquire) {
                return Err(worker_task_crash_error());
            }
            self.worker.complete_shutdown_after_loop()
        };
        if result.is_ok() {
            self.clean_shutdown = true;
        }
        result
    }
}

impl Drop for ProductionResponseWorkerHandle {
    fn drop(&mut self) {
        self.worker.request_stop();
        let _ = self.shutdown.send(true);
        let Some(ResponseWorkerJoinOwnership { join, permit }) = self.join.take() else {
            return;
        };
        if join.is_finished() {
            let _ = join_response_worker_thread(join, &self.worker);
            drop(permit);
            return;
        }
        permit.transfer(join, Arc::clone(&self.worker));
    }
}


#[cfg(test)]
#[path = "tests/reaper_spawn_failure_retains_join_ownership_for_later_recovery.rs"]
mod reaper_spawn_failure_retains_join_ownership_for_later_recovery;

#[cfg(test)]
#[path = "tests/join_registry_reservations_bound_retained_worker_growth.rs"]
mod join_registry_reservations_bound_retained_worker_growth;
