struct ActiveDefenseTeardownSupervisorState {
    retained_owners: usize,
    jobs: VecDeque<RetainedActiveDefenseCleanup>,
    service_running: bool,
}

struct ActiveDefenseTeardownSupervisor {
    state: Mutex<ActiveDefenseTeardownSupervisorState>,
    wake: Condvar,
    #[cfg(test)]
    fail_next_spawn: AtomicBool,
    #[cfg(test)]
    panic_next_service_attempt: AtomicBool,
}

struct ActiveDefenseTeardownPermit {
    supervisor: Arc<ActiveDefenseTeardownSupervisor>,
}

struct RetainedActiveDefenseCleanup {
    work: RetainedActiveDefenseCleanupWork,
    _permit: ActiveDefenseTeardownPermit,
}

enum RetainedActiveDefenseCleanupWork {
    Reserved(ReservedActiveDefenseCleanup),
    Published(DetachedActiveDefenseTeardown),
    #[cfg(test)]
    Test(Box<dyn FnMut() + Send + 'static>),
}

struct InFlightActiveDefenseCleanup {
    supervisor: Arc<ActiveDefenseTeardownSupervisor>,
    job: Option<RetainedActiveDefenseCleanup>,
}

static ACTIVE_DEFENSE_TEARDOWN_SUPERVISOR: OnceLock<Arc<ActiveDefenseTeardownSupervisor>> =
    OnceLock::new();

impl ActiveDefenseTeardownSupervisor {
    fn new() -> Self {
        Self {
            state: Mutex::new(ActiveDefenseTeardownSupervisorState {
                retained_owners: 0,
                jobs: VecDeque::new(),
                service_running: false,
            }),
            wake: Condvar::new(),
            #[cfg(test)]
            fail_next_spawn: AtomicBool::new(false),
            #[cfg(test)]
            panic_next_service_attempt: AtomicBool::new(false),
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ActiveDefenseTeardownSupervisorState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn acquire(
        self: &Arc<Self>,
    ) -> Result<ActiveDefenseTeardownPermit, ProductionActiveDefenseHostError> {
        {
            let mut state = self.lock_state();
            if state.retained_owners >= MAX_RETAINED_ACTIVE_DEFENSE_TEARDOWNS {
                return Err(ProductionActiveDefenseHostError::TeardownSupervisorCapacity);
            }
            state.retained_owners = state.retained_owners.saturating_add(1);
        }
        if let Err(error) =
            self.ensure_service_bounded(MAX_ACTIVE_DEFENSE_TEARDOWN_SERVICE_SPAWN_ATTEMPTS)
        {
            self.release_owner();
            return Err(ProductionActiveDefenseHostError::TeardownSupervisorUnavailable(error));
        }
        Ok(ActiveDefenseTeardownPermit {
            supervisor: Arc::clone(self),
        })
    }

    fn enqueue(self: &Arc<Self>, job: RetainedActiveDefenseCleanup) {
        {
            let mut state = self.lock_state();
            state.jobs.push_back(job);
            if state.jobs.len() > MAX_RETAINED_ACTIVE_DEFENSE_TEARDOWNS {
                tracing::error!(
                    retained_teardowns = state.jobs.len(),
                    audit_fault = "active_defense_teardown_capacity_invariant",
                    "active-defense retained teardown queue exceeded its reserved capacity"
                );
            }
        }
        self.wake.notify_one();
    }

    fn ensure_service_bounded(self: &Arc<Self>, max_attempts: usize) -> Result<(), String> {
        let mut attempts = 0_usize;
        loop {
            let mut state = self.lock_state();
            if state.service_running {
                return Ok(());
            }

            #[cfg(test)]
            let inject_failure = self.fail_next_spawn.swap(false, Ordering::AcqRel);
            #[cfg(not(test))]
            let inject_failure = false;
            let supervisor = Arc::clone(self);
            let spawn = if inject_failure {
                Err(std::io::Error::other(
                    "injected active-defense teardown service spawn failure",
                ))
            } else {
                std::thread::Builder::new()
                    .name("chio-active-defense-teardown".to_string())
                    .spawn(move || {
                        let result = catch_unwind(AssertUnwindSafe(|| supervisor.run()));
                        supervisor.service_finished(result.is_err());
                    })
            };
            match spawn {
                Ok(handle) => {
                    state.service_running = true;
                    drop(state);
                    drop(handle);
                    return Ok(());
                }
                Err(error) => {
                    attempts = attempts.saturating_add(1);
                    state.service_running = false;
                    drop(state);
                    tracing::error!(
                        error = %error,
                        audit_fault = "active_defense_teardown_service_spawn_retry",
                        "active-defense teardown service spawn failed and will retry with ownership retained"
                    );
                    if attempts >= max_attempts {
                        return Err(error.to_string());
                    }
                    std::thread::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL);
                }
            }
        }
    }

    fn ensure_service_until_available(self: &Arc<Self>) {
        loop {
            match self.ensure_service_bounded(MAX_ACTIVE_DEFENSE_TEARDOWN_SERVICE_SPAWN_ATTEMPTS) {
                Ok(()) => return,
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        audit_fault = "active_defense_teardown_service_recovery_retry",
                        "active-defense teardown supervisor recovery failed and will retry"
                    );
                    std::thread::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL);
                }
            }
        }
    }

    fn run(self: &Arc<Self>) {
        loop {
            let Some(mut cleanup) = self.take_next() else {
                return;
            };
            #[cfg(test)]
            if self
                .panic_next_service_attempt
                .swap(false, Ordering::AcqRel)
            {
                panic!("injected active-defense teardown service panic");
            }
            let runtime = loop {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => break runtime,
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            audit_fault = "active_defense_teardown_runtime_retry",
                            "active-defense teardown runtime could not start and will retry with ownership retained"
                        );
                        std::thread::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL);
                    }
                }
            };
            if let Some(work) = cleanup.work_mut() {
                runtime.block_on(work.run());
            } else {
                tracing::error!(
                    audit_fault = "active_defense_teardown_missing_inflight_job",
                    "active-defense teardown supervisor lost its in-flight job marker"
                );
            }
            cleanup.complete();
        }
    }

    fn take_next(self: &Arc<Self>) -> Option<InFlightActiveDefenseCleanup> {
        let mut state = self.lock_state();
        loop {
            if let Some(job) = state.jobs.pop_front() {
                return Some(InFlightActiveDefenseCleanup {
                    supervisor: Arc::clone(self),
                    job: Some(job),
                });
            }
            if state.retained_owners == 0 {
                return None;
            }
            state = match self.wake.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    fn service_finished(self: &Arc<Self>, panicked: bool) {
        let retry = {
            let mut state = self.lock_state();
            state.service_running = false;
            state.retained_owners > 0
        };
        self.wake.notify_all();
        if panicked {
            tracing::error!(
                audit_fault = "active_defense_teardown_service_panicked",
                "active-defense teardown service panic was contained and retained cleanup will retry"
            );
        }
        if retry {
            self.ensure_service_until_available();
        }
    }

    fn release_owner(&self) {
        let mut state = self.lock_state();
        if state.retained_owners == 0 {
            tracing::error!(
                audit_fault = "active_defense_teardown_permit_underflow",
                "active-defense teardown supervisor observed a permit underflow"
            );
            return;
        }
        state.retained_owners -= 1;
        drop(state);
        self.wake.notify_all();
    }

    #[cfg(test)]
    fn fail_next_spawn(&self) {
        self.fail_next_spawn.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn panic_next_service_attempt(&self) {
        self.panic_next_service_attempt
            .store(true, Ordering::Release);
    }
}

impl ActiveDefenseTeardownPermit {
    fn enqueue(self, work: RetainedActiveDefenseCleanupWork) {
        let supervisor = Arc::clone(&self.supervisor);
        supervisor.enqueue(RetainedActiveDefenseCleanup {
            work,
            _permit: self,
        });
    }
}

impl Drop for ActiveDefenseTeardownPermit {
    fn drop(&mut self) {
        self.supervisor.release_owner();
    }
}

impl InFlightActiveDefenseCleanup {
    fn work_mut(&mut self) -> Option<&mut RetainedActiveDefenseCleanupWork> {
        self.job.as_mut().map(|job| &mut job.work)
    }

    fn complete(mut self) {
        self.job = None;
    }
}

impl Drop for InFlightActiveDefenseCleanup {
    fn drop(&mut self) {
        let Some(job) = self.job.take() else {
            return;
        };
        {
            let mut state = self.supervisor.lock_state();
            state.jobs.push_front(job);
        }
        self.supervisor.wake.notify_one();
    }
}

impl RetainedActiveDefenseCleanupWork {
    async fn run(&mut self) {
        match self {
            Self::Reserved(cleanup) => cleanup.run().await,
            Self::Published(teardown) => teardown.run().await,
            #[cfg(test)]
            Self::Test(test) => test(),
        }
    }
}

fn acquire_active_defense_teardown_permit(
) -> Result<ActiveDefenseTeardownPermit, ProductionActiveDefenseHostError> {
    let supervisor = Arc::clone(
        ACTIVE_DEFENSE_TEARDOWN_SUPERVISOR
            .get_or_init(|| Arc::new(ActiveDefenseTeardownSupervisor::new())),
    );
    supervisor.acquire()
}

struct ReservedActiveDefenseCleanup {
    registry: Arc<ActiveDefenseServiceRegistry>,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
    published_services: Arc<dyn ActiveDefenseServices>,
    worker_handle: Option<ProductionResponseWorkerHandle>,
    active_worker: Arc<ProductionResponseWorker>,
    reservation_active: bool,
}

impl ReservedActiveDefenseCleanup {
    async fn run(&mut self) {
        loop {
            match self.lifecycle.close_runtime_admission() {
                Ok(()) => break,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        audit_fault = "active_defense_reserved_admission_close_retry",
                        "reserved active-defense admission close failed and will retry"
                    );
                    tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                }
            }
        }
        loop {
            let Some(worker_handle) = self.worker_handle.as_mut() else {
                break;
            };
            match worker_handle.shutdown().await {
                Ok(()) => {
                    self.worker_handle = None;
                    break;
                }
                Err(error) if self.active_worker.shutdown_is_complete() => {
                    tracing::warn!(
                        error = %error,
                        audit_fault = "active_defense_reserved_worker_shutdown_error_after_completion",
                        "active-defense reserved worker reported an error after shutdown completed"
                    );
                    self.worker_handle = None;
                    break;
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        audit_fault = "active_defense_reserved_worker_shutdown_retry",
                        "active-defense reserved worker shutdown failed and will retry"
                    );
                    tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                }
            }
        }
        self.lifecycle.release_authority_claim();
        while self.reservation_active {
            match self
                .registry
                .cancel_reserved_exact(&self.published_services)
            {
                Ok(()) => self.reservation_active = false,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        audit_fault = "active_defense_reserved_cleanup_retry",
                        "active-defense exact startup reservation cleanup failed and will retry"
                    );
                    tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                }
            }
        }
    }
}

struct ReservedProductionActiveDefenseStartup {
    registry: Arc<ActiveDefenseServiceRegistry>,
    security_store: Arc<SqliteSecurityStateStore>,
    declassification_lifecycle: ProductionDeclassificationReceiptLifecycle,
    orchestrator: Arc<ProductionActiveDefenseOrchestrator>,
    published_services: Arc<dyn ActiveDefenseServices>,
    worker_handle: Option<ProductionResponseWorkerHandle>,
    active_worker: Arc<ProductionResponseWorker>,
    worker_loop: ProductionResponseWorkerLoopConfig,
    teardown_permit: ActiveDefenseTeardownPermit,
    registry_published: bool,
    reservation_active: bool,
}

impl ReservedProductionActiveDefenseStartup {
    async fn rollback_reserved(&mut self) -> Result<(), String> {
        let mut rollback_errors = Vec::new();
        if let Err(error) = self.declassification_lifecycle.close_runtime_admission() {
            rollback_errors.push(format!("close active-defense admission: {error}"));
        }
        if let Some(worker_handle) = self.worker_handle.as_mut() {
            match worker_handle.shutdown().await {
                Ok(()) => self.worker_handle = None,
                Err(error) if self.active_worker.shutdown_is_complete() => {
                    self.worker_handle = None;
                    tracing::warn!(
                        error = %error,
                        audit_fault = "active_defense_startup_worker_shutdown_error_after_completion",
                        "active-defense startup worker reported an error after shutdown completed"
                    );
                }
                Err(error) => rollback_errors.push(format!("stop response worker: {error}")),
            }
        }
        if rollback_errors.is_empty() {
            self.declassification_lifecycle.release_authority_claim();
            if self.reservation_active {
                match self
                    .registry
                    .cancel_reserved_exact(&self.published_services)
                {
                    Ok(()) => self.reservation_active = false,
                    Err(error) => rollback_errors
                        .push(format!("cancel active-defense reservation: {error}")),
                }
            }
        }
        if rollback_errors.is_empty() {
            Ok(())
        } else {
            Err(rollback_errors.join("; "))
        }
    }

    fn into_reserved_cleanup(self) -> (ReservedActiveDefenseCleanup, ActiveDefenseTeardownPermit) {
        let Self {
            registry,
            declassification_lifecycle,
            published_services,
            worker_handle,
            active_worker,
            teardown_permit,
            reservation_active,
            ..
        } = self;
        (
            ReservedActiveDefenseCleanup {
                registry,
                lifecycle: declassification_lifecycle,
                published_services,
                worker_handle,
                active_worker,
                reservation_active,
            },
            teardown_permit,
        )
    }

    fn into_published_teardown(
        self,
    ) -> (DetachedActiveDefenseTeardown, ActiveDefenseTeardownPermit) {
        let Self {
            registry,
            security_store,
            declassification_lifecycle,
            orchestrator,
            published_services,
            worker_handle,
            active_worker,
            worker_loop,
            teardown_permit,
            ..
        } = self;
        (
            DetachedActiveDefenseTeardown {
                registry,
                security_store,
                lifecycle: declassification_lifecycle,
                orchestrator,
                published_services,
                worker_handle,
                active_worker,
                worker_loop,
                admission_closed: false,
                operation_quiescent: false,
                worker_stopped: false,
                unpublished: false,
                on_complete: None,
            },
            teardown_permit,
        )
    }

    fn try_into_host(
        mut self,
    ) -> Result<ProductionActiveDefenseHost, (Self, ProductionActiveDefenseHostError)> {
        let Some(worker_handle) = self.worker_handle.take() else {
            return Err((
                self,
                ProductionActiveDefenseHostError::WorkerTaskUnavailable,
            ));
        };
        Ok(ProductionActiveDefenseHost {
            registry: self.registry,
            security_store: self.security_store,
            declassification_lifecycle: self.declassification_lifecycle,
            orchestrator: self.orchestrator,
            published_services: self.published_services,
            teardown_ownership: Some(ProductionActiveDefenseTeardownOwnership::Live {
                worker_handle,
                permit: self.teardown_permit,
            }),
            active_worker: self.active_worker,
            worker_loop: self.worker_loop,
            published: true,
        })
    }
}

enum ProductionActiveDefenseStartupState {
    Reserved(Box<ReservedProductionActiveDefenseStartup>),
    Published(Box<ProductionActiveDefenseHost>),
}

struct ProductionActiveDefenseStartupGuard {
    state: Option<ProductionActiveDefenseStartupState>,
}

impl ProductionActiveDefenseStartupGuard {
    fn new(reserved: ReservedProductionActiveDefenseStartup) -> Self {
        Self {
            state: Some(ProductionActiveDefenseStartupState::Reserved(Box::new(
                reserved,
            ))),
        }
    }

    fn reserved_mut(
        &mut self,
    ) -> Result<&mut ReservedProductionActiveDefenseStartup, ProductionActiveDefenseHostError> {
        match self.state.as_mut() {
            Some(ProductionActiveDefenseStartupState::Reserved(reserved)) => Ok(reserved.as_mut()),
            Some(ProductionActiveDefenseStartupState::Published(_)) | None => {
                Err(ProductionActiveDefenseHostError::TeardownOwnershipUnavailable)
            }
        }
    }

    async fn rollback_reserved(&mut self) -> Result<(), String> {
        self.reserved_mut()
            .map_err(|error| error.to_string())?
            .rollback_reserved()
            .await?;
        self.state = None;
        Ok(())
    }

    fn mark_registry_published(&mut self) -> Result<(), ProductionActiveDefenseHostError> {
        let reserved = self.reserved_mut()?;
        reserved.registry_published = true;
        reserved.reservation_active = false;
        Ok(())
    }

    fn promote_to_host(&mut self) -> Result<(), ProductionActiveDefenseHostError> {
        let Some(ProductionActiveDefenseStartupState::Reserved(reserved)) = self.state.take()
        else {
            return Err(ProductionActiveDefenseHostError::TeardownOwnershipUnavailable);
        };
        match (*reserved).try_into_host() {
            Ok(host) => {
                self.state = Some(ProductionActiveDefenseStartupState::Published(Box::new(
                    host,
                )));
                Ok(())
            }
            Err((reserved, error)) => {
                self.state = Some(ProductionActiveDefenseStartupState::Reserved(Box::new(
                    reserved,
                )));
                Err(error)
            }
        }
    }

    fn published_host_mut(
        &mut self,
    ) -> Result<&mut ProductionActiveDefenseHost, ProductionActiveDefenseHostError> {
        match self.state.as_mut() {
            Some(ProductionActiveDefenseStartupState::Published(host)) => Ok(host.as_mut()),
            Some(ProductionActiveDefenseStartupState::Reserved(_)) | None => {
                Err(ProductionActiveDefenseHostError::TeardownOwnershipUnavailable)
            }
        }
    }

    fn take_host(
        mut self,
    ) -> Result<ProductionActiveDefenseHost, ProductionActiveDefenseHostError> {
        match self.state.take() {
            Some(ProductionActiveDefenseStartupState::Published(host)) => Ok(*host),
            Some(ProductionActiveDefenseStartupState::Reserved(_)) | None => {
                Err(ProductionActiveDefenseHostError::TeardownOwnershipUnavailable)
            }
        }
    }
}

impl Drop for ProductionActiveDefenseStartupGuard {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        match state {
            ProductionActiveDefenseStartupState::Reserved(reserved)
                if reserved.registry_published =>
            {
                let (teardown, permit) = (*reserved).into_published_teardown();
                spawn_detached_active_defense_teardown(teardown, permit);
            }
            ProductionActiveDefenseStartupState::Reserved(reserved) => {
                let (cleanup, permit) = (*reserved).into_reserved_cleanup();
                permit.enqueue(RetainedActiveDefenseCleanupWork::Reserved(cleanup));
            }
            ProductionActiveDefenseStartupState::Published(mut host) => {
                host.schedule_detached_teardown(Box::new(|| {}));
            }
        }
    }
}

enum ProductionActiveDefenseTeardownOwnership {
    Live {
        worker_handle: ProductionResponseWorkerHandle,
        permit: ActiveDefenseTeardownPermit,
    },
    Retained {
        teardown: Box<DetachedActiveDefenseTeardown>,
        permit: ActiveDefenseTeardownPermit,
    },
}

/// Owns the one production active-defense worker and the exact service
/// instance published to the runtime registry.
pub struct ProductionActiveDefenseHost {
    registry: Arc<ActiveDefenseServiceRegistry>,
    security_store: Arc<SqliteSecurityStateStore>,
    declassification_lifecycle: ProductionDeclassificationReceiptLifecycle,
    orchestrator: Arc<ProductionActiveDefenseOrchestrator>,
    published_services: Arc<dyn ActiveDefenseServices>,
    teardown_ownership: Option<ProductionActiveDefenseTeardownOwnership>,
    active_worker: Arc<ProductionResponseWorker>,
    worker_loop: ProductionResponseWorkerLoopConfig,
    published: bool,
}

impl ProductionActiveDefenseHost {
    pub async fn start(
        registry: Arc<ActiveDefenseServiceRegistry>,
        config: ProductionActiveDefenseHostConfig,
    ) -> Result<Self, ProductionActiveDefenseHostError> {
        let declassification_lifecycle = ProductionDeclassificationReceiptLifecycle::new(
            config.security_state_authority.clone(),
            Arc::clone(&config.indexed_evidence_store),
            Arc::clone(&config.signer),
            Arc::clone(&config.clock),
        )?;
        Self::start_with_declassification_lifecycle(registry, config, declassification_lifecycle)
            .await
    }

    pub(super) async fn start_with_declassification_lifecycle(
        registry: Arc<ActiveDefenseServiceRegistry>,
        config: ProductionActiveDefenseHostConfig,
        declassification_lifecycle: ProductionDeclassificationReceiptLifecycle,
    ) -> Result<Self, ProductionActiveDefenseHostError> {
        if !config.durability.is_persistent() {
            return Err(ProductionActiveDefenseHostError::EphemeralAuthority);
        }
        let security_store = Arc::clone(config.security_state_authority.store());
        declassification_lifecycle.ensure_authority(
            &config.security_state_authority,
            &config.indexed_evidence_store,
            &config.signer,
            &config.clock,
        )?;
        declassification_lifecycle.reconcile_and_drain_startup()?;
        let worker_loop = config.worker_loop;
        let alert_outbox = Arc::clone(&config.alert_outbox);
        let blast_radius = Arc::clone(&config.blast_radius);
        let orchestrator_context = ProductionActiveDefenseOrchestratorContext {
            security_state_authority: config.security_state_authority.clone(),
            indexed_evidence_store: Arc::clone(&config.indexed_evidence_store),
            signer: Arc::clone(&config.signer),
            scheduler_health: Arc::clone(&config.scheduler_health),
            response_policy_planner: Arc::clone(&config.response_policy_planner),
            response_coordinator: Arc::clone(&config.response_coordinator),
            clock: Arc::clone(&config.clock),
            config: config.active_defense,
            lifecycle: declassification_lifecycle.clone(),
        };
        let orchestrator = Arc::new(
            ProductionActiveDefenseOrchestrator::new_with_production_effects_and_lifecycle(
                orchestrator_context,
                alert_outbox,
                blast_radius,
            )?,
        );
        let published_services: Arc<dyn ActiveDefenseServices> = orchestrator.clone();
        let active_worker = Arc::clone(orchestrator.worker());
        let teardown_permit = acquire_active_defense_teardown_permit()?;
        registry.reserve_exact(Arc::clone(&published_services))?;
        let mut startup =
            ProductionActiveDefenseStartupGuard::new(ReservedProductionActiveDefenseStartup {
                registry: Arc::clone(&registry),
                security_store,
                declassification_lifecycle: declassification_lifecycle.clone(),
                orchestrator: Arc::clone(&orchestrator),
                published_services: Arc::clone(&published_services),
                worker_handle: None,
                active_worker,
                worker_loop,
                teardown_permit,
                registry_published: false,
                reservation_active: true,
            });
        #[cfg(test)]
        tokio::task::yield_now().await;

        let worker_start = startup
            .reserved_mut()?
            .orchestrator
            .start_worker_parked(worker_loop)
            .await;
        match worker_start {
            Ok(worker_handle) => {
                startup.reserved_mut()?.worker_handle = Some(worker_handle);
            }
            Err(error) => {
                if let Err(rollback) = startup.rollback_reserved().await {
                    return Err(ProductionActiveDefenseHostError::StartupRollback {
                        cause: error.to_string(),
                        rollback,
                    });
                }
                return Err(error.into());
            }
        }

        let arm = match startup.reserved_mut()?.worker_handle.as_mut() {
            Some(worker_handle) => worker_handle.arm().await,
            None => Err(ResponseWorkerTickError::WorkerStopped),
        };
        if let Err(error) = arm {
            if let Err(rollback) = startup.rollback_reserved().await {
                return Err(ProductionActiveDefenseHostError::StartupRollback {
                    cause: error.to_string(),
                    rollback,
                });
            }
            return Err(error.into());
        }

        let lifecycle_for_publication = declassification_lifecycle.clone();
        let publication = {
            let reserved = startup.reserved_mut()?;
            registry.commit_reserved_exact_with_release(&published_services, || {
                lifecycle_for_publication.publish_runtime_admission()?;
                let Some(worker_handle) = reserved.worker_handle.as_mut() else {
                    let _ = lifecycle_for_publication.close_runtime_admission();
                    return Err(ResponseWorkerTickError::WorkerStopped);
                };
                if let Err(error) = worker_handle.release_publication() {
                    let _ = lifecycle_for_publication.close_runtime_admission();
                    return Err(error);
                }
                Ok(())
            })
        };
        if let Err(publication) = publication {
            if let Err(rollback) = startup.rollback_reserved().await {
                return Err(ProductionActiveDefenseHostError::StartupRollback {
                    cause: publication.to_string(),
                    rollback,
                });
            }
            return Err(publication.into());
        }
        startup.mark_registry_published()?;
        startup.promote_to_host()?;

        let publication_readiness = startup
            .published_host_mut()?
            .live_worker_handle_mut()?
            .wait_for_publication_readiness()
            .await;
        if let Err(publication) = publication_readiness {
            match startup.published_host_mut()?.shutdown().await {
                Ok(()) => {
                    let cleaned = startup.take_host()?;
                    drop(cleaned);
                    return Err(publication.into());
                }
                Err(rollback) => {
                    return Err(ProductionActiveDefenseHostError::StartupRollback {
                        cause: publication.to_string(),
                        rollback: rollback.to_string(),
                    });
                }
            }
        }
        startup.take_host()
    }

    pub fn consume(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> Result<CorrelationConsumerReport, PortError> {
        self.orchestrator.consume(event)
    }

    #[must_use]
    pub fn worker_health(&self) -> ResponseWorkerHealth {
        self.orchestrator.worker_health()
    }

    /// Require both live port readiness and a running background TTL worker.
    ///
    /// Port probes alone are insufficient for production admission: a created,
    /// degraded, failed, or stopped worker cannot enforce expiry and rollback.
    pub fn ensure_ready(&self) -> Result<(), ProductionActiveDefenseHostError> {
        self.ensure_bootstrap_ready()?;
        self.orchestrator.ensure_ready()?;
        Ok(())
    }

    pub(crate) fn ensure_bootstrap_ready(&self) -> Result<(), ProductionActiveDefenseHostError> {
        self.declassification_lifecycle
            .ensure_runtime_admission_open()?;
        self.orchestrator.ensure_bootstrap_ready()?;
        if !self
            .live_worker_handle()
            .is_some_and(ProductionResponseWorkerHandle::is_running)
        {
            return Err(ProductionActiveDefenseHostError::WorkerTaskUnavailable);
        }
        let health = self.worker_health();
        if matches!(
            health.lifecycle,
            ResponseWorkerLifecycle::Running | ResponseWorkerLifecycle::Ready
        ) {
            Ok(())
        } else {
            Err(ProductionActiveDefenseHostError::UnhealthyWorker { health })
        }
    }

    pub fn resume_incomplete_active_responses(
        &self,
    ) -> Result<(), ProductionActiveDefenseHostError> {
        self.orchestrator
            .resume_incomplete_until_drained()
            .map_err(Into::into)
    }

    #[must_use]
    pub fn orchestrator(&self) -> &Arc<ProductionActiveDefenseOrchestrator> {
        &self.orchestrator
    }

    fn live_worker_handle(&self) -> Option<&ProductionResponseWorkerHandle> {
        match self.teardown_ownership.as_ref() {
            Some(ProductionActiveDefenseTeardownOwnership::Live { worker_handle, .. }) => {
                Some(worker_handle)
            }
            Some(ProductionActiveDefenseTeardownOwnership::Retained { .. }) | None => None,
        }
    }

    fn live_worker_handle_mut(
        &mut self,
    ) -> Result<&mut ProductionResponseWorkerHandle, ProductionActiveDefenseHostError> {
        match self.teardown_ownership.as_mut() {
            Some(ProductionActiveDefenseTeardownOwnership::Live { worker_handle, .. }) => {
                Ok(worker_handle)
            }
            Some(ProductionActiveDefenseTeardownOwnership::Retained { .. }) | None => {
                Err(ProductionActiveDefenseHostError::TeardownOwnershipUnavailable)
            }
        }
    }

    fn retained_teardown_mut(
        &mut self,
    ) -> Result<&mut DetachedActiveDefenseTeardown, ProductionActiveDefenseHostError> {
        match self.teardown_ownership.as_mut() {
            Some(ProductionActiveDefenseTeardownOwnership::Retained { teardown, .. }) => {
                Ok(teardown)
            }
            Some(ProductionActiveDefenseTeardownOwnership::Live { .. }) | None => {
                Err(ProductionActiveDefenseHostError::TeardownOwnershipUnavailable)
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), ProductionActiveDefenseHostError> {
        if !self.published {
            return Ok(());
        }
        self.retain_teardown()?;
        let teardown = self.retained_teardown_mut()?;
        if !teardown.admission_closed {
            teardown.lifecycle.close_runtime_admission()?;
            teardown.admission_closed = true;
        }
        if let Err(error) = detached_teardown_prepare_worker_stop(teardown) {
            teardown.ensure_teardown_worker_running().await?;
            let health = teardown.active_worker.health();
            let in_flight_sequence = health
                .tick_in_flight
                .then_some(health.last_tick_started_sequence)
                .flatten();
            if !matches!(
                &error,
                ProductionActiveDefenseHostError::ActiveOverlayContributions { .. }
            ) || in_flight_sequence.is_none()
            {
                return Err(error);
            }
            teardown
                .wait_for_tick_completion(
                    in_flight_sequence.ok_or(ResponseWorkerTickError::WorkerStopped)?,
                )
                .await?;
            detached_teardown_prepare_worker_stop(teardown)?;
        }
        teardown.quiesce_and_stop().await;
        teardown.worker_stopped = true;
        if !teardown.unpublished {
            let lifecycle = teardown.lifecycle.clone();
            teardown
                .registry
                .unpublish_exact_with_release(&teardown.published_services, || {
                    lifecycle.release_authority_claim();
                    Ok(())
                })?;
            teardown.unpublished = true;
        }
        let active_worker = Arc::clone(&teardown.active_worker);
        self.teardown_ownership = None;
        self.published = false;
        self.active_worker = active_worker;
        Ok(())
    }

    fn retain_teardown(&mut self) -> Result<(), ProductionActiveDefenseHostError> {
        let Some(ownership) = self.teardown_ownership.take() else {
            return Err(ProductionActiveDefenseHostError::TeardownOwnershipUnavailable);
        };
        self.teardown_ownership = Some(match ownership {
            retained @ ProductionActiveDefenseTeardownOwnership::Retained { .. } => retained,
            ProductionActiveDefenseTeardownOwnership::Live {
                worker_handle,
                permit,
            } => ProductionActiveDefenseTeardownOwnership::Retained {
                teardown: Box::new(DetachedActiveDefenseTeardown {
                    registry: Arc::clone(&self.registry),
                    security_store: Arc::clone(&self.security_store),
                    lifecycle: self.declassification_lifecycle.clone(),
                    orchestrator: Arc::clone(&self.orchestrator),
                    published_services: Arc::clone(&self.published_services),
                    worker_handle: Some(worker_handle),
                    active_worker: Arc::clone(&self.active_worker),
                    worker_loop: self.worker_loop,
                    admission_closed: false,
                    operation_quiescent: false,
                    worker_stopped: false,
                    unpublished: false,
                    on_complete: None,
                }),
                permit,
            },
        });
        Ok(())
    }

    pub(super) fn schedule_detached_teardown(
        &mut self,
        on_complete: Box<dyn FnOnce() + Send + Sync + 'static>,
    ) {
        let _ = self.declassification_lifecycle.close_runtime_admission();
        if !self.published {
            on_complete();
            return;
        }
        let Some(ownership) = self.teardown_ownership.take() else {
            tracing::error!(
                audit_fault = "active_defense_detached_teardown_missing_ownership",
                "published active-defense host has no retained teardown ownership"
            );
            on_complete();
            return;
        };
        let (mut teardown, permit) = match ownership {
            ProductionActiveDefenseTeardownOwnership::Live {
                worker_handle,
                permit,
            } => (
                DetachedActiveDefenseTeardown {
                    registry: Arc::clone(&self.registry),
                    security_store: Arc::clone(&self.security_store),
                    lifecycle: self.declassification_lifecycle.clone(),
                    orchestrator: Arc::clone(&self.orchestrator),
                    published_services: Arc::clone(&self.published_services),
                    worker_handle: Some(worker_handle),
                    active_worker: Arc::clone(&self.active_worker),
                    worker_loop: self.worker_loop,
                    admission_closed: false,
                    operation_quiescent: false,
                    worker_stopped: false,
                    unpublished: false,
                    on_complete: None,
                },
                permit,
            ),
            ProductionActiveDefenseTeardownOwnership::Retained { teardown, permit } => {
                (*teardown, permit)
            }
        };
        teardown.on_complete = Some(on_complete);
        self.published = false;
        spawn_detached_active_defense_teardown(teardown, permit);
    }
}

impl Drop for ProductionActiveDefenseHost {
    fn drop(&mut self) {
        if self.published {
            self.schedule_detached_teardown(Box::new(|| {}));
        }
    }
}

struct DetachedActiveDefenseTeardown {
    registry: Arc<ActiveDefenseServiceRegistry>,
    security_store: Arc<SqliteSecurityStateStore>,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
    orchestrator: Arc<ProductionActiveDefenseOrchestrator>,
    published_services: Arc<dyn ActiveDefenseServices>,
    worker_handle: Option<ProductionResponseWorkerHandle>,
    active_worker: Arc<ProductionResponseWorker>,
    worker_loop: ProductionResponseWorkerLoopConfig,
    admission_closed: bool,
    operation_quiescent: bool,
    worker_stopped: bool,
    unpublished: bool,
    on_complete: Option<Box<dyn FnOnce() + Send + Sync + 'static>>,
}

impl DetachedActiveDefenseTeardown {
    async fn run(&mut self) {
        if !self.admission_closed {
            loop {
                match self.lifecycle.close_runtime_admission() {
                    Ok(())
                    | Err(ResponseWorkerTickError::RuntimeLeasesActive(_))
                    | Err(ResponseWorkerTickError::DispatchRecorderLeasesActive(_))
                    | Err(ResponseWorkerTickError::ConsumerLeasesActive(_)) => {
                        self.admission_closed = true;
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            audit_fault = "active_defense_detached_admission_close_retry",
                            "detached active-defense admission close failed and will retry"
                        );
                        tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                    }
                }
            }
        }
        if !self.operation_quiescent {
            self.lifecycle.wait_for_operation_quiescence().await;
            self.operation_quiescent = true;
        }
        if !self.worker_stopped {
            self.quiesce_and_stop().await;
            self.worker_stopped = true;
        }
        if !self.unpublished {
            loop {
                let lifecycle = self.lifecycle.clone();
                match self
                    .registry
                    .unpublish_exact_with_release(&self.published_services, || {
                        lifecycle.release_authority_claim();
                        Ok(())
                    }) {
                    Ok(()) => {
                        self.unpublished = true;
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            audit_fault = "active_defense_detached_exact_unpublish_retry",
                            "detached active-defense exact unpublish failed and will retry"
                        );
                        tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                    }
                }
            }
        }
        if let Some(on_complete) = self.on_complete.take() {
            on_complete();
        }
    }

    async fn quiesce_and_stop(&mut self) {
        'worker_phase: loop {
            loop {
                match detached_teardown_prepare_worker_stop(self) {
                    Ok(()) => break,
                    Err(error) => {
                        if let Err(worker_error) = self.ensure_teardown_worker_running().await {
                            tracing::warn!(
                                error = %worker_error,
                                audit_fault = "active_defense_detached_recovery_worker_retry",
                                "detached active-defense recovery worker failed to start and will retry"
                            );
                        }
                        tracing::warn!(
                            error = %error,
                            audit_fault = "active_defense_detached_pre_stop_drain_retry",
                            "detached active-defense pre-stop drain failed and will retry while the worker remains live"
                        );
                        tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                    }
                }
            }
            loop {
                let shutdown = match self.worker_handle.as_mut() {
                    Some(worker_handle) => worker_handle.shutdown().await,
                    None if self.active_worker.shutdown_is_complete() => Ok(()),
                    None => Err(ResponseWorkerTickError::WorkerStopped),
                };
                match shutdown {
                    Ok(()) => break,
                    Err(error) if self.active_worker.shutdown_is_complete() => {
                        tracing::warn!(
                            error = %error,
                            audit_fault = "active_defense_detached_worker_shutdown_error_after_completion",
                            "detached active-defense worker reported an error after shutdown completed"
                        );
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            audit_fault = "active_defense_detached_worker_shutdown_retry",
                            "detached active-defense worker shutdown failed and will retry"
                        );
                        tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                    }
                }
            }
            loop {
                if let Err(error) = self.lifecycle.drain_to_zero() {
                    tracing::warn!(
                        error = %error,
                        audit_fault = "active_defense_detached_final_receipt_drain_retry",
                        "detached active-defense final receipt drain failed and will retry"
                    );
                    tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                    continue;
                }
                match ensure_detached_overlay_inventory_empty(self) {
                    Ok(()) => {}
                    Err(ProductionActiveDefenseHostError::ActiveOverlayContributions {
                        ..
                    }) => {
                        tracing::warn!(
                            audit_fault = "active_defense_detached_post_stop_overlay_race",
                            "active-defense overlay appeared during worker shutdown; recovery will resume"
                        );
                        tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                        continue 'worker_phase;
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            audit_fault = "active_defense_detached_final_inventory_retry",
                            "detached active-defense final inventory failed and will retry"
                        );
                        tokio::time::sleep(ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL).await;
                        continue;
                    }
                }
                break 'worker_phase;
            }
        }
    }

    async fn wait_for_tick_completion(
        &self,
        started_sequence: u64,
    ) -> Result<(), ResponseWorkerTickError> {
        loop {
            let health = self.active_worker.health();
            if health
                .last_tick_completed_sequence
                .is_some_and(|completed| completed >= started_sequence)
            {
                return Ok(());
            }
            if matches!(
                health.lifecycle,
                ResponseWorkerLifecycle::Failed | ResponseWorkerLifecycle::Stopped
            ) {
                return Err(ResponseWorkerTickError::WorkerStopped);
            }
            tokio::task::yield_now().await;
        }
    }

    async fn ensure_teardown_worker_running(&mut self) -> Result<(), ResponseWorkerTickError> {
        if self
            .worker_handle
            .as_ref()
            .is_some_and(ProductionResponseWorkerHandle::is_running)
            && !matches!(
                self.active_worker.health().lifecycle,
                ResponseWorkerLifecycle::Failed | ResponseWorkerLifecycle::Stopped
            )
        {
            return Ok(());
        }
        if let Some(worker_handle) = self.worker_handle.as_mut() {
            if let Err(error) = worker_handle.shutdown().await {
                tracing::warn!(
                    error = %error,
                    audit_fault = "active_defense_detached_failed_worker_join",
                    "detached active-defense teardown observed the failed primary worker"
                );
                if !self.active_worker.shutdown_is_complete() {
                    return Err(error);
                }
            }
        }
        if !self.active_worker.shutdown_is_complete() {
            return Err(ResponseWorkerTickError::WorkerStopped);
        }
        let (worker, handle) = self
            .orchestrator
            .start_teardown_recovery_worker(self.worker_loop)
            .await?;
        self.active_worker = worker;
        self.worker_handle = Some(handle);
        Ok(())
    }
}

fn detached_teardown_prepare_worker_stop(
    teardown: &DetachedActiveDefenseTeardown,
) -> Result<(), ProductionActiveDefenseHostError> {
    teardown.lifecycle.drain_to_zero()?;
    ensure_detached_overlay_inventory_empty(teardown)
}

fn ensure_detached_overlay_inventory_empty(
    teardown: &DetachedActiveDefenseTeardown,
) -> Result<(), ProductionActiveDefenseHostError> {
    let inventory = teardown.security_store.active_defense_overlay_inventory()?;
    if inventory.has_active_contributions() {
        return Err(ProductionActiveDefenseHostError::ActiveOverlayContributions { inventory });
    }
    Ok(())
}

fn spawn_detached_active_defense_teardown(
    teardown: DetachedActiveDefenseTeardown,
    permit: ActiveDefenseTeardownPermit,
) {
    permit.enqueue(RetainedActiveDefenseCleanupWork::Published(teardown));
}

#[cfg(test)]
mod retained_teardown_supervisor_tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::{Duration, Instant};

    use super::{ActiveDefenseTeardownSupervisor, RetainedActiveDefenseCleanupWork};

    fn wait_until(mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ready() {
            assert!(
                Instant::now() < deadline,
                "retained teardown did not complete"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn injected_service_spawn_failure_retains_and_completes_the_only_cleanup() {
        let supervisor = Arc::new(ActiveDefenseTeardownSupervisor::new());
        supervisor.fail_next_spawn();
        let permit = supervisor
            .acquire()
            .unwrap_or_else(|error| panic!("acquire retained teardown permit: {error}"));
        let completed = Arc::new(AtomicU64::new(0));
        let completed_for_job = Arc::clone(&completed);
        permit.enqueue(RetainedActiveDefenseCleanupWork::Test(Box::new(
            move || {
                completed_for_job.fetch_add(1, Ordering::AcqRel);
            },
        )));

        wait_until(|| completed.load(Ordering::Acquire) == 1);
        wait_until(|| supervisor.lock_state().retained_owners == 0);
    }

    #[test]
    fn panic_and_replacement_spawn_failure_retain_the_only_cleanup() {
        let supervisor = Arc::new(ActiveDefenseTeardownSupervisor::new());
        let permit = supervisor
            .acquire()
            .unwrap_or_else(|error| panic!("acquire retained teardown permit: {error}"));
        supervisor.panic_next_service_attempt();
        supervisor.fail_next_spawn();
        let completed = Arc::new(AtomicU64::new(0));
        let completed_for_job = Arc::clone(&completed);
        permit.enqueue(RetainedActiveDefenseCleanupWork::Test(Box::new(
            move || {
                completed_for_job.fetch_add(1, Ordering::AcqRel);
            },
        )));

        wait_until(|| completed.load(Ordering::Acquire) == 1);
        wait_until(|| supervisor.lock_state().retained_owners == 0);
    }

    #[test]
    fn concurrent_acquire_never_observes_running_before_spawn_succeeds() {
        let supervisor = Arc::new(ActiveDefenseTeardownSupervisor::new());
        supervisor.fail_next_spawn();
        let start = Arc::new(Barrier::new(3));
        let acquired = Arc::new(Barrier::new(3));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut joins = Vec::new();
        for _ in 0..2 {
            let supervisor_for_thread = Arc::clone(&supervisor);
            let start_for_thread = Arc::clone(&start);
            let acquired_for_thread = Arc::clone(&acquired);
            let observations_for_thread = Arc::clone(&observations);
            joins.push(std::thread::spawn(move || {
                start_for_thread.wait();
                let permit = supervisor_for_thread
                    .acquire()
                    .unwrap_or_else(|error| panic!("concurrent permit acquisition: {error}"));
                let running = supervisor_for_thread.lock_state().service_running;
                observations_for_thread
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(running);
                acquired_for_thread.wait();
                drop(permit);
            }));
        }
        start.wait();
        acquired.wait();
        for join in joins {
            join.join()
                .unwrap_or_else(|_| panic!("concurrent permit acquisition thread panicked"));
        }

        let observations = observations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(observations.as_slice(), &[true, true]);
    }
}
