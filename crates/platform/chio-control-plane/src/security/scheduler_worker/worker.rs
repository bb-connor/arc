use super::ResponseWorkerTickError;
use super::ErrorCode;
use super::PortError;
use super::catch_unwind;
use super::AssertUnwindSafe;
use super::AtomicBool;
use super::AtomicU64;
use super::Ordering;
use super::Arc;
use super::Mutex;
use super::Duration;
use super::Instant;
use super::oneshot;
use super::watch;
use super::MissedTickBehavior;
use super::ResponseWorkerTick;
use super::ResponseWorkerPort;
use super::ResponseWorkerLifecycle;
use super::ResponseWorkerHealth;

use super::acquire_response_worker_join_permit;
use super::ResponseWorkerTaskLiveness;


use super::ProductionResponseWorker;
use super::ProductionResponseWorkerHandle;
use super::ResponseWorkerStartupGuard;
use super::ResponseWorkerJoinOwnership;
use super::ResponseWorkerThreadCompletion;


pub(super) const WORKER_CLAIM_DOMAIN: &[u8] = b"chio.active-defense-worker-claim.v1\0";
pub(super) const MIN_WORKER_PROGRESS_DEADLINE: Duration = Duration::from_secs(1);
pub(super) const MAX_WORKER_PROGRESS_DEADLINE: Duration = Duration::from_secs(60);
pub(super) const MAX_WORKER_TICK_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(super) struct ResponseWorkerProgress {
    deadline: Option<Duration>,
    published_at: Option<Instant>,
    tick_started_at: Option<Instant>,
    tick_completed_at: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionResponseWorkerLoopConfig {
    pub tick_interval: Duration,
}

impl ProductionResponseWorkerLoopConfig {
    pub(super) fn validate(self) -> Result<Self, ResponseWorkerTickError> {
        if self.tick_interval.is_zero() || self.tick_interval > MAX_WORKER_TICK_INTERVAL {
            return Err(ResponseWorkerTickError::InvalidConfig);
        }
        Ok(self)
    }

    pub(super) fn progress_deadline(self) -> Duration {
        self.tick_interval
            .saturating_mul(3)
            .max(MIN_WORKER_PROGRESS_DEADLINE)
            .min(MAX_WORKER_PROGRESS_DEADLINE)
            .max(self.tick_interval.saturating_mul(2))
    }
}

impl ProductionResponseWorker {
    pub fn new(port: Arc<dyn ResponseWorkerPort>) -> Result<Self, ResponseWorkerTickError> {
        port.ensure_ready()?;
        Ok(Self {
            port,
            next_tick_sequence: AtomicU64::new(0),
            shutdown_requested: AtomicBool::new(false),
            shutdown_completed: AtomicBool::new(false),
            shutdown_completion: watch::channel(false).0,
            loop_started: AtomicBool::new(false),
            task_live: AtomicBool::new(false),
            thread_joined: AtomicBool::new(false),
            publication_ready: AtomicBool::new(false),
            health: Mutex::new(ResponseWorkerHealth::created()),
            progress: Mutex::new(ResponseWorkerProgress::default()),
        })
    }

    #[cfg(test)]
    pub(super) fn new_for_test<P>(port: Arc<P>) -> Result<Self, ResponseWorkerTickError>
    where
        P: ResponseWorkerPort + 'static,
    {
        Self::new(port)
    }

    fn live_lifecycle(&self) -> Result<ResponseWorkerLifecycle, ResponseWorkerTickError> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(ResponseWorkerTickError::WorkerStopped);
        }
        let lifecycle = self
            .health
            .lock()
            .map_err(|_| PortError::unavailable())?
            .lifecycle;
        if lifecycle == ResponseWorkerLifecycle::Failed {
            return Err(ResponseWorkerTickError::WorkerStopped);
        }
        if self.loop_started.load(Ordering::Acquire) && !self.task_live.load(Ordering::Acquire) {
            return Err(ResponseWorkerTickError::WorkerStopped);
        }
        Ok(lifecycle)
    }

    pub(in crate::security) fn ensure_bootstrap_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.live_lifecycle()?;
        self.port.ensure_ready()
    }

    pub fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.live_lifecycle()?;
        if self.loop_started.load(Ordering::Acquire)
            && !self.publication_ready.load(Ordering::Acquire)
        {
            return Err(ResponseWorkerTickError::WorkerPublicationPending);
        }
        self.ensure_progress()?;
        self.port.ensure_ready()
    }

    /// Await the worker task's clean post-loop shutdown certificate.
    pub async fn wait_for_shutdown_completion(&self) {
        let mut completion = self.shutdown_completion.subscribe();
        if *completion.borrow() {
            return;
        }
        while completion.changed().await.is_ok() {
            if *completion.borrow() {
                return;
            }
        }
    }

    #[must_use]
    pub(in crate::security) fn shutdown_is_complete(&self) -> bool {
        self.shutdown_completed.load(Ordering::Acquire)
    }

    pub(super) fn tick_once(&self) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(ResponseWorkerTickError::WorkerStopped);
        }
        let sequence = self.next_tick_sequence.fetch_add(1, Ordering::AcqRel);
        self.mark_tick_started(sequence);
        self.with_health(|health| {
            health.lifecycle = ResponseWorkerLifecycle::Running;
            health.ticks_attempted = health.ticks_attempted.saturating_add(1);
        });
        let result = self.port.tick(sequence, false);
        self.mark_tick_completed(sequence);
        match result {
            Ok(report) => {
                let lease_lost = !report.lease_lost_action_ids.is_empty();
                let declassification_pending = report.declassification_receipts_pending > 0;
                let degraded = lease_lost || declassification_pending;
                self.with_health(|health| {
                    health.lifecycle = if degraded {
                        ResponseWorkerLifecycle::Degraded
                    } else {
                        ResponseWorkerLifecycle::Ready
                    };
                    health.ticks_completed = health.ticks_completed.saturating_add(1);
                    health.last_error = if lease_lost {
                        Some("one or more scheduler leases were lost".to_string())
                    } else if declassification_pending {
                        Some(format!(
                            "{} declassification receipts remain pending",
                            report.declassification_receipts_pending
                        ))
                    } else {
                        None
                    };
                });
                Ok(report)
            }
            Err(error) => {
                if matches!(error, ResponseWorkerTickError::WorkerCrash(_)) {
                    self.mark_failed(&error);
                } else {
                    let message = error.to_string();
                    self.with_health(|health| {
                        health.lifecycle = ResponseWorkerLifecycle::Degraded;
                        health.last_error = Some(message);
                    });
                }
                Err(error)
            }
        }
    }

    pub(super) fn tick_once_catching_crash(&self) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        catch_unwind(AssertUnwindSafe(|| self.tick_once())).unwrap_or_else(|_| {
            let error = worker_task_crash_error();
            // Cleanup can fail too. Publish the terminal crash before trying
            // to release leases so that a second fault cannot hide the first.
            self.mark_failed(&error);
            Err(error)
        })
    }

    async fn tick_until_initial_ready(
        &self,
        config: ProductionResponseWorkerLoopConfig,
        shutdown_receiver: &mut watch::Receiver<bool>,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        let started_at = Instant::now();
        let deadline = config.progress_deadline();
        loop {
            let result = self.tick_once_catching_crash();
            let elapsed = started_at.elapsed();
            match result {
                Ok(report) if elapsed <= deadline => return Ok(report),
                Ok(_) => {
                    let health = self.health();
                    return Err(ResponseWorkerTickError::WorkerProgressStalled {
                        started_sequence: health.last_tick_started_sequence,
                        completed_sequence: health.last_tick_completed_sequence,
                    });
                }
                Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
                    if elapsed < deadline =>
                {
                    if shutdown_receiver.has_changed().is_err() || *shutdown_receiver.borrow() {
                        return Err(ResponseWorkerTickError::WorkerStopped);
                    }
                    tokio::task::yield_now().await;
                }
                Err(error @ ResponseWorkerTickError::WorkerCrash(_)) => return Err(error),
                Err(error) => {
                    let remaining = deadline.saturating_sub(elapsed);
                    if remaining.is_zero() {
                        return Err(error);
                    }
                    tokio::select! {
                        changed = shutdown_receiver.changed() => {
                            if changed.is_err() || *shutdown_receiver.borrow() {
                                return Err(ResponseWorkerTickError::WorkerStopped);
                            }
                        }
                        _ = tokio::time::sleep(config.tick_interval) => {}
                        _ = tokio::time::sleep(remaining) => return Err(error),
                    }
                }
            }
        }
    }

    pub(in crate::security) async fn start_parked(
        self: &Arc<Self>,
        config: ProductionResponseWorkerLoopConfig,
    ) -> Result<ProductionResponseWorkerHandle, ResponseWorkerTickError> {
        let config = config.validate()?;
        self.ensure_bootstrap_ready()?;
        let join_permit = acquire_response_worker_join_permit()?;
        self.loop_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ResponseWorkerTickError::WorkerAlreadyRunning)?;
        self.configure_progress(config.progress_deadline());
        self.with_health(|health| {
            health.lifecycle = ResponseWorkerLifecycle::Created;
            health.last_error = None;
        });
        let (shutdown, mut shutdown_receiver) = watch::channel(false);
        let (task_ready_sender, task_ready) = oneshot::channel();
        let (arm, mut arm_receiver) = oneshot::channel();
        let (armed_sender, armed) = oneshot::channel();
        let (publication_gate, mut publication_receiver) = oneshot::channel();
        let (publication_readiness_sender, publication_readiness) = oneshot::channel();
        let (thread_completion_sender, thread_completion) = watch::channel(false);
        let worker = Arc::clone(self);
        let join = std::thread::Builder::new()
            .name("chio-response-worker".to_string())
            .spawn(move || {
                let thread_completion_guard = ResponseWorkerThreadCompletion {
                    completion: thread_completion_sender,
                };
                let task_liveness = ResponseWorkerTaskLiveness::begin(Arc::clone(&worker));
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let message = error.to_string();
                        let _ = task_ready_sender.send(Err(message.clone()));
                        return Err(ResponseWorkerTickError::WorkerRuntime(message));
                    }
                };
                if task_ready_sender.send(Ok(())).is_err() {
                    return Err(ResponseWorkerTickError::WorkerTaskReadyHandshake);
                }
                let result = runtime.block_on(async move {
                    let arm_received = tokio::select! {
                        result = &mut arm_receiver => result.is_ok(),
                        _ = shutdown_receiver.changed() => {
                            worker.request_stop();
                            return worker.complete_shutdown_after_loop();
                        }
                    };
                    if !arm_received {
                        worker.request_stop();
                        worker.complete_shutdown_after_loop()?;
                        return Err(ResponseWorkerTickError::WorkerArmHandshake);
                    }
                    worker.mark_armed();
                    if armed_sender.send(()).is_err() {
                        worker.request_stop();
                        worker.complete_shutdown_after_loop()?;
                        return Err(ResponseWorkerTickError::WorkerArmHandshake);
                    }
                    let publication_released = tokio::select! {
                        result = &mut publication_receiver => result.is_ok(),
                        _ = shutdown_receiver.changed() => {
                            worker.request_stop();
                            return worker.complete_shutdown_after_loop();
                        }
                    };
                    if !publication_released {
                        worker.request_stop();
                        worker.complete_shutdown_after_loop()?;
                        return Err(ResponseWorkerTickError::WorkerPublicationGate);
                    }
                    let initial_tick = worker
                        .tick_until_initial_ready(config, &mut shutdown_receiver)
                        .await;
                    if let Err(error) = initial_tick {
                        let _ = publication_readiness_sender.send(Err(error.to_string()));
                        worker.request_stop();
                        worker.complete_shutdown_after_loop()?;
                        worker.mark_failed(&error);
                        return Err(error);
                    }
                    if let Err(error) = worker.mark_publication_ready() {
                        let _ = publication_readiness_sender.send(Err(error.to_string()));
                        worker.request_stop();
                        worker.complete_shutdown_after_loop()?;
                        worker.mark_failed(&error);
                        return Err(error);
                    }
                    if publication_readiness_sender.send(Ok(())).is_err() {
                        let error = ResponseWorkerTickError::WorkerPublicationGate;
                        worker.request_stop();
                        worker.complete_shutdown_after_loop()?;
                        worker.mark_failed(&error);
                        return Err(error);
                    }
                    let mut interval = tokio::time::interval_at(
                        tokio::time::Instant::now() + config.tick_interval,
                        config.tick_interval,
                    );
                    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {
                            changed = shutdown_receiver.changed() => {
                                if changed.is_err() || *shutdown_receiver.borrow() {
                                    break;
                                }
                            }
                            _ = interval.tick() => {
                                match worker.tick_once_catching_crash() {
                                    Ok(_) => {}
                                    Err(ResponseWorkerTickError::WorkerStopped)
                                        if *shutdown_receiver.borrow() =>
                                    {
                                        break;
                                    }
                                    Err(ResponseWorkerTickError::WorkerCrash(code)) => {
                                        let error = ResponseWorkerTickError::WorkerCrash(code);
                                        worker.request_stop();
                                        worker.complete_shutdown_after_loop()?;
                                        worker.mark_failed(&error);
                                        return Err(error);
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                    worker.complete_shutdown_after_loop()
                });
                drop(runtime);
                drop(task_liveness);
                drop(thread_completion_guard);
                result
            })
            .map_err(|error| {
                let error = ResponseWorkerTickError::WorkerRuntime(error.to_string());
                self.mark_failed(&error);
                error
            })?;
        let mut startup_guard = ResponseWorkerStartupGuard {
            shutdown: shutdown.clone(),
            join: Some(ResponseWorkerJoinOwnership {
                join,
                permit: join_permit,
            }),
            worker: Arc::clone(self),
            active: true,
        };
        let task_ready_error = match task_ready.await {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(ResponseWorkerTickError::WorkerRuntime(error)),
            Err(_) => Some(ResponseWorkerTickError::WorkerTaskReadyHandshake),
        };
        if let Some(error) = task_ready_error {
            return Err(error);
        }
        let join = startup_guard.take_join()?;
        Ok(ProductionResponseWorkerHandle {
            shutdown,
            arm: Some(arm),
            armed: Some(armed),
            publication_gate: Some(publication_gate),
            publication_readiness: Some(publication_readiness),
            thread_completion,
            join: Some(join),
            worker: Arc::clone(self),
            publication_released: false,
            publication_ready: false,
            clean_shutdown: false,
        })
    }

    pub(super) fn complete_shutdown_after_loop(&self) -> Result<(), ResponseWorkerTickError> {
        if self.shutdown_completed.load(Ordering::Acquire) {
            return Ok(());
        }
        let result = self.port.shutdown();
        self.with_health(|health| {
            // Cleanup completion is not recovery from a failed worker. Keep
            // the terminal fault and its cause observable throughout shutdown.
            if health.lifecycle == ResponseWorkerLifecycle::Failed {
                return;
            }
            health.lifecycle = if result.is_ok() {
                ResponseWorkerLifecycle::Stopped
            } else {
                ResponseWorkerLifecycle::Degraded
            };
            if let Err(error) = &result {
                health.last_error = Some(error.to_string());
            }
        });
        if result.is_ok() {
            self.shutdown_completed.store(true, Ordering::Release);
            let _ = self.shutdown_completion.send_replace(true);
        }
        result
    }

    #[must_use]
    pub fn health(&self) -> ResponseWorkerHealth {
        let mut health = self
            .health
            .lock()
            .map_or_else(|_| failed_health(), |health| health.clone());
        let (configured, pending, error) = self.port.declassification_outbox_status();
        health.declassification_outbox_configured = configured;
        health.declassification_receipts_pending = pending;
        health.declassification_outbox_error = error;
        health
    }

    fn with_health(&self, update: impl FnOnce(&mut ResponseWorkerHealth)) {
        if let Ok(mut health) = self.health.lock() {
            update(&mut health);
        }
    }

    pub(super) fn mark_failed(&self, error: &ResponseWorkerTickError) {
        self.task_live.store(false, Ordering::Release);
        self.with_health(|health| {
            health.lifecycle = ResponseWorkerLifecycle::Failed;
            health.last_error = Some(error.to_string());
        });
    }

    pub(super) fn configure_progress(&self, deadline: Duration) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.deadline = Some(deadline);
        }
    }

    #[cfg(test)]
    pub(in crate::security) fn set_progress_deadline_for_test(&self, deadline: Duration) {
        self.configure_progress(deadline);
    }

    fn mark_armed(&self) {
        self.with_health(|health| {
            health.lifecycle = ResponseWorkerLifecycle::Created;
            health.last_error = None;
        });
    }

    pub(super) fn mark_publication_released(&self) -> Result<(), ResponseWorkerTickError> {
        if !self.task_live.load(Ordering::Acquire) {
            return Err(ResponseWorkerTickError::WorkerStopped);
        }
        Ok(())
    }

    pub(super) fn mark_publication_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.progress
            .lock()
            .map_err(|_| PortError::unavailable())?
            .published_at = Some(Instant::now());
        self.publication_ready.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) fn request_stop(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
        self.with_health(|health| {
            if !matches!(
                health.lifecycle,
                ResponseWorkerLifecycle::Failed | ResponseWorkerLifecycle::Stopped
            ) {
                health.lifecycle = ResponseWorkerLifecycle::Degraded;
                health.last_error = Some("response worker shutdown requested".to_string());
            }
        });
    }

    fn mark_tick_started(&self, sequence: u64) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.tick_started_at = Some(Instant::now());
        }
        self.with_health(|health| {
            health.last_tick_started_sequence = Some(sequence);
            health.tick_in_flight = true;
        });
    }

    fn mark_tick_completed(&self, sequence: u64) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.tick_completed_at = Some(Instant::now());
        }
        self.with_health(|health| {
            health.last_tick_completed_sequence = Some(sequence);
            health.tick_in_flight = false;
        });
    }

    fn ensure_progress(&self) -> Result<(), ResponseWorkerTickError> {
        let now = Instant::now();
        let (deadline, published_at, tick_started_at, tick_completed_at) = {
            let progress = self.progress.lock().map_err(|_| PortError::unavailable())?;
            (
                progress.deadline,
                progress.published_at,
                progress.tick_started_at,
                progress.tick_completed_at,
            )
        };
        let (Some(deadline), Some(published_at)) = (deadline, published_at) else {
            return Ok(());
        };
        let health = self
            .health
            .lock()
            .map_err(|_| PortError::unavailable())?
            .clone();
        let progress_at = if health.tick_in_flight {
            tick_started_at.unwrap_or(published_at)
        } else {
            tick_completed_at.unwrap_or(published_at)
        };
        if now.saturating_duration_since(progress_at) <= deadline {
            return Ok(());
        }
        let error = ResponseWorkerTickError::WorkerProgressStalled {
            started_sequence: health.last_tick_started_sequence,
            completed_sequence: health.last_tick_completed_sequence,
        };
        self.with_health(|current| {
            current.lifecycle = ResponseWorkerLifecycle::Degraded;
            current.last_error = Some(error.to_string());
        });
        Err(error)
    }
}

pub(super) fn failed_health() -> ResponseWorkerHealth {
    ResponseWorkerHealth {
        lifecycle: ResponseWorkerLifecycle::Failed,
        ticks_attempted: 0,
        ticks_completed: 0,
        declassification_outbox_configured: false,
        declassification_receipts_pending: None,
        declassification_outbox_error: Some(
            "response worker health lock is unavailable".to_string(),
        ),
        last_tick_started_sequence: None,
        last_tick_completed_sequence: None,
        tick_in_flight: false,
        last_error: Some("response worker health lock is unavailable".to_string()),
    }
}

pub(super) fn worker_task_crash_error() -> ResponseWorkerTickError {
    ErrorCode::new("response.worker_task_crash").map_or(
        ResponseWorkerTickError::InvalidConfig,
        ResponseWorkerTickError::WorkerCrash,
    )
}

