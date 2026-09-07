use chio_core::{canonical_json_bytes, sha256};
use chio_quarantine::{
    ResponseExecutor, ResponseScheduler, ScheduledResponseExecutor, SchedulerError,
    SchedulerPolicy, SchedulerTickRequest, SchedulerWorkOutcome,
};
use chio_security_kernel::SecurityClock;
use chio_security_types::ports::{
    ActionId, DeclassificationEvidenceCommitStore, EffectPort, ErrorCode, GrantId, LeaseOwnerId,
    PortError, PortErrorKind, RecordId, ResponseDispatchStore, ResponseSchedulerStore,
    ScheduledWork, SchedulerHealthPort, SecurityAlertPort, SecurityReceiptSink, TenantId,
    MAX_DECLASSIFICATION_EVIDENCE_BATCH,
};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{oneshot, watch};
use tokio::time::MissedTickBehavior;

use super::adapters::{
    DeclassificationCompactionReport, DeclassificationReceiptDrainReport,
    DeclassificationReceiptOutboxDrainer, DeclassificationReconciliationReport,
};

const WORKER_CLAIM_DOMAIN: &[u8] = b"chio.active-defense-worker-claim.v1\0";
const MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES: u32 = 4_096;
const MIN_WORKER_PROGRESS_DEADLINE: Duration = Duration::from_secs(1);
const MAX_WORKER_PROGRESS_DEADLINE: Duration = Duration::from_secs(60);
const MAX_WORKER_TICK_INTERVAL: Duration = Duration::from_secs(30);
const MAX_RESPONSE_WORKER_JOIN_OWNERS: usize = 64;
const RESPONSE_WORKER_REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseWorkerTick {
    pub tenant_id: TenantId,
    pub declassification_receipts_appended: u32,
    pub declassification_receipts_acknowledged: u32,
    pub declassification_receipts_pending: u64,
    pub declassification_receipts_compacted: u32,
    pub claimed: usize,
    pub completed_action_ids: Vec<ActionId>,
    pub retry_action_ids: Vec<ActionId>,
    pub lease_lost_action_ids: Vec<ActionId>,
}

pub trait ResponseWorkerPort: Send + Sync {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError>;
    fn tick(
        &self,
        tick_sequence: u64,
        shutdown_requested: bool,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError>;
    fn shutdown(&self) -> Result<(), ResponseWorkerTickError>;

    fn declassification_outbox_status(&self) -> (bool, Option<u64>, Option<String>) {
        (false, None, None)
    }
}

#[derive(Debug, Error)]
pub enum ResponseWorkerTickError {
    #[error("response worker lost an acknowledgement")]
    AckLost,
    #[error("response worker configuration is invalid")]
    InvalidConfig,
    #[error("expired terminal scheduler cleanup remains pending")]
    TerminalSchedulerCleanupPending,
    #[error("declassification receipt outbox failed: {0}")]
    DeclassificationOutbox(PortError),
    #[error("declassification receipt outbox has {0} pending receipts")]
    DeclassificationOutboxPending(u64),
    #[error("declassification receipt outbox made no progress with {0} receipts pending")]
    DeclassificationOutboxNoProgress(u64),
    #[error(
        "declassification receipt outbox exceeded the bounded drain with {0} receipts pending"
    )]
    DeclassificationOutboxDrainLimit(u64),
    #[error(
        "declassification receipt startup reconciliation made no progress with {0} consumptions stranded"
    )]
    DeclassificationReconciliationNoProgress(u64),
    #[error(
        "declassification receipt startup reconciliation exceeded its bound with {0} consumptions stranded"
    )]
    DeclassificationReconciliationLimit(u64),
    #[error("production security runtime has {0} live publication leases")]
    RuntimeLeasesActive(u64),
    #[error("production security runtime has {0} live dispatch outcome recorder leases")]
    DispatchRecorderLeasesActive(u64),
    #[error("production active-defense host has {0} live event consumer leases")]
    ConsumerLeasesActive(u64),
    #[error("production security runtime admission is closed")]
    RuntimeAdmissionClosed,
    #[error("response worker port failed: {0}")]
    Port(#[from] PortError),
    #[error("response worker background loop is already running")]
    WorkerAlreadyRunning,
    #[error("response worker task-ready handshake failed")]
    WorkerTaskReadyHandshake,
    #[error("response worker arm handshake failed")]
    WorkerArmHandshake,
    #[error("response worker publication gate failed")]
    WorkerPublicationGate,
    #[error("response worker publication has not been observed")]
    WorkerPublicationPending,
    #[error("response worker initial tick failed: {0}")]
    WorkerInitialTick(String),
    #[error("response worker runtime failed: {0}")]
    WorkerRuntime(String),
    #[error("response worker join reaper failed: {0}")]
    WorkerReaper(String),
    #[error("response worker join registry is at capacity")]
    WorkerReaperCapacity,
    #[error(
        "response worker progress stalled after start {started_sequence:?} and completion {completed_sequence:?}"
    )]
    WorkerProgressStalled {
        started_sequence: Option<u64>,
        completed_sequence: Option<u64>,
    },
    #[error("active-defense services already have an owner")]
    ServicesAlreadyPublished,
    #[error("active-defense service ownership does not match the installed instance")]
    ServicesOwnershipMismatch,
    #[error("response scheduler failed: {0}")]
    Scheduler(#[from] SchedulerError),
    #[error("response worker crashed: {0}")]
    WorkerCrash(ErrorCode),
    #[error("response worker is stopped")]
    WorkerStopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseWorkerLifecycle {
    Created,
    Running,
    Ready,
    Degraded,
    Failed,
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DeclassificationOutboxHealth {
    Ready,
    Pending {
        receipts: u64,
    },
    Failed {
        pending_receipts: Option<u64>,
        error: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseWorkerHealth {
    pub lifecycle: ResponseWorkerLifecycle,
    pub ticks_attempted: u64,
    pub ticks_completed: u64,
    pub declassification_outbox_configured: bool,
    pub declassification_receipts_pending: Option<u64>,
    pub declassification_outbox_error: Option<String>,
    pub last_tick_started_sequence: Option<u64>,
    pub last_tick_completed_sequence: Option<u64>,
    pub tick_in_flight: bool,
    pub last_error: Option<String>,
}

impl ResponseWorkerHealth {
    #[must_use]
    pub const fn created() -> Self {
        Self {
            lifecycle: ResponseWorkerLifecycle::Created,
            ticks_attempted: 0,
            ticks_completed: 0,
            declassification_outbox_configured: false,
            declassification_receipts_pending: None,
            declassification_outbox_error: None,
            last_tick_started_sequence: None,
            last_tick_completed_sequence: None,
            tick_in_flight: false,
            last_error: None,
        }
    }
}

#[derive(Clone)]
pub(super) struct ProductionDeclassificationReceiptOutbox {
    port: Arc<dyn DeclassificationReceiptOutboxPort>,
    health: Arc<Mutex<DeclassificationOutboxHealth>>,
    compaction_cursor: Arc<Mutex<(Option<TenantId>, Option<GrantId>)>>,
}

trait DeclassificationReceiptOutboxPort: Send + Sync {
    fn ensure_ready(&self) -> Result<(), PortError>;
    fn count_pending(&self) -> Result<u64, PortError>;
    fn count_stranded(&self) -> Result<u64, PortError>;
    fn reconcile_stranded(
        &self,
        max_records: u32,
    ) -> Result<DeclassificationReconciliationReport, PortError>;
    fn drain_once(
        &self,
        max_receipts: u32,
    ) -> Result<DeclassificationReceiptDrainReport, PortError>;
    fn compact_once(
        &self,
        after_tenant_id: Option<TenantId>,
        after_grant_id: Option<GrantId>,
        max_records: u32,
    ) -> Result<DeclassificationCompactionReport, PortError>;
}

struct NativeDeclassificationReceiptOutboxPort {
    evidence_store: Arc<dyn DeclassificationEvidenceCommitStore>,
    drainer: Arc<DeclassificationReceiptOutboxDrainer>,
}

impl DeclassificationReceiptOutboxPort for NativeDeclassificationReceiptOutboxPort {
    fn ensure_ready(&self) -> Result<(), PortError> {
        self.drainer.ensure_ready()
    }

    fn count_pending(&self) -> Result<u64, PortError> {
        self.evidence_store
            .count_pending_declassification_evidence()
    }

    fn count_stranded(&self) -> Result<u64, PortError> {
        self.evidence_store
            .count_stranded_declassification_consumptions()
    }

    fn reconcile_stranded(
        &self,
        max_records: u32,
    ) -> Result<DeclassificationReconciliationReport, PortError> {
        self.drainer.reconcile_stranded(max_records)
    }

    fn drain_once(
        &self,
        max_receipts: u32,
    ) -> Result<DeclassificationReceiptDrainReport, PortError> {
        self.drainer.drain_once(max_receipts)
    }

    fn compact_once(
        &self,
        after_tenant_id: Option<TenantId>,
        after_grant_id: Option<GrantId>,
        max_records: u32,
    ) -> Result<DeclassificationCompactionReport, PortError> {
        self.drainer
            .compact_once(after_tenant_id, after_grant_id, max_records)
    }
}

impl ProductionDeclassificationReceiptOutbox {
    #[must_use]
    pub(super) fn new(
        evidence_store: Arc<dyn DeclassificationEvidenceCommitStore>,
        drainer: Arc<DeclassificationReceiptOutboxDrainer>,
    ) -> Self {
        Self {
            port: Arc::new(NativeDeclassificationReceiptOutboxPort {
                evidence_store,
                drainer,
            }),
            health: Arc::new(Mutex::new(DeclassificationOutboxHealth::Pending {
                receipts: 0,
            })),
            compaction_cursor: Arc::new(Mutex::new((None, None))),
        }
    }

    #[cfg(test)]
    fn new_for_test(port: Arc<dyn DeclassificationReceiptOutboxPort>) -> Self {
        Self {
            port,
            health: Arc::new(Mutex::new(DeclassificationOutboxHealth::Pending {
                receipts: 0,
            })),
            compaction_cursor: Arc::new(Mutex::new((None, None))),
        }
    }

    pub(super) fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        let pending = self.map_port(self.port.count_pending())?;
        if pending == 0 {
            self.set_health(DeclassificationOutboxHealth::Ready);
            Ok(())
        } else {
            self.set_health(DeclassificationOutboxHealth::Pending { receipts: pending });
            Err(ResponseWorkerTickError::DeclassificationOutboxPending(
                pending,
            ))
        }
    }

    pub(super) fn reconcile_and_drain_startup(
        &self,
    ) -> Result<DeclassificationReceiptDrainReport, ResponseWorkerTickError> {
        self.map_port(self.port.ensure_ready())?;
        let mut remaining = self.map_port(self.port.count_stranded())?;
        if remaining > 0 {
            let mut aggregate = DeclassificationReconciliationReport {
                reconciled: 0,
                remaining,
            };
            for _ in 0..MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES {
                let report = self.map_port(
                    self.port
                        .reconcile_stranded(MAX_DECLASSIFICATION_EVIDENCE_BATCH),
                )?;
                aggregate.reconciled = aggregate
                    .reconciled
                    .checked_add(report.reconciled)
                    .ok_or(ResponseWorkerTickError::InvalidConfig)?;
                aggregate.remaining = report.remaining;
                if report.remaining == 0 {
                    break;
                }
                if report.reconciled == 0 || report.remaining >= remaining {
                    let error = ResponseWorkerTickError::DeclassificationReconciliationNoProgress(
                        report.remaining,
                    );
                    self.record_failure(&error, self.pending_count());
                    return Err(error);
                }
                remaining = report.remaining;
            }
            if aggregate.remaining > 0 {
                let error = ResponseWorkerTickError::DeclassificationReconciliationLimit(
                    aggregate.remaining,
                );
                self.record_failure(&error, self.pending_count());
                return Err(error);
            }
        }
        self.drain_to_zero()
    }

    pub(super) fn drain_to_zero(
        &self,
    ) -> Result<DeclassificationReceiptDrainReport, ResponseWorkerTickError> {
        let mut remaining = self.map_port(self.port.count_pending())?;
        if remaining == 0 {
            self.set_health(DeclassificationOutboxHealth::Ready);
            return Ok(DeclassificationReceiptDrainReport::default());
        }
        self.set_health(DeclassificationOutboxHealth::Pending {
            receipts: remaining,
        });
        let mut aggregate = DeclassificationReceiptDrainReport {
            appended: 0,
            acknowledged: 0,
            deferred: 0,
            remaining,
        };
        for _ in 0..MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES {
            let report =
                self.map_port(self.port.drain_once(MAX_DECLASSIFICATION_EVIDENCE_BATCH))?;
            aggregate.appended = aggregate
                .appended
                .checked_add(report.appended)
                .ok_or(ResponseWorkerTickError::InvalidConfig)?;
            aggregate.acknowledged = aggregate
                .acknowledged
                .checked_add(report.acknowledged)
                .ok_or(ResponseWorkerTickError::InvalidConfig)?;
            aggregate.deferred = aggregate
                .deferred
                .checked_add(report.deferred)
                .ok_or(ResponseWorkerTickError::InvalidConfig)?;
            aggregate.remaining = report.remaining;
            if report.remaining == 0 {
                self.set_health(DeclassificationOutboxHealth::Ready);
                return Ok(aggregate);
            }
            if report.acknowledged == 0 || report.remaining >= remaining {
                let error =
                    ResponseWorkerTickError::DeclassificationOutboxNoProgress(report.remaining);
                self.record_failure(&error, Some(report.remaining));
                return Err(error);
            }
            remaining = report.remaining;
            self.set_health(DeclassificationOutboxHealth::Pending {
                receipts: remaining,
            });
        }
        let error = ResponseWorkerTickError::DeclassificationOutboxDrainLimit(remaining);
        self.record_failure(&error, Some(remaining));
        Err(error)
    }

    pub(super) fn drain_one_batch(
        &self,
    ) -> Result<DeclassificationReceiptDrainReport, ResponseWorkerTickError> {
        let report = self.map_port(self.port.drain_once(MAX_DECLASSIFICATION_EVIDENCE_BATCH))?;
        if report.remaining == 0 {
            self.set_health(DeclassificationOutboxHealth::Ready);
            return Ok(report);
        }
        if report.acknowledged == 0 {
            let error = ResponseWorkerTickError::DeclassificationOutboxNoProgress(report.remaining);
            self.record_failure(&error, Some(report.remaining));
            return Err(error);
        }
        self.set_health(DeclassificationOutboxHealth::Pending {
            receipts: report.remaining,
        });
        Ok(report)
    }

    pub(super) fn maintain_one_batch(
        &self,
    ) -> Result<
        (
            DeclassificationReceiptDrainReport,
            DeclassificationCompactionReport,
        ),
        ResponseWorkerTickError,
    > {
        let drained = self.drain_one_batch()?;
        let (after_tenant_id, after_grant_id) = self
            .compaction_cursor
            .lock()
            .map_err(|_| PortError::unavailable())?
            .clone();
        let compacted = self.map_port(self.port.compact_once(
            after_tenant_id,
            after_grant_id,
            MAX_DECLASSIFICATION_EVIDENCE_BATCH,
        ))?;
        let invalid_report = compacted.compacted > MAX_DECLASSIFICATION_EVIDENCE_BATCH
            || (compacted.compacted == 0
                && (compacted.last_tenant_id.is_some() || compacted.last_grant_id.is_some()))
            || (compacted.compacted > 0
                && (compacted.last_tenant_id.is_none() || compacted.last_grant_id.is_none()));
        if invalid_report {
            return self.map_port(Err(PortError::integrity_failure()));
        }
        let mut cursor = self
            .compaction_cursor
            .lock()
            .map_err(|_| PortError::unavailable())?;
        *cursor = if compacted.compacted == MAX_DECLASSIFICATION_EVIDENCE_BATCH {
            (
                compacted.last_tenant_id.clone(),
                compacted.last_grant_id.clone(),
            )
        } else {
            (None, None)
        };
        Ok((drained, compacted))
    }

    #[must_use]
    fn health(&self) -> DeclassificationOutboxHealth {
        self.health.lock().map_or_else(
            |_| DeclassificationOutboxHealth::Failed {
                pending_receipts: None,
                error: "declassification receipt outbox health lock is unavailable".to_string(),
            },
            |health| health.clone(),
        )
    }

    fn map_port<T>(&self, result: Result<T, PortError>) -> Result<T, ResponseWorkerTickError> {
        result.map_err(|source| {
            let error = ResponseWorkerTickError::DeclassificationOutbox(source);
            let pending = self.pending_count();
            self.record_failure(&error, pending);
            error
        })
    }

    fn pending_count(&self) -> Option<u64> {
        self.port.count_pending().ok()
    }

    fn set_health(&self, health: DeclassificationOutboxHealth) {
        if let Ok(mut current) = self.health.lock() {
            *current = health;
        }
    }

    fn record_failure(&self, error: &ResponseWorkerTickError, pending_receipts: Option<u64>) {
        self.set_health(DeclassificationOutboxHealth::Failed {
            pending_receipts,
            error: error.to_string(),
        });
    }
}

pub struct ProductionResponseWorker {
    port: Arc<dyn ResponseWorkerPort>,
    next_tick_sequence: AtomicU64,
    shutdown_requested: AtomicBool,
    shutdown_completed: AtomicBool,
    shutdown_completion: watch::Sender<bool>,
    loop_started: AtomicBool,
    task_live: AtomicBool,
    thread_joined: AtomicBool,
    publication_ready: AtomicBool,
    health: Mutex<ResponseWorkerHealth>,
    progress: Mutex<ResponseWorkerProgress>,
}

#[derive(Default)]
struct ResponseWorkerProgress {
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
    fn validate(self) -> Result<Self, ResponseWorkerTickError> {
        if self.tick_interval.is_zero() || self.tick_interval > MAX_WORKER_TICK_INTERVAL {
            return Err(ResponseWorkerTickError::InvalidConfig);
        }
        Ok(self)
    }

    fn progress_deadline(self) -> Duration {
        self.tick_interval
            .saturating_mul(3)
            .max(MIN_WORKER_PROGRESS_DEADLINE)
            .min(MAX_WORKER_PROGRESS_DEADLINE)
            .max(self.tick_interval.saturating_mul(2))
    }
}

pub struct ProductionResponseWorkerHandle {
    shutdown: watch::Sender<bool>,
    arm: Option<oneshot::Sender<()>>,
    armed: Option<oneshot::Receiver<()>>,
    publication_gate: Option<oneshot::Sender<()>>,
    publication_readiness: Option<oneshot::Receiver<Result<(), String>>>,
    thread_completion: watch::Receiver<bool>,
    join: Option<ResponseWorkerJoinOwnership>,
    worker: Arc<ProductionResponseWorker>,
    publication_released: bool,
    publication_ready: bool,
    clean_shutdown: bool,
}

struct ResponseWorkerStartupGuard {
    shutdown: watch::Sender<bool>,
    join: Option<ResponseWorkerJoinOwnership>,
    worker: Arc<ProductionResponseWorker>,
    active: bool,
}

struct ResponseWorkerJoinOwnership {
    join: std::thread::JoinHandle<Result<(), ResponseWorkerTickError>>,
    permit: ResponseWorkerJoinPermit,
}

struct ResponseWorkerJoinPermit {
    registry: Arc<ResponseWorkerReaperRegistry>,
}

struct ResponseWorkerJoinJob {
    join: std::thread::JoinHandle<Result<(), ResponseWorkerTickError>>,
    worker: Arc<ProductionResponseWorker>,
    _permit: ResponseWorkerJoinPermit,
}

struct ResponseWorkerReaperState {
    join_owners: usize,
    jobs: VecDeque<ResponseWorkerJoinJob>,
    reaper: Option<std::thread::JoinHandle<()>>,
}

struct ResponseWorkerReaperRegistry {
    state: Mutex<ResponseWorkerReaperState>,
    wake: Condvar,
    #[cfg(test)]
    fail_next_spawn: AtomicBool,
}

static RESPONSE_WORKER_REAPER_REGISTRY: OnceLock<Arc<ResponseWorkerReaperRegistry>> =
    OnceLock::new();

impl ResponseWorkerReaperRegistry {
    fn new() -> Self {
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

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ResponseWorkerReaperState> {
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

    fn enqueue(self: &Arc<Self>, job: ResponseWorkerJoinJob) {
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
    fn acquire_without_service_for_test(
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
    fn take_retained_job_for_test(&self) -> Option<ResponseWorkerJoinJob> {
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

fn acquire_response_worker_join_permit() -> Result<ResponseWorkerJoinPermit, ResponseWorkerTickError>
{
    let registry = Arc::clone(
        RESPONSE_WORKER_REAPER_REGISTRY
            .get_or_init(|| Arc::new(ResponseWorkerReaperRegistry::new())),
    );
    registry.acquire()
}

fn join_response_worker_thread(
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
    fn take_join(&mut self) -> Result<ResponseWorkerJoinOwnership, ResponseWorkerTickError> {
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

struct ResponseWorkerTaskLiveness {
    worker: Arc<ProductionResponseWorker>,
}

struct ResponseWorkerThreadCompletion {
    completion: watch::Sender<bool>,
}

impl Drop for ResponseWorkerThreadCompletion {
    fn drop(&mut self) {
        let _ = self.completion.send_replace(true);
    }
}

impl ResponseWorkerTaskLiveness {
    fn begin(worker: Arc<ProductionResponseWorker>) -> Self {
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
    pub(super) fn is_running(&self) -> bool {
        self.publication_released
            && self.publication_ready
            && self.worker.task_live.load(Ordering::Acquire)
            && self
                .join
                .as_ref()
                .is_some_and(|ownership| !ownership.join.is_finished())
    }

    pub(super) async fn arm(&mut self) -> Result<(), ResponseWorkerTickError> {
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

    pub(super) fn release_publication(&mut self) -> Result<(), ResponseWorkerTickError> {
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

    pub(super) async fn wait_for_publication_readiness(
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
    fn new_for_test<P>(port: Arc<P>) -> Result<Self, ResponseWorkerTickError>
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

    pub(super) fn ensure_bootstrap_ready(&self) -> Result<(), ResponseWorkerTickError> {
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
    pub(super) fn shutdown_is_complete(&self) -> bool {
        self.shutdown_completed.load(Ordering::Acquire)
    }

    fn tick_once(&self) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
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

    fn tick_once_catching_crash(&self) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        catch_unwind(AssertUnwindSafe(|| self.tick_once()))
            .unwrap_or_else(|_| Err(worker_task_crash_error()))
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

    pub(super) async fn start_parked(
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

    fn complete_shutdown_after_loop(&self) -> Result<(), ResponseWorkerTickError> {
        if self.shutdown_completed.load(Ordering::Acquire) {
            return Ok(());
        }
        let result = self.port.shutdown();
        self.with_health(|health| {
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

    fn mark_failed(&self, error: &ResponseWorkerTickError) {
        self.task_live.store(false, Ordering::Release);
        self.with_health(|health| {
            health.lifecycle = ResponseWorkerLifecycle::Failed;
            health.last_error = Some(error.to_string());
        });
    }

    fn configure_progress(&self, deadline: Duration) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.deadline = Some(deadline);
        }
    }

    #[cfg(test)]
    pub(super) fn set_progress_deadline_for_test(&self, deadline: Duration) {
        self.configure_progress(deadline);
    }

    fn mark_armed(&self) {
        self.with_health(|health| {
            health.lifecycle = ResponseWorkerLifecycle::Created;
            health.last_error = None;
        });
    }

    fn mark_publication_released(&self) -> Result<(), ResponseWorkerTickError> {
        if !self.task_live.load(Ordering::Acquire) {
            return Err(ResponseWorkerTickError::WorkerStopped);
        }
        Ok(())
    }

    fn mark_publication_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.progress
            .lock()
            .map_err(|_| PortError::unavailable())?
            .published_at = Some(Instant::now());
        self.publication_ready.store(true, Ordering::Release);
        Ok(())
    }

    fn request_stop(&self) {
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

fn failed_health() -> ResponseWorkerHealth {
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

fn worker_task_crash_error() -> ResponseWorkerTickError {
    ErrorCode::new("response.worker_task_crash").map_or(
        ResponseWorkerTickError::InvalidConfig,
        ResponseWorkerTickError::WorkerCrash,
    )
}

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/scheduler_worker_parts/part_01_registry.inc"
));
