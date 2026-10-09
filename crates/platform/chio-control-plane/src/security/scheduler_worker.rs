mod error;

use super::adapters::{
    DeclassificationCompactionReport, DeclassificationReceiptDrainReport,
    DeclassificationReceiptOutboxDrainer, DeclassificationReconciliationReport,
    DeclassificationRevalidationReport,
};
use chio_core::{canonical_json_bytes, sha256};
use chio_quarantine::{
    ResponseExecutor, ResponseScheduler, ScheduledResponseExecutor, SchedulerError,
    SchedulerPolicy, SchedulerTickRequest, SchedulerWorkOutcome,
};
use chio_security_kernel::Clock;
use chio_security_types::ports::{
    ActionId, DeclassificationEvidenceCommitStore, DeclassificationRetriedEvidenceQuery,
    EffectPort, ErrorCode, GrantId, LeaseOwnerId, PortError, PortErrorKind, RecordId,
    ResponseDispatchStore, ResponseSchedulerStore, ScheduledWork, SchedulerHealthPort,
    SecurityAlertPort, SecurityReceiptSink, TenantId, MAX_DECLASSIFICATION_EVIDENCE_BATCH,
};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
pub use error::ResponseWorkerTickError;
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch};
use tokio::time::MissedTickBehavior;

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

    /// Readiness to construct and start a worker that services expiry,
    /// rollback and receipt recovery. Runtime admission keeps `ensure_ready`.
    fn ensure_recovery_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.ensure_ready()
    }

    fn tick(
        &self,
        tick_sequence: u64,
        shutdown_requested: bool,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError>;
    fn shutdown(&self) -> Result<(), ResponseWorkerTickError>;

    /// A stop was requested. A tick in flight may end at its next safe point,
    /// which is never inside a store transaction. Work it leaves unprocessed
    /// is released by `shutdown`.
    fn request_stop(&self) {}

    fn declassification_outbox_status(&self) -> (bool, Option<u64>, Option<String>) {
        (false, None, None)
    }

    /// Correlation ingress rows this port's admission work refused, when it
    /// drains correlation ingress.
    fn correlation_ingress_rejections(&self) -> Option<CorrelationIngressRejectionHealth> {
        None
    }
}

/// Correlation ingress rows refused because the producer configuration no
/// longer admits them. Each refused row stays durably rejected with its reason.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CorrelationIngressRejectionHealth {
    /// Rejected rows in the durable ingress ledger, including rows rejected
    /// before this process started.
    pub rejected_total: u64,
    /// Rows this process rejected because no producer binding exists.
    pub unconfigured_producer: u64,
    /// Rows this process rejected because the binding names another key.
    pub unconfigured_producer_key: u64,
    /// Rows this process rejected because the binding pins another policy.
    pub unconfigured_policy_version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseWorkerLifecycle {
    Created,
    /// The first tick is in flight and no tick outcome exists yet. Later
    /// ticks keep the previous outcome; `ResponseWorkerHealth::tick_in_flight`
    /// reports them.
    Running,
    Ready,
    Degraded,
    Failed,
    Stopped,
}

impl ResponseWorkerLifecycle {
    /// The single readiness predicate for the worker, the host and runtime
    /// admission: the last completed tick left the worker ready.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::security) enum DeclassificationOutboxHealth {
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
    /// Security alert delivery driven by this worker, when configured.
    pub security_alert_delivery: Option<SecurityAlertDeliveryHealth>,
    /// Correlation ingress rows refused by this worker's admission work.
    pub correlation_ingress_rejections: Option<CorrelationIngressRejectionHealth>,
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
            security_alert_delivery: None,
            correlation_ingress_rejections: None,
        }
    }
}

mod alert_delivery;
pub(in crate::security) use alert_delivery::SecurityAlertDelivery;
pub use alert_delivery::SecurityAlertDeliveryHealth;

mod outbox;

#[cfg(test)]
use outbox::DeclassificationReceiptOutboxPort;
pub(in crate::security) use outbox::ProductionDeclassificationReceiptOutbox;

mod worker;
pub use worker::ProductionResponseWorkerLoopConfig;
use worker::{worker_task_crash_error, ResponseWorkerProgress, WORKER_CLAIM_DOMAIN};
#[cfg(test)]
use worker::{MAX_WORKER_PROGRESS_DEADLINE, MIN_WORKER_PROGRESS_DEADLINE};

mod custody;

use custody::{
    acquire_response_worker_join_permit, ResponseWorkerJoinPermit, ResponseWorkerTaskLiveness,
};

mod scheduler;
pub use scheduler::{ProductionResponseSchedulerConfig, SqliteResponseWorkerPort};

mod registry;
pub use registry::{ActiveDefenseServiceRegistry, ActiveDefenseServices};

#[cfg(test)]
mod tests;

pub struct ProductionResponseWorker {
    port: Arc<dyn ResponseWorkerPort>,
    alert_delivery: Option<Arc<SecurityAlertDelivery>>,
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

/// Where a parked worker is in its start, publication and stop handshake.
/// The host drives `Armed` and `PublicationReleased`, the worker thread drives
/// `Ready`, `Stopped` and `Failed`, and either side may request `Stopping`.
/// Phases only advance, and `Stopped` and `Failed` are final: a recorded
/// failure is never replaced by a later phase or a later error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum WorkerPhase {
    Created,
    Armed,
    PublicationReleased,
    Ready,
    Stopping,
    Stopped,
    Failed(String),
}

impl WorkerPhase {
    pub(super) const fn rank(&self) -> u8 {
        match self {
            Self::Created => 0,
            Self::Armed => 1,
            Self::PublicationReleased => 2,
            Self::Ready => 3,
            Self::Stopping => 4,
            Self::Stopped | Self::Failed(_) => 5,
        }
    }

    const fn is_final(&self) -> bool {
        matches!(self, Self::Stopped | Self::Failed(_))
    }

    /// A stop was requested or the worker already ended.
    pub(super) const fn stop_requested(&self) -> bool {
        self.rank() >= Self::Stopping.rank()
    }
}

pub(super) type WorkerPhaseSender = Arc<watch::Sender<WorkerPhase>>;

/// Moves the phase forward. Returns whether `next` was applied.
pub(super) fn advance_phase(phase: &watch::Sender<WorkerPhase>, next: WorkerPhase) -> bool {
    phase.send_if_modified(|current| {
        if current.is_final() || next.rank() <= current.rank() {
            return false;
        }
        *current = next;
        true
    })
}

pub struct ProductionResponseWorkerHandle {
    phase: WorkerPhaseSender,
    thread_completion: watch::Receiver<bool>,
    join: Option<ResponseWorkerJoinOwnership>,
    worker: Arc<ProductionResponseWorker>,
    publication_released: bool,
    publication_ready: bool,
    clean_shutdown: bool,
}

pub(super) struct ResponseWorkerStartupGuard {
    phase: WorkerPhaseSender,
    join: Option<ResponseWorkerJoinOwnership>,
    worker: Arc<ProductionResponseWorker>,
    active: bool,
}

pub(super) struct ResponseWorkerJoinOwnership {
    join: std::thread::JoinHandle<Result<(), ResponseWorkerTickError>>,
    permit: ResponseWorkerJoinPermit,
}

pub(super) struct ResponseWorkerThreadCompletion {
    completion: watch::Sender<bool>,
    phase: WorkerPhaseSender,
}
