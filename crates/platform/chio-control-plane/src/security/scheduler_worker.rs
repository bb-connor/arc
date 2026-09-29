mod error;

pub use error::ResponseWorkerTickError;

use chio_core::{canonical_json_bytes, sha256};
use chio_quarantine::{
    ResponseExecutor, ResponseScheduler, ScheduledResponseExecutor, SchedulerError,
    SchedulerPolicy, SchedulerTickRequest, SchedulerWorkOutcome,
};
use chio_security_kernel::Clock;
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
use tokio::sync::{oneshot, watch};
use tokio::time::MissedTickBehavior;

use super::adapters::{
    DeclassificationCompactionReport, DeclassificationReceiptDrainReport,
    DeclassificationReceiptOutboxDrainer, DeclassificationReconciliationReport,
};

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

mod outbox;

pub(in crate::security) use outbox::ProductionDeclassificationReceiptOutbox;
#[cfg(test)]
use outbox::DeclassificationReceiptOutboxPort;


mod worker;
pub use worker::ProductionResponseWorkerLoopConfig;
use worker::WORKER_CLAIM_DOMAIN;
#[cfg(test)]
use worker::MIN_WORKER_PROGRESS_DEADLINE;
#[cfg(test)]
use worker::MAX_WORKER_PROGRESS_DEADLINE;

use worker::ResponseWorkerProgress;

use worker::worker_task_crash_error;

mod custody;

#[cfg(test)]
use custody::MAX_RESPONSE_WORKER_JOIN_OWNERS;

use custody::ResponseWorkerJoinPermit;
#[cfg(test)]
use custody::ResponseWorkerJoinJob;

#[cfg(test)]
use custody::ResponseWorkerReaperRegistry;

use custody::acquire_response_worker_join_permit;
#[cfg(test)]
use custody::join_response_worker_thread;
use custody::ResponseWorkerTaskLiveness;

mod scheduler;
pub use scheduler::ProductionResponseSchedulerConfig;
pub use scheduler::SqliteResponseWorkerPort;







mod registry;
pub use registry::ActiveDefenseServices;
pub use registry::ActiveDefenseServiceRegistry;


#[cfg(test)]
mod tests;



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

pub(super) struct ResponseWorkerStartupGuard {
    shutdown: watch::Sender<bool>,
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
}
