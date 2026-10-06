//! One local worker owned by the existing joint admission runtime.
//! Clearing terminal raw envelope columns does not erase other payload owners,
//! immutable commitments, free SQLite pages, WAL history or backups.

use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chio_kernel::admission_operation::AdmissionDigest;
use chio_kernel::tool_outcome::ToolOutcomeStoreError;
use chio_store_sqlite::{ToolOutcomeCompactionLimits, ToolOutcomeCompactionPage};

#[path = "payload_maintenance/config.rs"]
mod config;

/// Explicit local operator policy. There is deliberately no TTL or interval default.
#[derive(Clone, Copy, Debug)]
pub struct TerminalPayloadMaintenanceConfig {
    /// Minimum age from the immutable raw blob's recording time. Every raw
    /// owner must also be terminal; TTL does not impose a deletion deadline.
    pub terminal_raw_payload_ttl: Duration,
    pub interval: Duration,
    pub page_limits: ToolOutcomeCompactionLimits,
}

impl TerminalPayloadMaintenanceConfig {
    pub fn validate(self) -> Result<Self, TerminalPayloadMaintenanceError> {
        if self.terminal_raw_payload_ttl.is_zero()
            || self.terminal_raw_payload_ttl.as_millis() == 0
            || self.terminal_raw_payload_ttl.as_millis() > u128::from(i64::MAX.unsigned_abs())
        {
            return Err(TerminalPayloadMaintenanceError::InvalidConfiguration("TTL"));
        }
        if self.interval.as_millis() == 0 || self.interval > Duration::from_secs(86_400) {
            return Err(TerminalPayloadMaintenanceError::InvalidConfiguration(
                "interval",
            ));
        }
        self.page_limits.validate()?;
        Ok(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TerminalPayloadMaintenanceError {
    #[error("invalid terminal raw payload maintenance {0}")]
    InvalidConfiguration(&'static str),
    #[error("terminal raw payload maintenance belongs to the remote authority's server owner")]
    RemoteAuthority,
    #[error("terminal raw payload maintenance already has an owned worker")]
    AlreadyRunning,
    #[error("terminal raw payload maintenance ownership is unavailable")]
    OwnershipUnavailable,
    #[error("failed to start terminal raw payload maintenance worker: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("terminal raw payload maintenance worker panicked")]
    WorkerPanicked,
    #[error(transparent)]
    Store(#[from] ToolOutcomeStoreError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalPayloadMaintenanceLifecycle {
    MissingConfiguration,
    Starting,
    Running,
    Ready,
    Degraded,
    Fenced,
    Failed,
    Stopped,
}

/// Status for this runtime's local worker, not a claim about remote retention.
#[derive(Clone, Debug)]
pub struct TerminalPayloadMaintenanceHealth {
    pub lifecycle: TerminalPayloadMaintenanceLifecycle,
    pub worker_running: bool,
    pub worker_joined: bool,
    pub ticks_attempted: u64,
    pub ticks_completed: u64,
    pub failures: u64,
    pub compacted: u64,
    pub compacted_bytes: u64,
    /// Current scan holds, conservatively retaining the last completed scan's
    /// counts until a new scan reaches its tail. These are blob counts.
    pub retained_non_completed: u64,
    pub retained_unsupported: u64,
    pub retained_owner_budget: u64,
    pub last_page: Option<ToolOutcomeCompactionPage>,
    pub last_error: Option<String>,
    /// Kept through later successful pages and clean shutdown.
    pub last_failure: Option<String>,
}

impl TerminalPayloadMaintenanceHealth {
    fn missing_configuration() -> Self {
        Self {
            lifecycle: TerminalPayloadMaintenanceLifecycle::MissingConfiguration,
            worker_running: false,
            worker_joined: false,
            ticks_attempted: 0,
            ticks_completed: 0,
            failures: 0,
            compacted: 0,
            compacted_bytes: 0,
            retained_non_completed: 0,
            retained_unsupported: 0,
            retained_owner_budget: 0,
            last_page: None,
            last_error: None,
            last_failure: None,
        }
    }
}

/// A server's owned worker on its already-open joint authority. The handle
/// retains no second connection and offers no caller timestamp or cutoff port.
#[derive(Clone)]
pub struct LocalTerminalPayloadMaintenance {
    owner: Arc<PayloadMaintenanceOwner>,
}

impl LocalTerminalPayloadMaintenance {
    pub(crate) fn start(
        authority: Arc<SqliteAuthorityStore>,
        config: TerminalPayloadMaintenanceConfig,
    ) -> Result<Self, TerminalPayloadMaintenanceError> {
        let config = config.validate()?;
        let fence = authority.mutation_fence();
        let owner = Arc::new(PayloadMaintenanceOwner::default());
        owner.start(authority, fence, config)?;
        Ok(Self { owner })
    }

    #[must_use]
    pub fn health(&self) -> TerminalPayloadMaintenanceHealth {
        self.owner.health()
    }

    pub fn shutdown(
        &self,
    ) -> Result<TerminalPayloadMaintenanceHealth, TerminalPayloadMaintenanceError> {
        self.owner.shutdown()
    }
}

impl DurableAdmissionRuntime {
    /// Start exactly one worker on this runtime's existing local authority,
    /// fence and clock. Remote clients cannot open a second authority here.
    pub fn start_terminal_payload_maintenance(
        &self,
        config: TerminalPayloadMaintenanceConfig,
    ) -> Result<(), TerminalPayloadMaintenanceError> {
        let config = config.validate()?;
        let authority = self
            .local_authority
            .clone()
            .ok_or(TerminalPayloadMaintenanceError::RemoteAuthority)?;
        self.payload_maintenance
            .start(authority, self.fence.clone(), config)
    }

    #[must_use]
    pub fn terminal_payload_maintenance_health(&self) -> TerminalPayloadMaintenanceHealth {
        self.payload_maintenance.health()
    }

    /// Stop and join before retiring the serving authority. Dropping the last
    /// runtime clone also performs this join, including on error return paths.
    pub fn shutdown_terminal_payload_maintenance(
        &self,
    ) -> Result<TerminalPayloadMaintenanceHealth, TerminalPayloadMaintenanceError> {
        self.payload_maintenance.shutdown()
    }
}

pub(super) struct PayloadMaintenanceOwner {
    slot: Mutex<WorkerSlot>,
}

struct WorkerSlot {
    worker: Option<OwnedWorker>,
    last_health: TerminalPayloadMaintenanceHealth,
}

impl Default for PayloadMaintenanceOwner {
    fn default() -> Self {
        Self {
            slot: Mutex::new(WorkerSlot {
                worker: None,
                last_health: TerminalPayloadMaintenanceHealth::missing_configuration(),
            }),
        }
    }
}

impl PayloadMaintenanceOwner {
    fn start(
        &self,
        authority: Arc<SqliteAuthorityStore>,
        fence: StoreMutationFence,
        config: TerminalPayloadMaintenanceConfig,
    ) -> Result<(), TerminalPayloadMaintenanceError> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| TerminalPayloadMaintenanceError::OwnershipUnavailable)?;
        if slot.worker.is_some() {
            return Err(TerminalPayloadMaintenanceError::AlreadyRunning);
        }
        let state = Arc::new(WorkerState::new(config));
        let worker_state = state.clone();
        let join = thread::Builder::new()
            .name("chio-terminal-payload-maintenance".into())
            .spawn(move || {
                worker_state.live.store(true, Ordering::Release);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    run_worker(&authority, &fence, config, &worker_state)
                }))
                .unwrap_or_else(|_| {
                    worker_state.fail(
                        TerminalPayloadMaintenanceLifecycle::Failed,
                        "terminal raw payload maintenance worker panicked".into(),
                    );
                    Err(TerminalPayloadMaintenanceError::WorkerPanicked)
                });
                if let Err(error) = &result {
                    if !matches!(
                        worker_state.health().lifecycle,
                        TerminalPayloadMaintenanceLifecycle::Fenced
                            | TerminalPayloadMaintenanceLifecycle::Failed
                    ) {
                        worker_state.fail(
                            TerminalPayloadMaintenanceLifecycle::Failed,
                            error.to_string().chars().take(512).collect(),
                        );
                    }
                }
                worker_state.live.store(false, Ordering::Release);
                worker_state.finish_loop();
                result
            })
            .map_err(TerminalPayloadMaintenanceError::Spawn)?;
        slot.worker = Some(OwnedWorker { state, join });
        Ok(())
    }

    fn health(&self) -> TerminalPayloadMaintenanceHealth {
        match self.slot.lock() {
            Ok(slot) => slot
                .worker
                .as_ref()
                .map_or_else(|| slot.last_health.clone(), |worker| worker.state.health()),
            Err(_) => {
                let mut health = TerminalPayloadMaintenanceHealth::missing_configuration();
                health.lifecycle = TerminalPayloadMaintenanceLifecycle::Failed;
                health.last_error =
                    Some("terminal raw payload maintenance ownership lock is poisoned".into());
                health.last_failure = health.last_error.clone();
                health
            }
        }
    }

    fn shutdown(
        &self,
    ) -> Result<TerminalPayloadMaintenanceHealth, TerminalPayloadMaintenanceError> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| TerminalPayloadMaintenanceError::OwnershipUnavailable)?;
        // Keep ownership locked through join so a concurrent start cannot overlap
        // the old loop after its handle is removed from the slot.
        if let Some(worker) = slot.worker.take() {
            let (health, result) = worker.stop_and_join();
            slot.last_health = health;
            result?;
        }
        Ok(slot.last_health.clone())
    }
}

impl Drop for PayloadMaintenanceOwner {
    fn drop(&mut self) {
        let slot = self
            .slot
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(worker) = slot.worker.take() {
            let (health, result) = worker.stop_and_join();
            slot.last_health = health;
            if let Err(error) = result {
                tracing::error!(error = %error, "terminal raw payload maintenance joined with a retained failure");
            }
        }
    }
}

struct OwnedWorker {
    state: Arc<WorkerState>,
    join: JoinHandle<Result<(), TerminalPayloadMaintenanceError>>,
}

impl OwnedWorker {
    fn stop_and_join(
        self,
    ) -> (
        TerminalPayloadMaintenanceHealth,
        Result<(), TerminalPayloadMaintenanceError>,
    ) {
        {
            let mut stopped = self
                .state
                .stop
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *stopped = true;
            self.state.wake.notify_all();
        }
        let result = match self.join.join() {
            Ok(result) => result,
            Err(_) => {
                self.state.fail(
                    TerminalPayloadMaintenanceLifecycle::Failed,
                    "terminal raw payload maintenance worker panicked".into(),
                );
                Err(TerminalPayloadMaintenanceError::WorkerPanicked)
            }
        };
        self.state
            .with_health(|health| health.health.worker_joined = true);
        (self.state.health(), result)
    }
}

struct HealthState {
    health: TerminalPayloadMaintenanceHealth,
    tick_started: Option<Instant>,
}

struct WorkerState {
    stop: Mutex<bool>,
    wake: Condvar,
    live: AtomicBool,
    health: Mutex<HealthState>,
    progress_deadline: Duration,
}

impl WorkerState {
    fn new(config: TerminalPayloadMaintenanceConfig) -> Self {
        let mut health = TerminalPayloadMaintenanceHealth::missing_configuration();
        health.lifecycle = TerminalPayloadMaintenanceLifecycle::Starting;
        Self {
            stop: Mutex::new(false),
            wake: Condvar::new(),
            live: AtomicBool::new(false),
            health: Mutex::new(HealthState {
                health,
                tick_started: None,
            }),
            progress_deadline: config
                .interval
                .saturating_mul(3)
                .clamp(Duration::from_secs(5), Duration::from_secs(60)),
        }
    }

    fn with_health(&self, update: impl FnOnce(&mut HealthState)) {
        let mut state = self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        update(&mut state);
    }

    fn health(&self) -> TerminalPayloadMaintenanceHealth {
        let state = self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut health = state.health.clone();
        health.worker_running = self.live.load(Ordering::Acquire);
        if state
            .tick_started
            .is_some_and(|at| at.elapsed() > self.progress_deadline)
        {
            health.lifecycle = TerminalPayloadMaintenanceLifecycle::Degraded;
            health.last_error =
                Some("terminal raw payload maintenance progress deadline elapsed".into());
        }
        health
    }

    fn fail(&self, lifecycle: TerminalPayloadMaintenanceLifecycle, message: String) {
        self.with_health(|state| {
            state.tick_started = None;
            state.health.lifecycle = lifecycle;
            state.health.failures = state.health.failures.saturating_add(1);
            state.health.last_error = Some(message.clone());
            state.health.last_failure = Some(message);
        });
    }

    fn finish_loop(&self) {
        self.with_health(|state| {
            state.tick_started = None;
            if !matches!(
                state.health.lifecycle,
                TerminalPayloadMaintenanceLifecycle::Fenced
                    | TerminalPayloadMaintenanceLifecycle::Failed
            ) {
                state.health.lifecycle = TerminalPayloadMaintenanceLifecycle::Stopped;
            }
        });
    }
}

fn run_worker(
    authority: &SqliteAuthorityStore,
    fence: &StoreMutationFence,
    config: TerminalPayloadMaintenanceConfig,
    state: &WorkerState,
) -> Result<(), TerminalPayloadMaintenanceError> {
    let store = authority.tool_outcome_store();
    let ttl = u64::try_from(config.terminal_raw_payload_ttl.as_millis())
        .map_err(|_| TerminalPayloadMaintenanceError::InvalidConfiguration("TTL"))?;
    let mut cursor: Option<AdmissionDigest> = None;
    let mut scan_holds = (0_u64, 0_u64, 0_u64);
    loop {
        if *state
            .stop
            .lock()
            .map_err(|_| TerminalPayloadMaintenanceError::OwnershipUnavailable)?
        {
            return Ok(());
        }
        state.with_health(|health| {
            health.tick_started = Some(Instant::now());
            health.health.lifecycle = TerminalPayloadMaintenanceLifecycle::Running;
            health.health.ticks_attempted = health.health.ticks_attempted.saturating_add(1);
        });
        match store.compact_terminal_invocation_blobs_page(
            ttl,
            fence,
            cursor.as_ref(),
            config.page_limits,
        ) {
            Ok(page) => {
                cursor = page.next_digest.clone();
                scan_holds.0 = scan_holds.0.saturating_add(page.retained_non_completed);
                scan_holds.1 = scan_holds.1.saturating_add(page.retained_unsupported);
                scan_holds.2 = scan_holds.2.saturating_add(page.retained_owner_budget);
                state.with_health(|health| {
                    health.tick_started = None;
                    if cursor.is_none() {
                        health.health.retained_non_completed = scan_holds.0;
                        health.health.retained_unsupported = scan_holds.1;
                        health.health.retained_owner_budget = scan_holds.2;
                    } else {
                        health.health.retained_non_completed = health.health.retained_non_completed.max(scan_holds.0);
                        health.health.retained_unsupported = health.health.retained_unsupported.max(scan_holds.1);
                        health.health.retained_owner_budget = health.health.retained_owner_budget.max(scan_holds.2);
                    }
                    let held = health.health.retained_non_completed > 0 || health.health.retained_unsupported > 0 || health.health.retained_owner_budget > 0;
                    health.health.lifecycle = if page.byte_budget_exhausted || held {
                        TerminalPayloadMaintenanceLifecycle::Degraded
                    } else {
                        TerminalPayloadMaintenanceLifecycle::Ready
                    };
                    health.health.ticks_completed = health.health.ticks_completed.saturating_add(1);
                    health.health.compacted =
                        health.health.compacted.saturating_add(page.compacted);
                    health.health.compacted_bytes = health
                        .health
                        .compacted_bytes
                        .saturating_add(page.compacted_bytes);
                    health.health.last_error = if page.byte_budget_exhausted || held {
                        let message = if page.byte_budget_exhausted {
                            "terminal raw payload maintenance page reached its payload byte budget; more eligible bytes remain"
                        } else if health.health.retained_non_completed > 0 {
                            "terminal raw payload maintenance holds unsupported terminal admission states; their bytes remain retained"
                        } else if health.health.retained_owner_budget > 0 {
                            "terminal raw payload maintenance holds custody above its owner row budget; their bytes remain retained"
                        } else {
                            "terminal raw payload maintenance holds unsupported replay profiles; their bytes remain retained"
                        }.to_string();
                        health.health.failures = health.health.failures.saturating_add(1);
                        health.health.last_failure = Some(message.clone());
                        Some(message)
                    } else { None };
                    health.health.last_page = Some(page.clone());
                });
                if cursor.is_none() {
                    scan_holds = (0, 0, 0);
                }
            }
            Err(error) => {
                let fenced = error == ToolOutcomeStoreError::Fenced;
                let message: String = error.to_string().chars().take(512).collect();
                tracing::warn!(reason = %message, "terminal raw payload maintenance page refused");
                state.fail(
                    if fenced {
                        TerminalPayloadMaintenanceLifecycle::Fenced
                    } else {
                        TerminalPayloadMaintenanceLifecycle::Degraded
                    },
                    message,
                );
                if fenced {
                    return Err(error.into());
                }
            }
        }
        let stopped = state
            .stop
            .lock()
            .map_err(|_| TerminalPayloadMaintenanceError::OwnershipUnavailable)?;
        let (stopped, _) = state
            .wake
            .wait_timeout_while(stopped, config.interval, |stopped| !*stopped)
            .map_err(|_| TerminalPayloadMaintenanceError::OwnershipUnavailable)?;
        if *stopped {
            return Ok(());
        }
    }
}
