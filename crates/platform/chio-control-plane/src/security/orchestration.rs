use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::Duration;

use chio_core::SigningBackend;
use chio_kernel::{ActiveResponseFindingAuthority, IndexedSecurityEvidenceStore};
use chio_quarantine::{CorrelationPolicy, TemporalRule};
use chio_security_kernel::SecurityClock;
use chio_security_types::ports::{
    AttestedFindingBatchStore, AttestedFindingResponseOutboxStore, BlastRadiusPort,
    CorrelationIngressStore, DeclassificationEvidenceCommitStore, Digest32, EffectPort,
    ExactSecurityReceiptSink, PortError, RecordId, ResponseStore, SchedulerHealthPort,
    SecurityAlertPort, SecurityReceiptSink, UnverifiedSecurityEvent,
};
use chio_store_sqlite::security_state::{ActiveDefenseOverlayInventory, SqliteSecurityStateStore};
use thiserror::Error;
use tokio::sync::watch;

use super::adapters::{
    effect_port::ActiveResponseEffectPort, DeclassificationReceiptDrainReport,
    DeclassificationReceiptOutboxDrainer, NativeActiveResponseFindingAuthority,
    NativeFindingAuthorityConfigError, NativeSchedulerHealthPort, NativeSecurityReceiptSink,
    SqliteSiemOutbox,
};
use super::event_consumer::{
    AttestedFindingBatchPlanner, AttestedFindingResponseCoordinator,
    AttestedFindingResponsePolicyPlanner, AttestedFindingResponseRecoveryLimits,
    CorrelationConsumerReport, DurableAttestedFindingBatchPlanner, DurableCorrelationIngress,
    NativeSecurityEventVerifier, ProductionCorrelationConsumer, SecurityEventVerifierConfigError,
    TrustedSecurityEventProducer, TrustedSecurityEventReceiptProducer,
};
use super::scheduler_worker::{
    ActiveDefenseServiceRegistry, ActiveDefenseServices, ProductionDeclassificationReceiptOutbox,
    ProductionResponseSchedulerConfig, ProductionResponseWorker, ProductionResponseWorkerHandle,
    ProductionResponseWorkerLoopConfig, ResponseWorkerHealth, ResponseWorkerLifecycle,
    ResponseWorkerPort, ResponseWorkerTick, ResponseWorkerTickError, SqliteResponseWorkerPort,
};
use super::AttestedCorrelationWriter;

const MAX_RETAINED_ACTIVE_DEFENSE_TEARDOWNS: usize = 64;
const MAX_ACTIVE_DEFENSE_TEARDOWN_SERVICE_SPAWN_ATTEMPTS: usize = 3;
const ACTIVE_DEFENSE_TEARDOWN_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct ProductionActiveDefenseConfig {
    pub scheduler: ProductionResponseSchedulerConfig,
    pub correlation_policy: CorrelationPolicy,
    pub rules: Vec<TemporalRule>,
    pub policy_hashes: BTreeMap<RecordId, Digest32>,
    pub trusted_event_producers: Vec<TrustedSecurityEventProducer>,
    pub trusted_event_receipt_producers: Vec<TrustedSecurityEventReceiptProducer>,
    pub max_event_age_ms: u64,
    pub max_future_skew_ms: u64,
    pub response_recovery_limits: AttestedFindingResponseRecoveryLimits,
}

#[derive(Debug, Error)]
pub enum ProductionActiveDefenseBuildError {
    #[error("active-defense finding authority configuration failed: {0}")]
    FindingAuthority(#[from] NativeFindingAuthorityConfigError),
    #[error("security event verifier configuration failed: {0}")]
    EventVerifier(#[from] SecurityEventVerifierConfigError),
    #[error("active-defense service port failed: {0}")]
    Port(#[from] PortError),
    #[error("active-defense response worker failed: {0}")]
    Worker(#[from] ResponseWorkerTickError),
}

#[derive(Clone)]
pub struct ProductionActiveDefenseHostConfig {
    pub(crate) durability: super::runtime::SecurityDurability,
    pub(crate) security_state_authority: ProductionSecurityStateAuthority,
    pub(crate) indexed_evidence_store: Arc<dyn IndexedSecurityEvidenceStore>,
    pub(crate) signer: Arc<dyn SigningBackend>,
    pub(crate) alert_outbox: Arc<SqliteSiemOutbox>,
    pub(crate) blast_radius: Arc<dyn BlastRadiusPort>,
    pub(crate) scheduler_health: Arc<dyn SchedulerHealthPort>,
    pub(crate) response_policy_planner: Arc<dyn AttestedFindingResponsePolicyPlanner>,
    pub(crate) response_coordinator: Arc<dyn AttestedFindingResponseCoordinator>,
    pub(crate) clock: Arc<dyn SecurityClock>,
    pub(crate) active_defense: ProductionActiveDefenseConfig,
    pub(crate) worker_loop: ProductionResponseWorkerLoopConfig,
}

pub(super) trait ProductionSecurityStateLifecycleOwner: Send + Sync {
    fn ensure_owned(&self) -> Result<(), ResponseWorkerTickError>;
    fn reset_for_startup_takeover(&self) -> Result<(), ResponseWorkerTickError>;
}

#[derive(Clone)]
pub(crate) struct ProductionSecurityStateAuthority {
    store: Arc<SqliteSecurityStateStore>,
    lifecycle_owner: Arc<dyn ProductionSecurityStateLifecycleOwner>,
    ownership_failed: Arc<AtomicBool>,
    lifecycle_claimed: Arc<AtomicBool>,
}

struct ProductionSecurityStateLifecycleClaim {
    claimed: Arc<AtomicBool>,
    active: AtomicBool,
}

impl ProductionSecurityStateLifecycleClaim {
    fn release(&self) {
        if self.active.swap(false, Ordering::AcqRel) {
            self.claimed.store(false, Ordering::Release);
        }
    }
}

impl Drop for ProductionSecurityStateLifecycleClaim {
    fn drop(&mut self) {
        self.release();
    }
}

impl ProductionSecurityStateAuthority {
    pub(super) fn new(
        store: Arc<SqliteSecurityStateStore>,
        lifecycle_owner: Arc<dyn ProductionSecurityStateLifecycleOwner>,
    ) -> Self {
        Self {
            store,
            lifecycle_owner,
            ownership_failed: Arc::new(AtomicBool::new(false)),
            lifecycle_claimed: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub(super) fn store(&self) -> &Arc<SqliteSecurityStateStore> {
        &self.store
    }

    fn ensure_owned(&self) -> Result<(), ResponseWorkerTickError> {
        if self.ownership_failed.load(Ordering::Acquire) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        if let Err(error) = self.lifecycle_owner.ensure_owned() {
            self.ownership_failed.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }

    fn reset_for_startup_takeover(&self) -> Result<(), ResponseWorkerTickError> {
        self.ensure_owned()?;
        if let Err(error) = self.lifecycle_owner.reset_for_startup_takeover() {
            self.ownership_failed.store(true, Ordering::Release);
            return Err(error);
        }
        self.ensure_owned()
    }

    fn claim_lifecycle(
        &self,
    ) -> Result<Arc<ProductionSecurityStateLifecycleClaim>, ResponseWorkerTickError> {
        self.ensure_owned()?;
        self.lifecycle_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ResponseWorkerTickError::RuntimeAdmissionClosed)?;
        Ok(Arc::new(ProductionSecurityStateLifecycleClaim {
            claimed: Arc::clone(&self.lifecycle_claimed),
            active: AtomicBool::new(true),
        }))
    }

    fn is_exact(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.store, &other.store)
            && Arc::ptr_eq(&self.lifecycle_owner, &other.lifecycle_owner)
            && Arc::ptr_eq(&self.ownership_failed, &other.ownership_failed)
            && Arc::ptr_eq(&self.lifecycle_claimed, &other.lifecycle_claimed)
    }
}

#[derive(Debug, Error)]
pub enum ProductionActiveDefenseHostError {
    #[error("production active-defense host requires filesystem-backed authorities")]
    EphemeralAuthority,
    #[error("active-defense host construction failed: {0}")]
    Build(#[from] ProductionActiveDefenseBuildError),
    #[error("active-defense host worker lifecycle failed: {0}")]
    Worker(#[from] ResponseWorkerTickError),
    #[error("active-defense response worker is not ready: {health:?}")]
    UnhealthyWorker { health: ResponseWorkerHealth },
    #[error("active-defense response worker task is not running")]
    WorkerTaskUnavailable,
    #[error("active-defense retained teardown supervisor is at capacity")]
    TeardownSupervisorCapacity,
    #[error("active-defense retained teardown supervisor is unavailable: {0}")]
    TeardownSupervisorUnavailable(String),
    #[error("active-defense teardown ownership is unavailable")]
    TeardownOwnershipUnavailable,
    #[error("active-defense overlay inventory failed: {0}")]
    OverlayInventory(#[from] PortError),
    #[error("active-defense services retain active overlay contributions: {inventory:?}")]
    ActiveOverlayContributions {
        inventory: ActiveDefenseOverlayInventory,
    },
    #[error("active-defense startup rollback failed after `{cause}`: {rollback}")]
    StartupRollback { cause: String, rollback: String },
}

struct ProductionRuntimeLeaseState {
    control: Mutex<ProductionRuntimeLeaseControl>,
    lease_counts: watch::Sender<ProductionLifecycleLeaseCounts>,
    worker: Mutex<Option<Weak<ProductionResponseWorker>>>,
    security_state_authority: ProductionSecurityStateAuthority,
}

impl ProductionRuntimeLeaseState {
    fn new(security_state_authority: ProductionSecurityStateAuthority) -> Self {
        Self {
            control: Mutex::new(ProductionRuntimeLeaseControl::default()),
            lease_counts: watch::channel(ProductionLifecycleLeaseCounts::default()).0,
            worker: Mutex::new(None),
            security_state_authority,
        }
    }
}

#[derive(Default)]
struct ProductionRuntimeLeaseControl {
    phase: ProductionRuntimeAdmissionPhase,
    runtime_leases: u64,
    dispatch_recorder_leases: u64,
    consumer_leases: u64,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct ProductionLifecycleLeaseCounts {
    runtime: u64,
    dispatch_recorders: u64,
    consumers: u64,
}

impl ProductionRuntimeLeaseControl {
    fn lease_counts(&self) -> ProductionLifecycleLeaseCounts {
        ProductionLifecycleLeaseCounts {
            runtime: self.runtime_leases,
            dispatch_recorders: self.dispatch_recorder_leases,
            consumers: self.consumer_leases,
        }
    }
}

impl ProductionRuntimeLeaseState {
    fn ensure_worker_bound(&self) -> Result<(), ResponseWorkerTickError> {
        if self
            .worker
            .lock()
            .map_err(|_| PortError::unavailable())?
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some()
        {
            Ok(())
        } else {
            Err(ResponseWorkerTickError::RuntimeAdmissionClosed)
        }
    }

    fn ensure_worker_admission_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.security_state_authority.ensure_owned()?;
        let worker = self.bound_worker()?;
        worker
            .ensure_ready()
            .map_err(|_| ResponseWorkerTickError::RuntimeAdmissionClosed)?;
        if matches!(
            worker.health().lifecycle,
            ResponseWorkerLifecycle::Running | ResponseWorkerLifecycle::Ready
        ) {
            Ok(())
        } else {
            Err(ResponseWorkerTickError::RuntimeAdmissionClosed)
        }
    }

    fn ensure_exact_worker_admission_ready(
        &self,
        expected: &Weak<ProductionResponseWorker>,
    ) -> Result<(), ResponseWorkerTickError> {
        let expected = expected
            .upgrade()
            .ok_or(ResponseWorkerTickError::RuntimeAdmissionClosed)?;
        let current = self.bound_worker()?;
        if !Arc::ptr_eq(&expected, &current) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        self.ensure_worker_admission_ready()
    }

    fn bound_worker(&self) -> Result<Arc<ProductionResponseWorker>, ResponseWorkerTickError> {
        self.worker
            .lock()
            .map_err(|_| PortError::unavailable())?
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or(ResponseWorkerTickError::RuntimeAdmissionClosed)
    }
}

impl ProductionLifecycleLeaseCounts {
    fn is_quiescent(self) -> bool {
        self.runtime == 0 && self.dispatch_recorders == 0 && self.consumers == 0
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum ProductionRuntimeAdmissionPhase {
    #[default]
    Closed,
    Prepared,
    Reconciled,
    Published,
}

#[derive(Clone, Copy)]
enum ProductionLifecycleLeaseKind {
    Runtime,
    DispatchRecorder,
    Consumer,
}

struct ProductionLifecycleLease {
    state: Arc<ProductionRuntimeLeaseState>,
    kind: ProductionLifecycleLeaseKind,
    worker: Weak<ProductionResponseWorker>,
    active: bool,
}

pub(super) struct ProductionRuntimeLease(ProductionLifecycleLease);

pub(super) struct ProductionDispatchRecorderLease {
    lease: ProductionLifecycleLease,
}

pub(super) struct ProductionConsumerLease {
    _lease: ProductionLifecycleLease,
}

impl ProductionRuntimeLease {
    fn new(lease: ProductionLifecycleLease) -> Self {
        Self(lease)
    }
}

impl ProductionRuntimeLease {
    #[must_use]
    pub(super) fn admission_is_open(&self) -> bool {
        self.0.state.control.lock().is_ok_and(|control| {
            matches!(control.phase, ProductionRuntimeAdmissionPhase::Published)
        }) && self
            .0
            .state
            .ensure_exact_worker_admission_ready(&self.0.worker)
            .is_ok()
    }
}

impl ProductionDispatchRecorderLease {
    fn new(lease: ProductionLifecycleLease) -> Self {
        Self { lease }
    }

    pub(super) fn consume_final_release(mut self) -> Result<(), ResponseWorkerTickError> {
        self.lease.consume_final_release()
    }
}

impl ProductionConsumerLease {
    fn new(lease: ProductionLifecycleLease) -> Self {
        Self { _lease: lease }
    }
}

impl Drop for ProductionLifecycleLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut control) = self.state.control.lock() {
            let leases = match self.kind {
                ProductionLifecycleLeaseKind::Runtime => &mut control.runtime_leases,
                ProductionLifecycleLeaseKind::DispatchRecorder => {
                    &mut control.dispatch_recorder_leases
                }
                ProductionLifecycleLeaseKind::Consumer => &mut control.consumer_leases,
            };
            *leases = leases.saturating_sub(1);
            self.active = false;
            let _ = self.state.lease_counts.send_replace(control.lease_counts());
        }
    }
}

impl ProductionLifecycleLease {
    fn consume_final_release(&mut self) -> Result<(), ResponseWorkerTickError> {
        if !self.active {
            return Err(ResponseWorkerTickError::Port(PortError::integrity_failure()));
        }
        // This control lock is the final-release linearization point shared
        // with close_runtime_admission.
        let mut control = self
            .state
            .control
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if !matches!(control.phase, ProductionRuntimeAdmissionPhase::Published) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        self.state
            .ensure_exact_worker_admission_ready(&self.worker)?;
        let leases = match self.kind {
            ProductionLifecycleLeaseKind::Runtime => &mut control.runtime_leases,
            ProductionLifecycleLeaseKind::DispatchRecorder => &mut control.dispatch_recorder_leases,
            ProductionLifecycleLeaseKind::Consumer => &mut control.consumer_leases,
        };
        if *leases == 0 {
            return Err(ResponseWorkerTickError::Port(PortError::integrity_failure()));
        }
        *leases -= 1;
        self.active = false;
        let _ = self.state.lease_counts.send_replace(control.lease_counts());
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct ProductionDeclassificationReceiptLifecycle {
    authority_claim: Arc<ProductionSecurityStateLifecycleClaim>,
    security_state_authority: ProductionSecurityStateAuthority,
    security_store: Arc<SqliteSecurityStateStore>,
    indexed_evidence_store: Arc<dyn IndexedSecurityEvidenceStore>,
    signer: Arc<dyn SigningBackend>,
    clock: Arc<dyn SecurityClock>,
    receipt_sink: Arc<NativeSecurityReceiptSink>,
    outbox: ProductionDeclassificationReceiptOutbox,
    runtime_leases: Arc<ProductionRuntimeLeaseState>,
}

impl ProductionDeclassificationReceiptLifecycle {
    pub(super) fn new(
        security_state_authority: ProductionSecurityStateAuthority,
        indexed_evidence_store: Arc<dyn IndexedSecurityEvidenceStore>,
        signer: Arc<dyn SigningBackend>,
        clock: Arc<dyn SecurityClock>,
    ) -> Result<Self, ResponseWorkerTickError> {
        security_state_authority.ensure_owned()?;
        let authority_claim = security_state_authority.claim_lifecycle()?;
        let security_store = Arc::clone(security_state_authority.store());
        let receipt_sink = Arc::new(NativeSecurityReceiptSink::new(
            Arc::clone(&indexed_evidence_store),
            Arc::clone(&signer),
        ));
        let evidence_store: Arc<dyn DeclassificationEvidenceCommitStore> = security_store.clone();
        let receipt_port: Arc<dyn ExactSecurityReceiptSink> = receipt_sink.clone();
        let drainer = Arc::new(DeclassificationReceiptOutboxDrainer::new_with_clock(
            Arc::clone(&evidence_store),
            receipt_port,
            Arc::clone(&clock),
        )?);
        let outbox = ProductionDeclassificationReceiptOutbox::new(evidence_store, drainer);
        Ok(Self {
            authority_claim,
            security_state_authority: security_state_authority.clone(),
            security_store,
            indexed_evidence_store,
            signer,
            clock,
            receipt_sink,
            outbox,
            runtime_leases: Arc::new(ProductionRuntimeLeaseState::new(security_state_authority)),
        })
    }

    pub(super) fn ensure_authority(
        &self,
        security_state_authority: &ProductionSecurityStateAuthority,
        indexed_evidence_store: &Arc<dyn IndexedSecurityEvidenceStore>,
        signer: &Arc<dyn SigningBackend>,
        clock: &Arc<dyn SecurityClock>,
    ) -> Result<(), ResponseWorkerTickError> {
        self.security_state_authority.ensure_owned()?;
        if !self
            .security_state_authority
            .is_exact(security_state_authority)
            || !Arc::ptr_eq(&self.indexed_evidence_store, indexed_evidence_store)
            || !Arc::ptr_eq(&self.signer, signer)
            || !Arc::ptr_eq(&self.clock, clock)
        {
            return Err(ResponseWorkerTickError::Port(PortError::integrity_failure()));
        }
        Ok(())
    }

    pub(super) fn reconcile_and_drain_startup(
        &self,
    ) -> Result<DeclassificationReceiptDrainReport, ResponseWorkerTickError> {
        self.prepare_startup()?;
        let report = self.outbox.reconcile_and_drain_startup()?;
        self.security_store.seal_declassification_live_dispatch()?;
        self.security_store
            .ensure_declassification_evidence_ready()?;
        self.security_state_authority.ensure_owned()?;
        let mut control = self
            .runtime_leases
            .control
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if !matches!(control.phase, ProductionRuntimeAdmissionPhase::Prepared) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        ensure_runtime_quiescent(&control)?;
        control.phase = ProductionRuntimeAdmissionPhase::Reconciled;
        Ok(report)
    }

    pub(super) fn prepare_startup(&self) -> Result<(), ResponseWorkerTickError> {
        {
            let mut control = self
                .runtime_leases
                .control
                .lock()
                .map_err(|_| PortError::unavailable())?;
            control.phase = ProductionRuntimeAdmissionPhase::Closed;
            ensure_runtime_quiescent(&control)?;
        }
        self.security_state_authority.ensure_owned()?;
        self.security_state_authority.reset_for_startup_takeover()?;
        self.security_state_authority.ensure_owned()?;
        let mut control = self
            .runtime_leases
            .control
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if !matches!(control.phase, ProductionRuntimeAdmissionPhase::Closed) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        ensure_runtime_quiescent(&control)?;
        control.phase = ProductionRuntimeAdmissionPhase::Prepared;
        Ok(())
    }

    pub(super) fn publish_runtime_admission(&self) -> Result<(), ResponseWorkerTickError> {
        self.security_state_authority.ensure_owned()?;
        let mut control = self
            .runtime_leases
            .control
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if !matches!(control.phase, ProductionRuntimeAdmissionPhase::Reconciled) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        ensure_runtime_quiescent(&control)?;
        self.runtime_leases.ensure_worker_bound()?;
        control.phase = ProductionRuntimeAdmissionPhase::Published;
        Ok(())
    }

    pub(super) fn close_runtime_admission(&self) -> Result<(), ResponseWorkerTickError> {
        let mut control = self
            .runtime_leases
            .control
            .lock()
            .map_err(|_| PortError::unavailable())?;
        control.phase = ProductionRuntimeAdmissionPhase::Closed;
        ensure_runtime_quiescent(&control)
    }

    fn release_authority_claim(&self) {
        self.authority_claim.release();
    }

    pub(super) fn ensure_runtime_admission_open(&self) -> Result<(), ResponseWorkerTickError> {
        let control = self
            .runtime_leases
            .control
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if !matches!(control.phase, ProductionRuntimeAdmissionPhase::Published) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        self.runtime_leases.ensure_worker_admission_ready()
    }

    pub(super) fn acquire_runtime_lease(
        &self,
    ) -> Result<ProductionRuntimeLease, ResponseWorkerTickError> {
        self.acquire_lease(ProductionLifecycleLeaseKind::Runtime)
            .map(ProductionRuntimeLease::new)
    }

    pub(super) fn acquire_dispatch_recorder_lease(
        &self,
    ) -> Result<ProductionDispatchRecorderLease, ResponseWorkerTickError> {
        self.acquire_lease(ProductionLifecycleLeaseKind::DispatchRecorder)
            .map(ProductionDispatchRecorderLease::new)
    }

    pub(super) fn acquire_consumer_lease(
        &self,
    ) -> Result<ProductionConsumerLease, ResponseWorkerTickError> {
        self.acquire_lease(ProductionLifecycleLeaseKind::Consumer)
            .map(ProductionConsumerLease::new)
    }

    pub(super) fn acquire_consumer_lease_for(
        &self,
        worker: &Arc<ProductionResponseWorker>,
    ) -> Result<ProductionConsumerLease, ResponseWorkerTickError> {
        self.acquire_lease_for(ProductionLifecycleLeaseKind::Consumer, Some(worker))
            .map(ProductionConsumerLease::new)
    }

    fn acquire_lease(
        &self,
        kind: ProductionLifecycleLeaseKind,
    ) -> Result<ProductionLifecycleLease, ResponseWorkerTickError> {
        self.acquire_lease_for(kind, None)
    }

    fn acquire_lease_for(
        &self,
        kind: ProductionLifecycleLeaseKind,
        expected_worker: Option<&Arc<ProductionResponseWorker>>,
    ) -> Result<ProductionLifecycleLease, ResponseWorkerTickError> {
        let mut control = self
            .runtime_leases
            .control
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if !matches!(control.phase, ProductionRuntimeAdmissionPhase::Published) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        let worker = self.runtime_leases.bound_worker()?;
        if expected_worker.is_some_and(|expected| !Arc::ptr_eq(expected, &worker)) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        self.runtime_leases.ensure_worker_admission_ready()?;
        let leases = match kind {
            ProductionLifecycleLeaseKind::Runtime => &mut control.runtime_leases,
            ProductionLifecycleLeaseKind::DispatchRecorder => &mut control.dispatch_recorder_leases,
            ProductionLifecycleLeaseKind::Consumer => &mut control.consumer_leases,
        };
        *leases = leases
            .checked_add(1)
            .ok_or(ResponseWorkerTickError::InvalidConfig)?;
        let _ = self
            .runtime_leases
            .lease_counts
            .send_replace(control.lease_counts());
        drop(control);
        Ok(ProductionLifecycleLease {
            state: Arc::clone(&self.runtime_leases),
            kind,
            worker: Arc::downgrade(&worker),
            active: true,
        })
    }

    pub(super) fn bind_worker(
        &self,
        worker: &Arc<ProductionResponseWorker>,
    ) -> Result<(), ResponseWorkerTickError> {
        self.security_state_authority.ensure_owned()?;
        let control = self
            .runtime_leases
            .control
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if !matches!(control.phase, ProductionRuntimeAdmissionPhase::Reconciled) {
            return Err(ResponseWorkerTickError::RuntimeAdmissionClosed);
        }
        let mut retained = self
            .runtime_leases
            .worker
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if let Some(existing) = retained.as_ref().and_then(Weak::upgrade) {
            if Arc::ptr_eq(&existing, worker) {
                return Ok(());
            }
            if !matches!(
                existing.health().lifecycle,
                ResponseWorkerLifecycle::Failed | ResponseWorkerLifecycle::Stopped
            ) {
                return Err(ResponseWorkerTickError::Port(PortError::integrity_failure()));
            }
        }
        *retained = Some(Arc::downgrade(worker));
        Ok(())
    }

    pub(super) fn drain_to_zero(
        &self,
    ) -> Result<DeclassificationReceiptDrainReport, ResponseWorkerTickError> {
        self.security_state_authority.ensure_owned()?;
        self.outbox.drain_to_zero()
    }

    pub(super) async fn wait_for_operation_quiescence(&self) {
        let mut lease_counts = self.runtime_leases.lease_counts.subscribe();
        if lease_counts.borrow_and_update().is_quiescent() {
            return;
        }
        while lease_counts.changed().await.is_ok() {
            if lease_counts.borrow_and_update().is_quiescent() {
                return;
            }
        }
    }

    #[must_use]
    pub(super) fn receipt_sink(&self) -> Arc<dyn SecurityReceiptSink> {
        self.receipt_sink.clone()
    }

    #[must_use]
    pub(super) fn active_response_receipt_sink(&self) -> Arc<NativeSecurityReceiptSink> {
        Arc::clone(&self.receipt_sink)
    }

    #[must_use]
    pub(super) fn exact_receipt_sink(&self) -> Arc<dyn ExactSecurityReceiptSink> {
        self.receipt_sink.clone()
    }

    #[must_use]
    pub(super) fn outbox(&self) -> ProductionDeclassificationReceiptOutbox {
        self.outbox.clone()
    }

    #[must_use]
    pub(super) fn signer_public_key(&self) -> chio_core::PublicKey {
        self.signer.public_key()
    }
}

fn ensure_runtime_quiescent(
    control: &ProductionRuntimeLeaseControl,
) -> Result<(), ResponseWorkerTickError> {
    if control.runtime_leases != 0 {
        return Err(ResponseWorkerTickError::RuntimeLeasesActive(
            control.runtime_leases,
        ));
    }
    if control.dispatch_recorder_leases != 0 {
        return Err(ResponseWorkerTickError::DispatchRecorderLeasesActive(
            control.dispatch_recorder_leases,
        ));
    }
    if control.consumer_leases != 0 {
        return Err(ResponseWorkerTickError::ConsumerLeasesActive(
            control.consumer_leases,
        ));
    }
    Ok(())
}

/// Production active-defense services built around one durable security store
/// and one indexed evidence authority.
///
/// The receipt sink and finding authority intentionally receive clones of the
/// same indexed evidence store. A finding therefore cannot reach planning
/// without first being signed, appended, reloaded, and verified from that
/// authority. The durable batch planner is always constructed here from the
/// exact production security store. Callers provide policy selection and
/// signed authorization artifacts only; the retained production kernel is the
/// sole admission and execution coordinator.
struct PlanningRecoveryResponseWorkerPort {
    inner: Arc<dyn ResponseWorkerPort>,
    planner: Arc<DurableAttestedFindingBatchPlanner>,
    correlation_ingress: Arc<DurableCorrelationIngress>,
    recovery_limits: AttestedFindingResponseRecoveryLimits,
}

impl PlanningRecoveryResponseWorkerPort {
    fn new(
        inner: Arc<dyn ResponseWorkerPort>,
        planner: Arc<DurableAttestedFindingBatchPlanner>,
        correlation_ingress: Arc<DurableCorrelationIngress>,
        recovery_limits: AttestedFindingResponseRecoveryLimits,
    ) -> Self {
        Self {
            inner,
            planner,
            correlation_ingress,
            recovery_limits,
        }
    }
}

impl ResponseWorkerPort for PlanningRecoveryResponseWorkerPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.inner.ensure_ready()?;
        self.planner.ensure_bootstrap_ready()?;
        self.correlation_ingress.ensure_ready()?;
        Ok(())
    }

    fn tick(
        &self,
        tick_sequence: u64,
        shutdown_requested: bool,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        if self.planner.response_coordinator_is_ready() {
            self.correlation_ingress
                .drain_once(self.recovery_limits.max_records_per_pass())?;
            self.planner
                .resume_incomplete_pass(self.recovery_limits.max_records_per_pass())?;
        }
        let tick = self.inner.tick(tick_sequence, shutdown_requested)?;
        Ok(tick)
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        self.inner.shutdown()
    }

    fn declassification_outbox_status(&self) -> (bool, Option<u64>, Option<String>) {
        self.inner.declassification_outbox_status()
    }
}

pub struct ProductionActiveDefenseOrchestrator {
    worker: Arc<ProductionResponseWorker>,
    worker_port: Arc<dyn ResponseWorkerPort>,
    consumer: Arc<ProductionCorrelationConsumer>,
    correlation_ingress: Arc<DurableCorrelationIngress>,
    response_planner: Arc<DurableAttestedFindingBatchPlanner>,
    response_recovery_limits: AttestedFindingResponseRecoveryLimits,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
}

pub(super) struct ProductionActiveDefenseOrchestratorContext {
    security_state_authority: ProductionSecurityStateAuthority,
    indexed_evidence_store: Arc<dyn IndexedSecurityEvidenceStore>,
    signer: Arc<dyn SigningBackend>,
    scheduler_health: Arc<dyn SchedulerHealthPort>,
    response_policy_planner: Arc<dyn AttestedFindingResponsePolicyPlanner>,
    response_coordinator: Arc<dyn AttestedFindingResponseCoordinator>,
    clock: Arc<dyn SecurityClock>,
    config: ProductionActiveDefenseConfig,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
}

impl ProductionActiveDefenseOrchestrator {
    pub(super) fn new_with_production_effects_and_lifecycle(
        context: ProductionActiveDefenseOrchestratorContext,
        alert_outbox: Arc<SqliteSiemOutbox>,
        blast_radius: Arc<dyn BlastRadiusPort>,
    ) -> Result<Self, ProductionActiveDefenseBuildError> {
        context.lifecycle.ensure_authority(
            &context.security_state_authority,
            &context.indexed_evidence_store,
            &context.signer,
            &context.clock,
        )?;
        let security_store = Arc::clone(context.security_state_authority.store());
        let effects: Arc<dyn EffectPort> = Arc::new(ActiveResponseEffectPort::production(
            Arc::clone(&security_store),
            Arc::clone(&alert_outbox),
            blast_radius,
        )?);
        let alerts: Arc<dyn SecurityAlertPort> = alert_outbox;
        Self::new_with_lifecycle(context, effects, alerts)
    }

    fn new_with_lifecycle(
        context: ProductionActiveDefenseOrchestratorContext,
        effects: Arc<dyn EffectPort>,
        alerts: Arc<dyn SecurityAlertPort>,
    ) -> Result<Self, ProductionActiveDefenseBuildError> {
        let ProductionActiveDefenseOrchestratorContext {
            security_state_authority,
            indexed_evidence_store,
            signer,
            scheduler_health,
            response_policy_planner,
            response_coordinator,
            clock,
            config,
            lifecycle,
        } = context;
        let rule_policy_versions: BTreeSet<_> = config
            .rules
            .iter()
            .map(|rule| rule.policy_version().clone())
            .collect();
        if config.max_future_skew_ms > config.correlation_policy.bounded_lateness_ms()
            || config
                .trusted_event_producers
                .iter()
                .any(|producer| !rule_policy_versions.contains(&producer.policy_version))
        {
            return Err(PortError::invalid_data().into());
        }
        let response_recovery_limits = config.response_recovery_limits;
        lifecycle.ensure_authority(
            &security_state_authority,
            &indexed_evidence_store,
            &signer,
            &clock,
        )?;
        let security_store = Arc::clone(security_state_authority.store());
        let receipt_sink = lifecycle.receipt_sink();
        let response_store: Arc<dyn ResponseStore> = security_store.clone();
        let scheduler_health: Arc<dyn SchedulerHealthPort> =
            Arc::new(NativeSchedulerHealthPort::new(
                response_store,
                scheduler_health,
                Arc::clone(&receipt_sink),
            ));
        let finding_authority: Arc<dyn ActiveResponseFindingAuthority> =
            Arc::new(NativeActiveResponseFindingAuthority::new(
                Arc::clone(&indexed_evidence_store),
                vec![lifecycle.signer_public_key()],
            )?);
        let attestor = Arc::new(AttestedCorrelationWriter::new(
            Arc::clone(&receipt_sink),
            Arc::clone(&finding_authority),
            config.policy_hashes,
        ));
        let verifier = Arc::new(NativeSecurityEventVerifier::new(
            Arc::clone(&clock),
            config.trusted_event_producers,
            config.trusted_event_receipt_producers,
            config.max_event_age_ms,
            config.max_future_skew_ms,
        )?);
        let finding_batch_store: Arc<dyn AttestedFindingBatchStore> = security_store.clone();
        let finding_response_outbox_store: Arc<dyn AttestedFindingResponseOutboxStore> =
            security_store.clone();
        let durable_planner = Arc::new(DurableAttestedFindingBatchPlanner::new(
            finding_batch_store,
            finding_response_outbox_store,
            finding_authority,
            response_policy_planner,
            response_coordinator,
            Arc::clone(&clock),
        )?);
        let consumer = Arc::new(ProductionCorrelationConsumer::new(
            Arc::clone(&verifier),
            Arc::clone(&security_store),
            config.correlation_policy,
            config.rules,
            attestor,
            Arc::clone(&durable_planner),
        )?);
        let correlation_ingress_store: Arc<dyn CorrelationIngressStore> = security_store.clone();
        let correlation_ingress = Arc::new(DurableCorrelationIngress::new(
            correlation_ingress_store,
            Arc::clone(&consumer),
        )?);
        let scheduler_worker_port: Arc<dyn ResponseWorkerPort> =
            Arc::new(SqliteResponseWorkerPort::new_with_declassification_outbox(
                Arc::clone(&security_store),
                lifecycle.outbox(),
                effects,
                receipt_sink,
                alerts,
                scheduler_health,
                clock,
                config.scheduler,
            )?);
        let worker_port: Arc<dyn ResponseWorkerPort> =
            Arc::new(PlanningRecoveryResponseWorkerPort::new(
                scheduler_worker_port,
                Arc::clone(&durable_planner),
                Arc::clone(&correlation_ingress),
                response_recovery_limits,
            ));
        let worker = Arc::new(ProductionResponseWorker::new(Arc::clone(&worker_port))?);
        lifecycle.bind_worker(&worker)?;
        let services = Self {
            worker,
            worker_port,
            consumer,
            correlation_ingress,
            response_planner: durable_planner,
            response_recovery_limits,
            lifecycle,
        };
        services.ensure_bootstrap_ready()?;
        Ok(services)
    }

    fn ensure_bootstrap_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.consumer.ensure_bootstrap_ready()?;
        self.worker.ensure_bootstrap_ready()
    }

    pub fn consume(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> Result<CorrelationConsumerReport, PortError> {
        let _consumer_lease = self
            .lifecycle
            .acquire_consumer_lease_for(&self.worker)
            .map_err(|_| PortError::unavailable())?;
        self.correlation_ingress.consume(event)
    }

    pub(super) async fn start_worker_parked(
        &self,
        config: ProductionResponseWorkerLoopConfig,
    ) -> Result<ProductionResponseWorkerHandle, ResponseWorkerTickError> {
        self.worker.start_parked(config).await
    }

    pub(crate) fn resume_incomplete_until_drained(&self) -> Result<(), PortError> {
        self.correlation_ingress
            .drain_until_empty(self.response_recovery_limits)?;
        self.response_planner
            .resume_incomplete_until_drained(self.response_recovery_limits)
            .map(|_| ())
    }

    async fn start_teardown_recovery_worker(
        &self,
        config: ProductionResponseWorkerLoopConfig,
    ) -> Result<
        (
            Arc<ProductionResponseWorker>,
            ProductionResponseWorkerHandle,
        ),
        ResponseWorkerTickError,
    > {
        let worker = Arc::new(ProductionResponseWorker::new(Arc::clone(
            &self.worker_port,
        ))?);
        let mut handle = worker.start_parked(config).await?;
        if let Err(error) = handle.arm().await {
            let _ = handle.shutdown().await;
            return Err(error);
        }
        if let Err(error) = handle.release_publication() {
            let _ = handle.shutdown().await;
            return Err(error);
        }
        if let Err(error) = handle.wait_for_publication_readiness().await {
            let _ = handle.shutdown().await;
            return Err(error);
        }
        Ok((worker, handle))
    }

    #[must_use]
    pub fn worker(&self) -> &Arc<ProductionResponseWorker> {
        &self.worker
    }
}

impl ActiveDefenseServices for ProductionActiveDefenseOrchestrator {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.consumer.ensure_ready()?;
        self.worker.ensure_ready()
    }

    fn ensure_bootstrap_ready(&self) -> Result<(), ResponseWorkerTickError> {
        ProductionActiveDefenseOrchestrator::ensure_bootstrap_ready(self)
    }

    fn worker_health(&self) -> ResponseWorkerHealth {
        self.worker.health()
    }
}

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/orchestration_teardown.inc"
));
