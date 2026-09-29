
pub(super) use super::{
    join_response_worker_thread, ActiveDefenseServiceRegistry, ActiveDefenseServices,
    DeclassificationCompactionReport, DeclassificationOutboxHealth,
    DeclassificationReceiptDrainReport, DeclassificationReceiptOutboxPort,
    DeclassificationReconciliationReport, ProductionDeclassificationReceiptOutbox,
    ProductionResponseSchedulerConfig, ProductionResponseWorker,
    ProductionResponseWorkerHandle, ProductionResponseWorkerLoopConfig, ResponseWorkerHealth,
    ResponseWorkerJoinJob, ResponseWorkerLifecycle, ResponseWorkerPort,
    ResponseWorkerReaperRegistry, ResponseWorkerTick, ResponseWorkerTickError,
    SqliteResponseWorkerPort, MAX_RESPONSE_WORKER_JOIN_OWNERS, MAX_WORKER_PROGRESS_DEADLINE,
    MIN_WORKER_PROGRESS_DEADLINE,
};
pub(super) use chio_quarantine::{
    build_response_plan, ResponseStateMachine, ResponseTransitionRequest, SchedulerPolicy,
    SchedulerWorkOutcome,
};
pub(super) use chio_security_kernel::Clock;
pub(super) use chio_security_types::ports::{
    ActionId, AlertDeliveryQuery, AlertDeliveryStatus, CanonicalBody, EffectExecutionStatus,
    EffectPort, EffectRequest, EffectResult, EffectResultQuery, ErrorCode, GrantId,
    LeaseOwnerId, OpaqueReceiptRef, PortError, PortResult, ReceiptAppendRequest, RecordId,
    ResponsePlanRecord, ResponseSchedulerStore, ResponseStore, ScheduledWork,
    SchedulerHealthPageRequest, SchedulerHealthPort, SchedulerRetryRequest, SecurityAlert,
    SecurityAlertPort, SecurityReceiptSink, SessionId, TenantId,
    MAX_DECLASSIFICATION_EVIDENCE_BATCH,
};
pub(super) use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
    ResponseEffectSpec, ResponsePlanInput, ResponseState, ResponseTarget,
};
pub(super) use chio_store_sqlite::security_state::SqliteSecurityStateStore;
pub(super) use std::collections::VecDeque;
pub(super) use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
pub(super) use std::sync::{Arc, Mutex};
pub(super) use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) type RequestedCompaction = (Option<TenantId>, Option<GrantId>, u32);

pub(super) struct ScriptedDeclassificationOutboxPort {
    pub(super) available: AtomicBool,
    pub(super) pending: AtomicU64,
    pub(super) stranded: AtomicU64,
    pub(super) reconciliations: Mutex<VecDeque<Result<DeclassificationReconciliationReport, PortError>>>,
    pub(super) drains: Mutex<VecDeque<Result<DeclassificationReceiptDrainReport, PortError>>>,
    pub(super) compactions: Mutex<VecDeque<Result<DeclassificationCompactionReport, PortError>>>,
    pub(super) requested_batches: Mutex<Vec<u32>>,
    pub(super) requested_compactions: Mutex<Vec<RequestedCompaction>>,
    pub(super) events: Arc<Mutex<Vec<&'static str>>>,
}

impl ScriptedDeclassificationOutboxPort {
    pub(super) fn new(
        pending: u64,
        stranded: u64,
        reconciliations: Vec<Result<DeclassificationReconciliationReport, PortError>>,
        drains: Vec<Result<DeclassificationReceiptDrainReport, PortError>>,
    ) -> Self {
        Self {
            available: AtomicBool::new(true),
            pending: AtomicU64::new(pending),
            stranded: AtomicU64::new(stranded),
            reconciliations: Mutex::new(reconciliations.into()),
            drains: Mutex::new(drains.into()),
            compactions: Mutex::new(VecDeque::new()),
            requested_batches: Mutex::new(Vec::new()),
            requested_compactions: Mutex::new(Vec::new()),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(super) fn with_compactions(
        self,
        compactions: Vec<Result<DeclassificationCompactionReport, PortError>>,
    ) -> Self {
        if let Ok(mut scripted) = self.compactions.lock() {
            *scripted = compactions.into();
        }
        self
    }

    pub(super) fn with_events(mut self, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        self.events = events;
        self
    }

    pub(super) fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::Release);
    }

    pub(super) fn set_pending(&self, pending: u64) {
        self.pending.store(pending, Ordering::Release);
    }

    pub(super) fn events(&self) -> Vec<&'static str> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |events| events.clone())
    }

    pub(super) fn requested_batches(&self) -> Vec<u32> {
        self.requested_batches
            .lock()
            .map_or_else(|_| Vec::new(), |batches| batches.clone())
    }

    pub(super) fn requested_compactions(&self) -> Vec<(Option<TenantId>, Option<GrantId>, u32)> {
        self.requested_compactions
            .lock()
            .map_or_else(|_| Vec::new(), |requests| requests.clone())
    }

    pub(super) fn record(&self, event: &'static str) -> Result<(), PortError> {
        self.events
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(event);
        Ok(())
    }
}

impl DeclassificationReceiptOutboxPort for ScriptedDeclassificationOutboxPort {
    fn ensure_ready(&self) -> Result<(), PortError> {
        self.record("ensure")?;
        if self.available.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(PortError::unavailable())
        }
    }

    fn count_pending(&self) -> Result<u64, PortError> {
        self.record("count_pending")?;
        Ok(self.pending.load(Ordering::Acquire))
    }

    fn count_stranded(&self) -> Result<u64, PortError> {
        self.record("count_stranded")?;
        Ok(self.stranded.load(Ordering::Acquire))
    }

    fn reconcile_stranded(
        &self,
        _: u32,
    ) -> Result<DeclassificationReconciliationReport, PortError> {
        self.record("reconcile")?;
        let report = self
            .reconciliations
            .lock()
            .map_err(|_| PortError::unavailable())?
            .pop_front()
            .ok_or_else(PortError::unavailable)??;
        self.stranded.store(report.remaining, Ordering::Release);
        Ok(report)
    }

    fn drain_once(
        &self,
        max_receipts: u32,
    ) -> Result<DeclassificationReceiptDrainReport, PortError> {
        self.record("drain")?;
        self.requested_batches
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(max_receipts);
        let report = self
            .drains
            .lock()
            .map_err(|_| PortError::unavailable())?
            .pop_front()
            .ok_or_else(PortError::unavailable)??;
        self.pending.store(report.remaining, Ordering::Release);
        Ok(report)
    }

    fn compact_once(
        &self,
        after_tenant_id: Option<TenantId>,
        after_grant_id: Option<GrantId>,
        max_records: u32,
    ) -> Result<DeclassificationCompactionReport, PortError> {
        self.record("compact")?;
        self.requested_compactions
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push((after_tenant_id, after_grant_id, max_records));
        self.compactions
            .lock()
            .map_err(|_| PortError::unavailable())?
            .pop_front()
            .unwrap_or(Ok(DeclassificationCompactionReport::default()))
    }
}

#[derive(Default)]
pub(super) struct ScriptedWorkerPort {
    pub(super) ticks: Mutex<VecDeque<Result<ResponseWorkerTick, ResponseWorkerTickError>>>,
    pub(super) tick_calls: AtomicU64,
    pub(super) ticks_in_flight: AtomicU64,
    pub(super) maximum_concurrent_ticks: AtomicU64,
    pub(super) shutdown_calls: Mutex<u32>,
    pub(super) ready: Mutex<bool>,
}

impl ScriptedWorkerPort {
    pub(super) fn with_ticks(ticks: Vec<Result<ResponseWorkerTick, ResponseWorkerTickError>>) -> Self {
        Self {
            ticks: Mutex::new(ticks.into()),
            tick_calls: AtomicU64::new(0),
            ticks_in_flight: AtomicU64::new(0),
            maximum_concurrent_ticks: AtomicU64::new(0),
            shutdown_calls: Mutex::new(0),
            ready: Mutex::new(true),
        }
    }

    pub(super) fn shutdown_calls(&self) -> u32 {
        self.shutdown_calls.lock().map_or(0, |calls| *calls)
    }

    pub(super) fn tick_calls(&self) -> u64 {
        self.tick_calls.load(Ordering::Acquire)
    }

    pub(super) fn maximum_concurrent_ticks(&self) -> u64 {
        self.maximum_concurrent_ticks.load(Ordering::Acquire)
    }

    pub(super) fn set_ready(&self, ready: bool) {
        if let Ok(mut current) = self.ready.lock() {
            *current = ready;
        }
    }
}

impl ResponseWorkerPort for ScriptedWorkerPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        match self.ready.lock() {
            Ok(ready) if *ready => Ok(()),
            Ok(_) | Err(_) => Err(ResponseWorkerTickError::Port(PortError::unavailable())),
        }
    }

    fn tick(&self, _: u64, _: bool) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        self.tick_calls.fetch_add(1, Ordering::AcqRel);
        let in_flight = self
            .ticks_in_flight
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.maximum_concurrent_ticks
            .fetch_max(in_flight, Ordering::AcqRel);
        let result = match self.ticks.lock() {
            Ok(mut ticks) => ticks
                .pop_front()
                .ok_or(ResponseWorkerTickError::WorkerStopped)
                .and_then(|result| result),
            Err(_) => Err(ResponseWorkerTickError::Port(PortError::unavailable())),
        };
        self.ticks_in_flight.fetch_sub(1, Ordering::AcqRel);
        result
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        let mut calls = self
            .shutdown_calls
            .lock()
            .map_err(|_| ResponseWorkerTickError::Port(PortError::unavailable()))?;
        *calls = calls.saturating_add(1);
        Ok(())
    }
}

pub(super) struct BlockingWorkerPort {
    pub(super) block_from_sequence: u64,
    pub(super) tick_started: AtomicBool,
    pub(super) tick_in_flight: AtomicBool,
    pub(super) release_tick: AtomicBool,
    pub(super) shutdown_calls: AtomicU64,
    pub(super) shutdown_during_tick: AtomicBool,
}

impl BlockingWorkerPort {
    pub(super) fn new() -> Self {
        Self::blocking_from_sequence(1)
    }

    pub(super) fn blocking_initial_tick() -> Self {
        Self::blocking_from_sequence(0)
    }

    pub(super) fn blocking_from_sequence(block_from_sequence: u64) -> Self {
        Self {
            block_from_sequence,
            tick_started: AtomicBool::new(false),
            tick_in_flight: AtomicBool::new(false),
            release_tick: AtomicBool::new(false),
            shutdown_calls: AtomicU64::new(0),
            shutdown_during_tick: AtomicBool::new(false),
        }
    }

    pub(super) fn release(&self) {
        self.release_tick.store(true, Ordering::Release);
    }
}

impl ResponseWorkerPort for BlockingWorkerPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }

    fn tick(
        &self,
        tick_sequence: u64,
        _: bool,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        if tick_sequence < self.block_from_sequence {
            return Ok(tick("initial-publication-readiness"));
        }
        self.tick_in_flight.store(true, Ordering::Release);
        self.tick_started.store(true, Ordering::Release);
        while !self.release_tick.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        self.tick_in_flight.store(false, Ordering::Release);
        Ok(tick("action-blocking"))
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        if self.tick_in_flight.load(Ordering::Acquire) {
            self.shutdown_during_tick.store(true, Ordering::Release);
        }
        self.shutdown_calls.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

pub(super) struct WorkerBackedServices {
    pub(super) worker: Arc<ProductionResponseWorker>,
}

impl ActiveDefenseServices for WorkerBackedServices {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.worker.ensure_ready()
    }

    fn ensure_bootstrap_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.worker.ensure_bootstrap_ready()
    }

    fn worker_health(&self) -> ResponseWorkerHealth {
        self.worker.health()
    }
}

pub(super) fn tenant() -> TenantId {
    TenantId::new("tenant-worker").unwrap_or_else(|error| panic!("tenant id: {error}"))
}
mod startup_reconciles_then_drains_to_zero_before_readiness;

mod unavailable_sink_blocks_startup_before_reconcile_or_drain;

mod periodic_drain_failure_can_recover_on_a_later_batch;

mod periodic_compaction_is_bounded_and_paginates_from_the_last_compacted_key;

mod periodic_compaction_failure_fails_maintenance_and_outbox_health;

mod pending_or_no_progress_outbox_fails_readiness_and_drain;


pub(super) fn tick(action: &str) -> ResponseWorkerTick {
    ResponseWorkerTick {
        tenant_id: tenant(),
        declassification_receipts_appended: 0,
        declassification_receipts_acknowledged: 0,
        declassification_receipts_pending: 0,
        declassification_receipts_compacted: 0,
        claimed: 1,
        completed_action_ids: vec![
            ActionId::new(action).unwrap_or_else(|error| panic!("action id: {error}"))
        ],
        retry_action_ids: Vec::new(),
        lease_lost_action_ids: Vec::new(),
    }
}

pub(super) struct SqliteTestClock(pub(super) AtomicU64);

impl SqliteTestClock {
    pub(super) fn now(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    pub(super) fn set(&self, now_unix_ms: u64) {
        self.0.store(now_unix_ms, Ordering::Release);
    }
}

impl chio_security_types::clock::Clock for SqliteTestClock {
    fn read(
        &self,
    ) -> core::result::Result<
        chio_security_types::clock::ClockReading,
        chio_security_types::clock::ClockError,
    > {
        let value = self.0.load(Ordering::Acquire);
        chio_security_types::clock::Clock::read(
            &chio_security_types::clock::FixedClock::from_millis(value),
        )
    }
}

pub(super) struct OrderingClock {
    pub(super) now_unix_ms: u64,
    pub(super) events: Arc<Mutex<Vec<&'static str>>>,
}

impl chio_security_types::clock::Clock for OrderingClock {
    fn read(
        &self,
    ) -> core::result::Result<
        chio_security_types::clock::ClockReading,
        chio_security_types::clock::ClockError,
    > {
        let value: PortResult<u64> = (|| {
            self.events
                .lock()
                .map_err(|_| PortError::unavailable())?
                .push("claim");
            Ok(self.now_unix_ms)
        })();
        let value = value.map_err(|_| chio_security_types::clock::ClockError::Unavailable)?;
        chio_security_types::clock::Clock::read(
            &chio_security_types::clock::FixedClock::from_millis(value),
        )
    }
}

pub(super) struct SqliteTestPorts;

impl EffectPort for SqliteTestPorts {
    fn ensure_effects_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn execute(&self, _: &EffectRequest) -> PortResult<EffectResult> {
        Err(PortError::unavailable())
    }

    fn load_result(&self, _: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        Ok(EffectExecutionStatus::NotExecuted)
    }
}

impl SecurityReceiptSink for SqliteTestPorts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        Ok(request.evidence_id.clone())
    }
}

impl SecurityAlertPort for SqliteTestPorts {
    fn ensure_alerts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
        Ok(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: alert.occurred_at_unix_ms,
        })
    }

    fn load_delivery(
        &self,
        query: &AlertDeliveryQuery,
    ) -> PortResult<Option<AlertDeliveryStatus>> {
        Ok(Some(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: query.alert.occurred_at_unix_ms,
        }))
    }
}

impl SchedulerHealthPort for SqliteTestPorts {
    fn ensure_scheduler_health_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn page_once(
        &self,
        request: &SchedulerHealthPageRequest,
    ) -> PortResult<AlertDeliveryStatus> {
        Ok(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: request.occurred_at_unix_ms,
        })
    }

    fn load_delivery(
        &self,
        query: &AlertDeliveryQuery,
    ) -> PortResult<Option<AlertDeliveryStatus>> {
        Ok(Some(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: query.alert.occurred_at_unix_ms,
        }))
    }
}

pub(super) fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("system clock: {error}"))
        .as_millis()
        .try_into()
        .unwrap_or_else(|error| panic!("millisecond conversion: {error}"))
}

pub(super) fn install_due_sqlite_plan(
    store: &Arc<SqliteSecurityStateStore>,
    action_id: &str,
    due_at_unix_ms: u64,
) -> ResponsePlanRecord {
    let created_at_unix_ms = due_at_unix_ms.saturating_sub(1_000);
    let canonical_contribution = CanonicalBody::new(b"{\"posture_rank\":3}".to_vec())
        .unwrap_or_else(|error| panic!("contribution body: {error}"));
    let contribution_hash = chio_security_types::ports::Digest32::new(
        *chio_core::sha256(canonical_contribution.as_bytes()).as_bytes(),
    );
    let plan = build_response_plan(ResponsePlanInput {
        execution: chio_security_types::ResponseExecutionBinding::new(
            chio_security_types::ResponseExecutionMode::Live,
        ),
        action_id: ActionId::new(action_id)
            .unwrap_or_else(|error| panic!("action id: {error}")),
        trigger_finding_id: RecordId::new("finding-scheduler-worker")
            .unwrap_or_else(|error| panic!("finding id: {error}")),
        trigger_finding_hash: chio_security_types::ports::Digest32::new([11; 32]),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("finding-scheduler-worker-receipt")
            .unwrap_or_else(|error| panic!("finding receipt: {error}")),
        tenant_id: tenant(),
        policy_version: RecordId::new("policy-scheduler-worker")
            .unwrap_or_else(|error| panic!("policy version: {error}")),
        policy_hash: chio_security_types::ports::Digest32::new([12; 32]),
        affected_ids: vec![RecordId::new("affected-scheduler-worker")
            .unwrap_or_else(|error| panic!("affected id: {error}"))],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: SessionId::new("session-scheduler-worker")
                    .unwrap_or_else(|error| panic!("session id: {error}")),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: chio_security_types::ports::Digest32::new([13; 32]),
        }],
        ttl_ms: due_at_unix_ms.saturating_sub(created_at_unix_ms),
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: RecordId::new("capability-scheduler-worker")
                .unwrap_or_else(|error| panic!("capability id: {error}")),
            capability_digest: chio_security_types::ports::Digest32::new([14; 32]),
            expires_at_unix_ms: due_at_unix_ms.saturating_add(10_000),
            executor_subject: RecordId::new("executor-scheduler-worker")
                .unwrap_or_else(|error| panic!("executor subject: {error}")),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: RecordId::new("submitter-scheduler-worker")
            .unwrap_or_else(|error| panic!("submitter: {error}")),
        reason_hash: chio_security_types::ports::Digest32::new([15; 32]),
    })
    .unwrap_or_else(|error| panic!("response plan: {error}"));
    ResponseStateMachine::new(Arc::clone(store))
        .create(
            chio_security_types::FreshLiveAdmission::new(plan)
                .unwrap_or_else(|error| panic!("live fixture plan: {error}")),
        )
        .unwrap_or_else(|error| panic!("create plan: {error}"))
}

pub(super) fn sqlite_worker_port(
    store: Arc<SqliteSecurityStateStore>,
    clock: Arc<SqliteTestClock>,
    owner: &str,
    claim_incarnation: &str,
    lease_duration_ms: u64,
) -> Arc<SqliteResponseWorkerPort> {
    let ports = Arc::new(SqliteTestPorts);
    Arc::new(
        SqliteResponseWorkerPort::new_with_claim_incarnation_for_test(
            store,
            Arc::clone(&ports) as Arc<dyn EffectPort>,
            Arc::clone(&ports) as Arc<dyn SecurityReceiptSink>,
            Arc::clone(&ports) as Arc<dyn SecurityAlertPort>,
            ports as Arc<dyn SchedulerHealthPort>,
            clock,
            ProductionResponseSchedulerConfig {
                tenant_id: tenant(),
                lease_owner_id: LeaseOwnerId::new(owner)
                    .unwrap_or_else(|error| panic!("lease owner id: {error}")),
                scheduler_policy: SchedulerPolicy {
                    lease_duration_ms,
                    base_backoff_ms: 10,
                    max_backoff_ms: 20,
                    operator_page_threshold_ms: 100,
                    max_claims: 8,
                },
                renewal_margin_ms: 5,
            },
            RecordId::new(claim_incarnation)
                .unwrap_or_else(|error| panic!("claim incarnation id: {error}")),
        )
        .unwrap_or_else(|error| panic!("worker port: {error}")),
    )
}

pub(super) fn record_retry_and_reclaim(
    store: &SqliteSecurityStateStore,
    clock: &SqliteTestClock,
    port: &SqliteResponseWorkerPort,
    work: &ScheduledWork,
    tick_sequence: u64,
    transition_id: RecordId,
) -> ScheduledWork {
    let retry_now_unix_ms = clock.now();
    let not_before_unix_ms = retry_now_unix_ms.saturating_add(1);
    store
        .record_retry(&SchedulerRetryRequest {
            work: work.clone(),
            expected_attempts: 0,
            error_code: ErrorCode::new("response.terminal_recovery_test")
                .unwrap_or_else(|error| panic!("terminal retry error code: {error}")),
            first_failure_at_unix_ms: retry_now_unix_ms,
            now_unix_ms: retry_now_unix_ms,
            not_before_unix_ms,
            health_event_id: None,
            transition_id,
        })
        .unwrap_or_else(|error| panic!("terminal retry persistence: {error}"));
    clock.set(not_before_unix_ms);
    let reclaimed = port
        .claim(tick_sequence)
        .unwrap_or_else(|error| panic!("terminal retry reclaim: {error}"));
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].action_id, work.action_id);
    assert!(reclaimed[0].fencing_token > work.fencing_token);
    reclaimed[0].clone()
}




mod periodic_tick_claims_recovery_before_one_bounded_outbox_batch;



mod expired_terminal_cleanup_rolls_back_the_batch_on_late_corruption;

mod sqlite_worker_claims_simultaneously_due_actions_transactionally_in_deterministic_order;



mod production_worker_restart_recovers_after_ack_loss_without_duplicate_completion;

mod production_worker_surfaces_stale_fence_as_lease_loss_not_completion;

mod worker_progress_deadline_has_an_absolute_validated_boundary;

mod pending_declassification_receipts_keep_worker_health_degraded;

mod post_loop_cleanup_releases_owned_work_and_is_idempotent;





mod production_worker_allows_only_one_background_loop;

mod worker_owned_thread_survives_caller_starvation_and_joins_before_restart;

mod progress_deadline_begins_when_the_worker_reaches_publication_readiness;

mod crashed_worker_thread_revokes_liveness_before_the_progress_deadline;

mod successful_cleanup_preserves_the_terminal_worker_failure;

mod panicking_worker_preserves_its_crash_when_cleanup_also_fails;

mod parked_worker_commit_failure_stops_with_zero_ticks;

mod publication_remains_unready_until_the_first_tick_completes;

mod cancelled_publication_wait_transfers_join_ownership_without_blocking_drop;

mod initial_tick_retries_non_crash_failures_on_the_configured_cadence;

mod initial_tick_deadline_exhaustion_fails_publication_and_joins_the_thread;

mod immediate_post_release_crash_keeps_the_degraded_services_published;

mod wedged_tick_fails_readiness_and_awaited_shutdown_never_drains_concurrently;

mod cancelled_shutdown_retains_join_until_the_blocked_tick_exits;

mod dropping_handle_signals_stop_without_concurrent_drain_or_zombie_tick;

mod worker_crash_marks_health_failed_and_restart_can_take_over;

mod terminated_primary_reuses_its_durable_port_without_concurrent_ticks;


pub(super) struct TestServices {
    pub(super) ready: Mutex<bool>,
}

impl ActiveDefenseServices for TestServices {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        match self.ready.lock() {
            Ok(ready) if *ready => Ok(()),
            Ok(_) | Err(_) => Err(ResponseWorkerTickError::Port(PortError::unavailable())),
        }
    }

    fn worker_health(&self) -> ResponseWorkerHealth {
        ResponseWorkerHealth::created()
    }
}

pub(super) struct SequencedServices {
    pub(super) readiness: Mutex<VecDeque<bool>>,
}

impl ActiveDefenseServices for SequencedServices {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        match self.readiness.lock() {
            Ok(mut readiness) => match readiness.pop_front() {
                Some(true) => Ok(()),
                Some(false) | None => {
                    Err(ResponseWorkerTickError::Port(PortError::unavailable()))
                }
            },
            Err(_) => Err(ResponseWorkerTickError::Port(PortError::unavailable())),
        }
    }

    fn worker_health(&self) -> ResponseWorkerHealth {
        ResponseWorkerHealth::created()
    }
}

pub(super) struct BootstrapOnlyServices;

impl ActiveDefenseServices for BootstrapOnlyServices {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Err(ResponseWorkerTickError::Port(PortError::unavailable()))
    }

    fn ensure_bootstrap_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }

    fn worker_health(&self) -> ResponseWorkerHealth {
        ResponseWorkerHealth::created()
    }
}
mod service_publication_can_precede_operational_kernel_binding;

mod service_publication_is_atomic_when_replacement_readiness_fails;

mod service_publication_rechecks_readiness_at_commit_time;

mod service_publication_rejects_duplicate_ownership_without_replacement;


