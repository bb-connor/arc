#[cfg(test)]
mod tests {
    use super::{
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
    use chio_quarantine::{
        build_response_plan, ResponseStateMachine, ResponseTransitionRequest, SchedulerPolicy,
        SchedulerWorkOutcome,
    };
    use chio_security_kernel::SecurityClock;
    use chio_security_types::ports::{
        ActionId, AlertDeliveryQuery, AlertDeliveryStatus, CanonicalBody, EffectExecutionStatus,
        EffectPort, EffectRequest, EffectResult, EffectResultQuery, ErrorCode, GrantId,
        LeaseOwnerId, OpaqueReceiptRef, PortError, PortResult, ReceiptAppendRequest, RecordId,
        ResponsePlanRecord, ResponseSchedulerStore, ResponseStore, ScheduledWork,
        SchedulerHealthPageRequest, SchedulerHealthPort, SchedulerRetryRequest, SecurityAlert,
        SecurityAlertPort, SecurityReceiptSink, SessionId, TenantId,
        MAX_DECLASSIFICATION_EVIDENCE_BATCH,
    };
    use chio_security_types::{
        OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
        ResponseEffectSpec, ResponsePlanInput, ResponseState, ResponseTarget,
    };
    use chio_store_sqlite::security_state::{SecurityStateClock, SqliteSecurityStateStore};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    type RequestedCompaction = (Option<TenantId>, Option<GrantId>, u32);

    struct ScriptedDeclassificationOutboxPort {
        available: AtomicBool,
        pending: AtomicU64,
        stranded: AtomicU64,
        reconciliations: Mutex<VecDeque<Result<DeclassificationReconciliationReport, PortError>>>,
        drains: Mutex<VecDeque<Result<DeclassificationReceiptDrainReport, PortError>>>,
        compactions: Mutex<VecDeque<Result<DeclassificationCompactionReport, PortError>>>,
        requested_batches: Mutex<Vec<u32>>,
        requested_compactions: Mutex<Vec<RequestedCompaction>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ScriptedDeclassificationOutboxPort {
        fn new(
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

        fn with_compactions(
            self,
            compactions: Vec<Result<DeclassificationCompactionReport, PortError>>,
        ) -> Self {
            if let Ok(mut scripted) = self.compactions.lock() {
                *scripted = compactions.into();
            }
            self
        }

        fn with_events(mut self, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            self.events = events;
            self
        }

        fn set_available(&self, available: bool) {
            self.available.store(available, Ordering::Release);
        }

        fn set_pending(&self, pending: u64) {
            self.pending.store(pending, Ordering::Release);
        }

        fn events(&self) -> Vec<&'static str> {
            self.events
                .lock()
                .map_or_else(|_| Vec::new(), |events| events.clone())
        }

        fn requested_batches(&self) -> Vec<u32> {
            self.requested_batches
                .lock()
                .map_or_else(|_| Vec::new(), |batches| batches.clone())
        }

        fn requested_compactions(&self) -> Vec<(Option<TenantId>, Option<GrantId>, u32)> {
            self.requested_compactions
                .lock()
                .map_or_else(|_| Vec::new(), |requests| requests.clone())
        }

        fn record(&self, event: &'static str) -> Result<(), PortError> {
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
    struct ScriptedWorkerPort {
        ticks: Mutex<VecDeque<Result<ResponseWorkerTick, ResponseWorkerTickError>>>,
        tick_calls: AtomicU64,
        ticks_in_flight: AtomicU64,
        maximum_concurrent_ticks: AtomicU64,
        shutdown_calls: Mutex<u32>,
        ready: Mutex<bool>,
    }

    impl ScriptedWorkerPort {
        fn with_ticks(ticks: Vec<Result<ResponseWorkerTick, ResponseWorkerTickError>>) -> Self {
            Self {
                ticks: Mutex::new(ticks.into()),
                tick_calls: AtomicU64::new(0),
                ticks_in_flight: AtomicU64::new(0),
                maximum_concurrent_ticks: AtomicU64::new(0),
                shutdown_calls: Mutex::new(0),
                ready: Mutex::new(true),
            }
        }

        fn shutdown_calls(&self) -> u32 {
            self.shutdown_calls.lock().map_or(0, |calls| *calls)
        }

        fn tick_calls(&self) -> u64 {
            self.tick_calls.load(Ordering::Acquire)
        }

        fn maximum_concurrent_ticks(&self) -> u64 {
            self.maximum_concurrent_ticks.load(Ordering::Acquire)
        }

        fn set_ready(&self, ready: bool) {
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

    struct BlockingWorkerPort {
        block_from_sequence: u64,
        tick_started: AtomicBool,
        tick_in_flight: AtomicBool,
        release_tick: AtomicBool,
        shutdown_calls: AtomicU64,
        shutdown_during_tick: AtomicBool,
    }

    impl BlockingWorkerPort {
        fn new() -> Self {
            Self::blocking_from_sequence(1)
        }

        fn blocking_initial_tick() -> Self {
            Self::blocking_from_sequence(0)
        }

        fn blocking_from_sequence(block_from_sequence: u64) -> Self {
            Self {
                block_from_sequence,
                tick_started: AtomicBool::new(false),
                tick_in_flight: AtomicBool::new(false),
                release_tick: AtomicBool::new(false),
                shutdown_calls: AtomicU64::new(0),
                shutdown_during_tick: AtomicBool::new(false),
            }
        }

        fn release(&self) {
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

    struct WorkerBackedServices {
        worker: Arc<ProductionResponseWorker>,
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

    fn tenant() -> TenantId {
        TenantId::new("tenant-worker").unwrap_or_else(|error| panic!("tenant id: {error}"))
    }

    #[test]
    fn startup_reconciles_then_drains_to_zero_before_readiness() {
        let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
            2,
            1,
            vec![Ok(DeclassificationReconciliationReport {
                reconciled: 1,
                remaining: 0,
            })],
            vec![
                Ok(DeclassificationReceiptDrainReport {
                    appended: 1,
                    acknowledged: 1,
                    deferred: 0,
                    remaining: 1,
                }),
                Ok(DeclassificationReceiptDrainReport {
                    appended: 1,
                    acknowledged: 1,
                    deferred: 0,
                    remaining: 0,
                }),
            ],
        ));
        let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
        let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

        let report = outbox
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("startup drain: {error}"));

        assert_eq!(report.appended, 2);
        assert_eq!(report.acknowledged, 2);
        assert_eq!(report.remaining, 0);
        assert_eq!(
            scripted.events(),
            vec![
                "ensure",
                "count_stranded",
                "reconcile",
                "count_pending",
                "drain",
                "drain",
            ]
        );
        assert_eq!(outbox.health(), DeclassificationOutboxHealth::Ready);
    }

    #[test]
    fn unavailable_sink_blocks_startup_before_reconcile_or_drain() {
        let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
            1,
            1,
            Vec::new(),
            Vec::new(),
        ));
        scripted.set_available(false);
        let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
        let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

        assert!(matches!(
            outbox.reconcile_and_drain_startup(),
            Err(ResponseWorkerTickError::DeclassificationOutbox(_))
        ));
        assert_eq!(scripted.events(), vec!["ensure", "count_pending"]);
        assert!(matches!(
            outbox.health(),
            DeclassificationOutboxHealth::Failed { .. }
        ));
    }

    #[test]
    fn periodic_drain_failure_can_recover_on_a_later_batch() {
        let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
            1,
            0,
            Vec::new(),
            vec![
                Err(PortError::unavailable()),
                Ok(DeclassificationReceiptDrainReport {
                    appended: 1,
                    acknowledged: 1,
                    deferred: 0,
                    remaining: 0,
                }),
            ],
        ));
        let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
        let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

        assert!(outbox.drain_one_batch().is_err());
        assert!(matches!(
            outbox.health(),
            DeclassificationOutboxHealth::Failed { .. }
        ));
        let recovered = outbox
            .drain_one_batch()
            .unwrap_or_else(|error| panic!("recovery drain: {error}"));
        assert_eq!(recovered.acknowledged, 1);
        assert_eq!(outbox.health(), DeclassificationOutboxHealth::Ready);
        assert_eq!(
            scripted.requested_batches(),
            vec![
                MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                MAX_DECLASSIFICATION_EVIDENCE_BATCH,
            ]
        );
    }

    #[test]
    fn periodic_compaction_is_bounded_and_paginates_from_the_last_compacted_key() {
        let first_tenant = TenantId::new("tenant-compaction-a")
            .unwrap_or_else(|error| panic!("first compaction tenant: {error}"));
        let first_grant = GrantId::new("grant-compaction-a")
            .unwrap_or_else(|error| panic!("first compaction grant: {error}"));
        let second_tenant = TenantId::new("tenant-compaction-b")
            .unwrap_or_else(|error| panic!("second compaction tenant: {error}"));
        let second_grant = GrantId::new("grant-compaction-b")
            .unwrap_or_else(|error| panic!("second compaction grant: {error}"));
        let scripted = Arc::new(
            ScriptedDeclassificationOutboxPort::new(
                0,
                0,
                Vec::new(),
                vec![
                    Ok(DeclassificationReceiptDrainReport::default()),
                    Ok(DeclassificationReceiptDrainReport::default()),
                ],
            )
            .with_compactions(vec![
                Ok(DeclassificationCompactionReport {
                    compacted: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                    last_tenant_id: Some(first_tenant.clone()),
                    last_grant_id: Some(first_grant.clone()),
                }),
                Ok(DeclassificationCompactionReport {
                    compacted: 1,
                    last_tenant_id: Some(second_tenant),
                    last_grant_id: Some(second_grant),
                }),
            ]),
        );
        let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
        let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

        let (_, first) = outbox
            .maintain_one_batch()
            .unwrap_or_else(|error| panic!("first maintenance page: {error}"));
        let (_, second) = outbox
            .maintain_one_batch()
            .unwrap_or_else(|error| panic!("second maintenance page: {error}"));

        assert_eq!(first.compacted, MAX_DECLASSIFICATION_EVIDENCE_BATCH);
        assert_eq!(second.compacted, 1);
        assert_eq!(
            scripted.requested_compactions(),
            vec![
                (None, None, MAX_DECLASSIFICATION_EVIDENCE_BATCH),
                (
                    Some(first_tenant),
                    Some(first_grant),
                    MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                ),
            ]
        );
    }

    #[test]
    fn periodic_compaction_failure_fails_maintenance_and_outbox_health() {
        let scripted = Arc::new(
            ScriptedDeclassificationOutboxPort::new(
                0,
                0,
                Vec::new(),
                vec![Ok(DeclassificationReceiptDrainReport::default())],
            )
            .with_compactions(vec![Err(PortError::unavailable())]),
        );
        let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted;
        let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

        assert!(matches!(
            outbox.maintain_one_batch(),
            Err(ResponseWorkerTickError::DeclassificationOutbox(_))
        ));
        assert!(matches!(
            outbox.health(),
            DeclassificationOutboxHealth::Failed { .. }
        ));
    }

    #[test]
    fn pending_or_no_progress_outbox_fails_readiness_and_drain() {
        let scripted = Arc::new(ScriptedDeclassificationOutboxPort::new(
            3,
            0,
            Vec::new(),
            vec![Ok(DeclassificationReceiptDrainReport {
                appended: 0,
                acknowledged: 0,
                deferred: 0,
                remaining: 3,
            })],
        ));
        let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
        let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

        assert!(matches!(
            outbox.ensure_ready(),
            Err(ResponseWorkerTickError::DeclassificationOutboxPending(3))
        ));
        assert!(matches!(
            outbox.drain_one_batch(),
            Err(ResponseWorkerTickError::DeclassificationOutboxNoProgress(3))
        ));
        assert!(matches!(
            outbox.health(),
            DeclassificationOutboxHealth::Failed {
                pending_receipts: Some(3),
                ..
            }
        ));
    }

    fn tick(action: &str) -> ResponseWorkerTick {
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

    struct SqliteTestClock(AtomicU64);

    impl SqliteTestClock {
        fn now(&self) -> u64 {
            self.0.load(Ordering::Acquire)
        }

        fn set(&self, now_unix_ms: u64) {
            self.0.store(now_unix_ms, Ordering::Release);
        }
    }

    impl SecurityClock for SqliteTestClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }

    impl SecurityStateClock for SqliteTestClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }

    struct OrderingClock {
        now_unix_ms: u64,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl SecurityClock for OrderingClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            self.events
                .lock()
                .map_err(|_| PortError::unavailable())?
                .push("claim");
            Ok(self.now_unix_ms)
        }
    }

    struct SqliteTestPorts;

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

    fn current_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system clock: {error}"))
            .as_millis()
            .try_into()
            .unwrap_or_else(|error| panic!("millisecond conversion: {error}"))
    }

    fn install_due_sqlite_plan(
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
            .create(plan)
            .unwrap_or_else(|error| panic!("create plan: {error}"))
    }

    fn sqlite_worker_port(
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

    fn record_retry_and_reclaim(
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

    #[test]
    fn sqlite_worker_operation_gate_recovers_after_panic_for_cleanup() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let now_unix_ms = current_unix_ms();
        let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                directory.path().join("operation-gate-poison.sqlite"),
                Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("security store: {error}")),
        );
        let port = sqlite_worker_port(
            store,
            clock,
            "worker-operation-gate-poison",
            "incarnation-operation-gate-poison",
            100,
        );
        let panicking_port = Arc::clone(&port);
        let panicked = std::thread::spawn(move || {
            let _operation_guard = panicking_port
                .operation_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("forced worker operation panic");
        })
        .join();
        assert!(panicked.is_err());
        let report = port
            .tick(0, false)
            .unwrap_or_else(|error| panic!("post-panic worker tick: {error}"));
        assert_eq!(report.claimed, 0);
        port.shutdown()
            .unwrap_or_else(|error| panic!("post-panic worker shutdown: {error}"));
    }

    #[test]
    fn sqlite_worker_shutdown_forgets_a_naturally_expired_safe_lease() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("expired-safe-shutdown.sqlite");
        let now_unix_ms = current_unix_ms();
        let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &path,
                Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("security store: {error}")),
        );
        install_due_sqlite_plan(
            &store,
            "action-expired-safe-shutdown",
            now_unix_ms.saturating_sub(1),
        );
        let port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-expired-safe-shutdown",
            "incarnation-expired-safe-shutdown",
            100,
        );
        let work = port
            .claim(0)
            .unwrap_or_else(|error| panic!("safe lease claim: {error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("safe lease claim missing"));
        clock.set(work.lease_expires_at_unix_ms.saturating_add(1));

        port.shutdown()
            .unwrap_or_else(|error| panic!("expired safe lease shutdown: {error}"));
        assert!(port
            .owned_leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty());
        let connection = rusqlite::Connection::open(path)
            .unwrap_or_else(|error| panic!("expired safe lease readback: {error}"));
        let durable_leases = connection
            .query_row(
                "SELECT COUNT(*) FROM security_scheduler_leases WHERE tenant_id = ?1 AND action_id = ?2",
                rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("expired safe lease count: {error}"));
        assert_eq!(durable_leases, 1);
    }

    #[test]
    fn periodic_tick_drains_one_bounded_batch_before_scheduler_claim() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("bounded-outbox-tick.sqlite"))
                .unwrap_or_else(|error| panic!("security store: {error}")),
        );
        let events = Arc::new(Mutex::new(Vec::new()));
        let scripted = Arc::new(
            ScriptedDeclassificationOutboxPort::new(
                0,
                0,
                Vec::new(),
                vec![Ok(DeclassificationReceiptDrainReport {
                    appended: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                    acknowledged: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                    deferred: 0,
                    remaining: 7,
                })],
            )
            .with_compactions(vec![Ok(DeclassificationCompactionReport {
                compacted: 1,
                last_tenant_id: Some(tenant()),
                last_grant_id: Some(
                    GrantId::new("grant-bounded-outbox")
                        .unwrap_or_else(|error| panic!("compaction grant: {error}")),
                ),
            })])
            .with_events(Arc::clone(&events)),
        );
        let outbox_port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
        let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(outbox_port);
        let ports = Arc::new(SqliteTestPorts);
        let clock: Arc<dyn SecurityClock> = Arc::new(OrderingClock {
            now_unix_ms: current_unix_ms(),
            events: Arc::clone(&events),
        });
        let worker = SqliteResponseWorkerPort::new_with_declassification_outbox(
            store,
            outbox,
            Arc::clone(&ports) as Arc<dyn EffectPort>,
            Arc::clone(&ports) as Arc<dyn SecurityReceiptSink>,
            Arc::clone(&ports) as Arc<dyn SecurityAlertPort>,
            ports as Arc<dyn SchedulerHealthPort>,
            clock,
            ProductionResponseSchedulerConfig {
                tenant_id: tenant(),
                lease_owner_id: LeaseOwnerId::new("worker-bounded-outbox")
                    .unwrap_or_else(|error| panic!("lease owner id: {error}")),
                scheduler_policy: SchedulerPolicy {
                    lease_duration_ms: 5_000,
                    base_backoff_ms: 10,
                    max_backoff_ms: 20,
                    operator_page_threshold_ms: 100,
                    max_claims: 8,
                },
                renewal_margin_ms: 5,
            },
        )
        .unwrap_or_else(|error| panic!("worker port: {error}"));
        scripted.set_pending(u64::from(MAX_DECLASSIFICATION_EVIDENCE_BATCH).saturating_add(7));
        events
            .lock()
            .unwrap_or_else(|_| panic!("event lock"))
            .clear();

        let report = worker
            .tick(0, false)
            .unwrap_or_else(|error| panic!("worker tick: {error}"));

        assert_eq!(
            report.declassification_receipts_acknowledged,
            MAX_DECLASSIFICATION_EVIDENCE_BATCH
        );
        assert_eq!(report.declassification_receipts_pending, 7);
        assert_eq!(report.declassification_receipts_compacted, 1);
        assert_eq!(report.claimed, 0);
        assert_eq!(scripted.events(), vec!["drain", "compact", "claim"]);
        assert_eq!(
            scripted.requested_batches(),
            vec![MAX_DECLASSIFICATION_EVIDENCE_BATCH]
        );
        assert_eq!(
            scripted.requested_compactions(),
            vec![(None, None, MAX_DECLASSIFICATION_EVIDENCE_BATCH)]
        );
        assert_eq!(
            worker.declassification_outbox_status(),
            (true, Some(7), None)
        );
    }

    #[test]
    fn sqlite_worker_restart_replays_lost_claim_ack_and_shutdown_releases_lease() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("response-worker.sqlite");
        let now_unix_ms = current_unix_ms();
        let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let first_store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &path,
                Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("security store: {error}")),
        );
        install_due_sqlite_plan(
            &first_store,
            "action-sqlite-restart",
            now_unix_ms.saturating_sub(1),
        );
        let first_port = sqlite_worker_port(
            Arc::clone(&first_store),
            Arc::clone(&clock),
            "worker-sqlite-restart",
            "incarnation-sqlite-restart-first",
            100,
        );
        let claimed = first_port
            .claim(0)
            .unwrap_or_else(|error| panic!("first claim: {error}"));
        assert_eq!(claimed.len(), 1);
        drop(first_port);
        drop(first_store);

        let reopened_store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &path,
                Arc::clone(&clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("reopen security store: {error}")),
        );
        let same_owner_port = sqlite_worker_port(
            Arc::clone(&reopened_store),
            Arc::clone(&clock),
            "worker-sqlite-restart",
            "incarnation-sqlite-restart-live",
            100,
        );
        assert!(same_owner_port
            .claim(0)
            .unwrap_or_else(|error| panic!("live same-owner claim: {error}"))
            .is_empty());
        reopened_store
            .validate_lease(&claimed[0])
            .unwrap_or_else(|error| panic!("live restart changed prior lease: {error}"));
        drop(same_owner_port);

        let takeover_now_unix_ms = claimed[0].lease_expires_at_unix_ms.saturating_add(1);
        clock.set(takeover_now_unix_ms);
        let restarted_port = sqlite_worker_port(
            Arc::clone(&reopened_store),
            Arc::clone(&clock),
            "worker-sqlite-restart",
            "incarnation-sqlite-restart-takeover",
            100,
        );
        let takeover = restarted_port
            .claim(0)
            .unwrap_or_else(|error| panic!("takeover claim: {error}"));
        assert_eq!(takeover.len(), 1);
        assert_eq!(takeover[0].action_id, claimed[0].action_id);
        assert_eq!(takeover[0].lease_owner_id, claimed[0].lease_owner_id);
        assert!(takeover[0].fencing_token > claimed[0].fencing_token);
        let plan_key = chio_security_types::ports::ResponsePlanKey {
            tenant_id: claimed[0].tenant_id.clone(),
            action_id: claimed[0].action_id.clone(),
        };
        let before_stale_attempt = reopened_store
            .load_plan(&plan_key)
            .unwrap_or_else(|error| panic!("plan before stale attempt: {error}"));
        assert!(matches!(
            restarted_port
                .scheduler
                .process(&claimed[0], takeover_now_unix_ms),
            Ok(SchedulerWorkOutcome::LeaseLost { action_id })
                if action_id == claimed[0].action_id
        ));
        assert_eq!(
            reopened_store
                .load_plan(&plan_key)
                .unwrap_or_else(|error| panic!("plan after stale attempt: {error}")),
            before_stale_attempt
        );
        let restarted = ProductionResponseWorker::new_for_test(restarted_port)
            .unwrap_or_else(|error| panic!("restarted worker: {error}"));
        restarted
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("worker shutdown: {error}"));
        let connection = rusqlite::Connection::open(&path)
            .unwrap_or_else(|error| panic!("restart lease readback: {error}"));
        let remaining_leases = connection
            .query_row(
                "SELECT COUNT(*) FROM security_scheduler_leases WHERE tenant_id = ?1 AND action_id = ?2",
                rusqlite::params![claimed[0].tenant_id.as_str(), claimed[0].action_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("restart lease count: {error}"));
        assert_eq!(remaining_leases, 0);

        let terminal_path = directory.path().join("response-worker-terminal.sqlite");
        let terminal_now_unix_ms = current_unix_ms();
        let terminal_clock = Arc::new(SqliteTestClock(AtomicU64::new(terminal_now_unix_ms)));
        let terminal_store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &terminal_path,
                Arc::clone(&terminal_clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("terminal security store: {error}")),
        );
        let terminal_plan = install_due_sqlite_plan(
            &terminal_store,
            "action-sqlite-restart-terminal",
            terminal_now_unix_ms.saturating_sub(1),
        );
        let terminal_port = sqlite_worker_port(
            Arc::clone(&terminal_store),
            Arc::clone(&terminal_clock),
            "worker-sqlite-restart-terminal",
            "incarnation-sqlite-terminal-first",
            100,
        );
        let initial_terminal_work = terminal_port
            .claim(0)
            .unwrap_or_else(|error| panic!("terminal first claim: {error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("terminal first claim missing"));
        let terminal_work = record_retry_and_reclaim(
            &terminal_store,
            &terminal_clock,
            &terminal_port,
            &initial_terminal_work,
            1,
            RecordId::new("terminal-recovery-retry")
                .unwrap_or_else(|error| panic!("terminal retry transition: {error}")),
        );
        ResponseStateMachine::new(Arc::clone(&terminal_store))
            .transition_scheduled(
                &terminal_plan,
                &terminal_work,
                &ResponseTransitionRequest {
                    expected_generation: terminal_plan.generation,
                    target_state: ResponseState::Cancelled,
                    occurred_at_unix_ms: terminal_clock.now(),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            )
            .unwrap_or_else(|error| panic!("terminal transition: {error}"));
        drop(terminal_port);
        drop(terminal_store);

        let terminal_reopened = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &terminal_path,
                Arc::clone(&terminal_clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("terminal store reopen: {error}")),
        );
        let terminal_restarted = sqlite_worker_port(
            Arc::clone(&terminal_reopened),
            Arc::clone(&terminal_clock),
            "worker-sqlite-restart-terminal",
            "incarnation-sqlite-terminal-restart",
            100,
        );
        assert!(terminal_restarted
            .claim(0)
            .unwrap_or_else(|error| panic!("live terminal restart claim: {error}"))
            .is_empty());
        let connection = rusqlite::Connection::open(&terminal_path)
            .unwrap_or_else(|error| panic!("live terminal readback: {error}"));
        let live_terminal_counts = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM security_scheduler_leases
                     WHERE tenant_id = ?1 AND action_id = ?2),
                    (SELECT COUNT(*) FROM security_scheduler_retries
                     WHERE tenant_id = ?1 AND action_id = ?2)
                "#,
                rusqlite::params![
                    terminal_work.tenant_id.as_str(),
                    terminal_work.action_id.as_str()
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap_or_else(|error| panic!("live terminal counts: {error}"));
        assert_eq!(live_terminal_counts, (1, 1));
        drop(connection);

        terminal_clock.set(terminal_work.lease_expires_at_unix_ms.saturating_add(1));
        assert!(terminal_restarted
            .claim(1)
            .unwrap_or_else(|error| panic!("expired terminal cleanup: {error}"))
            .is_empty());
        let connection = rusqlite::Connection::open(terminal_path)
            .unwrap_or_else(|error| panic!("terminal cleanup readback: {error}"));
        let terminal_cleanup_counts = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM security_scheduler_leases
                     WHERE tenant_id = ?1 AND action_id = ?2),
                    (SELECT COUNT(*) FROM security_scheduler_retries
                     WHERE tenant_id = ?1 AND action_id = ?2)
                "#,
                rusqlite::params![
                    terminal_work.tenant_id.as_str(),
                    terminal_work.action_id.as_str()
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap_or_else(|error| panic!("terminal cleanup counts: {error}"));
        assert_eq!(terminal_cleanup_counts, (0, 0));

        let batch_path = directory
            .path()
            .join("response-worker-terminal-batch.sqlite");
        let batch_now_unix_ms = current_unix_ms();
        let batch_clock = Arc::new(SqliteTestClock(AtomicU64::new(batch_now_unix_ms)));
        let batch_store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &batch_path,
                Arc::clone(&batch_clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("terminal batch store: {error}")),
        );
        let batch_plans = (0..9)
            .map(|index| {
                install_due_sqlite_plan(
                    &batch_store,
                    &format!("action-sqlite-terminal-batch-{index}"),
                    batch_now_unix_ms.saturating_sub(1),
                )
            })
            .collect::<Vec<_>>();
        let batch_port = sqlite_worker_port(
            Arc::clone(&batch_store),
            Arc::clone(&batch_clock),
            "worker-sqlite-terminal-batch",
            "incarnation-sqlite-terminal-batch-first",
            100,
        );
        let mut initial_batch_work = batch_port
            .claim(0)
            .unwrap_or_else(|error| panic!("terminal batch first claim: {error}"));
        initial_batch_work.extend(
            batch_port
                .claim(1)
                .unwrap_or_else(|error| panic!("terminal batch second claim: {error}")),
        );
        assert_eq!(initial_batch_work.len(), 9);
        let mut batch_work = Vec::with_capacity(initial_batch_work.len());
        for (index, initial_work) in initial_batch_work.iter().enumerate() {
            let plan = batch_plans
                .iter()
                .find(|plan| plan.action_id == initial_work.action_id)
                .unwrap_or_else(|| panic!("terminal batch plan missing"));
            let tick_sequence = u64::try_from(index)
                .unwrap_or_else(|error| panic!("terminal batch tick conversion: {error}"))
                .saturating_add(10);
            let work = record_retry_and_reclaim(
                &batch_store,
                &batch_clock,
                &batch_port,
                initial_work,
                tick_sequence,
                RecordId::new(format!(
                    "terminal-batch-retry-{}",
                    initial_work.action_id.as_str()
                ))
                .unwrap_or_else(|error| panic!("terminal batch retry transition: {error}")),
            );
            ResponseStateMachine::new(Arc::clone(&batch_store))
                .transition_scheduled(
                    plan,
                    &work,
                    &ResponseTransitionRequest {
                        expected_generation: plan.generation,
                        target_state: ResponseState::Cancelled,
                        occurred_at_unix_ms: batch_clock.now(),
                        applying_lease_expires_at_unix_ms: None,
                        error_code: None,
                    },
                )
                .unwrap_or_else(|error| panic!("terminal batch transition: {error}"));
            batch_work.push(work);
        }
        let batch_expiry = batch_work
            .iter()
            .map(|work| work.lease_expires_at_unix_ms)
            .max()
            .unwrap_or_else(|| panic!("terminal batch expiry missing"));
        drop(batch_port);
        drop(batch_store);

        batch_clock.set(batch_expiry.saturating_add(1));
        let batch_reopened = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                &batch_path,
                Arc::clone(&batch_clock) as Arc<dyn SecurityStateClock>,
            )
            .unwrap_or_else(|error| panic!("terminal batch reopen: {error}")),
        );
        let batch_restarted = sqlite_worker_port(
            batch_reopened,
            batch_clock,
            "worker-sqlite-terminal-batch",
            "incarnation-sqlite-terminal-batch-restart",
            100,
        );
        assert!(matches!(
            batch_restarted.claim(0),
            Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
        ));
        let connection = rusqlite::Connection::open(&batch_path)
            .unwrap_or_else(|error| panic!("terminal batch continuation readback: {error}"));
        let continuation_counts = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM security_scheduler_leases),
                    (SELECT COUNT(*) FROM security_scheduler_retries)
                "#,
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap_or_else(|error| panic!("terminal batch continuation counts: {error}"));
        assert_eq!(continuation_counts, (1, 1));
        drop(connection);
        assert!(batch_restarted
            .claim(1)
            .unwrap_or_else(|error| panic!("terminal batch final cleanup: {error}"))
            .is_empty());
        let connection = rusqlite::Connection::open(batch_path)
            .unwrap_or_else(|error| panic!("terminal batch cleanup readback: {error}"));
        let batch_cleanup_counts = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM security_scheduler_leases),
                    (SELECT COUNT(*) FROM security_scheduler_retries)
                "#,
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap_or_else(|error| panic!("terminal batch cleanup counts: {error}"));
        assert_eq!(batch_cleanup_counts, (0, 0));
    }

    include!("part_02_tests_tail.inc");
}
