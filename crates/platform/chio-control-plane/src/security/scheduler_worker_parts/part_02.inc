#[cfg(test)]
mod tests {
    use super::{
        join_response_worker_thread, ActiveDefenseServiceRegistry, ActiveDefenseServices,
        DeclassificationCompactionReport, DeclassificationOutboxHealth,
        DeclassificationReceiptDrainReport, DeclassificationReceiptOutboxPort,
        DeclassificationReconciliationReport, ProductionDeclassificationReceiptOutbox,
        ProductionResponseSchedulerConfig, ProductionResponseWorker,
        ProductionResponseWorkerHandle, ProductionResponseWorkerLoopConfig,
        ResponseWorkerHealth, ResponseWorkerJoinJob, ResponseWorkerLifecycle, ResponseWorkerPort,
        ResponseWorkerReaperRegistry, ResponseWorkerTick, ResponseWorkerTickError,
        SqliteResponseWorkerPort, MAX_RESPONSE_WORKER_JOIN_OWNERS,
        MAX_WORKER_PROGRESS_DEADLINE, MIN_WORKER_PROGRESS_DEADLINE,
    };
    use chio_quarantine::{SchedulerPolicy, SchedulerWorkOutcome};
    use chio_security_kernel::SecurityClock;
    use chio_security_types::ports::{
        ActionId, AlertDeliveryQuery, AlertDeliveryStatus, CanonicalBody, EffectExecutionStatus,
        EffectPort, EffectRequest, EffectResult, EffectResultQuery, ErrorCode, GrantId,
        LeaseOwnerId, OpaqueReceiptRef, PortError, PortResult, ReceiptAppendRequest, RecordId,
        ResponsePlanRecord, ResponseSchedulerStore, ResponseStore, SchedulerHealthPageRequest,
        SchedulerHealthPort, SecurityAlert, SecurityAlertPort, SecurityReceiptSink, TenantId,
        MAX_DECLASSIFICATION_EVIDENCE_BATCH,
    };
    use chio_store_sqlite::security_state::SqliteSecurityStateStore;
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
        fn set(&self, now_unix_ms: u64) {
            self.0.store(now_unix_ms, Ordering::Release);
        }
    }

    impl SecurityClock for SqliteTestClock {
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
        store: &SqliteSecurityStateStore,
        action_id: &str,
        due_at_unix_ms: u64,
    ) -> ResponsePlanRecord {
        let body = CanonicalBody::new(br#"{"state":"planned"}"#.to_vec())
            .unwrap_or_else(|error| panic!("plan body: {error}"));
        let record = ResponsePlanRecord {
            tenant_id: tenant(),
            action_id: ActionId::new(action_id)
                .unwrap_or_else(|error| panic!("action id: {error}")),
            generation: 0,
            state: RecordId::new("planned").unwrap_or_else(|error| panic!("state id: {error}")),
            body_hash: chio_security_types::ports::Digest32::new(
                *chio_core::sha256(body.as_bytes()).as_bytes(),
            ),
            canonical_body: body,
            due_at_unix_ms: Some(due_at_unix_ms),
        };
        store
            .create(&record)
            .unwrap_or_else(|error| panic!("create plan: {error}"));
        record
    }

    fn sqlite_worker_port(
        store: Arc<SqliteSecurityStateStore>,
        clock: Arc<SqliteTestClock>,
        owner: &str,
        lease_duration_ms: u64,
    ) -> Arc<SqliteResponseWorkerPort> {
        let ports = Arc::new(SqliteTestPorts);
        Arc::new(
            SqliteResponseWorkerPort::new(
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
            )
            .unwrap_or_else(|error| panic!("worker port: {error}")),
        )
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
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("response-worker.sqlite"))
                .unwrap_or_else(|error| panic!("security store: {error}")),
        );
        let now_unix_ms = current_unix_ms();
        install_due_sqlite_plan(
            &store,
            "action-sqlite-restart",
            now_unix_ms.saturating_sub(1),
        );
        let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let first_port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-sqlite-restart",
            5_000,
        );
        let claimed = first_port
            .claim(0)
            .unwrap_or_else(|error| panic!("first claim: {error}"));
        assert_eq!(claimed.len(), 1);
        drop(first_port);

        let restarted_port =
            sqlite_worker_port(Arc::clone(&store), clock, "worker-sqlite-restart", 5_000);
        let replayed = restarted_port
            .claim(0)
            .unwrap_or_else(|error| panic!("replayed claim: {error}"));
        assert_eq!(replayed, claimed);
        let restarted = ProductionResponseWorker::new_for_test(restarted_port)
            .unwrap_or_else(|error| panic!("restarted worker: {error}"));
        restarted
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("worker shutdown: {error}"));
        assert!(store.validate_lease(&claimed[0]).is_err());
    }

    #[test]
    fn sqlite_worker_stale_fence_loses_after_expiry_takeover() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("response-fence.sqlite"))
                .unwrap_or_else(|error| panic!("security store: {error}")),
        );
        let now_unix_ms = current_unix_ms();
        install_due_sqlite_plan(&store, "action-sqlite-fence", now_unix_ms.saturating_sub(1));
        let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
        let stale_port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-sqlite-stale",
            150,
        );
        let _stale_worker = ProductionResponseWorker::new_for_test(Arc::clone(&stale_port))
            .unwrap_or_else(|error| panic!("stale worker: {error}"));
        clock.set(current_unix_ms());
        let stale_work = stale_port
            .claim(0)
            .unwrap_or_else(|error| panic!("stale claim: {error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("stale work missing"));

        std::thread::sleep(Duration::from_millis(200));
        let takeover_now = current_unix_ms();
        clock.set(takeover_now);
        let takeover_port = sqlite_worker_port(
            Arc::clone(&store),
            Arc::clone(&clock),
            "worker-sqlite-takeover",
            5_000,
        );
        let takeover_work = takeover_port
            .claim(0)
            .unwrap_or_else(|error| panic!("takeover claim: {error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("takeover work missing"));
        assert!(takeover_work.fencing_token > stale_work.fencing_token);
        assert!(matches!(
            stale_port.scheduler.process(&stale_work, takeover_now),
            Ok(SchedulerWorkOutcome::LeaseLost { .. })
        ));
        let takeover = ProductionResponseWorker::new_for_test(takeover_port)
            .unwrap_or_else(|error| panic!("takeover worker: {error}"));
        takeover
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("takeover shutdown: {error}"));
    }

    #[test]
    fn production_worker_restart_recovers_after_ack_loss_without_duplicate_completion() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Err(ResponseWorkerTickError::AckLost),
            Ok(tick("action-recovered")),
        ]));
        let first = ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("first worker: {error}"));
        assert!(matches!(
            first.tick_once(),
            Err(ResponseWorkerTickError::AckLost)
        ));

        let restarted = ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("restarted worker: {error}"));
        let recovered = restarted
            .tick_once()
            .unwrap_or_else(|error| panic!("recovery tick: {error}"));
        assert_eq!(recovered.completed_action_ids.len(), 1);
        assert_eq!(
            recovered.completed_action_ids[0].as_str(),
            "action-recovered"
        );
    }

    #[test]
    fn production_worker_surfaces_stale_fence_as_lease_loss_not_completion() {
        let stale = ResponseWorkerTick {
            tenant_id: tenant(),
            declassification_receipts_appended: 0,
            declassification_receipts_acknowledged: 0,
            declassification_receipts_pending: 0,
            declassification_receipts_compacted: 0,
            claimed: 1,
            completed_action_ids: Vec::new(),
            retry_action_ids: Vec::new(),
            lease_lost_action_ids: vec![
                ActionId::new("action-stale").unwrap_or_else(|error| panic!("action id: {error}"))
            ],
        };
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(stale)]));
        let worker = ProductionResponseWorker::new_for_test(port)
            .unwrap_or_else(|error| panic!("worker: {error}"));
        let report = worker
            .tick_once()
            .unwrap_or_else(|error| panic!("stale tick: {error}"));
        assert!(report.completed_action_ids.is_empty());
        assert_eq!(report.lease_lost_action_ids.len(), 1);
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
    }

    #[test]
    fn worker_progress_deadline_has_an_absolute_validated_boundary() {
        let rapid = ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(1),
        };
        assert_eq!(rapid.progress_deadline(), MIN_WORKER_PROGRESS_DEADLINE);

        let boundary = ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_secs(30),
        };
        let validated = boundary
            .validate()
            .unwrap_or_else(|error| panic!("valid progress boundary rejected: {error}"));
        assert_eq!(validated, boundary);
        assert_eq!(boundary.progress_deadline(), MAX_WORKER_PROGRESS_DEADLINE);

        let above_boundary = ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_secs(30) + Duration::from_nanos(1),
        };
        assert!(matches!(
            above_boundary.validate(),
            Err(ResponseWorkerTickError::InvalidConfig)
        ));
    }

    #[test]
    fn pending_declassification_receipts_keep_worker_health_degraded() {
        let mut pending = tick("action-with-pending-evidence");
        pending.declassification_receipts_pending = 3;
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(pending)]));
        let worker = ProductionResponseWorker::new_for_test(port)
            .unwrap_or_else(|error| panic!("worker: {error}"));

        worker
            .tick_once()
            .unwrap_or_else(|error| panic!("pending evidence tick: {error}"));

        let health = worker.health();
        assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Degraded);
        assert_eq!(
            health.last_error.as_deref(),
            Some("3 declassification receipts remain pending")
        );
    }

    #[test]
    fn post_loop_cleanup_releases_owned_work_and_is_idempotent() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
        let worker = ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}"));
        worker
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("first shutdown: {error}"));
        worker
            .complete_shutdown_after_loop()
            .unwrap_or_else(|error| panic!("second shutdown: {error}"));
        assert_eq!(port.shutdown_calls(), 1);
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    }

    #[test]
    fn reaper_spawn_failure_retains_join_ownership_for_later_recovery() {
        let registry = Arc::new(ResponseWorkerReaperRegistry::new());
        registry.fail_next_spawn.store(true, Ordering::Release);
        let permit = registry
            .acquire_without_service_for_test()
            .unwrap_or_else(|error| panic!("join permit: {error}"));
        let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let worker_for_thread = Arc::clone(&worker);
        let join = std::thread::spawn(move || worker_for_thread.complete_shutdown_after_loop());

        registry.enqueue(ResponseWorkerJoinJob {
            join,
            worker: Arc::clone(&worker),
            _permit: permit,
        });

        {
            let state = registry.lock_state();
            assert_eq!(state.jobs.len(), 1);
            assert_eq!(state.join_owners, 1);
            assert!(state.reaper.is_none());
        }
        let ResponseWorkerJoinJob {
            join,
            worker,
            _permit,
        } = registry
            .take_retained_job_for_test()
            .unwrap_or_else(|| panic!("retained join ownership was lost"));
        join_response_worker_thread(join, &worker)
            .unwrap_or_else(|error| panic!("retained join: {error}"));
        drop(_permit);
        assert_eq!(registry.lock_state().join_owners, 0);
        assert!(worker.thread_joined.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls(), 1);
    }

    #[test]
    fn join_registry_reservations_bound_retained_worker_growth() {
        let registry = Arc::new(ResponseWorkerReaperRegistry::new());
        let mut permits = Vec::new();
        for _ in 0..MAX_RESPONSE_WORKER_JOIN_OWNERS {
            permits.push(
                registry
                    .acquire_without_service_for_test()
                    .unwrap_or_else(|error| panic!("join permit: {error}")),
            );
        }
        assert!(matches!(
            registry.acquire_without_service_for_test(),
            Err(ResponseWorkerTickError::WorkerReaperCapacity)
        ));
        drop(permits);
        assert_eq!(registry.lock_state().join_owners, 0);
    }

    #[tokio::test]
    async fn production_worker_allows_only_one_background_loop() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(tick(
            "initial-publication-readiness",
        ))]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let config = ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_secs(30),
        };
        let mut handle = worker
            .start_parked(config)
            .await
            .unwrap_or_else(|error| panic!("first start: {error}"));

        assert!(matches!(
            worker.start_parked(config).await,
            Err(ResponseWorkerTickError::WorkerAlreadyRunning)
        ));

        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("release publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));

        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
        assert_eq!(port.shutdown_calls(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn worker_owned_thread_survives_caller_starvation_and_joins_before_restart() {
        let ticks = (0..64)
            .map(|_| Ok(tick("worker-owned-thread-progress")))
            .collect();
        let port = Arc::new(ScriptedWorkerPort::with_ticks(ticks));

        for generation in 0..2 {
            let worker = Arc::new(
                ProductionResponseWorker::new_for_test(Arc::clone(&port))
                    .unwrap_or_else(|error| panic!("worker {generation}: {error}")),
            );
            let mut handle = worker
                .start_parked(ProductionResponseWorkerLoopConfig {
                    tick_interval: Duration::from_millis(10),
                })
                .await
                .unwrap_or_else(|error| panic!("start worker {generation}: {error}"));
            handle
                .arm()
                .await
                .unwrap_or_else(|error| panic!("arm worker {generation}: {error}"));
            handle
                .release_publication()
                .unwrap_or_else(|error| panic!("publish worker {generation}: {error}"));
            handle
                .wait_for_publication_readiness()
                .await
                .unwrap_or_else(|error| {
                    panic!("publication readiness for worker {generation}: {error}")
                });
            let completed_before_starvation = worker.health().ticks_completed;

            std::thread::sleep(Duration::from_millis(100));

            let completed_after_starvation = worker.health().ticks_completed;
            assert!(completed_after_starvation > completed_before_starvation);
            worker
                .ensure_ready()
                .unwrap_or_else(|error| panic!("worker {generation} stalled: {error}"));
            handle
                .shutdown()
                .await
                .unwrap_or_else(|error| panic!("shutdown worker {generation}: {error}"));
            assert!(!worker.task_live.load(Ordering::Acquire));
            assert!(worker.shutdown_is_complete());
            assert!(handle.join.is_none());
        }

        assert_eq!(port.shutdown_calls(), 2);
    }

    #[test]
    fn progress_deadline_begins_when_the_worker_reaches_publication_readiness() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(Vec::new()));
        let worker = ProductionResponseWorker::new_for_test(port)
            .unwrap_or_else(|error| panic!("worker: {error}"));
        worker.configure_progress(Duration::from_millis(1));
        worker.task_live.store(true, Ordering::Release);
        worker
            .mark_publication_released()
            .unwrap_or_else(|error| panic!("release publication: {error}"));

        std::thread::sleep(Duration::from_millis(20));
        worker
            .ensure_ready()
            .unwrap_or_else(|error| panic!("unobserved publication stalled: {error}"));

        worker
            .mark_publication_ready()
            .unwrap_or_else(|error| panic!("mark publication ready: {error}"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(matches!(
            worker.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerProgressStalled { .. })
        ));
    }

    #[tokio::test]
    async fn crashed_worker_thread_revokes_liveness_before_the_progress_deadline() {
        let crash = ResponseWorkerTickError::WorkerCrash(
            ErrorCode::new("response.worker-thread-crash")
                .unwrap_or_else(|error| panic!("worker crash code: {error}")),
        );
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Ok(tick("initial-publication-readiness")),
            Err(crash),
        ]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("release publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while worker.health().lifecycle != ResponseWorkerLifecycle::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("worker thread did not report its crash"));

        assert!(!handle.is_running());
        assert!(matches!(
            worker.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerStopped)
        ));
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Failed);

        assert!(handle.shutdown().await.is_err());
        assert_eq!(port.shutdown_calls(), 1);
    }

    #[tokio::test]
    async fn parked_worker_commit_failure_stops_with_zero_ticks() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Ok(tick(
            "action-must-not-run",
        ))]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let services: Arc<dyn ActiveDefenseServices> = Arc::new(WorkerBackedServices {
            worker: Arc::clone(&worker),
        });
        let registry = ActiveDefenseServiceRegistry::default();
        registry
            .reserve_exact(Arc::clone(&services))
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        tokio::task::yield_now().await;
        assert_eq!(port.tick_calls(), 0);
        assert!(registry.snapshot().is_none());

        port.set_ready(false);
        let release_called = AtomicBool::new(false);
        assert!(registry
            .commit_reserved_exact_with_release(&services, || {
                release_called.store(true, Ordering::Release);
                handle.release_publication()
            })
            .is_err());
        assert!(!release_called.load(Ordering::Acquire));
        assert!(registry.snapshot().is_none());
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("parked shutdown: {error}"));
        assert_eq!(port.tick_calls(), 0);
        assert_eq!(port.shutdown_calls(), 1);
        registry
            .cancel_reserved_exact(&services)
            .unwrap_or_else(|error| panic!("cancel reserve: {error}"));
    }

    #[tokio::test]
    async fn publication_remains_unready_until_the_first_tick_completes() {
        let port = Arc::new(BlockingWorkerPort::blocking_initial_tick());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let services: Arc<dyn ActiveDefenseServices> = Arc::new(WorkerBackedServices {
            worker: Arc::clone(&worker),
        });
        let registry = ActiveDefenseServiceRegistry::default();
        registry
            .reserve_exact(Arc::clone(&services))
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_secs(30),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        assert!(registry.snapshot().is_none());
        assert!(!port.tick_started.load(Ordering::Acquire));

        registry
            .commit_reserved_exact_with_release(&services, || handle.release_publication())
            .unwrap_or_else(|error| panic!("publish: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("initial publication tick did not start"));

        assert!(registry.snapshot().is_some());
        assert!(!handle.is_running());
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Running);
        assert!(matches!(
            services.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerPublicationPending)
        ));
        port.release();
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        assert!(handle.is_running());
        let health = worker.health();
        assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
        assert!(health.ticks_completed >= 1);
        services
            .ensure_ready()
            .unwrap_or_else(|error| panic!("published services are not ready: {error}"));
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
        registry
            .unpublish_exact(&services)
            .unwrap_or_else(|error| panic!("unpublish: {error}"));
    }

    #[tokio::test]
    async fn cancelled_publication_wait_transfers_join_ownership_without_blocking_drop() {
        let port = Arc::new(BlockingWorkerPort::blocking_initial_tick());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_secs(30),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("initial publication tick did not start"));

        let startup = async move {
            handle.wait_for_publication_readiness().await?;
            Ok::<ProductionResponseWorkerHandle, ResponseWorkerTickError>(handle)
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), startup)
                .await
                .is_err()
        );
        assert!(worker.shutdown_requested.load(Ordering::Acquire));
        assert!(!worker.thread_joined.load(Ordering::Acquire));

        port.release();
        tokio::time::timeout(
            Duration::from_secs(1),
            worker.wait_for_shutdown_completion(),
        )
        .await
        .unwrap_or_else(|_| panic!("cancelled startup worker did not stop"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !worker.thread_joined.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("cancelled startup worker thread was not joined"));
        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn initial_tick_retries_non_crash_failures_on_the_configured_cadence() {
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Err(ResponseWorkerTickError::Port(PortError::unavailable())),
            Err(ResponseWorkerTickError::Port(PortError::unavailable())),
            Ok(tick("initial-retry-success")),
        ]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));

        let health = worker.health();
        assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Ready);
        assert_eq!(health.ticks_attempted, 3);
        assert_eq!(health.ticks_completed, 1);
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
    }

    #[tokio::test]
    async fn initial_tick_deadline_exhaustion_fails_publication_and_joins_the_thread() {
        let failures = (0..8)
            .map(|_| Err(ResponseWorkerTickError::Port(PortError::unavailable())))
            .collect();
        let port = Arc::new(ScriptedWorkerPort::with_ticks(failures));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));

        assert!(matches!(
            handle.wait_for_publication_readiness().await,
            Err(ResponseWorkerTickError::WorkerInitialTick(_))
        ));
        assert!(handle.shutdown().await.is_err());
        assert!(!worker.task_live.load(Ordering::Acquire));
        assert!(handle.join.is_none());
    }

    #[tokio::test]
    async fn immediate_post_release_crash_keeps_the_degraded_services_published() {
        let failure = ResponseWorkerTickError::WorkerCrash(
            ErrorCode::new("response.post_release_crash")
                .unwrap_or_else(|error| panic!("error code: {error}")),
        );
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![Err(failure)]));
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(port)
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let services: Arc<dyn ActiveDefenseServices> = Arc::new(WorkerBackedServices {
            worker: Arc::clone(&worker),
        });
        let registry = ActiveDefenseServiceRegistry::default();
        registry
            .reserve_exact(Arc::clone(&services))
            .unwrap_or_else(|error| panic!("reserve: {error}"));
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));

        registry
            .commit_reserved_exact_with_release(&services, || handle.release_publication())
            .unwrap_or_else(|error| panic!("publish: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while worker.health().lifecycle != ResponseWorkerLifecycle::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("post-release worker crash was not observed"));

        assert!(registry.snapshot().is_some());
        assert!(services.ensure_ready().is_err());
        assert!(handle.shutdown().await.is_err());
        registry
            .unpublish_exact(&services)
            .unwrap_or_else(|error| panic!("unpublish failed services: {error}"));
    }

    #[tokio::test]
    async fn wedged_tick_fails_readiness_and_awaited_shutdown_never_drains_concurrently() {
        let port = Arc::new(BlockingWorkerPort::new());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        worker.configure_progress(Duration::from_millis(30));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("tick did not start"));
        tokio::time::sleep(Duration::from_millis(40)).await;

        assert!(matches!(
            worker.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerProgressStalled { .. })
        ));
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
        assert!(worker.health().tick_in_flight);

        port.release();
        handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    }

    #[tokio::test]
    async fn cancelled_shutdown_retains_join_until_the_blocked_tick_exits() {
        let port = Arc::new(BlockingWorkerPort::new());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("tick did not start"));

        assert!(
            tokio::time::timeout(Duration::from_millis(20), handle.shutdown())
                .await
                .is_err()
        );
        assert!(worker.shutdown_requested.load(Ordering::Acquire));
        assert!(handle.join.is_some());
        assert!(port.tick_in_flight.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
        assert!(!worker.shutdown_is_complete());

        let mut resumed_shutdown = Box::pin(handle.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut resumed_shutdown)
                .await
                .is_err()
        );
        assert!(port.tick_in_flight.load(Ordering::Acquire));
        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
        assert!(!worker.shutdown_is_complete());
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            worker.wait_for_shutdown_completion(),
        )
        .await
        .is_err());

        port.release();
        resumed_shutdown
            .as_mut()
            .await
            .unwrap_or_else(|error| panic!("resumed shutdown: {error}"));
        drop(resumed_shutdown);

        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 1);
        assert!(worker.shutdown_is_complete());
        tokio::time::timeout(
            Duration::from_secs(1),
            worker.wait_for_shutdown_completion(),
        )
        .await
        .unwrap_or_else(|_| panic!("worker did not publish clean shutdown completion"));
        assert!(handle.clean_shutdown);
        assert!(handle.join.is_none());
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    }

    #[tokio::test]
    async fn dropping_handle_signals_stop_without_concurrent_drain_or_zombie_tick() {
        let port = Arc::new(BlockingWorkerPort::new());
        let worker = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("worker: {error}")),
        );
        let mut handle = worker
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("parked start: {error}"));
        handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm: {error}"));
        handle
            .release_publication()
            .unwrap_or_else(|error| panic!("publication: {error}"));
        handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("publication readiness: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !port.tick_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("tick did not start"));

        drop(handle);
        assert_eq!(port.shutdown_calls.load(Ordering::Acquire), 0);
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);
        port.release();
        tokio::time::timeout(
            Duration::from_secs(1),
            worker.wait_for_shutdown_completion(),
        )
        .await
        .unwrap_or_else(|_| panic!("worker did not stop"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !worker.thread_joined.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("dropped worker thread was not joined"));
        assert!(!port.shutdown_during_tick.load(Ordering::Acquire));
        assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    }

    #[test]
    fn worker_crash_marks_health_failed_and_restart_can_take_over() {
        let failure = ResponseWorkerTickError::WorkerCrash(
            ErrorCode::new("response.worker_crash")
                .unwrap_or_else(|error| panic!("error code: {error}")),
        );
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Err(failure),
            Ok(tick("action-after-crash")),
        ]));
        let crashed = ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}"));
        assert!(crashed.tick_once().is_err());
        assert_eq!(crashed.health().lifecycle, ResponseWorkerLifecycle::Failed);

        let restarted = ProductionResponseWorker::new_for_test(port)
            .unwrap_or_else(|error| panic!("restart: {error}"));
        assert_eq!(
            restarted
                .tick_once()
                .unwrap_or_else(|error| panic!("takeover: {error}"))
                .completed_action_ids
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn terminated_primary_reuses_its_durable_port_without_concurrent_ticks() {
        let failure = ResponseWorkerTickError::WorkerCrash(
            ErrorCode::new("response.primary_crash")
                .unwrap_or_else(|error| panic!("error code: {error}")),
        );
        let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
            Err(failure),
            Ok(tick("teardown-recovery")),
        ]));
        let primary = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("primary worker: {error}")),
        );
        let mut primary_handle = primary
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start primary: {error}"));
        primary_handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm primary: {error}"));
        primary_handle
            .release_publication()
            .unwrap_or_else(|error| panic!("release primary: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while primary.health().lifecycle != ResponseWorkerLifecycle::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("primary did not fail"));
        assert!(primary_handle.shutdown().await.is_err());
        assert!(primary.shutdown_is_complete());

        let recovery = Arc::new(
            ProductionResponseWorker::new_for_test(Arc::clone(&port))
                .unwrap_or_else(|error| panic!("recovery worker: {error}")),
        );
        let mut recovery_handle = recovery
            .start_parked(ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(10),
            })
            .await
            .unwrap_or_else(|error| panic!("start recovery: {error}"));
        recovery_handle
            .arm()
            .await
            .unwrap_or_else(|error| panic!("arm recovery: {error}"));
        recovery_handle
            .release_publication()
            .unwrap_or_else(|error| panic!("release recovery: {error}"));
        recovery_handle
            .wait_for_publication_readiness()
            .await
            .unwrap_or_else(|error| panic!("recovery publication readiness: {error}"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while port.tick_calls() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("recovery worker did not tick"));
        recovery_handle
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown recovery: {error}"));

        assert_eq!(port.maximum_concurrent_ticks(), 1);
    }

    struct TestServices {
        ready: Mutex<bool>,
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

    struct SequencedServices {
        readiness: Mutex<VecDeque<bool>>,
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

    struct BootstrapOnlyServices;

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

    #[test]
    fn service_publication_can_precede_operational_kernel_binding() {
        let registry = ActiveDefenseServiceRegistry::default();
        let services: Arc<dyn ActiveDefenseServices> = Arc::new(BootstrapOnlyServices);
        registry
            .publish(Arc::clone(&services))
            .unwrap_or_else(|error| panic!("publish bootstrap-ready services: {error}"));
        let installed = registry
            .snapshot()
            .unwrap_or_else(|| panic!("bootstrap-ready services are missing"));
        assert!(Arc::ptr_eq(&installed, &services));
        assert!(installed.ensure_ready().is_err());
    }

    #[test]
    fn service_publication_is_atomic_when_replacement_readiness_fails() {
        let registry = ActiveDefenseServiceRegistry::default();
        let first = Arc::new(TestServices {
            ready: Mutex::new(true),
        });
        let first_services: Arc<dyn ActiveDefenseServices> = first.clone();
        registry
            .publish(Arc::clone(&first_services))
            .unwrap_or_else(|error| panic!("publish first: {error}"));
        let replacement = Arc::new(TestServices {
            ready: Mutex::new(false),
        });
        assert!(registry.publish(replacement).is_err());
        let installed = registry
            .snapshot()
            .unwrap_or_else(|| panic!("installed services missing"));
        assert!(Arc::ptr_eq(&installed, &first_services));
    }

    #[test]
    fn service_publication_rechecks_readiness_at_commit_time() {
        let registry = ActiveDefenseServiceRegistry::default();
        let services = Arc::new(SequencedServices {
            readiness: Mutex::new(VecDeque::from([true, true, false])),
        });
        assert!(registry.publish(services).is_err());
        assert!(registry.snapshot().is_none());
    }

    #[test]
    fn service_publication_rejects_duplicate_ownership_without_replacement() {
        let registry = ActiveDefenseServiceRegistry::default();
        let first: Arc<dyn ActiveDefenseServices> = Arc::new(TestServices {
            ready: Mutex::new(true),
        });
        registry
            .publish(Arc::clone(&first))
            .unwrap_or_else(|error| panic!("publish first: {error}"));
        let duplicate: Arc<dyn ActiveDefenseServices> = Arc::new(TestServices {
            ready: Mutex::new(true),
        });

        assert!(matches!(
            registry.publish(duplicate),
            Err(ResponseWorkerTickError::ServicesAlreadyPublished)
        ));
        let installed = registry
            .snapshot()
            .unwrap_or_else(|| panic!("installed services missing"));
        assert!(Arc::ptr_eq(&installed, &first));
    }
}
