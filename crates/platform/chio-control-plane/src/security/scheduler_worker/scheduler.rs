use super::{
    canonical_json_bytes, sha256, ActionId, Arc, BTreeMap, Clock, DeclassificationOutboxHealth,
    EffectPort, LeaseOwnerId, Mutex, OsRng, PortError, PortErrorKind,
    ProductionDeclassificationReceiptOutbox, RecordId, ResponseDispatchStore, ResponseExecutor,
    ResponseScheduler, ResponseSchedulerStore, ResponseWorkerPort, ResponseWorkerTick,
    ResponseWorkerTickError, RngCore, ScheduledResponseExecutor, ScheduledWork, SchedulerError,
    SchedulerHealthPort, SchedulerPolicy, SchedulerTickRequest, SchedulerWorkOutcome,
    SecurityAlertPort, SecurityReceiptSink, Serialize, SqliteSecurityStateStore, TenantId,
    WORKER_CLAIM_DOMAIN,
};

#[derive(Clone, Debug)]
pub struct ProductionResponseSchedulerConfig {
    pub tenant_id: TenantId,
    /// Stable scheduler identity. Each process gets a separate random claim
    /// incarnation and can take over this owner's prior work only after expiry.
    pub lease_owner_id: LeaseOwnerId,
    pub scheduler_policy: SchedulerPolicy,
    pub renewal_margin_ms: u64,
}

impl ProductionResponseSchedulerConfig {
    fn validate(&self) -> Result<(), ResponseWorkerTickError> {
        self.scheduler_policy.validate()?;
        if self.renewal_margin_ms == 0
            || self.renewal_margin_ms >= self.scheduler_policy.lease_duration_ms
        {
            return Err(ResponseWorkerTickError::InvalidConfig);
        }
        Ok(())
    }
}

pub(super) type DynResponseScheduler = ResponseScheduler<
    dyn ResponseSchedulerStore,
    dyn ScheduledResponseExecutor,
    dyn SchedulerHealthPort,
>;

#[derive(Clone)]
pub(super) struct OwnedLease {
    work: ScheduledWork,
    safe_to_release: bool,
}

pub struct SqliteResponseWorkerPort {
    store: Arc<SqliteSecurityStateStore>,
    declassification_outbox: Option<ProductionDeclassificationReceiptOutbox>,
    effects: Arc<dyn EffectPort>,
    receipts: Arc<dyn SecurityReceiptSink>,
    alerts: Arc<dyn SecurityAlertPort>,
    health_port: Arc<dyn SchedulerHealthPort>,
    scheduler: Arc<DynResponseScheduler>,
    clock: Arc<dyn Clock>,
    config: ProductionResponseSchedulerConfig,
    claim_incarnation_id: RecordId,
    operation_lock: Mutex<()>,
    owned_leases: Mutex<BTreeMap<String, OwnedLease>>,
}

impl SqliteResponseWorkerPort {
    pub fn new(
        store: Arc<SqliteSecurityStateStore>,
        effects: Arc<dyn EffectPort>,
        receipts: Arc<dyn SecurityReceiptSink>,
        alerts: Arc<dyn SecurityAlertPort>,
        health_port: Arc<dyn SchedulerHealthPort>,
        clock: Arc<dyn Clock>,
        config: ProductionResponseSchedulerConfig,
    ) -> Result<Self, ResponseWorkerTickError> {
        Self::new_internal(
            store,
            None,
            effects,
            receipts,
            alerts,
            health_port,
            clock,
            config,
            None,
        )
    }

    pub(in crate::security) fn new_with_declassification_outbox(
        store: Arc<SqliteSecurityStateStore>,
        declassification_outbox: ProductionDeclassificationReceiptOutbox,
        effects: Arc<dyn EffectPort>,
        receipts: Arc<dyn SecurityReceiptSink>,
        alerts: Arc<dyn SecurityAlertPort>,
        health_port: Arc<dyn SchedulerHealthPort>,
        clock: Arc<dyn Clock>,
        config: ProductionResponseSchedulerConfig,
    ) -> Result<Self, ResponseWorkerTickError> {
        Self::new_internal(
            store,
            Some(declassification_outbox),
            effects,
            receipts,
            alerts,
            health_port,
            clock,
            config,
            None,
        )
    }

    #[cfg(test)]
    pub(super) fn new_with_claim_incarnation_for_test(
        store: Arc<SqliteSecurityStateStore>,
        effects: Arc<dyn EffectPort>,
        receipts: Arc<dyn SecurityReceiptSink>,
        alerts: Arc<dyn SecurityAlertPort>,
        health_port: Arc<dyn SchedulerHealthPort>,
        clock: Arc<dyn Clock>,
        config: ProductionResponseSchedulerConfig,
        claim_incarnation_id: RecordId,
    ) -> Result<Self, ResponseWorkerTickError> {
        Self::new_internal(
            store,
            None,
            effects,
            receipts,
            alerts,
            health_port,
            clock,
            config,
            Some(claim_incarnation_id),
        )
    }

    fn new_internal(
        store: Arc<SqliteSecurityStateStore>,
        declassification_outbox: Option<ProductionDeclassificationReceiptOutbox>,
        effects: Arc<dyn EffectPort>,
        receipts: Arc<dyn SecurityReceiptSink>,
        alerts: Arc<dyn SecurityAlertPort>,
        health_port: Arc<dyn SchedulerHealthPort>,
        clock: Arc<dyn Clock>,
        config: ProductionResponseSchedulerConfig,
        claim_incarnation_id: Option<RecordId>,
    ) -> Result<Self, ResponseWorkerTickError> {
        config.validate()?;
        let claim_incarnation_id = match claim_incarnation_id {
            Some(claim_incarnation_id) => claim_incarnation_id,
            None => response_worker_claim_incarnation_id()?,
        };
        let scheduler_store: Arc<dyn ResponseSchedulerStore> = store.clone();
        let executor: Arc<dyn ScheduledResponseExecutor> = Arc::new(ResponseExecutor::new(
            Arc::clone(&scheduler_store),
            Arc::clone(&effects),
            Arc::clone(&receipts),
            Arc::clone(&alerts),
        ));
        let scheduler = Arc::new(ResponseScheduler::new(
            scheduler_store,
            executor,
            Arc::clone(&health_port),
            config.scheduler_policy,
        )?);
        let worker = Self {
            store,
            declassification_outbox,
            effects,
            receipts,
            alerts,
            health_port,
            scheduler,
            clock,
            config,
            claim_incarnation_id,
            operation_lock: Mutex::new(()),
            owned_leases: Mutex::new(BTreeMap::new()),
        };
        worker.ensure_ready()?;
        Ok(worker)
    }

    pub(super) fn claim(
        &self,
        tick_sequence: u64,
    ) -> Result<Vec<ScheduledWork>, ResponseWorkerTickError> {
        if self.cleanup_expired_terminal_leases()? {
            return Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending);
        }
        let now_unix_ms = self
            .clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)
            .map_err(PortError::from)?;
        let claim_id = worker_claim_id(
            &self.config.tenant_id,
            &self.config.lease_owner_id,
            &self.claim_incarnation_id,
            tick_sequence,
            now_unix_ms,
        )?;
        let claimed = self.scheduler.claim(&SchedulerTickRequest {
            tenant_id: self.config.tenant_id.clone(),
            claim_id,
            lease_owner_id: self.config.lease_owner_id.clone(),
            now_unix_ms,
        })?;
        let mut owned = self
            .owned_leases
            .lock()
            .map_err(|_| PortError::unavailable())?;
        for work in &claimed {
            if let Some(previous) = owned.get(work.action_id.as_str()) {
                if previous.work.tenant_id != work.tenant_id
                    || previous.work.action_id != work.action_id
                    || previous.work.fencing_token >= work.fencing_token
                {
                    return Err(ResponseWorkerTickError::Port(PortError::integrity_failure()));
                }
            }
        }
        for work in &claimed {
            owned.insert(
                work.action_id.as_str().to_owned(),
                OwnedLease {
                    work: work.clone(),
                    safe_to_release: true,
                },
            );
        }
        Ok(claimed)
    }

    fn cleanup_expired_terminal_leases(&self) -> Result<bool, ResponseWorkerTickError> {
        let (_, terminal_remaining) = self.store.cleanup_expired_terminal_scheduler_leases(
            &self.config.tenant_id,
            self.config.scheduler_policy.max_claims,
        )?;
        Ok(terminal_remaining)
    }

    fn prepare_work(&self, work: &ScheduledWork) -> Result<ScheduledWork, ResponseWorkerTickError> {
        let now_unix_ms = self
            .clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)
            .map_err(PortError::from)?;
        let mut current = work.clone();
        if current.lease_expires_at_unix_ms.saturating_sub(now_unix_ms)
            <= self.config.renewal_margin_ms
        {
            current = self.scheduler.renew(&current, now_unix_ms)?;
        }
        let mut owned = self
            .owned_leases
            .lock()
            .map_err(|_| PortError::unavailable())?;
        let entry = owned
            .get_mut(current.action_id.as_str())
            .ok_or_else(PortError::integrity_failure)?;
        entry.work = current.clone();
        entry.safe_to_release = false;
        Ok(current)
    }

    fn forget_owned(&self, action_id: &ActionId) -> Result<(), ResponseWorkerTickError> {
        self.owned_leases
            .lock()
            .map_err(|_| PortError::unavailable())?
            .remove(action_id.as_str());
        Ok(())
    }

    fn forget_invalid_owned(&self, action_id: &ActionId) -> Result<(), ResponseWorkerTickError> {
        let work = self
            .owned_leases
            .lock()
            .map_err(|_| PortError::unavailable())?
            .get(action_id.as_str())
            .map(|lease| lease.work.clone());
        if let Some(work) = work {
            if matches!(
                self.store.validate_lease(&work),
                Err(error) if error.kind() == PortErrorKind::Conflict
            ) {
                self.forget_owned(action_id)?;
            }
        }
        Ok(())
    }

    fn release_safe_owned(&self) -> Result<(), ResponseWorkerTickError> {
        let safe = {
            let owned = self
                .owned_leases
                .lock()
                .map_err(|_| PortError::unavailable())?;
            owned
                .values()
                .filter(|lease| lease.safe_to_release)
                .map(|lease| lease.work.clone())
                .collect::<Vec<_>>()
        };
        for work in safe {
            match self.scheduler.release_for_shutdown(&work) {
                Ok(()) => self.forget_owned(&work.action_id)?,
                Err(SchedulerError::Store(error)) if error.kind() == PortErrorKind::Conflict => {
                    self.forget_owned(&work.action_id)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn operation_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        match self.operation_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl ResponseWorkerPort for SqliteResponseWorkerPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.store.ensure_dispatch_ready()?;
        self.effects.ensure_effects_ready()?;
        self.receipts.ensure_receipts_ready()?;
        self.alerts.ensure_alerts_ready()?;
        self.health_port.ensure_scheduler_health_ready()?;
        if let Some(outbox) = &self.declassification_outbox {
            outbox.ensure_ready()?;
        }
        Ok(())
    }

    fn tick(
        &self,
        tick_sequence: u64,
        shutdown_requested: bool,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        let _operation_guard = self.operation_guard();
        if shutdown_requested {
            self.release_safe_owned()?;
            return Err(ResponseWorkerTickError::WorkerStopped);
        }
        let claimed = self.claim(tick_sequence)?;
        let mut report = ResponseWorkerTick {
            tenant_id: self.config.tenant_id.clone(),
            declassification_receipts_appended: 0,
            declassification_receipts_acknowledged: 0,
            declassification_receipts_pending: 0,
            declassification_receipts_compacted: 0,
            claimed: claimed.len(),
            completed_action_ids: Vec::new(),
            retry_action_ids: Vec::new(),
            lease_lost_action_ids: Vec::new(),
        };
        for work in claimed {
            let processed = (|| -> Result<SchedulerWorkOutcome, ResponseWorkerTickError> {
                let current = self.prepare_work(&work)?;
                let now_unix_ms = self
                    .clock
                    .unix_millis()
                    .map(chio_security_types::clock::UnixMillis::get)
                    .map_err(PortError::from)?;
                Ok(self.scheduler.process(&current, now_unix_ms)?)
            })();
            match processed {
                Ok(SchedulerWorkOutcome::Completed { action_id, .. }) => {
                    self.forget_owned(&action_id)?;
                    report.completed_action_ids.push(action_id);
                }
                Ok(SchedulerWorkOutcome::RetryScheduled { action_id, .. })
                | Ok(SchedulerWorkOutcome::ProcessingFailed { action_id, .. }) => {
                    self.forget_owned(&action_id)?;
                    report.retry_action_ids.push(action_id);
                }
                Ok(SchedulerWorkOutcome::LeaseLost { action_id }) => {
                    self.forget_owned(&action_id)?;
                    report.lease_lost_action_ids.push(action_id);
                }
                Err(error) => {
                    self.forget_invalid_owned(&work.action_id)?;
                    self.release_safe_owned()?;
                    return Err(error);
                }
            }
        }
        // A broken declassification outbox must close admission, but cannot
        // prevent independent, already-authorized response rollback. Each
        // response still commits its own required receipts through the executor.
        if let Some(outbox) = &self.declassification_outbox {
            let (declassification, compaction) = outbox.maintain_one_batch()?;
            report.declassification_receipts_appended = declassification.appended;
            report.declassification_receipts_acknowledged = declassification.acknowledged;
            report.declassification_receipts_pending = declassification.remaining;
            report.declassification_receipts_compacted = compaction.compacted;
        }
        Ok(report)
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        let _operation_guard = self.operation_guard();
        self.release_safe_owned()?;
        if let Some(outbox) = &self.declassification_outbox {
            outbox.drain_to_zero()?;
        }
        Ok(())
    }

    fn declassification_outbox_status(&self) -> (bool, Option<u64>, Option<String>) {
        self.declassification_outbox
            .as_ref()
            .map_or((false, None, None), |outbox| {
                outbox_health_status(outbox.health())
            })
    }
}

pub(super) fn outbox_health_status(
    health: DeclassificationOutboxHealth,
) -> (bool, Option<u64>, Option<String>) {
    match health {
        DeclassificationOutboxHealth::Ready => (true, Some(0), None),
        DeclassificationOutboxHealth::Pending { receipts } => (true, Some(receipts), None),
        DeclassificationOutboxHealth::Failed {
            pending_receipts,
            error,
        } => (true, pending_receipts, Some(error)),
    }
}

#[derive(Serialize)]
pub(super) struct WorkerClaimCommitment<'a> {
    tenant_id: &'a str,
    lease_owner_id: &'a str,
    claim_incarnation_id: &'a str,
    tick_sequence: u64,
    now_unix_ms: u64,
}

pub(super) fn response_worker_claim_incarnation_id() -> Result<RecordId, ResponseWorkerTickError> {
    let mut incarnation_bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut incarnation_bytes)
        .map_err(|_| PortError::unavailable())?;
    RecordId::new(format!(
        "response-worker-incarnation-{}",
        hex::encode(incarnation_bytes)
    ))
    .map_err(PortError::from)
    .map_err(ResponseWorkerTickError::from)
}

pub(super) fn worker_claim_id(
    tenant_id: &TenantId,
    lease_owner_id: &LeaseOwnerId,
    claim_incarnation_id: &RecordId,
    tick_sequence: u64,
    now_unix_ms: u64,
) -> Result<RecordId, ResponseWorkerTickError> {
    let canonical = canonical_json_bytes(&WorkerClaimCommitment {
        tenant_id: tenant_id.as_str(),
        lease_owner_id: lease_owner_id.as_str(),
        claim_incarnation_id: claim_incarnation_id.as_str(),
        tick_sequence,
        now_unix_ms,
    })
    .map_err(|_| PortError::invalid_data())?;
    let mut preimage = Vec::with_capacity(WORKER_CLAIM_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(WORKER_CLAIM_DOMAIN);
    preimage.extend_from_slice(&canonical);
    RecordId::new(format!(
        "active-defense-worker-claim-{}",
        hex::encode(sha256(&preimage).as_bytes())
    ))
    .map_err(PortError::from)
    .map_err(ResponseWorkerTickError::from)
}

#[cfg(test)]
#[path = "tests/sqlite_worker_operation_gate_recovers_after_panic_for_cleanup.rs"]
mod sqlite_worker_operation_gate_recovers_after_panic_for_cleanup;

#[cfg(test)]
#[path = "tests/sqlite_worker_shutdown_forgets_a_naturally_expired_safe_lease.rs"]
mod sqlite_worker_shutdown_forgets_a_naturally_expired_safe_lease;

#[cfg(test)]
#[path = "tests/sqlite_worker_restart_replays_lost_claim_ack_and_shutdown_releases_lease.rs"]
mod sqlite_worker_restart_replays_lost_claim_ack_and_shutdown_releases_lease;

#[cfg(test)]
#[path = "tests/sqlite_worker_stale_fence_loses_after_expiry_takeover.rs"]
mod sqlite_worker_stale_fence_loses_after_expiry_takeover;
