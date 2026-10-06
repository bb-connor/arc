use super::{
    Arc, DeclassificationCompactionReport, DeclassificationEvidenceCommitStore,
    DeclassificationOutboxHealth, DeclassificationReceiptDrainReport,
    DeclassificationReceiptOutboxDrainer, DeclassificationReconciliationReport,
    DeclassificationRetriedEvidenceQuery, DeclassificationRevalidationReport, GrantId, Mutex,
    PortError, PortErrorKind, ResponseWorkerTickError, TenantId,
    MAX_DECLASSIFICATION_EVIDENCE_BATCH,
};

pub(super) const MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES: u32 = 4_096;

#[derive(Clone)]
pub(in crate::security) struct ProductionDeclassificationReceiptOutbox {
    port: Arc<dyn DeclassificationReceiptOutboxPort>,
    health: Arc<Mutex<DeclassificationOutboxHealth>>,
    compaction_cursor: Arc<Mutex<(Option<TenantId>, Option<GrantId>)>>,
    /// The first non-transient delivery or integrity failure. The store
    /// schedules the failed receipt for retry, so later drains can find
    /// nothing due; until every receipt is delivered or a full revalidation
    /// passes, those drains and readiness keep failing with this cause.
    fatal_failure: Arc<Mutex<Option<PortError>>>,
}

pub(super) trait DeclassificationReceiptOutboxPort: Send + Sync {
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
    /// Read-only: re-runs the delivery checks for one page of retried evidence.
    fn revalidate_retried_once(
        &self,
        query: &DeclassificationRetriedEvidenceQuery,
    ) -> Result<DeclassificationRevalidationReport, PortError>;
    fn compact_once(
        &self,
        after_tenant_id: Option<TenantId>,
        after_grant_id: Option<GrantId>,
        max_records: u32,
    ) -> Result<DeclassificationCompactionReport, PortError>;
}

pub(super) struct NativeDeclassificationReceiptOutboxPort {
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

    fn revalidate_retried_once(
        &self,
        query: &DeclassificationRetriedEvidenceQuery,
    ) -> Result<DeclassificationRevalidationReport, PortError> {
        self.drainer.revalidate_retried_once(query)
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
    pub(in crate::security) fn new(
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
            fatal_failure: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub(super) fn new_for_test(port: Arc<dyn DeclassificationReceiptOutboxPort>) -> Self {
        Self {
            port,
            health: Arc::new(Mutex::new(DeclassificationOutboxHealth::Pending {
                receipts: 0,
            })),
            compaction_cursor: Arc::new(Mutex::new((None, None))),
            fatal_failure: Arc::new(Mutex::new(None)),
        }
    }

    /// Durably committed receipts awaiting delivery are a health detail, not a
    /// readiness failure. A drain that fails fails its tick, and the worker's
    /// readiness follows that tick; its failure stays visible here until
    /// nothing is pending.
    pub(in crate::security) fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        let pending = self.map_port(self.port.count_pending())?;
        if pending == 0 {
            self.clear_fatal_failure();
            self.set_health(DeclassificationOutboxHealth::Ready);
        } else if let Some(source) = self.fatal_failure() {
            let error = ResponseWorkerTickError::DeclassificationOutbox(source);
            self.record_failure(&error, Some(pending));
            return Err(error);
        } else if !matches!(self.health(), DeclassificationOutboxHealth::Failed { .. }) {
            self.set_health(DeclassificationOutboxHealth::Pending { receipts: pending });
        }
        Ok(())
    }

    pub(in crate::security) fn reconcile_and_drain_startup(
        &self,
    ) -> Result<DeclassificationReceiptDrainReport, ResponseWorkerTickError> {
        self.map_port(self.port.ensure_ready())?;
        // A latched failure clears only after every retried receipt passes its
        // delivery checks again; the readiness audit does not bind each
        // receipt to its exact sink record.
        self.revalidate_retried_evidence()?;
        self.clear_fatal_failure();
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

    /// Pages through every retried receipt with the drain's per-batch and
    /// pass bounds. Reaching the pass bound on a full page fails closed rather
    /// than skipping the remainder.
    fn revalidate_retried_evidence(&self) -> Result<(), ResponseWorkerTickError> {
        let mut query = DeclassificationRetriedEvidenceQuery {
            after_tenant_id: None,
            after_grant_id: None,
            after_phase: None,
            max_records: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
        };
        let mut revalidated = 0_u64;
        for _ in 0..MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES {
            let report = self.map_port(self.port.revalidate_retried_once(&query))?;
            let cursor_set = report.last_tenant_id.is_some()
                && report.last_grant_id.is_some()
                && report.last_phase.is_some();
            let cursor_clear = report.last_tenant_id.is_none()
                && report.last_grant_id.is_none()
                && report.last_phase.is_none();
            let invalid_report = report.revalidated > MAX_DECLASSIFICATION_EVIDENCE_BATCH
                || (report.revalidated == 0 && !cursor_clear)
                || (report.revalidated > 0 && !cursor_set);
            if invalid_report {
                return self.map_port(Err(PortError::integrity_failure()));
            }
            revalidated = revalidated
                .checked_add(u64::from(report.revalidated))
                .ok_or(ResponseWorkerTickError::InvalidConfig)?;
            if report.revalidated < MAX_DECLASSIFICATION_EVIDENCE_BATCH {
                return Ok(());
            }
            query = DeclassificationRetriedEvidenceQuery {
                after_tenant_id: report.last_tenant_id,
                after_grant_id: report.last_grant_id,
                after_phase: report.last_phase,
                max_records: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
            };
        }
        let error = ResponseWorkerTickError::DeclassificationRevalidationLimit(revalidated);
        self.record_failure(&error, self.pending_count());
        Err(error)
    }

    pub(in crate::security) fn drain_to_zero(
        &self,
    ) -> Result<DeclassificationReceiptDrainReport, ResponseWorkerTickError> {
        let mut remaining = self.map_port(self.port.count_pending())?;
        if remaining == 0 {
            self.clear_fatal_failure();
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
            remaining_due: remaining,
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
            aggregate.remaining_due = report.remaining_due;
            if report.remaining == 0 {
                self.clear_fatal_failure();
                self.set_health(DeclassificationOutboxHealth::Ready);
                return Ok(aggregate);
            }
            self.fail_if_fatal(report.remaining)?;
            if report.remaining_due == 0 {
                // Every remaining receipt is in retry backoff: durable pending
                // work, not a failure to make progress.
                self.set_health(DeclassificationOutboxHealth::Pending {
                    receipts: report.remaining,
                });
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
            self.clear_fatal_failure();
            self.set_health(DeclassificationOutboxHealth::Ready);
            return Ok(report);
        }
        self.fail_if_fatal(report.remaining)?;
        if report.acknowledged == 0 && report.remaining_due > 0 {
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
    pub(in crate::security) fn health(&self) -> DeclassificationOutboxHealth {
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
            if source.kind() != PortErrorKind::Unavailable {
                self.latch_fatal_failure(&source);
            }
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

    fn fatal_failure(&self) -> Option<PortError> {
        self.fatal_failure.lock().map_or_else(
            |_| Some(PortError::unavailable()),
            |latched| latched.clone(),
        )
    }

    fn latch_fatal_failure(&self, source: &PortError) {
        if let Ok(mut latched) = self.fatal_failure.lock() {
            latched.get_or_insert_with(|| source.clone());
        }
    }

    fn clear_fatal_failure(&self) {
        if let Ok(mut latched) = self.fatal_failure.lock() {
            *latched = None;
        }
    }

    /// Receipts remain after a latched fatal failure, so the drain fails with
    /// the original cause even when nothing was due.
    fn fail_if_fatal(&self, remaining: u64) -> Result<(), ResponseWorkerTickError> {
        match self.fatal_failure() {
            Some(source) => {
                let error = ResponseWorkerTickError::DeclassificationOutbox(source);
                self.record_failure(&error, Some(remaining));
                Err(error)
            }
            None => Ok(()),
        }
    }

    fn record_failure(&self, error: &ResponseWorkerTickError, pending_receipts: Option<u64>) {
        self.set_health(DeclassificationOutboxHealth::Failed {
            pending_receipts,
            error: error.to_string(),
        });
    }
}
