use super::*;

pub(super) const MAX_DECLASSIFICATION_OUTBOX_DRAIN_PASSES: u32 = 4_096;

#[derive(Clone)]
pub(in crate::security) struct ProductionDeclassificationReceiptOutbox {
    port: Arc<dyn DeclassificationReceiptOutboxPort>,
    health: Arc<Mutex<DeclassificationOutboxHealth>>,
    compaction_cursor: Arc<Mutex<(Option<TenantId>, Option<GrantId>)>>,
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

    pub(in crate::security) fn reconcile_and_drain_startup(
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

    pub(in crate::security) fn drain_to_zero(
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
    pub(super) fn health(&self) -> DeclassificationOutboxHealth {
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
