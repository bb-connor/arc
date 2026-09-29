use super::Arc;
use super::ActiveDefenseReceiptBody;
use super::FlowDenial;
use super::Clock;
use super::SystemClock;
use super::derive_declassification_transition_id;
use super::DeclassificationCompactionQuery;
use super::DeclassificationCompactionRequest;
use super::DeclassificationEvidenceAckRequest;
use super::DeclassificationEvidenceCommitStore;
use super::DeclassificationEvidencePhase;
use super::DeclassificationEvidenceQuery;
use super::DeclassificationEvidenceRecord;
use super::DeclassificationEvidenceRetryRequest;
use super::DeclassificationOutcomeEvidenceCommit;
use super::DeclassificationOutcomeRequest;
use super::DeclassificationTransitionBinding;
use super::DeclassificationUseState;
use super::Digest32;
use super::ExactSecurityReceiptSink;
use super::GrantId;
use super::PortError;
use super::PortErrorKind;
use super::PortResult;
use super::ReceiptAppendRequest;

use super::TenantId;
use super::MAX_DECLASSIFICATION_EVIDENCE_BATCH;

use super::active_defense_receipt_request;
use super::append_exact_receipt;
use super::declassification_outcome_body;

use super::DeclassificationOutcomeBodyInput;


#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeclassificationReceiptDrainReport {
    pub appended: u32,
    pub acknowledged: u32,
    pub deferred: u32,
    pub remaining: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeclassificationReconciliationReport {
    pub reconciled: u32,
    pub remaining: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeclassificationCompactionReport {
    pub compacted: u32,
    pub last_tenant_id: Option<TenantId>,
    pub last_grant_id: Option<GrantId>,
}

#[derive(Clone)]
pub struct DeclassificationReceiptOutboxDrainer {
    store: Arc<dyn DeclassificationEvidenceCommitStore>,
    sink: Arc<dyn ExactSecurityReceiptSink>,
    clock: Arc<dyn Clock>,
}

impl DeclassificationReceiptOutboxDrainer {
    pub fn new(
        store: Arc<dyn DeclassificationEvidenceCommitStore>,
        sink: Arc<dyn ExactSecurityReceiptSink>,
    ) -> PortResult<Self> {
        Self::new_with_clock(store, sink, Arc::new(SystemClock))
    }

    pub fn new_with_clock(
        store: Arc<dyn DeclassificationEvidenceCommitStore>,
        sink: Arc<dyn ExactSecurityReceiptSink>,
        clock: Arc<dyn Clock>,
    ) -> PortResult<Self> {
        let drainer = Self { store, sink, clock };
        drainer.ensure_ready()?;
        Ok(drainer)
    }

    /// Run the full schema and semantic integrity audit before publication.
    pub fn ensure_ready(&self) -> PortResult<()> {
        self.store.ensure_declassification_evidence_ready()?;
        self.sink.ensure_receipts_ready()
    }

    pub fn seal_live_dispatch(&self) -> PortResult<()> {
        self.store.seal_declassification_live_dispatch()
    }

    /// Reconcile crash-stranded consumptions only while startup is quiescent,
    /// before the runtime or its services are published. Calling this during
    /// dispatch can race the legitimate consumed-pending-dispatch interval.
    pub fn reconcile_stranded(
        &self,
        max_records: u32,
    ) -> PortResult<DeclassificationReconciliationReport> {
        self.store.begin_declassification_reconciliation()?;
        let result = self.reconcile_stranded_active(max_records);
        let cleanup = self.store.end_declassification_reconciliation();
        match (result, cleanup) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn reconcile_stranded_active(
        &self,
        max_records: u32,
    ) -> PortResult<DeclassificationReconciliationReport> {
        if max_records == 0 || max_records > MAX_DECLASSIFICATION_EVIDENCE_BATCH {
            return Err(PortError::invalid_data());
        }
        let stranded = self
            .store
            .load_stranded_declassification_consumptions_batch(max_records)?;
        let mut reconciled = 0_u32;
        for consumption in stranded {
            let body = chio_core::canonical::UntrustedJsonText::from_wire(consumption.receipt.canonical_body.as_bytes(), 64 * 1024 * 1024).and_then(|input| input.decode_signed::<ActiveDefenseReceiptBody>()).map_err(|error| PortError::with_source(chio_security_types::ports::PortErrorKind::IntegrityFailure, error.code(), error))?;
            let ActiveDefenseReceiptBody::DeclassificationConsumption(body) = body else {
                return Err(PortError::integrity_failure());
            };
            if body.grant_id != consumption.grant_id
                || body.request_hash != consumption.request_hash
                || body.state != DeclassificationUseState::ConsumedPendingDispatch
            {
                return Err(PortError::integrity_failure());
            }
            let (new_state, transition_binding) = if consumption.acknowledged {
                (
                    DeclassificationUseState::OutcomeUnknown,
                    DeclassificationTransitionBinding::RecoveryOutcomeUnknown {
                        tenant_id: consumption.tenant_id.clone(),
                        grant_id: consumption.grant_id.clone(),
                        request_hash: consumption.request_hash,
                        predecessor_evidence_id: consumption.receipt.evidence_id.clone(),
                        predecessor_transition_id: consumption.receipt.transition_id.clone(),
                    },
                )
            } else {
                (
                    DeclassificationUseState::DispatchFailed,
                    DeclassificationTransitionBinding::RecoveryUndeliveredConsumption {
                        tenant_id: consumption.tenant_id.clone(),
                        grant_id: consumption.grant_id.clone(),
                        request_hash: consumption.request_hash,
                        predecessor_evidence_id: consumption.receipt.evidence_id.clone(),
                        predecessor_transition_id: consumption.receipt.transition_id.clone(),
                    },
                )
            };
            let recovery_time_unix_ms = self
                .clock
                .unix_millis()
                .map(chio_security_types::clock::UnixMillis::get)?;
            if recovery_time_unix_ms < consumption.receipt.occurred_at_unix_ms {
                return Err(PortError::integrity_failure());
            }
            let outcome_body = declassification_outcome_body(
                DeclassificationOutcomeBodyInput {
                    tenant_id: consumption.tenant_id.clone(),
                    prior_receipt_id: consumption.receipt.evidence_id.clone(),
                    policy: body.policy,
                    grant_id: consumption.grant_id.clone(),
                    grant_hash: body.grant_hash,
                    request_hash: consumption.request_hash,
                    occurred_at_unix_ms: recovery_time_unix_ms,
                    to_state: new_state,
                },
                &transition_binding,
            )
            .map_err(|_| PortError::integrity_failure())?;
            let transition_id = derive_declassification_transition_id(&transition_binding)
                .map_err(|_| PortError::integrity_failure())?;
            let receipt = active_defense_receipt_request(&outcome_body)
                .map_err(|_| PortError::integrity_failure())?;
            self.store.commit_declassification_outcome_evidence(
                &DeclassificationOutcomeEvidenceCommit {
                    transition_binding,
                    outcome: DeclassificationOutcomeRequest {
                        tenant_id: consumption.tenant_id,
                        grant_id: consumption.grant_id,
                        request_hash: consumption.request_hash,
                        expected_state: DeclassificationUseState::ConsumedPendingDispatch,
                        new_state,
                        transition_id,
                    },
                    predecessor_evidence_id: consumption.receipt.evidence_id,
                    receipt,
                },
            )?;
            reconciled = reconciled
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
        }
        Ok(DeclassificationReconciliationReport {
            reconciled,
            remaining: self.store.count_stranded_declassification_consumptions()?,
        })
    }

    /// Drain one bounded receipt batch. Startup must call `ensure_ready` first;
    /// retained periodic calls remain bounded and do not repeat the full audit.
    pub fn drain_once(&self, max_receipts: u32) -> PortResult<DeclassificationReceiptDrainReport> {
        if max_receipts == 0 || max_receipts > MAX_DECLASSIFICATION_EVIDENCE_BATCH {
            return Err(PortError::invalid_data());
        }
        let now_unix_ms = self
            .clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)?;
        let pending = self
            .store
            .load_pending_declassification_evidence_batch(now_unix_ms, max_receipts)?;
        let mut appended = 0_u32;
        let mut acknowledged = 0_u32;
        let mut deferred = 0_u32;
        let mut first_integrity_error = None;
        for evidence in pending {
            let attempt = (|| {
                if evidence.phase == DeclassificationEvidencePhase::Outcome {
                    self.verify_outcome_predecessor(&evidence)?;
                }
                let exact = append_exact_receipt(self.sink.as_ref(), &evidence.receipt)?;
                acknowledge_exact_evidence(
                    self.store.as_ref(),
                    &evidence,
                    exact.durable_record_hash,
                    now_unix_ms,
                )?;
                Ok::<(), PortError>(())
            })();
            match attempt {
                Ok(()) => {
                    appended = appended
                        .checked_add(1)
                        .ok_or_else(PortError::integrity_failure)?;
                    acknowledged = acknowledged
                        .checked_add(1)
                        .ok_or_else(PortError::integrity_failure)?;
                }
                Err(error) => {
                    let retry = self.store.record_declassification_evidence_retry(
                        &DeclassificationEvidenceRetryRequest {
                            tenant_id: evidence.tenant_id.clone(),
                            grant_id: evidence.grant_id.clone(),
                            phase: evidence.phase,
                            evidence_id: evidence.receipt.evidence_id.clone(),
                            body_hash: evidence.receipt.body_hash,
                            transition_id: evidence.receipt.transition_id.clone(),
                            failed_at_unix_ms: now_unix_ms,
                            error_code: error.code().clone(),
                        },
                    );
                    deferred = deferred
                        .checked_add(1)
                        .ok_or_else(PortError::integrity_failure)?;
                    if error.kind() != PortErrorKind::Unavailable && first_integrity_error.is_none()
                    {
                        first_integrity_error = Some(error);
                    }
                    if let Err(retry_error) = retry {
                        if first_integrity_error.is_none() {
                            first_integrity_error = Some(retry_error);
                        }
                    }
                }
            }
        }
        if let Some(error) = first_integrity_error {
            return Err(error);
        }
        Ok(DeclassificationReceiptDrainReport {
            appended,
            acknowledged,
            deferred,
            remaining: self.store.count_pending_declassification_evidence()?,
        })
    }

    fn verify_outcome_predecessor(
        &self,
        outcome: &DeclassificationEvidenceRecord,
    ) -> PortResult<()> {
        let predecessor = self
            .store
            .load_declassification_evidence(&DeclassificationEvidenceQuery {
                tenant_id: outcome.tenant_id.clone(),
                grant_id: outcome.grant_id.clone(),
                phase: DeclassificationEvidencePhase::Consumption,
            })?
            .ok_or_else(PortError::integrity_failure)?;
        if outcome.predecessor_evidence_id.as_ref() != Some(&predecessor.receipt.evidence_id)
            || !predecessor.acknowledged
        {
            return Err(PortError::integrity_failure());
        }
        let exact = append_exact_receipt(self.sink.as_ref(), &predecessor.receipt)?;
        if predecessor.durable_sink_record_hash != Some(exact.durable_record_hash) {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    pub fn compact_once(
        &self,
        after_tenant_id: Option<TenantId>,
        after_grant_id: Option<GrantId>,
        max_records: u32,
    ) -> PortResult<DeclassificationCompactionReport> {
        let readiness_cursor = self.store.declassification_evidence_readiness_cursor()?;
        let compacted_at_unix_ms = self
            .clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)?;
        let candidates = self.store.load_declassification_compaction_candidates(
            &DeclassificationCompactionQuery {
                readiness_cursor: readiness_cursor.clone(),
                now_unix_ms: compacted_at_unix_ms,
                after_tenant_id,
                after_grant_id,
                max_records,
            },
        )?;
        let mut report = DeclassificationCompactionReport::default();
        for candidate in candidates {
            if candidate.use_record.state == DeclassificationUseState::OutcomeUnknown {
                return Err(PortError::integrity_failure());
            }
            let consumption_exact = self
                .sink
                .load_exact(&candidate.consumption.receipt.evidence_id)?
                .ok_or_else(PortError::integrity_failure)?;
            let outcome_exact = self
                .sink
                .load_exact(&candidate.outcome.receipt.evidence_id)?
                .ok_or_else(PortError::integrity_failure)?;
            if consumption_exact.receipt != candidate.consumption.receipt
                || outcome_exact.receipt != candidate.outcome.receipt
                || candidate.consumption.durable_sink_record_hash
                    != Some(consumption_exact.durable_record_hash)
                || candidate.outcome.durable_sink_record_hash
                    != Some(outcome_exact.durable_record_hash)
            {
                return Err(PortError::integrity_failure());
            }
            let consumption_body = chio_core::canonical::UntrustedJsonText::from_wire(candidate.consumption.receipt.canonical_body.as_bytes(), 64 * 1024 * 1024).and_then(|input| input.decode_signed::<ActiveDefenseReceiptBody>()).map_err(|error| PortError::with_source(chio_security_types::ports::PortErrorKind::IntegrityFailure, error.code(), error))?;
            let ActiveDefenseReceiptBody::DeclassificationConsumption(consumption_body) =
                consumption_body
            else {
                return Err(PortError::integrity_failure());
            };
            self.store
                .compact_declassification_evidence(&DeclassificationCompactionRequest {
                    readiness_cursor: readiness_cursor.clone(),
                    tenant_id: candidate.use_record.tenant_id.clone(),
                    grant_id: candidate.use_record.grant_id.clone(),
                    request_hash: candidate.use_record.request_hash,
                    terminal_state: candidate.use_record.state,
                    consumption_evidence_id: candidate.consumption.receipt.evidence_id.clone(),
                    consumption_body_hash: candidate.consumption.receipt.body_hash,
                    consumption_transition_id: candidate.consumption.receipt.transition_id.clone(),
                    consumption_occurred_at_unix_ms: candidate
                        .consumption
                        .receipt
                        .occurred_at_unix_ms,
                    consumption_sink_record_hash: consumption_exact.durable_record_hash,
                    outcome_evidence_id: candidate.outcome.receipt.evidence_id.clone(),
                    outcome_body_hash: candidate.outcome.receipt.body_hash,
                    outcome_transition_id: candidate.outcome.receipt.transition_id.clone(),
                    outcome_occurred_at_unix_ms: candidate.outcome.receipt.occurred_at_unix_ms,
                    outcome_sink_record_hash: outcome_exact.durable_record_hash,
                    policy_hash: consumption_body.policy.policy_hash,
                    compacted_at_unix_ms,
                })?;
            report.compacted = report
                .compacted
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
            report.last_tenant_id = Some(candidate.use_record.tenant_id);
            report.last_grant_id = Some(candidate.use_record.grant_id);
        }
        Ok(report)
    }
}

pub(super) fn acknowledge_exact_evidence(
    store: &dyn DeclassificationEvidenceCommitStore,
    evidence: &DeclassificationEvidenceRecord,
    durable_sink_record_hash: Digest32,
    verified_at_unix_ms: u64,
) -> PortResult<()> {
    store.acknowledge_declassification_evidence(&DeclassificationEvidenceAckRequest {
        tenant_id: evidence.tenant_id.clone(),
        grant_id: evidence.grant_id.clone(),
        phase: evidence.phase,
        evidence_id: evidence.receipt.evidence_id.clone(),
        body_hash: evidence.receipt.body_hash,
        transition_id: evidence.receipt.transition_id.clone(),
        durable_sink_record_hash,
        verified_at_unix_ms,
    })
}

pub(super) fn append_and_ack_exact_evidence(
    store: &dyn DeclassificationEvidenceCommitStore,
    sink: &dyn ExactSecurityReceiptSink,
    tenant_id: &TenantId,
    grant_id: &GrantId,
    phase: DeclassificationEvidencePhase,
    expected_receipt: &ReceiptAppendRequest,
    verified_at_unix_ms: u64,
) -> Result<(), FlowDenial> {
    let evidence = store
        .load_declassification_evidence(&DeclassificationEvidenceQuery {
            tenant_id: tenant_id.clone(),
            grant_id: grant_id.clone(),
            phase,
        })
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?
        .ok_or(FlowDenial::DeclassificationStoreFailure)?;
    if evidence.receipt != *expected_receipt
        || evidence.tenant_id != *tenant_id
        || evidence.grant_id != *grant_id
        || evidence.phase != phase
        || verified_at_unix_ms < evidence.receipt.occurred_at_unix_ms
    {
        return Err(FlowDenial::DeclassificationBindingMismatch);
    }
    let exact = append_exact_receipt(sink, &evidence.receipt)
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    if evidence.acknowledged && evidence.durable_sink_record_hash != Some(exact.durable_record_hash)
    {
        return Err(FlowDenial::DeclassificationBindingMismatch);
    }
    acknowledge_exact_evidence(
        store,
        &evidence,
        exact.durable_record_hash,
        verified_at_unix_ms,
    )
    .map_err(|_| FlowDenial::DeclassificationStoreFailure)
}
