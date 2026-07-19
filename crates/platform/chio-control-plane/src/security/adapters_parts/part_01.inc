pub use native_evidence::{
    AlertDispatchReport, AlertOutboxConfig, NativeActiveResponseFindingAuthority,
    NativeFindingAuthorityConfigError, NativeSchedulerHealthPort, NativeSecurityReceiptSink,
    SqliteSiemOutbox,
};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chio_core::crypto::PublicKey;
use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    DeclassificationConsumptionReceiptBody, DeclassificationOutcomeReceiptBody,
    FlowDenialReceiptBody,
};
use chio_data_guards::{FindingLocation, StructuredClassifier};
use chio_flow::{
    canonical_request_hash, evaluate_pre_invocation, evaluate_pre_invocation_with_declassification,
    information_label_hash, prepare_egress_fence, prepare_pre_invocation, verify_declassification,
    CategoryLabelMap, DeclassificationDispatchOutcome, DeclassificationError,
    DeclassificationVerificationRequest, FlowAdmission, FlowDenial, InformationFlowLattice,
    PostInvocationFlow, ResolvedFlowRequest,
};
use chio_manifest::{AdmittedToolSecurity, BridgeSecurityMetadata, VerifiedManifestRegistry};
use chio_security_kernel::{
    FlowDispatchOutcomeRecorder, FlowPostInvocationInput, FlowPostInvocationResolver,
    FlowPreDispatchInput, FlowPreDispatchPort, FlowPreInvocationInput, FlowPreInvocationPort,
    FlowPreInvocationResolver, SecurityClock, SystemSecurityClock,
};
use chio_security_types::flow::DeclassificationPurpose;
use chio_security_types::ports::{
    derive_declassification_event_id, derive_declassification_transition_id, BoundedVec, ByteRange,
    CanonicalBody, ClassificationFinding, ClassificationPort, ClassificationRequest,
    ClassificationResult, ClassifierId, ClassifierVersion, DeclassificationCompactionQuery,
    DeclassificationCompactionRequest, DeclassificationConsume, DeclassificationConsumeRequest,
    DeclassificationConsumptionEvidenceCommit, DeclassificationEvidenceAckRequest,
    DeclassificationEvidenceCommitStore, DeclassificationEvidencePhase,
    DeclassificationEvidenceQuery, DeclassificationEvidenceRecord,
    DeclassificationEvidenceRetryRequest, DeclassificationOutcomeEvidenceCommit,
    DeclassificationOutcomeRequest, DeclassificationTransitionBinding, DeclassificationUseQuery,
    DeclassificationUseState, DeclassificationUseStore, DestinationId, Digest32, EgressFenceCommit,
    ErrorCode, EventId, ExactReceiptRecord, ExactSecurityReceiptSink, FlowJoinRequest,
    FlowStateKey, FlowStateSnapshot, FlowStateStore, GrantId, OpaqueReceiptRef, PortError,
    PortErrorKind, PortResult, ReceiptAppendRequest, RecordId, RequestId, SecurityReceiptSink,
    TenantId, MAX_DECLASSIFICATION_EVIDENCE_BATCH,
};
use chio_security_types::InformationLabel;

pub struct StructuredClassificationAdapter {
    classifier: Arc<dyn StructuredClassifier>,
}

impl StructuredClassificationAdapter {
    #[must_use]
    pub fn new(classifier: Arc<dyn StructuredClassifier>) -> Self {
        Self { classifier }
    }
}

impl ClassificationPort for StructuredClassificationAdapter {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        let actual_digest = chio_core::sha256(request.payload.as_bytes());
        if actual_digest.as_bytes() != request.payload_digest.as_bytes() {
            return Err(PortError::integrity_failure());
        }
        let result = self
            .classifier
            .classify(request.payload.as_bytes())
            .map_err(|_| PortError::unavailable())?;
        if result.payload_digest() != request.payload_digest.as_bytes()
            || result.payload_len()
                != u64::try_from(request.payload.as_bytes().len())
                    .map_err(|_| PortError::invalid_data())?
        {
            return Err(PortError::integrity_failure());
        }
        let classifier_id = ClassifierId::new(result.identity().id()).map_err(PortError::from)?;
        let classifier_version =
            ClassifierVersion::new(result.identity().version()).map_err(PortError::from)?;
        let findings = result
            .findings()
            .iter()
            .map(|finding| {
                let (byte_range, field_path) = match finding.location() {
                    FindingLocation::ByteRange { start, end } => (
                        Some(ByteRange {
                            start: *start,
                            end: *end,
                        }),
                        None,
                    ),
                    FindingLocation::FieldPath(path) => {
                        (None, Some(RecordId::new(path).map_err(PortError::from)?))
                    }
                };
                Ok(ClassificationFinding {
                    category: RecordId::new(finding.category()).map_err(PortError::from)?,
                    confidence_basis_points: finding.confidence_basis_points(),
                    byte_range,
                    field_path,
                })
            })
            .collect::<PortResult<Vec<_>>>()?;
        Ok(ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: Digest32::new(*result.payload_digest()),
            classifier_id,
            classifier_version,
            findings: BoundedVec::new(findings).map_err(|_| PortError::invalid_data())?,
        })
    }
}

#[derive(Clone)]
pub struct FlowResolverConfig {
    operator_input_floor: InformationLabel,
    category_labels: CategoryLabelMap,
    trusted_declassification_authorities: BTreeMap<RecordId, PublicKey>,
    fence_ttl_ms: u64,
    declassification_evidence: Option<DeclassificationEvidenceConfig>,
    receipt_evidence: Option<FlowReceiptEvidenceConfig>,
}

#[derive(Clone)]
struct DeclassificationEvidenceConfig {
    store: Arc<dyn DeclassificationEvidenceCommitStore>,
    sink: Arc<dyn ExactSecurityReceiptSink>,
    policy: ActiveDefensePolicyBinding,
}

#[derive(Clone)]
struct FlowReceiptEvidenceConfig {
    sink: Arc<dyn SecurityReceiptSink>,
    policy: ActiveDefensePolicyBinding,
}

impl FlowResolverConfig {
    pub fn new(
        operator_input_floor: InformationLabel,
        category_labels: CategoryLabelMap,
        trusted_declassification_authorities: BTreeMap<RecordId, PublicKey>,
        fence_ttl_ms: u64,
    ) -> Result<Self, FlowResolverConfigError> {
        if fence_ttl_ms == 0 {
            return Err(FlowResolverConfigError::ZeroFenceTtl);
        }
        Ok(Self {
            operator_input_floor,
            category_labels,
            trusted_declassification_authorities,
            fence_ttl_ms,
            declassification_evidence: None,
            receipt_evidence: None,
        })
    }

    pub fn with_declassification_evidence(
        mut self,
        store: Arc<dyn DeclassificationEvidenceCommitStore>,
        sink: Arc<dyn ExactSecurityReceiptSink>,
        policy: ActiveDefensePolicyBinding,
    ) -> PortResult<Self> {
        store.ensure_declassification_evidence_ready()?;
        sink.ensure_receipts_ready()?;
        store.seal_declassification_live_dispatch()?;
        self.declassification_evidence = Some(DeclassificationEvidenceConfig {
            store,
            sink,
            policy,
        });
        Ok(self)
    }

    #[must_use]
    pub fn with_receipt_evidence(
        mut self,
        sink: Arc<dyn SecurityReceiptSink>,
        policy: ActiveDefensePolicyBinding,
    ) -> Self {
        self.receipt_evidence = Some(FlowReceiptEvidenceConfig { sink, policy });
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FlowResolverConfigError {
    #[error("flow egress fence TTL must be nonzero")]
    ZeroFenceTtl,
}

pub struct PersistentFlowResolver {
    manifests: Arc<VerifiedManifestRegistry>,
    state: Arc<dyn FlowStateStore>,
    classifier: Arc<dyn ClassificationPort>,
    clock: Arc<dyn SecurityClock>,
    config: FlowResolverConfig,
}

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
    clock: Arc<dyn SecurityClock>,
}

impl DeclassificationReceiptOutboxDrainer {
    pub fn new(
        store: Arc<dyn DeclassificationEvidenceCommitStore>,
        sink: Arc<dyn ExactSecurityReceiptSink>,
    ) -> PortResult<Self> {
        Self::new_with_clock(store, sink, Arc::new(SystemSecurityClock))
    }

    pub fn new_with_clock(
        store: Arc<dyn DeclassificationEvidenceCommitStore>,
        sink: Arc<dyn ExactSecurityReceiptSink>,
        clock: Arc<dyn SecurityClock>,
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
            let body = serde_json::from_slice::<ActiveDefenseReceiptBody>(
                consumption.receipt.canonical_body.as_bytes(),
            )
            .map_err(|_| PortError::integrity_failure())?;
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
            let recovery_time_unix_ms = self.clock.now_unix_ms()?;
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
        let now_unix_ms = self.clock.now_unix_ms()?;
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
        let compacted_at_unix_ms = self.clock.now_unix_ms()?;
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
            let consumption_body = serde_json::from_slice::<ActiveDefenseReceiptBody>(
                candidate.consumption.receipt.canonical_body.as_bytes(),
            )
            .map_err(|_| PortError::integrity_failure())?;
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

struct AtomicDeclassificationConsumptionStore {
    store: Arc<dyn DeclassificationEvidenceCommitStore>,
    commit: DeclassificationConsumptionEvidenceCommit,
}

impl DeclassificationUseStore for AtomicDeclassificationConsumptionStore {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume> {
        if request != &self.commit.consumption {
            return Err(PortError::conflict());
        }
        self.store
            .commit_declassification_consumption_evidence(&self.commit)
    }

    fn record_outcome(&self, _: &DeclassificationOutcomeRequest) -> PortResult<()> {
        Err(PortError::unavailable())
    }
}

struct PersistentDeclassificationOutcomeRecorder {
    evidence: DeclassificationEvidenceConfig,
    released: DeclassificationOutcomeEvidenceCommit,
    dispatch_failed: DeclassificationOutcomeEvidenceCommit,
    outcome_unknown_after_dispatch: DeclassificationOutcomeEvidenceCommit,
    verified_at_unix_ms: u64,
    completed_outcome: Option<DeclassificationDispatchOutcome>,
}

impl FlowDispatchOutcomeRecorder for PersistentDeclassificationOutcomeRecorder {
    fn record(&mut self, outcome: DeclassificationDispatchOutcome) -> Result<(), FlowDenial> {
        if let Some(completed) = self.completed_outcome {
            return if completed == outcome {
                Ok(())
            } else {
                Err(FlowDenial::DeclassificationBindingMismatch)
            };
        }
        let prepared = match outcome {
            DeclassificationDispatchOutcome::Released => &self.released,
            DeclassificationDispatchOutcome::DispatchFailed => &self.dispatch_failed,
            DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch => {
                &self.outcome_unknown_after_dispatch
            }
        };
        let store = self.evidence.store.as_ref();
        let receipt = commit_terminal_declassification_evidence(store, prepared)?;
        append_and_ack_exact_evidence(
            store,
            self.evidence.sink.as_ref(),
            &prepared.outcome.tenant_id,
            &prepared.outcome.grant_id,
            DeclassificationEvidencePhase::Outcome,
            &receipt,
            self.verified_at_unix_ms,
        )?;
        self.completed_outcome = Some(outcome);
        Ok(())
    }
}

fn prepare_declassification_outcome_evidence(
    evidence: &DeclassificationEvidenceConfig,
    consumption: &DeclassificationConsumptionEvidenceCommit,
    grant_hash: Digest32,
    occurred_at_unix_ms: u64,
    transition_binding: DeclassificationTransitionBinding,
) -> Result<DeclassificationOutcomeEvidenceCommit, FlowDenial> {
    let new_state = transition_binding
        .terminal_state()
        .ok_or(FlowDenial::DeclassificationBindingMismatch)?;
    if new_state == DeclassificationUseState::ConsumedPendingDispatch
        || transition_binding.tenant_id() != &consumption.consumption.tenant_id
        || transition_binding.grant_id() != &consumption.consumption.grant_id
        || transition_binding.request_hash() != consumption.consumption.request_hash
        || occurred_at_unix_ms < consumption.receipt.occurred_at_unix_ms
    {
        return Err(FlowDenial::DeclassificationBindingMismatch);
    }
    let transition_id = derive_declassification_transition_id(&transition_binding)
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
    let body = declassification_outcome_body(
        DeclassificationOutcomeBodyInput {
            tenant_id: consumption.consumption.tenant_id.clone(),
            prior_receipt_id: consumption.receipt.evidence_id.clone(),
            policy: evidence.policy.clone(),
            grant_id: consumption.consumption.grant_id.clone(),
            grant_hash,
            request_hash: consumption.consumption.request_hash,
            occurred_at_unix_ms,
            to_state: new_state,
        },
        &transition_binding,
    )?;
    Ok(DeclassificationOutcomeEvidenceCommit {
        transition_binding,
        outcome: DeclassificationOutcomeRequest {
            tenant_id: consumption.consumption.tenant_id.clone(),
            grant_id: consumption.consumption.grant_id.clone(),
            request_hash: consumption.consumption.request_hash,
            expected_state: DeclassificationUseState::ConsumedPendingDispatch,
            new_state,
            transition_id,
        },
        predecessor_evidence_id: consumption.receipt.evidence_id.clone(),
        receipt: active_defense_receipt_request(&body)?,
    })
}

fn commit_terminal_declassification_evidence(
    store: &dyn DeclassificationEvidenceCommitStore,
    prepared: &DeclassificationOutcomeEvidenceCommit,
) -> Result<ReceiptAppendRequest, FlowDenial> {
    if store
        .commit_declassification_outcome_evidence(prepared)
        .is_ok()
    {
        return Ok(prepared.receipt.clone());
    }
    let existing = store
        .load_declassification_evidence(&DeclassificationEvidenceQuery {
            tenant_id: prepared.outcome.tenant_id.clone(),
            grant_id: prepared.outcome.grant_id.clone(),
            phase: DeclassificationEvidencePhase::Outcome,
        })
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?
        .ok_or(FlowDenial::DeclassificationStoreFailure)?;
    if existing.request_hash != prepared.outcome.request_hash
        || existing.state != prepared.outcome.new_state
        || existing.transition_binding != prepared.transition_binding
        || existing.predecessor_evidence_id.as_ref() != Some(&prepared.predecessor_evidence_id)
        || existing.receipt != prepared.receipt
    {
        return Err(FlowDenial::DeclassificationBindingMismatch);
    }
    Ok(existing.receipt)
}

impl PersistentFlowResolver {
    #[must_use]
    pub fn new(
        manifests: Arc<VerifiedManifestRegistry>,
        state: Arc<dyn FlowStateStore>,
        classifier: Arc<dyn ClassificationPort>,
        clock: Arc<dyn SecurityClock>,
        config: FlowResolverConfig,
    ) -> Self {
        Self {
            manifests,
            state,
            classifier,
            clock,
            config,
        }
    }

    pub fn commit_dispatch(
        &self,
        input: &FlowPreInvocationInput<'_>,
        dispatch_commitment_id: RecordId,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        if input.request.declassification_grant.is_some() {
            if self.config.declassification_evidence.is_none() {
                return Err(FlowDenial::DeclassificationStoreFailure);
            }
            return self.commit_dispatch_with_evidence(input, dispatch_commitment_id);
        }
        let request = self.resolve_pre(input, false)?;
        let admission = evaluate_pre_invocation(request)?;
        self.commit_admission(&admission, dispatch_commitment_id)?;
        Ok(None)
    }

    fn commit_dispatch_with_evidence(
        &self,
        input: &FlowPreInvocationInput<'_>,
        dispatch_commitment_id: RecordId,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        let evidence = self
            .config
            .declassification_evidence
            .as_ref()
            .cloned()
            .ok_or(FlowDenial::DeclassificationStoreFailure)?;
        let grant_hash = declassification_grant_hash(
            input
                .request
                .declassification_grant
                .as_ref()
                .ok_or(FlowDenial::DeclassificationBindingMismatch)?,
        )?;
        let request = self.resolve_pre(input, false)?;
        let request_id = request.request_id.clone();
        let verified_at_unix_ms = request.now_unix_ms;
        let verified = request
            .declassification
            .as_ref()
            .ok_or(FlowDenial::DeclassificationBindingMismatch)?;
        let grant_expires_at_unix_ms = verified
            .expires_at_unix_seconds()
            .checked_mul(1_000)
            .ok_or(FlowDenial::DeclassificationStoreFailure)?;
        let consumption_binding = DeclassificationTransitionBinding::Consumption {
            tenant_id: verified.tenant_id().clone(),
            grant_id: verified.grant_id().clone(),
            request_hash: verified.request_hash(),
            request_id: request_id.clone(),
        };
        let use_query = DeclassificationUseQuery {
            tenant_id: verified.tenant_id().clone(),
            grant_id: verified.grant_id().clone(),
        };
        let existing_use = evidence
            .store
            .load_declassification_use(&use_query)
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
        let existing_evidence = evidence
            .store
            .load_declassification_evidence(&DeclassificationEvidenceQuery {
                tenant_id: verified.tenant_id().clone(),
                grant_id: verified.grant_id().clone(),
                phase: DeclassificationEvidencePhase::Consumption,
            })
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
        let consumption_commit = match (existing_use, existing_evidence) {
            (None, None) => {
                let body = declassification_consumption_body(
                    verified.tenant_id().clone(),
                    evidence.policy.clone(),
                    verified.grant_id().clone(),
                    grant_hash,
                    verified.request_hash(),
                    request.now_unix_ms,
                    &consumption_binding,
                )?;
                DeclassificationConsumptionEvidenceCommit {
                    consumption: DeclassificationConsumeRequest {
                        tenant_id: verified.tenant_id().clone(),
                        grant_id: verified.grant_id().clone(),
                        request_hash: verified.request_hash(),
                        consumed_at_unix_ms: request.now_unix_ms,
                        grant_expires_at_unix_ms,
                    },
                    transition_binding: consumption_binding.clone(),
                    receipt: active_defense_receipt_request(&body)?,
                }
            }
            (Some(use_record), Some(evidence_record)) => {
                let expected_body = declassification_consumption_body(
                    verified.tenant_id().clone(),
                    evidence.policy.clone(),
                    verified.grant_id().clone(),
                    grant_hash,
                    verified.request_hash(),
                    use_record.consumed_at_unix_ms,
                    &consumption_binding,
                )?;
                let expected_receipt = active_defense_receipt_request(&expected_body)?;
                if use_record.request_hash != verified.request_hash()
                    || use_record.grant_expires_at_unix_ms != grant_expires_at_unix_ms
                    || use_record.consumption_binding != consumption_binding
                    || evidence_record.request_hash != verified.request_hash()
                    || evidence_record.state != DeclassificationUseState::ConsumedPendingDispatch
                    || evidence_record.transition_binding != consumption_binding
                    || evidence_record.receipt != expected_receipt
                {
                    return Err(FlowDenial::DeclassificationBindingMismatch);
                }
                DeclassificationConsumptionEvidenceCommit {
                    consumption: DeclassificationConsumeRequest {
                        tenant_id: use_record.tenant_id,
                        grant_id: use_record.grant_id,
                        request_hash: use_record.request_hash,
                        consumed_at_unix_ms: use_record.consumed_at_unix_ms,
                        grant_expires_at_unix_ms: use_record.grant_expires_at_unix_ms,
                    },
                    transition_binding: consumption_binding,
                    receipt: evidence_record.receipt,
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(FlowDenial::DeclassificationStoreFailure);
            }
        };
        let outcome_occurred_at_unix_ms = verified_at_unix_ms;
        let outcome_binding = DeclassificationTransitionBinding::DispatchFailed {
            tenant_id: consumption_commit.consumption.tenant_id.clone(),
            grant_id: consumption_commit.consumption.grant_id.clone(),
            request_hash: consumption_commit.consumption.request_hash,
            request_id: request_id.clone(),
            dispatch_commitment_id: dispatch_commitment_id.clone(),
        };
        let dispatch_failed = prepare_declassification_outcome_evidence(
            &evidence,
            &consumption_commit,
            grant_hash,
            outcome_occurred_at_unix_ms,
            outcome_binding,
        )?;
        let outcome_unknown_after_dispatch = prepare_declassification_outcome_evidence(
            &evidence,
            &consumption_commit,
            grant_hash,
            outcome_occurred_at_unix_ms,
            DeclassificationTransitionBinding::OutcomeUnknownAfterDispatch {
                tenant_id: consumption_commit.consumption.tenant_id.clone(),
                grant_id: consumption_commit.consumption.grant_id.clone(),
                request_hash: consumption_commit.consumption.request_hash,
                request_id: request_id.clone(),
                dispatch_commitment_id: dispatch_commitment_id.clone(),
            },
        )?;
        let receipt_failure = prepare_declassification_outcome_evidence(
            &evidence,
            &consumption_commit,
            grant_hash,
            outcome_occurred_at_unix_ms,
            DeclassificationTransitionBinding::ReceiptPersistenceFailed {
                tenant_id: consumption_commit.consumption.tenant_id.clone(),
                grant_id: consumption_commit.consumption.grant_id.clone(),
                request_hash: consumption_commit.consumption.request_hash,
                request_id: request_id.clone(),
                dispatch_commitment_id: dispatch_commitment_id.clone(),
            },
        )?;
        let released = prepare_declassification_outcome_evidence(
            &evidence,
            &consumption_commit,
            grant_hash,
            outcome_occurred_at_unix_ms,
            DeclassificationTransitionBinding::Released {
                tenant_id: consumption_commit.consumption.tenant_id.clone(),
                grant_id: consumption_commit.consumption.grant_id.clone(),
                request_hash: consumption_commit.consumption.request_hash,
                request_id,
                dispatch_commitment_id: dispatch_commitment_id.clone(),
            },
        )?;
        let atomic_store = AtomicDeclassificationConsumptionStore {
            store: Arc::clone(&evidence.store),
            commit: consumption_commit.clone(),
        };
        let admission = evaluate_pre_invocation_with_declassification(request, &atomic_store)?;
        let consumed = admission
            .declassification
            .as_ref()
            .ok_or(FlowDenial::DeclassificationStoreFailure)?;
        if consumed.tenant_id() != &consumption_commit.consumption.tenant_id
            || consumed.grant_id() != &consumption_commit.consumption.grant_id
            || consumed.request_hash() != consumption_commit.consumption.request_hash
        {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        if let Err(error) = append_and_ack_exact_evidence(
            evidence.store.as_ref(),
            evidence.sink.as_ref(),
            consumed.tenant_id(),
            consumed.grant_id(),
            DeclassificationEvidencePhase::Consumption,
            &consumption_commit.receipt,
            verified_at_unix_ms,
        ) {
            self.persist_dispatch_failed_evidence(&evidence, &receipt_failure)?;
            return Err(error);
        }
        if let Err(error) = self.commit_admission_at(
            &admission,
            dispatch_commitment_id,
            outcome_occurred_at_unix_ms,
        ) {
            let outcome_receipt =
                self.persist_dispatch_failed_evidence(&evidence, &dispatch_failed)?;
            append_and_ack_exact_evidence(
                evidence.store.as_ref(),
                evidence.sink.as_ref(),
                consumed.tenant_id(),
                consumed.grant_id(),
                DeclassificationEvidencePhase::Outcome,
                &outcome_receipt,
                outcome_occurred_at_unix_ms,
            )?;
            return Err(error);
        }
        Ok(Some(Box::new(PersistentDeclassificationOutcomeRecorder {
            evidence,
            released,
            dispatch_failed,
            outcome_unknown_after_dispatch,
            verified_at_unix_ms: outcome_occurred_at_unix_ms,
            completed_outcome: None,
        })))
    }

    fn persist_dispatch_failed_evidence(
        &self,
        evidence: &DeclassificationEvidenceConfig,
        prepared: &DeclassificationOutcomeEvidenceCommit,
    ) -> Result<ReceiptAppendRequest, FlowDenial> {
        if prepared.transition_binding.terminal_state()
            != Some(DeclassificationUseState::DispatchFailed)
            || !prepared.transition_binding.is_live_dispatch_binding()
            || prepared.outcome.new_state != DeclassificationUseState::DispatchFailed
        {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        commit_terminal_declassification_evidence(evidence.store.as_ref(), prepared)
    }

    fn commit_admission_at(
        &self,
        admission: &FlowAdmission,
        dispatch_commitment_id: RecordId,
        committed_at_unix_ms: u64,
    ) -> Result<(), FlowDenial> {
        let persisted = self.persist_admission(admission)?;
        let Some(fence_request) = prepare_egress_fence(admission, &persisted)? else {
            return Ok(());
        };
        let fence = self
            .state
            .acquire_egress_fence(&fence_request)
            .map_err(|_| FlowDenial::StateChanged)?;
        self.state
            .commit_egress_fence(&EgressFenceCommit {
                fence,
                dispatch_commitment_id,
                committed_at_unix_ms,
            })
            .map_err(|_| FlowDenial::StateChanged)?;
        Ok(())
    }

    fn commit_admission(
        &self,
        admission: &FlowAdmission,
        dispatch_commitment_id: RecordId,
    ) -> Result<(), FlowDenial> {
        let persisted = self.persist_admission(admission)?;
        let Some(fence_request) = prepare_egress_fence(admission, &persisted)? else {
            return Ok(());
        };
        let fence = self
            .state
            .acquire_egress_fence(&fence_request)
            .map_err(|_| FlowDenial::StateChanged)?;
        let committed_at_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|_| FlowDenial::StateChanged)?;
        self.state
            .commit_egress_fence(&EgressFenceCommit {
                fence,
                dispatch_commitment_id,
                committed_at_unix_ms,
            })
            .map_err(|_| FlowDenial::StateChanged)?;
        Ok(())
    }

    fn resolve_pre(
        &self,
        input: &FlowPreInvocationInput<'_>,
        require_context_generation: bool,
    ) -> Result<ResolvedFlowRequest, FlowDenial> {
        let key = flow_key(input.security_context);
        let state = self.load_state(&key)?;
        if require_context_generation {
            let expected_flow_state_generation = input
                .security_context
                .flow_state_generation()
                .ok_or(FlowDenial::StateChanged)?;
            if state.context_generation != expected_flow_state_generation {
                return Err(FlowDenial::StateChanged);
            }
        }
        let (security, bridge) = self
            .resolve_admitted_tool_security(&input.request.server_id, &input.request.tool_name)?;
        let manifest = bridge
            .flow()
            .cloned()
            .unwrap_or_else(non_egress_declaration);
        let canonical_request = canonical_body(&input.request.arguments)?;
        let request_id = RequestId::new(input.request.request_id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let payload_digest = digest(canonical_request.as_bytes());
        let classified = self
            .config
            .category_labels
            .classify(
                self.classifier.as_ref(),
                &ClassificationRequest {
                    tenant_id: key.tenant_id.clone(),
                    request_id: request_id.clone(),
                    payload: canonical_request.clone(),
                    payload_digest,
                },
            )
            .map_err(|_| FlowDenial::ClassifierFailure)?;
        let complete_source = classified
            .label()
            .join(&self.config.operator_input_floor)
            .and_then(|label| label.join(&state.principal_label))
            .and_then(|label| label.join(&state.lineage_label))
            .and_then(|label| label.join(&state.session_label))
            .map_err(|_| FlowDenial::StateOverflow)?;
        let now_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|_| FlowDenial::StateChanged)?;
        let capability_id = RecordId::new(input.request.capability.id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let agent_id = RecordId::new(input.request.agent_id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let tool_name = RecordId::new(input.request.tool_name.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let destination_id = DestinationId::new(input.request.server_id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let purpose = match input.request.declassification_grant.as_ref() {
            Some(grant) => grant.body().purpose().clone(),
            None => DeclassificationPurpose::new("not-applicable")
                .map_err(|_| FlowDenial::InvalidManifest)?,
        };
        let declassification = input
            .request
            .declassification_grant
            .as_ref()
            .map(|grant| {
                verify_declassification(
                    grant,
                    &DeclassificationVerificationRequest {
                        capability_id: capability_id.clone(),
                        tenant_id: key.tenant_id.clone(),
                        subject_id: key.principal_id.clone(),
                        agent_id: agent_id.clone(),
                        session_id: key.session_id.clone(),
                        source_label: complete_source,
                        destination_id: destination_id.clone(),
                        tool_name: tool_name.clone(),
                        purpose: purpose.clone(),
                        policy_purposes: security.declassification_purposes().clone(),
                        manifest_purposes: manifest.declassification_purposes.clone(),
                        canonical_request: canonical_request.clone(),
                        now_unix_ms,
                        trusted_authorities: self
                            .config
                            .trusted_declassification_authorities
                            .clone(),
                    },
                )
                .map_err(map_declassification_error)
            })
            .transpose()?;
        let fence_expires_at_unix_ms = now_unix_ms
            .checked_add(self.config.fence_ttl_ms)
            .ok_or(FlowDenial::StateOverflow)?;
        let flow_transition_id = flow_transition_id(
            "flow-pre",
            &state.key,
            state.context_generation,
            &request_id,
            payload_digest,
        )?;
        Ok(ResolvedFlowRequest {
            request_id,
            request_hash: canonical_request_hash(&canonical_request)
                .map_err(map_declassification_error)?,
            transition_id: flow_transition_id,
            state,
            payload_label: classified.label().clone(),
            operator_input_floor: self.config.operator_input_floor.clone(),
            runtime_egress: security.effective_egress(),
            capability_id,
            agent_id,
            tool_name,
            destination_id,
            purpose,
            effective_declassification_purposes: security.declassification_purposes().clone(),
            trusted_declassification_authorities: self
                .config
                .trusted_declassification_authorities
                .clone(),
            now_unix_ms,
            declassification,
            policy_clearances: BoundedVec::new(security.policy_clearances().to_vec())
                .map_err(|_| FlowDenial::InvalidManifest)?,
            manifest,
            fence_expires_at_unix_ms,
        })
    }

    fn load_state(&self, key: &FlowStateKey) -> Result<FlowStateSnapshot, FlowDenial> {
        self.state
            .load(key)
            .map_err(|_| FlowDenial::StateChanged)?
            .ok_or(FlowDenial::StateChanged)
    }

    fn resolve_admitted_tool_security(
        &self,
        server_id: &str,
        tool_name: &str,
    ) -> Result<(&AdmittedToolSecurity, BridgeSecurityMetadata), FlowDenial> {
        let regular = Self::pair_admitted_security(
            self.manifests.tool_security(server_id, tool_name),
            self.manifests.bridge_security(server_id, tool_name),
        )?;
        let server_tool = Self::pair_admitted_security(
            self.manifests
                .tool_security_for_server_tool(server_id, tool_name),
            self.manifests
                .bridge_security_for_server_tool(server_id, tool_name),
        )?;
        let (security, bridge) = match (regular, server_tool) {
            (Some(pair), None) | (None, Some(pair)) => pair,
            (None, None) | (Some(_), Some(_)) => return Err(FlowDenial::InvalidManifest),
        };
        self.validate_bridge_security(server_id, tool_name, &bridge)?;
        Ok((security, bridge))
    }

    fn pair_admitted_security(
        security: Option<&AdmittedToolSecurity>,
        bridge: Option<BridgeSecurityMetadata>,
    ) -> Result<Option<(&AdmittedToolSecurity, BridgeSecurityMetadata)>, FlowDenial> {
        match (security, bridge) {
            (Some(security), Some(bridge)) => Ok(Some((security, bridge))),
            (None, None) => Ok(None),
            _ => Err(FlowDenial::InvalidManifest),
        }
    }

    fn validate_bridge_security(
        &self,
        server_id: &str,
        tool_name: &str,
        bridge: &BridgeSecurityMetadata,
    ) -> Result<(), FlowDenial> {
        self.manifests
            .validate_bridge_security(server_id, tool_name, bridge)
            .map_err(|_| FlowDenial::InvalidManifest)
    }

    fn persist_admission(
        &self,
        admission: &FlowAdmission,
    ) -> Result<FlowStateSnapshot, FlowDenial> {
        self.state
            .join(&admission.taint_transition)
            .map_err(|_| FlowDenial::StateChanged)
    }
}

impl FlowPreInvocationResolver for PersistentFlowResolver {
    fn resolve(
        &self,
        input: &FlowPreInvocationInput<'_>,
    ) -> Result<ResolvedFlowRequest, FlowDenial> {
        self.resolve_pre(input, true)
    }

    fn persist(&self, admission: &FlowAdmission) -> Result<(), FlowDenial> {
        self.persist_admission(admission).map(|_| ())
    }
}

impl FlowPreInvocationPort for PersistentFlowResolver {
    fn evaluate(&self, input: &FlowPreInvocationInput<'_>) -> Result<(), FlowDenial> {
        let resolved = self.resolve_pre(input, true)?;
        let receipt_context = self
            .config
            .receipt_evidence
            .as_ref()
            .map(|_| FlowDenialReceiptContext::from_resolved(&resolved))
            .transpose()?;
        let prepared = match prepare_pre_invocation(resolved) {
            Ok(prepared) => prepared,
            Err(denial) => {
                if let Some(context) = receipt_context.as_ref() {
                    self.attest_flow_denial(context, denial)?;
                }
                return Err(denial);
            }
        };
        match self.persist_admission(prepared.admission()) {
            Ok(_) => Ok(()),
            Err(denial) => {
                if let Some(context) = receipt_context.as_ref() {
                    self.attest_flow_denial(context, denial)?;
                }
                Err(denial)
            }
        }
    }
}

impl PersistentFlowResolver {
    fn attest_flow_denial(
        &self,
        context: &FlowDenialReceiptContext,
        denial: FlowDenial,
    ) -> Result<(), FlowDenial> {
        let Some(receipt_evidence) = self.config.receipt_evidence.as_ref() else {
            return Ok(());
        };
        let body = context.body(receipt_evidence.policy.clone(), denial)?;
        append_active_defense_body(receipt_evidence.sink.as_ref(), &body)?;
        Ok(())
    }
}

struct FlowDenialReceiptContext {
    tenant_id: TenantId,
    request_hash: Digest32,
    source_label_hash: Digest32,
    destination_label_hash: Digest32,
    occurred_at_unix_ms: u64,
    flow_transition_id: RecordId,
}

impl FlowDenialReceiptContext {
    fn from_resolved(resolved: &ResolvedFlowRequest) -> Result<Self, FlowDenial> {
        let source_label = resolved
            .payload_label
            .join(&resolved.operator_input_floor)
            .and_then(|label| label.join(&resolved.state.principal_label))
            .and_then(|label| label.join(&resolved.state.lineage_label))
            .and_then(|label| label.join(&resolved.state.session_label))
            .map_err(|_| FlowDenial::StateOverflow)?;
        let source_label_hash =
            information_label_hash(&source_label).map_err(map_declassification_error)?;
        let destination_commitment = serde_json::json!({
            "destination_id": resolved.destination_id.as_str(),
            "manifest_clearance": &resolved.manifest.input_clearance,
            "policy_clearances": resolved.policy_clearances.as_slice(),
        });
        let destination_label_hash = digest(
            &chio_core::canonical_json_bytes(&destination_commitment)
                .map_err(|_| FlowDenial::InvalidManifest)?,
        );
        Ok(Self {
            tenant_id: resolved.state.key.tenant_id.clone(),
            request_hash: resolved.request_hash,
            source_label_hash,
            destination_label_hash,
            occurred_at_unix_ms: resolved.now_unix_ms,
            flow_transition_id: resolved.transition_id.clone(),
        })
    }

    fn body(
        &self,
        policy: ActiveDefensePolicyBinding,
        denial: FlowDenial,
    ) -> Result<ActiveDefenseReceiptBody, FlowDenial> {
        let denial_code = flow_denial_code(denial)?;
        let transition_id = transition_id(
            "flow-denial-receipt",
            self.flow_transition_id.as_str().as_bytes(),
        )?;
        let guard_evidence_hash = digest(
            &chio_core::canonical_json_bytes(&serde_json::json!({
                "denial_code": denial_code.as_str(),
                "destination_label_hash": self.destination_label_hash.as_bytes(),
                "flow_transition_id": self.flow_transition_id.as_str(),
                "request_hash": self.request_hash.as_bytes(),
                "source_label_hash": self.source_label_hash.as_bytes(),
            }))
            .map_err(|_| FlowDenial::StateOverflow)?,
        );
        let event_id = event_id("flow-denial-event", transition_id.as_str().as_bytes())?;
        Ok(ActiveDefenseReceiptBody::FlowDenial(
            FlowDenialReceiptBody {
                header: active_defense_header(
                    self.occurred_at_unix_ms,
                    self.tenant_id.clone(),
                    transition_id,
                    Vec::new(),
                )?,
                policy,
                request_hash: self.request_hash,
                source_label_hash: self.source_label_hash,
                destination_label_hash: self.destination_label_hash,
                guard_evidence_hash,
                denial_code,
                event_id,
            },
        ))
    }
}

impl FlowPreDispatchPort for PersistentFlowResolver {
    fn commit(
        &self,
        input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        let canonical_request = chio_core::canonical_json_bytes(input.request)
            .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
        if canonical_request.as_slice() != input.canonical_request {
            return Err(FlowDenial::DeclassificationBindingMismatch);
        }
        self.commit_dispatch(
            &FlowPreInvocationInput {
                security_context: input.security_context,
                request: input.request,
            },
            input.dispatch_commitment_id.clone(),
        )
    }
}

impl FlowPostInvocationResolver for PersistentFlowResolver {
    fn resolve(
        &self,
        input: &FlowPostInvocationInput<'_>,
    ) -> Result<PostInvocationFlow, FlowDenial> {
        let key = flow_key(input.security_context);
        let state = self.load_state(&key)?;
        let (security, bridge) = self
            .resolve_admitted_tool_security(&input.request.server_id, &input.request.tool_name)?;
        let canonical_response = canonical_body(input.response)?;
        let request_id = RequestId::new(input.request.request_id.clone())
            .map_err(|_| FlowDenial::InvalidManifest)?;
        let payload_digest = digest(canonical_response.as_bytes());
        let classified = self
            .config
            .category_labels
            .classify(
                self.classifier.as_ref(),
                &ClassificationRequest {
                    tenant_id: key.tenant_id.clone(),
                    request_id: request_id.clone(),
                    payload: canonical_response,
                    payload_digest,
                },
            )
            .map_err(|_| FlowDenial::ClassifierFailure)?;
        let flow_transition_id = flow_transition_id(
            "flow-post",
            &state.key,
            state.context_generation,
            &request_id,
            payload_digest,
        )?;
        Ok(PostInvocationFlow {
            request_id,
            payload_digest,
            state,
            classified,
            operator_output_floor: security.effective_output_floor().clone(),
            manifest: bridge
                .flow()
                .cloned()
                .unwrap_or_else(non_egress_declaration),
            transition_id: flow_transition_id,
        })
    }

    fn persist(&self, transition: &FlowJoinRequest) -> Result<(), FlowDenial> {
        self.state
            .join(transition)
            .map(|_| ())
            .map_err(|_| FlowDenial::StateChanged)
    }
}

fn flow_key(context: &chio_kernel::SecurityInvocationContextV1) -> FlowStateKey {
    FlowStateKey {
        tenant_id: context.tenant_id().clone(),
        principal_id: context.principal_id().clone(),
        lineage_id: context.lineage_root_id().clone(),
        session_id: context.session_id().clone(),
        isolation_epoch_id: context.isolation_epoch_id().clone(),
    }
}

fn canonical_body(value: &serde_json::Value) -> Result<CanonicalBody, FlowDenial> {
    let bytes =
        chio_core::canonical_json_bytes(value).map_err(|_| FlowDenial::ClassifierFailure)?;
    CanonicalBody::new(bytes).map_err(|_| FlowDenial::ClassifierFailure)
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn declassification_grant_hash<T: serde::Serialize>(grant: &T) -> Result<Digest32, FlowDenial> {
    let canonical = chio_core::canonical_json_bytes(grant)
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
    Ok(digest(&canonical))
}

fn active_defense_header(
    occurred_at_unix_ms: u64,
    tenant_id: TenantId,
    transition_id: RecordId,
    prior_receipt_ids: Vec<OpaqueReceiptRef>,
) -> Result<ActiveDefenseReceiptHeader, FlowDenial> {
    ActiveDefenseReceiptHeader::new(
        occurred_at_unix_ms,
        tenant_id,
        transition_id,
        prior_receipt_ids,
    )
    .map_err(|_| FlowDenial::DeclassificationStoreFailure)
}

fn append_active_defense_body(
    sink: &dyn SecurityReceiptSink,
    body: &ActiveDefenseReceiptBody,
) -> Result<OpaqueReceiptRef, FlowDenial> {
    let request = active_defense_receipt_request(body)?;
    let appended = sink
        .sign_and_append(&request)
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    if appended != request.evidence_id {
        return Err(FlowDenial::DeclassificationStoreFailure);
    }
    Ok(request.evidence_id)
}

fn active_defense_receipt_request(
    body: &ActiveDefenseReceiptBody,
) -> Result<ReceiptAppendRequest, FlowDenial> {
    body.validate()
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    let canonical = chio_core::canonical_json_bytes(body)
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    let evidence_id = body
        .evidence_id()
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    Ok(ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: RecordId::new(body.kind().as_str())
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?,
        evidence_id: evidence_id.clone(),
        canonical_body: CanonicalBody::new(canonical)
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?,
        body_hash: body
            .body_digest()
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?,
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    })
}

fn append_exact_receipt(
    sink: &dyn ExactSecurityReceiptSink,
    request: &ReceiptAppendRequest,
) -> PortResult<ExactReceiptRecord> {
    if let Some(exact) = sink.load_exact(&request.evidence_id)? {
        if exact.receipt != *request {
            return Err(PortError::conflict());
        }
        if exact
            .durable_record_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(PortError::integrity_failure());
        }
        return Ok(exact);
    }
    let appended = sink.sign_and_append(request)?;
    if appended != request.evidence_id {
        return Err(PortError::integrity_failure());
    }
    let exact = sink
        .load_exact(&request.evidence_id)?
        .ok_or_else(PortError::integrity_failure)?;
    if exact.receipt != *request
        || exact
            .durable_record_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(exact)
}

fn acknowledge_exact_evidence(
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

fn append_and_ack_exact_evidence(
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
