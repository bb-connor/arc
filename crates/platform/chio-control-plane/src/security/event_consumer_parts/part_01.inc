use super::AttestedCorrelationWriter;
use chio_core::capability::governance::{
    GovernedApprovalToken, GovernedTransactionIntent,
};
use chio_core::capability::token::CapabilityToken;
use chio_core::{canonical_json_bytes, sha256, Hash, PublicKey};
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::decision::ToolCallAction;
use chio_core_types::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core_types::SignedSecurityEvent;
use chio_kernel::threshold_approval::{
    authorization_capability_hash, ThresholdApprovalProposal,
};
use chio_kernel::{
    active_response_admission_artifact_payload_digest, active_response_submission_proof_digest,
    ActiveResponseAdmissionRequest, ActiveResponseAuthorizationRequest,
    ActiveResponseArtifactAuthorityAttestation,
    ActiveResponseExecutionEvidence,
    ActiveResponseExecutionOutcome,
    ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseFindingAuthority, ActiveResponseFindingAuthorityError,
    ActiveResponseSubmissionProof,
    AuthoritativeCorrelatedFindingEvidence, ChioKernel, KernelError,
    DispatchCommittedActiveResponseResume, PreDispatchActiveResponseReconstruction,
    PreparedActiveResponseAdmission,
};
use chio_quarantine::{
    build_response_plan, opaque_admission_artifact, ApprovalCoordinatorError,
    CorrelationOutcome, CorrelationPolicy, CorrelationStatus, ResponseApprovalCoordinator,
    TemporalCorrelator, TemporalRule,
};
use chio_security_kernel::{SecurityClock, SecurityEventIngress};
use chio_security_types::ports::{
    derive_attested_finding_action_id, derive_attested_finding_batch_id,
    derive_attested_finding_reservation_id, validate_attested_finding_batch_body,
    AdmissionArtifactRef, ApprovalVerifierPort, AttestedFindingBatchBinding,
    AttestedFindingBatchBindings,
    AttestedFindingBatchBody,
    AttestedFindingBatchKey, AttestedFindingBatchPublication, AttestedFindingBatchStore,
    AttestedFindingResponseAdmissionState, AttestedFindingResponseCompletionOutcome,
    AttestedFindingResponseCompletionState, AttestedFindingResponseOutboxHealth,
    AttestedFindingResponseOutboxKey, AttestedFindingResponseOutboxRecord,
    AttestedFindingResponseOutboxStore, AttestedFindingResponseOutboxTransition,
    AttestedFindingResponsePlanBody, AttestedFindingResponsePlanPublication,
    AttestedFindingResponsePlanningState,
    CanonicalBody, CorrelationIngressStore, Digest32, ErrorCode, EventPartitionScan,
    GovernedApprovalRequest, GovernedApprovalReservation,
    GovernedApprovalReservationMutation, OpaqueReceiptRef, PortError, PortErrorKind, PortResult,
    ProducerId,
    PreparedActiveResponseDispatchBinding,
    ProducerTrustClass, RecordId, RuleId, SecurityEventStore, SecurityEventVerifierPort, TenantId,
    UnverifiedSecurityEvent, VerifiedSecurityEvent,
    ATTESTED_FINDING_BATCH_SCHEMA_VERSION, ATTESTED_FINDING_RESPONSE_INITIAL_RETRY_MS,
    ATTESTED_FINDING_RESPONSE_MAX_RETRY_MS, ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION,
    MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN,
};
#[cfg(test)]
use chio_security_types::ports::{
    ResponseDispatchApproval, PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::SecurityEventBody;
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectSpec, ResponsePlan,
    ResponsePlanInput,
};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

const EVENT_EVIDENCE_HASH_DOMAIN: &[u8] = b"chio.verified-security-event-evidence.v1\0";
const RECEIPT_EVENT_EVIDENCE_HASH_DOMAIN: &[u8] =
    b"chio.verified-security-event-receipt-evidence.v1\0";
pub const SECURITY_EVENT_RECEIPT_PROJECTION_VERSION: &str =
    "chio.security-event-receipt-projection.v1";

#[derive(Clone, Debug)]
pub struct TrustedSecurityEventProducer {
    pub tenant_id: TenantId,
    pub producer_id: ProducerId,
    pub producer_key_id: RecordId,
    pub policy_version: RecordId,
    pub producer_key: PublicKey,
}

#[derive(Clone, Debug)]
pub struct TrustedSecurityEventReceiptProducer {
    pub tenant_id: TenantId,
    pub producer_id: ProducerId,
    pub signer_key_id: RecordId,
    pub signer_key: PublicKey,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEventReceiptProjection {
    pub version: String,
    pub body: SecurityEventBody,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecurityEventVerifierConfigError {
    #[error("security event verifier requires at least one trusted producer")]
    MissingTrustedProducer,
    #[error("security event verifier has a duplicate tenant and producer binding")]
    DuplicateProducerBinding,
    #[error("security event verifier has a duplicate receipt tenant and producer binding")]
    DuplicateReceiptProducerBinding,
    #[error("security event verifier freshness bounds are invalid")]
    InvalidFreshnessBounds,
}

pub struct NativeSecurityEventVerifier {
    clock: Arc<dyn SecurityClock>,
    trusted: BTreeMap<(TenantId, ProducerId), TrustedSecurityEventProducer>,
    trusted_receipts: BTreeMap<(TenantId, ProducerId), TrustedSecurityEventReceiptProducer>,
    max_event_age_ms: u64,
    max_future_skew_ms: u64,
}

impl NativeSecurityEventVerifier {
    pub fn new(
        clock: Arc<dyn SecurityClock>,
        producers: Vec<TrustedSecurityEventProducer>,
        receipt_producers: Vec<TrustedSecurityEventReceiptProducer>,
        max_event_age_ms: u64,
        max_future_skew_ms: u64,
    ) -> Result<Self, SecurityEventVerifierConfigError> {
        if producers.is_empty() && receipt_producers.is_empty() {
            return Err(SecurityEventVerifierConfigError::MissingTrustedProducer);
        }
        if max_event_age_ms == 0 || max_future_skew_ms > max_event_age_ms {
            return Err(SecurityEventVerifierConfigError::InvalidFreshnessBounds);
        }
        let mut trusted = BTreeMap::new();
        for producer in producers {
            let key = (producer.tenant_id.clone(), producer.producer_id.clone());
            if trusted.insert(key, producer).is_some() {
                return Err(SecurityEventVerifierConfigError::DuplicateProducerBinding);
            }
        }
        let mut trusted_receipts = BTreeMap::new();
        for producer in receipt_producers {
            let key = (producer.tenant_id.clone(), producer.producer_id.clone());
            if trusted_receipts.insert(key, producer).is_some() {
                return Err(SecurityEventVerifierConfigError::DuplicateReceiptProducerBinding);
            }
        }
        Ok(Self {
            clock,
            trusted,
            trusted_receipts,
            max_event_age_ms,
            max_future_skew_ms,
        })
    }

    pub fn ensure_ready(&self) -> PortResult<()> {
        if self.trusted.is_empty() && self.trusted_receipts.is_empty() {
            return Err(PortError::integrity_failure());
        }
        self.clock.now_unix_ms().map(|_| ())
    }

    fn verify_time_bounds(
        &self,
        event_time_unix_ms: u64,
        received_at_unix_ms: u64,
    ) -> PortResult<()> {
        let now_unix_ms = self.clock.now_unix_ms()?;
        let latest = now_unix_ms
            .checked_add(self.max_future_skew_ms)
            .ok_or_else(PortError::invalid_data)?;
        if event_time_unix_ms > latest
            || received_at_unix_ms > latest
            || now_unix_ms.saturating_sub(event_time_unix_ms) > self.max_event_age_ms
            || received_at_unix_ms.saturating_sub(event_time_unix_ms) > self.max_event_age_ms
        {
            return Err(PortError::invalid_data());
        }
        Ok(())
    }

    fn verified_event(
        &self,
        event: &UnverifiedSecurityEvent,
        trust_class: ProducerTrustClass,
        evidence_hash: Digest32,
    ) -> VerifiedSecurityEvent {
        VerifiedSecurityEvent {
            tenant_id: event.tenant_id.clone(),
            event_id: event.event_id.clone(),
            producer_id: event.producer_id.clone(),
            trust_class,
            event_time_unix_ms: event.event_time_unix_ms,
            received_at_unix_ms: event.received_at_unix_ms,
            canonical_body: event.canonical_body.clone(),
            body_hash: event.body_hash,
            evidence_hash,
        }
    }

    fn parse_bound_body(&self, event: &UnverifiedSecurityEvent) -> PortResult<SecurityEventBody> {
        let body: SecurityEventBody = serde_json::from_slice(event.canonical_body.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
        body.validate().map_err(|_| PortError::invalid_data())?;
        let canonical_body = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
        let body_hash = Digest32::new(*sha256(&canonical_body).as_bytes());
        if canonical_body.as_slice() != event.canonical_body.as_bytes()
            || body_hash != event.body_hash
            || body.tenant_id != event.tenant_id
            || body.event_id != event.event_id
            || body.producer_id != event.producer_id
            || body.event_time_unix_ms != event.event_time_unix_ms
            || body.ingest_time_unix_ms != event.received_at_unix_ms
        {
            return Err(PortError::integrity_failure());
        }
        Ok(body)
    }

    fn verify_internal_event(
        &self,
        event: &UnverifiedSecurityEvent,
        body: &SecurityEventBody,
        enforce_freshness: bool,
    ) -> PortResult<VerifiedSecurityEvent> {
        let signed: SignedSecurityEvent = serde_json::from_slice(event.source_evidence.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
        let canonical_signed =
            canonical_json_bytes(&signed).map_err(|_| PortError::invalid_data())?;
        let trusted = self
            .trusted
            .get(&(event.tenant_id.clone(), event.producer_id.clone()))
            .ok_or_else(PortError::integrity_failure)?;
        let signature_valid = signed
            .verify_trusted_producer(
                &trusted.producer_id,
                &trusted.producer_key_id,
                &trusted.producer_key,
            )
            .map_err(|_| PortError::integrity_failure())?;
        if canonical_signed.as_slice() != event.source_evidence.as_bytes()
            || !signature_valid
            || signed.body() != body
            || body.policy_version != trusted.policy_version
            || body.trust_class != ProducerTrustClass::InternalDetector
        {
            return Err(PortError::integrity_failure());
        }
        if enforce_freshness {
            self.verify_time_bounds(event.event_time_unix_ms, event.received_at_unix_ms)?;
        }
        Ok(self.verified_event(
            event,
            ProducerTrustClass::InternalDetector,
            domain_hash(EVENT_EVIDENCE_HASH_DOMAIN, &canonical_signed),
        ))
    }

    fn verify_receipt_event(
        &self,
        event: &UnverifiedSecurityEvent,
        body: &SecurityEventBody,
        enforce_freshness: bool,
    ) -> PortResult<VerifiedSecurityEvent> {
        let receipt: ChioReceipt = serde_json::from_slice(event.source_evidence.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
        let canonical_receipt =
            canonical_json_bytes(&receipt).map_err(|_| PortError::invalid_data())?;
        let trusted = self
            .trusted_receipts
            .get(&(event.tenant_id.clone(), event.producer_id.clone()))
            .ok_or_else(PortError::integrity_failure)?;
        let signature_valid = receipt
            .verify_signature()
            .map_err(|_| PortError::integrity_failure())?;
        let projection_value = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("security_event_projection"))
            .cloned()
            .ok_or_else(PortError::integrity_failure)?;
        let projection: SecurityEventReceiptProjection =
            serde_json::from_value(projection_value).map_err(|_| PortError::integrity_failure())?;
        let expected_action = ToolCallAction::from_parameters(json!({
            "event_id": body.event_id.as_str(),
            "producer_id": body.producer_id.as_str(),
            "projection_version": SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
        }))
        .map_err(|_| PortError::invalid_data())?;
        let expected_metadata = json!({"security_event_projection": projection});
        let expected_content_hash = hex::encode(event.body_hash.as_bytes());
        if canonical_receipt.as_slice() != event.source_evidence.as_bytes()
            || !signature_valid
            || receipt.kernel_key != trusted.signer_key
            || body.producer_key_id != trusted.signer_key_id
            || body.trust_class != ProducerTrustClass::VerifiedReceipt
            || projection.version != SECURITY_EVENT_RECEIPT_PROJECTION_VERSION
            || projection.body != *body
            || receipt.timestamp != body.ingest_time_unix_ms / 1_000
            || receipt.capability_id != "chio.security-event.projection"
            || receipt.tool_server != "chio.kernel"
            || receipt.tool_name != "security_event"
            || receipt.action.parameters != expected_action.parameters
            || receipt.action.parameter_hash != expected_action.parameter_hash
            || receipt.decision.is_some()
            || receipt.receipt_kind != ReceiptKind::TraceObservation
            || receipt.boundary_class != BoundaryClass::DetectOnly
            || receipt.observation_outcome != Some(ObservationOutcome::Observed)
            || receipt.tool_origin != ToolOrigin::ChioInternal
            || receipt.redaction_mode != RedactionMode::Redacted
            || !receipt.actor_chain.is_empty()
            || !receipt.evidence.is_empty()
            || receipt.metadata.as_ref() != Some(&expected_metadata)
            || receipt.trust_level != TrustLevel::Verified
            || receipt.tenant_id.as_deref() != Some(body.tenant_id.as_str())
            || receipt.content_hash != expected_content_hash
            || receipt.bbs_projection_version.is_some()
            || receipt.bbs_signature.is_some()
        {
            return Err(PortError::integrity_failure());
        }
        if enforce_freshness {
            self.verify_time_bounds(event.event_time_unix_ms, event.received_at_unix_ms)?;
        }
        Ok(self.verified_event(
            event,
            ProducerTrustClass::VerifiedReceipt,
            domain_hash(RECEIPT_EVENT_EVIDENCE_HASH_DOMAIN, &canonical_receipt),
        ))
    }

    fn verify_durable(&self, event: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent> {
        self.ensure_ready()?;
        let body = self.parse_bound_body(event)?;
        match body.trust_class {
            ProducerTrustClass::InternalDetector => {
                self.verify_internal_event(event, &body, false)
            }
            ProducerTrustClass::VerifiedReceipt => {
                self.verify_receipt_event(event, &body, false)
            }
        }
    }
}

impl SecurityEventVerifierPort for NativeSecurityEventVerifier {
    fn verify(&self, event: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent> {
        self.ensure_ready()?;
        let body = self.parse_bound_body(event)?;
        match body.trust_class {
            ProducerTrustClass::InternalDetector => self.verify_internal_event(event, &body, true),
            ProducerTrustClass::VerifiedReceipt => self.verify_receipt_event(event, &body, true),
        }
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    Digest32::new(*sha256(&preimage).as_bytes())
}

pub trait AttestedFindingBatchPlanner: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;

    fn ensure_bootstrap_ready(&self) -> PortResult<()> {
        self.ensure_ready()
    }

    /// Atomically publishes one complete set of authoritative findings.
    ///
    /// Implementations must treat the ordered evidence-id set as the
    /// idempotency key and publish all reserved action and dispatch identities
    /// or none. Raw correlation output is intentionally absent from this
    /// interface.
    fn publish_attested_batch(
        &self,
        findings: &[AuthoritativeCorrelatedFindingEvidence],
    ) -> PortResult<()>;

    /// Read back the exact durable batch published under its tenant-scoped key.
    /// Implementations that cannot prove durable publication must fail closed
    /// rather than acknowledge and drop findings.
    fn load_published_attested_batch(
        &self,
        _key: &AttestedFindingBatchKey,
    ) -> PortResult<AttestedFindingBatchPublication> {
        Err(PortError::integrity_failure())
    }
}

fn build_attested_finding_batch_publication(
    findings: &[AuthoritativeCorrelatedFindingEvidence],
) -> PortResult<AttestedFindingBatchPublication> {
    let ordered_evidence_ids = findings
        .iter()
        .map(|finding| finding.evidence_id().clone())
        .collect::<Vec<_>>();
    let batch_id = derive_attested_finding_batch_id(&ordered_evidence_ids)?;
    let tenant_id = findings
        .first()
        .map(|finding| finding.body().header.tenant_id.clone())
        .ok_or_else(PortError::invalid_data)?;
    let mut bindings = Vec::with_capacity(findings.len());
    for (ordinal, finding) in findings.iter().enumerate() {
        let evidence_id = finding.evidence_id().clone();
        let receipt = finding.body();
        let action_id = derive_attested_finding_action_id(
            &batch_id,
            ordinal,
            &receipt.header.tenant_id,
            &evidence_id,
            &receipt.finding_id,
            &receipt.finding_hash,
        )?;
        let reservation_id =
            derive_attested_finding_reservation_id(&batch_id, &action_id, &evidence_id)?;
        bindings.push(AttestedFindingBatchBinding {
            tenant_id: receipt.header.tenant_id.clone(),
            evidence_id,
            finding_id: receipt.finding_id.clone(),
            finding_hash: receipt.finding_hash,
            action_id,
            reservation_id,
        });
    }
    let body = AttestedFindingBatchBody {
        schema_version: ATTESTED_FINDING_BATCH_SCHEMA_VERSION,
        batch_id,
        tenant_id,
        bindings: AttestedFindingBatchBindings::new(bindings)
            .map_err(|_| PortError::invalid_data())?,
    };
    validate_attested_finding_batch_body(&body)?;
    let canonical = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
    let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
    Ok(AttestedFindingBatchPublication {
        body,
        canonical_body: CanonicalBody::new(canonical).map_err(|_| PortError::invalid_data())?,
        body_hash,
    })
}

fn build_reserved_response_plan(
    finding: &AuthoritativeCorrelatedFindingEvidence,
    batch_id: &RecordId,
    ordinal: u32,
    binding: &AttestedFindingBatchBinding,
    policy: &dyn AttestedFindingResponsePolicyPlanner,
) -> PortResult<ReservedAttestedFindingResponsePlan> {
    validate_authoritative_finding_binding(finding, binding)?;
    let receipt = finding.body();
    let AttestedFindingResponsePolicySelection {
        affected_ids,
        effects,
        ttl_ms,
        created_at_unix_ms,
        operator_capability,
        approval_requirement,
        submitter,
        reason_hash,
        admission_artifact_ref,
    } = policy.select_response_policy(finding, binding)?;
    let response_plan = build_response_plan(ResponsePlanInput {
        action_id: binding.action_id.clone(),
        trigger_finding_id: receipt.finding_id.clone(),
        trigger_finding_hash: receipt.finding_hash,
        trigger_finding_receipt_id: binding.evidence_id.clone(),
        tenant_id: binding.tenant_id.clone(),
        policy_version: receipt.policy.policy_version.clone(),
        policy_hash: receipt.policy.policy_hash,
        affected_ids,
        effects,
        ttl_ms,
        created_at_unix_ms,
        operator_capability,
        approval_requirement,
        submitter,
        reason_hash,
    })
    .map_err(|_| PortError::invalid_data())?;
    if response_plan.action_id != binding.action_id
        || response_plan.trigger_finding_receipt_id != binding.evidence_id
        || response_plan.trigger_finding_id != binding.finding_id
        || response_plan.trigger_finding_hash != binding.finding_hash
        || response_plan.tenant_id != binding.tenant_id
    {
        return Err(PortError::integrity_failure());
    }
    Ok(ReservedAttestedFindingResponsePlan {
        finding: finding.clone(),
        batch_id: batch_id.clone(),
        ordinal,
        binding: binding.clone(),
        response_plan,
        admission_artifact_ref,
        admission_artifact_digest: None,
    })
}

fn validate_authoritative_finding_binding(
    finding: &AuthoritativeCorrelatedFindingEvidence,
    binding: &AttestedFindingBatchBinding,
) -> PortResult<()> {
    let receipt = finding.body();
    if binding.evidence_id != *finding.evidence_id()
        || binding.tenant_id != receipt.header.tenant_id
        || binding.finding_id != receipt.finding_id
        || binding.finding_hash != receipt.finding_hash
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn build_attested_finding_response_plan_publication(
    plan: &ReservedAttestedFindingResponsePlan,
) -> PortResult<AttestedFindingResponsePlanPublication> {
    let body = AttestedFindingResponsePlanBody {
        schema_version: ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION,
        batch_id: plan.batch_id().clone(),
        ordinal: plan.ordinal(),
        binding: plan.binding().clone(),
        response_plan: plan.response_plan().clone(),
        admission_artifact_ref: plan.admission_artifact_ref().clone(),
    };
    let canonical = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
    Ok(AttestedFindingResponsePlanPublication {
        body,
        body_hash: Digest32::new(*sha256(&canonical).as_bytes()),
        canonical_body: CanonicalBody::new(canonical).map_err(|_| PortError::invalid_data())?,
    })
}

/// Production adapter that publishes the complete ordered finding batch and a
/// durable response outbox. Batch bindings reserve planning identities only.
/// The kernel later derives the one authoritative execution dispatch identity.
pub struct VerifiedSecurityEventIngress {
    verifier: Arc<NativeSecurityEventVerifier>,
    store: Arc<SqliteSecurityStateStore>,
}

impl VerifiedSecurityEventIngress {
    pub fn new(
        verifier: Arc<NativeSecurityEventVerifier>,
        store: Arc<SqliteSecurityStateStore>,
    ) -> PortResult<Self> {
        verifier.ensure_ready()?;
        store.ensure_correlation_ingress_ready()?;
        Ok(Self { verifier, store })
    }
}

impl SecurityEventIngress for VerifiedSecurityEventIngress {
    fn verify_and_append(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<chio_security_types::ports::EventAppend> {
        let verified = SecurityEventVerifierPort::verify(self.verifier.as_ref(), event)?;
        self.store
            .enqueue_verified_correlation_event(event, &verified)
    }
}

/// Durable delivery loop from the authenticated ingress ledger into temporal
/// correlation. The source envelope is reverified on every recovery attempt;
/// acknowledgement happens only after correlation evidence and response work
/// have been durably read back by `ProductionCorrelationConsumer`.
pub(crate) struct DurableCorrelationIngress {
    store: Arc<dyn CorrelationIngressStore>,
    consumer: Arc<ProductionCorrelationConsumer>,
}

impl DurableCorrelationIngress {
    pub(crate) fn new(
        store: Arc<dyn CorrelationIngressStore>,
        consumer: Arc<ProductionCorrelationConsumer>,
    ) -> PortResult<Self> {
        store.ensure_correlation_ingress_ready()?;
        Ok(Self { store, consumer })
    }

    pub(crate) fn ensure_ready(&self) -> PortResult<()> {
        self.store.ensure_correlation_ingress_ready()
    }

    pub(crate) fn consume(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<CorrelationConsumerReport> {
        let verified = self.consumer.verify_live(event)?;
        self.store
            .enqueue_verified_correlation_event(event, &verified)?;
        let consumed = self.consumer.consume_verified(&verified)?;
        if consumed.finalized {
            self.store.acknowledge_correlated_event(event)?;
        }
        Ok(consumed.report)
    }

    pub(crate) fn drain_once(&self, max_results: u32) -> PortResult<u32> {
        let pending = self.store.load_pending_correlation_events(max_results)?;
        let mut acknowledged = 0_u32;
        for event in pending.as_slice() {
            let verified = self.consumer.verify_durable(event)?;
            self.store
                .validate_pending_correlation_event(event, &verified)?;
            let consumed = self.consumer.consume_verified(&verified)?;
            if consumed.finalized {
                self.store.acknowledge_correlated_event(event)?;
                acknowledged = acknowledged
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
            }
        }
        Ok(acknowledged)
    }

    pub(crate) fn drain_until_empty(
        &self,
        limits: AttestedFindingResponseRecoveryLimits,
    ) -> PortResult<u64> {
        let started = Instant::now();
        let mut acknowledged = 0_u64;
        while acknowledged < limits.max_startup_records {
            if u64::try_from(started.elapsed().as_millis())
                .map_or(true, |elapsed| elapsed > limits.max_startup_wall_clock_ms)
            {
                return Err(PortError::unavailable());
            }
            let remaining = limits.max_startup_records.saturating_sub(acknowledged);
            let max_results = u64::from(limits.max_records_per_pass)
                .min(remaining)
                .try_into()
                .map_err(|_| PortError::integrity_failure())?;
            let drained = self.drain_once(max_results)?;
            acknowledged = acknowledged
                .checked_add(u64::from(drained))
                .ok_or_else(PortError::integrity_failure)?;
            let pending = self.store.count_pending_correlation_events()?;
            if pending == 0 {
                return Ok(acknowledged);
            }
            if drained == 0 {
                // A bounded-lateness tail remains durably pending until the
                // worker clock advances its idle watermark.
                return Ok(acknowledged);
            }
        }
        if self.store.count_pending_correlation_events()? == 0 {
            Ok(acknowledged)
        } else {
            Err(PortError::unavailable())
        }
    }
}

trait CorrelationEventVerifier: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;
    fn now_unix_ms(&self) -> PortResult<u64>;
    fn verify(&self, event: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent>;
    fn verify_durable(&self, event: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent>;
}

impl CorrelationEventVerifier for NativeSecurityEventVerifier {
    fn ensure_ready(&self) -> PortResult<()> {
        NativeSecurityEventVerifier::ensure_ready(self)
    }

    fn now_unix_ms(&self) -> PortResult<u64> {
        self.clock.now_unix_ms()
    }

    fn verify(&self, event: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent> {
        SecurityEventVerifierPort::verify(self, event)
    }

    fn verify_durable(&self, event: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent> {
        NativeSecurityEventVerifier::verify_durable(self, event)
    }
}

trait CorrelationPort: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;
    fn accepts_policy(&self, policy_version: &RecordId) -> bool;
    fn correlate(
        &self,
        event: &VerifiedSecurityEvent,
        observed_at_unix_ms: u64,
    ) -> PortResult<Vec<RuleCorrelationOutcome>>;
}

trait CorrelationAttestor: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;
    fn attest(
        &self,
        outcome: &CorrelationOutcome,
    ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>>;
}

impl CorrelationAttestor for AttestedCorrelationWriter {
    fn ensure_ready(&self) -> PortResult<()> {
        AttestedCorrelationWriter::ensure_ready(self)
    }

    fn attest(
        &self,
        outcome: &CorrelationOutcome,
    ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
        self.attest_outcome(outcome)
    }
}

struct RuleCorrelationOutcome {
    rule_id: RuleId,
    outcome: CorrelationOutcome,
}

fn correlation_delivery_error(outcome: &CorrelationOutcome) -> Option<PortError> {
    outcome.detector_health.iter().find_map(|health| match health.kind {
        chio_security_types::DetectorHealthKind::StoreUnavailable
        | chio_security_types::DetectorHealthKind::TruncatedScan => {
            Some(PortError::unavailable())
        }
        chio_security_types::DetectorHealthKind::StoreConflict => Some(PortError::conflict()),
        chio_security_types::DetectorHealthKind::CorruptEvent
        | chio_security_types::DetectorHealthKind::CorruptState => {
            Some(PortError::integrity_failure())
        }
        chio_security_types::DetectorHealthKind::StateOverflow => None,
    })
}

struct SqliteTemporalCorrelationPort {
    store: Arc<SqliteSecurityStateStore>,
    correlator: TemporalCorrelator<SqliteSecurityStateStore>,
    rules: Vec<TemporalRule>,
}

impl SqliteTemporalCorrelationPort {
    fn new(
        store: Arc<SqliteSecurityStateStore>,
        policy: CorrelationPolicy,
        mut rules: Vec<TemporalRule>,
    ) -> PortResult<Self> {
        if rules.is_empty() {
            return Err(PortError::invalid_data());
        }
        rules.sort_by(|left, right| {
            (left.policy_version(), left.rule_id()).cmp(&(right.policy_version(), right.rule_id()))
        });
        if rules.windows(2).any(|pair| {
            pair[0].policy_version() == pair[1].policy_version()
                && pair[0].rule_id() == pair[1].rule_id()
        }) {
            return Err(PortError::invalid_data());
        }
        Ok(Self {
            store: Arc::clone(&store),
            correlator: TemporalCorrelator::new(store, policy),
            rules,
        })
    }
}

impl CorrelationPort for SqliteTemporalCorrelationPort {
    fn ensure_ready(&self) -> PortResult<()> {
        let tenant_id = TenantId::new("active-defense-readiness").map_err(PortError::from)?;
        let rule_id = RuleId::new("active-defense-readiness").map_err(PortError::from)?;
        self.store.scan_partition(&EventPartitionScan {
                tenant_id: tenant_id.clone(),
                rule_id: rule_id.clone(),
                partition_hash: Digest32::new([0_u8; 32]),
                after_event_time_unix_ms: None,
                after_event_id: None,
                through_event_time_unix_ms: 0,
                max_results: 1,
            })?;
        self.store
            .load_correlation_outcome(&chio_security_types::ports::CorrelationOutcomeKey {
                tenant_id,
                rule_id,
                event_id: chio_security_types::ports::EventId::new("active-defense-readiness")
                    .map_err(PortError::from)?,
            })
            .map(|_| ())
    }

    fn accepts_policy(&self, policy_version: &RecordId) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.policy_version() == policy_version)
    }

    fn correlate(
        &self,
        event: &VerifiedSecurityEvent,
        observed_at_unix_ms: u64,
    ) -> PortResult<Vec<RuleCorrelationOutcome>> {
        let body: SecurityEventBody = serde_json::from_slice(event.canonical_body.as_bytes())
            .map_err(|_| PortError::integrity_failure())?;
        body.validate()
            .map_err(|_| PortError::integrity_failure())?;
        let mut outcomes = Vec::new();
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.policy_version() == &body.policy_version)
        {
            let outcome = match self.correlator.load_durable_outcome(rule, event)? {
                Some(outcome) => outcome,
                None => {
                    let attempted =
                        self.correlator
                            .ingest_observed_at(rule, event, observed_at_unix_ms);
                    self.correlator
                        .load_durable_outcome(rule, event)?
                        .unwrap_or(attempted)
                }
            };
            outcomes.push(RuleCorrelationOutcome {
                rule_id: rule.rule_id().clone(),
                outcome,
            });
        }
        if outcomes.is_empty() {
            return Err(PortError::integrity_failure());
        }
        Ok(outcomes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationRuleReport {
    pub rule_id: RuleId,
    pub status: CorrelationStatus,
    pub automatic_response_suppressed: bool,
    pub watermark_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationConsumerReport {
    pub event_id: chio_security_types::ports::EventId,
    pub rules: Vec<CorrelationRuleReport>,
    pub attested_finding_ids: Vec<OpaqueReceiptRef>,
}

struct CorrelationConsumption {
    report: CorrelationConsumerReport,
    finalized: bool,
}

pub struct ProductionCorrelationConsumer {
    verifier: Arc<dyn CorrelationEventVerifier>,
    correlation: Arc<dyn CorrelationPort>,
    attestor: Arc<dyn CorrelationAttestor>,
    planner: Arc<dyn AttestedFindingBatchPlanner>,
}

impl ProductionCorrelationConsumer {
    pub fn new(
        verifier: Arc<NativeSecurityEventVerifier>,
        security_store: Arc<SqliteSecurityStateStore>,
        correlation_policy: CorrelationPolicy,
        rules: Vec<TemporalRule>,
        attestor: Arc<AttestedCorrelationWriter>,
        planner: Arc<DurableAttestedFindingBatchPlanner>,
    ) -> PortResult<Self> {
        let rule_policy_versions: BTreeSet<_> = rules
            .iter()
            .map(|rule| rule.policy_version().clone())
            .collect();
        if verifier.max_future_skew_ms > correlation_policy.bounded_lateness_ms()
            || verifier
                .trusted
                .values()
                .any(|producer| !rule_policy_versions.contains(&producer.policy_version))
        {
            return Err(PortError::invalid_data());
        }
        let correlation = Arc::new(SqliteTemporalCorrelationPort::new(
            security_store,
            correlation_policy,
            rules,
        )?);
        let consumer = Self {
            verifier,
            correlation,
            attestor,
            planner,
        };
        consumer.ensure_bootstrap_ready()?;
        Ok(consumer)
    }

    #[cfg(test)]
    fn from_parts(
        verifier: Arc<dyn CorrelationEventVerifier>,
        correlation: Arc<dyn CorrelationPort>,
        attestor: Arc<dyn CorrelationAttestor>,
        planner: Arc<dyn AttestedFindingBatchPlanner>,
    ) -> PortResult<Self> {
        let consumer = Self {
            verifier,
            correlation,
            attestor,
            planner,
        };
        consumer.ensure_ready()?;
        Ok(consumer)
    }

    pub(crate) fn ensure_bootstrap_ready(&self) -> PortResult<()> {
        self.verifier.ensure_ready()?;
        self.correlation.ensure_ready()?;
        self.attestor.ensure_ready()?;
        self.planner.ensure_bootstrap_ready()
    }

    pub fn ensure_ready(&self) -> PortResult<()> {
        self.verifier.ensure_ready()?;
        self.correlation.ensure_ready()?;
        self.attestor.ensure_ready()?;
        self.planner.ensure_ready()
    }

    #[cfg(test)]
    fn consume(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<CorrelationConsumerReport> {
        self.ensure_ready()?;
        let verified = self.verifier.verify(event)?;
        self.consume_verified_after_ready(&verified)
            .map(|consumed| consumed.report)
    }

    fn verify_live(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<VerifiedSecurityEvent> {
        let verified = self.verifier.verify(event)?;
        self.ensure_supported_policy(&verified)?;
        Ok(verified)
    }

    fn verify_durable(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<VerifiedSecurityEvent> {
        self.ensure_ready()?;
        let verified = self.verifier.verify_durable(event)?;
        self.ensure_supported_policy(&verified)?;
        Ok(verified)
    }

    fn ensure_supported_policy(&self, verified: &VerifiedSecurityEvent) -> PortResult<()> {
        let body: SecurityEventBody = serde_json::from_slice(verified.canonical_body.as_bytes())
            .map_err(|_| PortError::integrity_failure())?;
        if self.correlation.accepts_policy(&body.policy_version) {
            Ok(())
        } else {
            Err(PortError::integrity_failure())
        }
    }

    fn consume_verified(
        &self,
        verified: &VerifiedSecurityEvent,
    ) -> PortResult<CorrelationConsumption> {
        self.ensure_ready()?;
        self.consume_verified_after_ready(verified)
    }

    fn consume_verified_after_ready(
        &self,
        verified: &VerifiedSecurityEvent,
    ) -> PortResult<CorrelationConsumption> {
        let observed_at_unix_ms = self.verifier.now_unix_ms()?;
        let outcomes = self
            .correlation
            .correlate(verified, observed_at_unix_ms)?;
        let mut reports = Vec::with_capacity(outcomes.len());
        let mut authoritative = Vec::new();
        let mut evidence_ids = BTreeSet::new();
        let mut attested_finding_ids = Vec::new();
        let mut delivery_error = None;
        let mut finalized = true;
        for correlated in outcomes {
            let deferred = correlated.outcome.status == CorrelationStatus::Deferred;
            finalized &= !deferred;
            if delivery_error.is_none() {
                delivery_error = correlation_delivery_error(&correlated.outcome);
            }
            reports.push(CorrelationRuleReport {
                rule_id: correlated.rule_id,
                status: correlated.outcome.status,
                automatic_response_suppressed: correlated.outcome.automatic_response_suppressed,
                watermark_unix_ms: correlated.outcome.watermark_unix_ms,
            });
            if deferred {
                continue;
            }
            for finding in self.attestor.attest(&correlated.outcome)? {
                if !evidence_ids.insert(finding.evidence_id().clone()) {
                    return Err(PortError::integrity_failure());
                }
                attested_finding_ids.push(finding.evidence_id().clone());
                authoritative.push(finding);
            }
        }
        if let Some(error) = delivery_error {
            return Err(error);
        }
        if !authoritative.is_empty() {
            self.planner.publish_attested_batch(&authoritative)?;
            let expected = build_attested_finding_batch_publication(&authoritative)?;
            let persisted =
                self.planner
                    .load_published_attested_batch(&AttestedFindingBatchKey {
                        tenant_id: expected.body.tenant_id.clone(),
                        batch_id: expected.body.batch_id.clone(),
                    })?;
            if persisted != expected || persisted.body.bindings.len() != authoritative.len() {
                return Err(PortError::integrity_failure());
            }
        }
        Ok(CorrelationConsumption {
            report: CorrelationConsumerReport {
                event_id: verified.event_id.clone(),
                rules: reports,
                attested_finding_ids,
            },
            finalized,
        })
    }
}
