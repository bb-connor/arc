use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{PublicKey, SigningBackend};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    ActiveDefenseResponseBinding, SchedulerHealthReceiptBody,
};
use chio_kernel::{
    ActiveResponseExecutorError, ActiveResponseFindingAuthority,
    ActiveResponseFindingAuthorityError, ActiveResponseReceiptProofSource,
    AuthoritativeCorrelatedFindingEvidence, IndexedSecurityEvidenceStore, ReceiptStoreError,
};
use chio_quarantine::decode_response_record;
use chio_security_types::ports::{
    AlertDeliveryQuery, AlertDeliveryStatus, Digest32, ExactReceiptRecord,
    ExactSecurityReceiptSink, OpaqueReceiptRef, PortError, PortResult, ReceiptAppendRequest,
    RecordId, ResponsePlanKey, ResponseStore, SchedulerHealthPageRequest, SchedulerHealthPort,
    SecurityAlert, SecurityAlertPort, SecurityReceiptSink, TenantId,
};
use chio_siem::{Alert, AlertBackend, AlertSeverity};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tokio::sync::Mutex as AsyncMutex;

mod delivery;

const RECEIPT_READINESS_DOMAIN: &[u8] = b"chio.native-security-receipt-readiness.v1\0";
const ALERT_OUTBOX_SCHEMA_VERSION: u8 = 1;
const OUTBOX_TABLE: &str = "chio_security_alert_outbox";
const BACKEND_DELIVERY_TABLE: &str = "chio_security_alert_outbox_backend";

/// Signs validated Chio-native active-defense bodies and persists the signed
/// Chio receipt through the configured authoritative receipt store.
pub struct NativeSecurityReceiptSink {
    store: Arc<dyn IndexedSecurityEvidenceStore>,
    signer: Arc<dyn SigningBackend>,
}

impl NativeSecurityReceiptSink {
    #[must_use]
    pub fn new(
        store: Arc<dyn IndexedSecurityEvidenceStore>,
        signer: Arc<dyn SigningBackend>,
    ) -> Self {
        Self { store, signer }
    }

    fn validate_request(request: &ReceiptAppendRequest) -> PortResult<ActiveDefenseReceiptBody> {
        let body: ActiveDefenseReceiptBody = chio_core::canonical::UntrustedJsonText::from_wire(
            request.canonical_body.as_bytes(),
            64 * 1024 * 1024,
        )
        .and_then(|input| input.decode_signed())
        .map_err(|error| {
            PortError::with_source(
                chio_security_types::ports::PortErrorKind::InvalidData,
                error.code(),
                error,
            )
        })?;
        let canonical = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
        if canonical.as_slice() != request.canonical_body.as_bytes()
            || body.header().tenant_id != request.tenant_id
            || body.header().transition_id != request.transition_id
            || body.header().occurred_at_unix_ms != request.occurred_at_unix_ms
            || body.kind().as_str() != request.evidence_type.as_str()
            || body.body_digest().map_err(|_| PortError::invalid_data())? != request.body_hash
            || body.evidence_id().map_err(|_| PortError::invalid_data())? != request.evidence_id
        {
            return Err(PortError::integrity_failure());
        }
        Ok(body)
    }

    fn build_signed_receipt(
        &self,
        request: &ReceiptAppendRequest,
        body: &ActiveDefenseReceiptBody,
    ) -> PortResult<ChioReceipt> {
        let (receipt_kind, boundary_class, observation_outcome, decision, trust_level) =
            receipt_semantics(body);
        let action = ToolCallAction::from_parameters(json!({
            "evidence_id": request.evidence_id.as_str(),
            "kind": body.kind().as_str(),
            "transition_id": request.transition_id.as_str(),
        }))
        .map_err(|_| PortError::invalid_data())?;
        let metadata = json!({
            "active_defense_body": body,
            "active_defense_evidence_id": request.evidence_id.as_str(),
            "occurred_at_unix_ms": request.occurred_at_unix_ms,
        });
        let receipt_body = ChioReceiptBody {
            id: String::new(),
            timestamp: request.occurred_at_unix_ms / 1_000,
            capability_id: "chio.active-defense.system".to_owned(),
            tool_server: "chio.kernel".to_owned(),
            tool_name: body.kind().as_str().to_owned(),
            action,
            decision,
            receipt_kind,
            boundary_class,
            observation_outcome,
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
            content_hash: hex::encode(request.body_hash.as_bytes()),
            policy_hash: hex::encode(policy_hash(body).as_bytes()),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level,
            tenant_id: Some(request.tenant_id.as_str().to_owned()),
            kernel_key: self
                .signer
                .public_key()
                .map_err(|_| PortError::unavailable())?,
            bbs_projection_version: None,
        };
        ChioReceipt::sign_with_backend(receipt_body, self.signer.as_ref())
            .map_err(|_| PortError::unavailable())
    }
}

impl SecurityReceiptSink for NativeSecurityReceiptSink {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        self.store
            .ensure_indexed_security_evidence_ready()
            .map_err(|_| PortError::unavailable())?;
        self.signer
            .sign_bytes(RECEIPT_READINESS_DOMAIN)
            .map_err(|_| PortError::unavailable())?;
        Ok(())
    }

    fn sign_and_append(
        &self,
        request: &ReceiptAppendRequest,
    ) -> PortResult<chio_security_types::ports::OpaqueReceiptRef> {
        if let Some(existing) = ExactSecurityReceiptSink::load_exact(self, &request.evidence_id)? {
            return if existing.receipt == *request {
                Ok(request.evidence_id.clone())
            } else {
                Err(PortError::conflict())
            };
        }
        let body = Self::validate_request(request)?;
        let signed = self.build_signed_receipt(request, &body)?;
        let persisted = self
            .store
            .append_indexed_security_evidence(&request.evidence_id, &signed)
            .map_err(map_append_error)?;
        verify_native_security_receipt(
            &request.evidence_id,
            &body,
            &persisted,
            &[self
                .signer
                .public_key()
                .map_err(|_| PortError::unavailable())?],
        )
        .map_err(|_| PortError::integrity_failure())?;
        tracing::debug!(target: "chio::response_lifecycle",
            boundary = "receipt_persisted", tenant_id = request.tenant_id.as_str(),
            evidence_id = request.evidence_id.as_str(), transition_id = request.transition_id.as_str(),
            body_hash = hex::encode(request.body_hash.as_bytes()));
        Ok(request.evidence_id.clone())
    }
}

impl ExactSecurityReceiptSink for NativeSecurityReceiptSink {
    fn load_exact(&self, evidence_id: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>> {
        let Some(signed) = self
            .store
            .load_indexed_security_evidence(evidence_id)
            .map_err(map_append_error)?
        else {
            return Ok(None);
        };
        let body =
            extract_active_defense_body(&signed).map_err(|_| PortError::integrity_failure())?;
        verify_native_security_receipt(
            evidence_id,
            &body,
            &signed,
            &[self
                .signer
                .public_key()
                .map_err(|_| PortError::unavailable())?],
        )
        .map_err(|_| PortError::integrity_failure())?;
        let receipt = active_defense_append_request(&body)?;
        if receipt.evidence_id != *evidence_id {
            return Err(PortError::integrity_failure());
        }
        let canonical_signed =
            canonical_json_bytes(&signed).map_err(|_| PortError::integrity_failure())?;
        let durable_record_hash = Digest32::new(*chio_core::sha256(&canonical_signed).as_bytes());
        if durable_record_hash.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(PortError::integrity_failure());
        }
        Ok(Some(ExactReceiptRecord {
            receipt,
            durable_record_hash,
        }))
    }
}

impl ActiveResponseReceiptProofSource for NativeSecurityReceiptSink {
    fn ensure_active_response_receipt_proofs_ready(
        &self,
    ) -> Result<(), ActiveResponseExecutorError> {
        self.store
            .ensure_indexed_security_evidence_ready()
            .map_err(|error| {
                ActiveResponseExecutorError::NotReady(format!(
                    "signed active-response receipt index is unavailable: {error}"
                ))
            })
    }

    fn load_signed_active_response_receipt(
        &self,
        evidence_id: &OpaqueReceiptRef,
    ) -> Result<Option<ChioReceipt>, ActiveResponseExecutorError> {
        self.store
            .load_indexed_security_evidence(evidence_id)
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "signed active-response receipt readback failed: {error}"
                ))
            })
    }
}

/// Scheduler health adapter that persists a native causal receipt before the
/// operator page is handed to the external alert outbox.
pub struct NativeSchedulerHealthPort {
    store: Arc<dyn ResponseStore>,
    inner: Arc<dyn SchedulerHealthPort>,
    receipts: Arc<dyn SecurityReceiptSink>,
}

impl NativeSchedulerHealthPort {
    #[must_use]
    pub fn new(
        store: Arc<dyn ResponseStore>,
        inner: Arc<dyn SchedulerHealthPort>,
        receipts: Arc<dyn SecurityReceiptSink>,
    ) -> Self {
        Self {
            store,
            inner,
            receipts,
        }
    }

    fn receipt_body(
        &self,
        request: &SchedulerHealthPageRequest,
    ) -> PortResult<ActiveDefenseReceiptBody> {
        if request.event_id != request.alert.event_id
            || request.idempotency_key != request.alert.idempotency_key
            || request.first_failure_at_unix_ms != request.alert.occurred_at_unix_ms
            || request.tenant_id != request.alert.tenant_id
            || request.first_failure_at_unix_ms > request.occurred_at_unix_ms
            || request.attempts == 0
            || request.scheduler_fencing_token == 0
        {
            return Err(PortError::integrity_failure());
        }
        let key = ResponsePlanKey {
            tenant_id: request.tenant_id.clone(),
            action_id: request.action_id.clone(),
        };
        let record = self
            .store
            .load_plan(&key)?
            .ok_or_else(PortError::integrity_failure)?;
        let snapshot =
            decode_response_record(&record).map_err(|_| PortError::integrity_failure())?;
        let cursor = self
            .store
            .load_receipt_cursor(&key)?
            .ok_or_else(PortError::integrity_failure)?;
        if snapshot.plan.tenant_id != request.tenant_id
            || snapshot.plan.action_id != request.action_id
            || cursor.tenant_id != request.tenant_id
            || cursor.action_id != request.action_id
            || cursor.plan_hash != snapshot.plan.plan_hash
            || cursor.generation
                != u64::try_from(snapshot.mutations.len())
                    .map_err(|_| PortError::integrity_failure())?
        {
            return Err(PortError::integrity_failure());
        }
        scheduler_health_body(request, &snapshot, cursor.current_evidence_id)
    }
}

impl SchedulerHealthPort for NativeSchedulerHealthPort {
    fn ensure_scheduler_health_ready(&self) -> PortResult<()> {
        self.receipts.ensure_receipts_ready()?;
        self.inner.ensure_scheduler_health_ready()
    }

    fn page_once(&self, request: &SchedulerHealthPageRequest) -> PortResult<AlertDeliveryStatus> {
        let body = self.receipt_body(request)?;
        let append = active_defense_append_request(&body)?;
        let appended = self.receipts.sign_and_append(&append)?;
        if appended != append.evidence_id {
            return Err(PortError::integrity_failure());
        }
        self.inner.page_once(request)
    }

    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>> {
        self.inner.load_delivery(query)
    }
}

fn scheduler_health_body(
    request: &SchedulerHealthPageRequest,
    snapshot: &chio_security_types::ResponseSnapshot,
    prior_receipt_id: chio_security_types::ports::OpaqueReceiptRef,
) -> PortResult<ActiveDefenseReceiptBody> {
    let transition_commitment = json!({
        "attempts": request.attempts,
        "error_code": request.error_code.as_str(),
        "event_id": request.event_id.as_str(),
        "observed_at_unix_ms": request.occurred_at_unix_ms,
        "page_idempotency_key": request.idempotency_key.as_str(),
        "scheduler_fencing_token": request.scheduler_fencing_token,
    });
    let transition_bytes =
        canonical_json_bytes(&transition_commitment).map_err(|_| PortError::invalid_data())?;
    let transition_id = RecordId::new(format!(
        "scheduler-health-observation-{}",
        chio_core::sha256(&transition_bytes).to_hex()
    ))
    .map_err(|_| PortError::invalid_data())?;
    let body = ActiveDefenseReceiptBody::SchedulerHealth(SchedulerHealthReceiptBody {
        header: ActiveDefenseReceiptHeader::new(
            request.occurred_at_unix_ms,
            request.tenant_id.clone(),
            transition_id,
            vec![prior_receipt_id],
        )
        .map_err(|_| PortError::invalid_data())?,
        response: ActiveDefenseResponseBinding {
            policy: ActiveDefensePolicyBinding {
                policy_version: snapshot.plan.policy_version.clone(),
                policy_hash: snapshot.plan.policy_hash,
            },
            plan_hash: snapshot.plan.plan_hash,
            action_id: snapshot.plan.action_id.clone(),
            trigger_finding_id: snapshot.plan.trigger_finding_id.clone(),
            trigger_finding_hash: snapshot.plan.trigger_finding_hash,
            trigger_finding_receipt_id: snapshot.plan.trigger_finding_receipt_id.clone(),
            affected_set_hash: snapshot.plan.affected_set_hash,
            plan_expires_at_unix_ms: snapshot.plan.expires_at_unix_ms,
        },
        event_id: request.event_id.clone(),
        first_failure_at_unix_ms: request.first_failure_at_unix_ms,
        attempts: request.attempts,
        scheduler_fencing_token: request.scheduler_fencing_token,
        error_code: request.error_code.clone(),
        evidence_hash: request.alert.evidence_hash,
    });
    body.validate()
        .map_err(|_| PortError::integrity_failure())?;
    Ok(body)
}

fn active_defense_append_request(
    body: &ActiveDefenseReceiptBody,
) -> PortResult<ReceiptAppendRequest> {
    body.validate().map_err(|_| PortError::invalid_data())?;
    let canonical = canonical_json_bytes(body).map_err(|_| PortError::invalid_data())?;
    Ok(ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: RecordId::new(body.kind().as_str())
            .map_err(|_| PortError::invalid_data())?,
        evidence_id: body.evidence_id().map_err(|_| PortError::invalid_data())?,
        canonical_body: chio_security_types::ports::CanonicalBody::new(canonical)
            .map_err(|_| PortError::invalid_data())?,
        body_hash: body.body_digest().map_err(|_| PortError::invalid_data())?,
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeFindingAuthorityConfigError {
    #[error("native finding authority requires at least one trusted receipt signer")]
    MissingTrustedSigner,
}

/// Production active-response authority backed only by the durable logical
/// evidence index. Raw correlator output never enters this authority.
pub struct NativeActiveResponseFindingAuthority {
    store: Arc<dyn IndexedSecurityEvidenceStore>,
    trusted_receipt_signers: Vec<PublicKey>,
}

impl NativeActiveResponseFindingAuthority {
    pub fn new(
        store: Arc<dyn IndexedSecurityEvidenceStore>,
        trusted_receipt_signers: Vec<PublicKey>,
    ) -> Result<Self, NativeFindingAuthorityConfigError> {
        let mut deduplicated = Vec::with_capacity(trusted_receipt_signers.len());
        for signer in trusted_receipt_signers {
            if !deduplicated.contains(&signer) {
                deduplicated.push(signer);
            }
        }
        if deduplicated.is_empty() {
            return Err(NativeFindingAuthorityConfigError::MissingTrustedSigner);
        }
        Ok(Self {
            store,
            trusted_receipt_signers: deduplicated,
        })
    }

    fn verify_correlated_finding(
        &self,
        evidence_id: &chio_security_types::ports::OpaqueReceiptRef,
        receipt: &ChioReceipt,
    ) -> Result<AuthoritativeCorrelatedFindingEvidence, ActiveResponseFindingAuthorityError> {
        let body = extract_active_defense_body(receipt)?;
        let ActiveDefenseReceiptBody::CorrelatedFinding(finding) = body else {
            return Err(ActiveResponseFindingAuthorityError::Integrity(
                "indexed evidence is not a correlated-finding receipt".to_string(),
            ));
        };
        verify_native_security_receipt(
            evidence_id,
            &ActiveDefenseReceiptBody::CorrelatedFinding(finding.clone()),
            receipt,
            &self.trusted_receipt_signers,
        )?;
        AuthoritativeCorrelatedFindingEvidence::from_verified_signed_receipt(
            evidence_id.clone(),
            finding,
        )
    }
}

impl ActiveResponseFindingAuthority for NativeActiveResponseFindingAuthority {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
        self.store
            .ensure_indexed_security_evidence_ready()
            .map_err(|error| {
                ActiveResponseFindingAuthorityError::Unavailable(format!(
                    "indexed finding store readiness failed: {error}"
                ))
            })
    }

    fn load_correlated_finding(
        &self,
        evidence_id: &chio_security_types::ports::OpaqueReceiptRef,
    ) -> Result<Option<AuthoritativeCorrelatedFindingEvidence>, ActiveResponseFindingAuthorityError>
    {
        let receipt = self
            .store
            .load_indexed_security_evidence(evidence_id)
            .map_err(map_finding_store_error)?;
        receipt
            .as_ref()
            .map(|receipt| self.verify_correlated_finding(evidence_id, receipt))
            .transpose()
    }
}

fn map_append_error(error: ReceiptStoreError) -> PortError {
    match error {
        ReceiptStoreError::Conflict(_)
        | ReceiptStoreError::Canonical(_)
        | ReceiptStoreError::CryptoDecode(_)
        | ReceiptStoreError::Json(_) => PortError::integrity_failure(),
        _ => PortError::unavailable(),
    }
}

fn map_finding_store_error(error: ReceiptStoreError) -> ActiveResponseFindingAuthorityError {
    match error {
        ReceiptStoreError::Conflict(_)
        | ReceiptStoreError::Canonical(_)
        | ReceiptStoreError::CryptoDecode(_)
        | ReceiptStoreError::Json(_) => {
            ActiveResponseFindingAuthorityError::Integrity(error.to_string())
        }
        _ => ActiveResponseFindingAuthorityError::Unavailable(error.to_string()),
    }
}

fn extract_active_defense_body(
    receipt: &ChioReceipt,
) -> Result<ActiveDefenseReceiptBody, ActiveResponseFindingAuthorityError> {
    let body = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("active_defense_body"))
        .cloned()
        .ok_or_else(|| {
            ActiveResponseFindingAuthorityError::Integrity(
                "indexed receipt is missing its closed active-defense body".to_string(),
            )
        })?;
    serde_json::from_value(body).map_err(|error| {
        ActiveResponseFindingAuthorityError::Integrity(format!(
            "indexed active-defense body is malformed: {error}"
        ))
    })
}

fn verify_native_security_receipt(
    evidence_id: &chio_security_types::ports::OpaqueReceiptRef,
    body: &ActiveDefenseReceiptBody,
    receipt: &ChioReceipt,
    trusted_receipt_signers: &[PublicKey],
) -> Result<(), ActiveResponseFindingAuthorityError> {
    let signature_valid = receipt.verify_signature().map_err(|error| {
        ActiveResponseFindingAuthorityError::Integrity(format!(
            "indexed receipt signature verification failed: {error}"
        ))
    })?;
    let metadata = receipt.metadata.as_ref().ok_or_else(|| {
        ActiveResponseFindingAuthorityError::Integrity(
            "indexed receipt is missing active-defense metadata".to_string(),
        )
    })?;
    let metadata_evidence_id = metadata
        .get("active_defense_evidence_id")
        .and_then(serde_json::Value::as_str);
    let metadata_time = metadata
        .get("occurred_at_unix_ms")
        .and_then(serde_json::Value::as_u64);
    let extracted_body = extract_active_defense_body(receipt)?;
    let derived_evidence_id = extracted_body.evidence_id().map_err(|error| {
        ActiveResponseFindingAuthorityError::Integrity(format!(
            "indexed receipt evidence ID derivation failed: {error}"
        ))
    })?;
    let body_digest = body.body_digest().map_err(|error| {
        ActiveResponseFindingAuthorityError::Integrity(format!(
            "indexed receipt body digest failed: {error}"
        ))
    })?;
    let expected_action = ToolCallAction::from_parameters(json!({
        "evidence_id": evidence_id.as_str(),
        "kind": body.kind().as_str(),
        "transition_id": body.header().transition_id.as_str(),
    }))
    .map_err(|error| {
        ActiveResponseFindingAuthorityError::Integrity(format!(
            "indexed receipt action derivation failed: {error}"
        ))
    })?;
    let expected_metadata = json!({
        "active_defense_body": body,
        "active_defense_evidence_id": evidence_id.as_str(),
        "occurred_at_unix_ms": body.header().occurred_at_unix_ms,
    });
    let (
        expected_receipt_kind,
        expected_boundary_class,
        expected_observation_outcome,
        expected_decision,
        expected_trust_level,
    ) = receipt_semantics(body);
    let expected_policy_hash = hex::encode(policy_hash(body).as_bytes());
    if !signature_valid
        || !trusted_receipt_signers.contains(&receipt.kernel_key)
        || &extracted_body != body
        || &derived_evidence_id != evidence_id
        || metadata_evidence_id != Some(evidence_id.as_str())
        || metadata_time != Some(body.header().occurred_at_unix_ms)
        || receipt.capability_id != "chio.active-defense.system"
        || receipt.tool_server != "chio.kernel"
        || receipt.tool_name != body.kind().as_str()
        || receipt.tool_origin != ToolOrigin::ChioInternal
        || receipt.timestamp != body.header().occurred_at_unix_ms / 1_000
        || receipt.action.parameters != expected_action.parameters
        || receipt.action.parameter_hash != expected_action.parameter_hash
        || receipt.receipt_kind != expected_receipt_kind
        || receipt.boundary_class != expected_boundary_class
        || receipt.observation_outcome != expected_observation_outcome
        || receipt.decision != expected_decision
        || receipt.redaction_mode != RedactionMode::Redacted
        || receipt.trust_level != expected_trust_level
        || !receipt.actor_chain.is_empty()
        || !receipt.evidence.is_empty()
        || receipt.bbs_projection_version.is_some()
        || receipt.bbs_signature.is_some()
        || metadata != &expected_metadata
        || receipt.tenant_id.as_deref() != Some(body.header().tenant_id.as_str())
        || receipt.content_hash != hex::encode(body_digest.as_bytes())
        || receipt.policy_hash != expected_policy_hash
    {
        return Err(ActiveResponseFindingAuthorityError::Integrity(
            "indexed active-defense receipt binding is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn receipt_semantics(
    body: &ActiveDefenseReceiptBody,
) -> (
    ReceiptKind,
    BoundaryClass,
    Option<ObservationOutcome>,
    Option<Decision>,
    TrustLevel,
) {
    match body {
        ActiveDefenseReceiptBody::FlowDenial(_) => (
            ReceiptKind::MediatedDecision,
            BoundaryClass::Prevent,
            None,
            Some(Decision::Deny {
                reason: "active-defense flow policy denied the request".to_owned(),
                guard: "chio.flow".to_owned(),
            }),
            TrustLevel::Mediated,
        ),
        ActiveDefenseReceiptBody::ResponsePlan(_) => (
            ReceiptKind::AdvisoryEvaluation,
            BoundaryClass::AdvisoryOnly,
            Some(ObservationOutcome::Evaluated),
            None,
            TrustLevel::Advisory,
        ),
        _ => (
            ReceiptKind::TraceObservation,
            BoundaryClass::DetectOnly,
            Some(ObservationOutcome::Observed),
            None,
            TrustLevel::Verified,
        ),
    }
}

fn policy_hash(body: &ActiveDefenseReceiptBody) -> &Digest32 {
    match body {
        ActiveDefenseReceiptBody::FlowDenial(body) => &body.policy.policy_hash,
        ActiveDefenseReceiptBody::DeclassificationConsumption(body) => &body.policy.policy_hash,
        ActiveDefenseReceiptBody::DeclassificationOutcome(body) => &body.policy.policy_hash,
        ActiveDefenseReceiptBody::TripwireObservation(body) => &body.policy.policy_hash,
        ActiveDefenseReceiptBody::CorrelatedFinding(body) => &body.policy.policy_hash,
        ActiveDefenseReceiptBody::ResponsePlan(body) => &body.response.policy.policy_hash,
        ActiveDefenseReceiptBody::ResponseStateTransition(body) => {
            &body.response.policy.policy_hash
        }
        ActiveDefenseReceiptBody::EffectTransition(body) => &body.response.policy.policy_hash,
        ActiveDefenseReceiptBody::ResponseCompletion(body) => &body.response.policy.policy_hash,
        ActiveDefenseReceiptBody::LiftRollbackCompletion(body) => &body.response.policy.policy_hash,
        ActiveDefenseReceiptBody::DetectorHealth(body) => &body.policy.policy_hash,
        ActiveDefenseReceiptBody::SchedulerHealth(body) => &body.response.policy.policy_hash,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlertOutboxConfig {
    pub base_retry_ms: u64,
    pub max_retry_ms: u64,
    pub max_attempts: u32,
}

impl Default for AlertOutboxConfig {
    fn default() -> Self {
        Self {
            base_retry_ms: 1_000,
            max_retry_ms: 300_000,
            max_attempts: 12,
        }
    }
}

impl AlertOutboxConfig {
    fn validate(self) -> PortResult<Self> {
        if self.base_retry_ms == 0
            || self.max_retry_ms == 0
            || self.base_retry_ms > self.max_retry_ms
            || self.max_attempts == 0
        {
            return Err(PortError::invalid_data());
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AlertDispatchReport {
    /// Due rows processed by the call; always `delivered + failed`.
    pub attempted: usize,
    /// Rows confirmed by every configured backend.
    pub delivered: usize,
    /// Rows left pending because at least one backend dispatch failed.
    pub failed: usize,
    /// Failed rows that reached `max_attempts` and are no longer due.
    pub parked: usize,
    /// Backend dispatches issued, at most one per row and unconfirmed backend.
    pub backend_dispatches: usize,
    /// Backend dispatches that failed.
    pub backend_failures: usize,
}

/// Undelivered rows of the security paging outbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AlertOutboxBacklog {
    /// Rows that are due now or will be retried under backoff.
    pub pending: u64,
    /// Rows that exhausted their delivery attempts. They are never dispatched
    /// again and stay parked until an operator resolves them.
    pub parked: u64,
}

/// SQLite-backed security paging outbox. `page` means durable admission only;
/// actual backend delivery advances the row from pending to delivered.
///
/// A row becomes delivered only after every configured backend has confirmed
/// it. Each backend outcome is recorded durably per row, so a retry dispatches
/// only to the backends that have not confirmed the row.
pub struct SqliteSiemOutbox {
    connection: Arc<Mutex<Connection>>,
    backends: Vec<Arc<dyn AlertBackend>>,
    config: AlertOutboxConfig,
    delivery_lock: Arc<AsyncMutex<()>>,
}

impl SqliteSiemOutbox {
    pub fn open(
        path: impl AsRef<Path>,
        backends: Vec<Arc<dyn AlertBackend>>,
        config: AlertOutboxConfig,
    ) -> PortResult<Self> {
        let config = config.validate()?;
        validate_backends(&backends)?;
        let connection = Connection::open(path).map_err(|_| PortError::unavailable())?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| PortError::unavailable())?;
        verify_backend_table(&connection)?;
        connection
            .execute_batch(&outbox_schema_sql())
            .map_err(|_| PortError::unavailable())?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            backends,
            config,
            delivery_lock: Arc::new(AsyncMutex::new(())),
        })
    }

    fn connection(&self) -> PortResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| PortError::unavailable())
    }

    fn ensure_ready(&self) -> PortResult<()> {
        validate_backends(&self.backends)?;
        let connection = self.connection()?;
        delivery::store::ensure_ready(&connection)
    }

    fn page_alert(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
        validate_alert(alert)?;
        let canonical = canonical_json_bytes(alert).map_err(|_| PortError::invalid_data())?;
        let command_hash = chio_core::sha256(&canonical);
        let occurred_at = sqlite_time(alert.occurred_at_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PortError::unavailable())?;
        let existing = load_status(
            &transaction,
            alert.idempotency_key.as_str(),
            &canonical,
            command_hash.as_bytes(),
        )?;
        let status = match existing {
            Some(status) => status,
            None => {
                transaction
                    .execute(
                        &format!(
                            "INSERT INTO {OUTBOX_TABLE}
                             (idempotency_key, command_json, command_hash, status, attempts,
                              next_attempt_at_unix_ms, delivered_at_unix_ms)
                             VALUES (?1, ?2, ?3, 'pending', 0, ?4, NULL)"
                        ),
                        params![
                            alert.idempotency_key.as_str(),
                            canonical.as_slice(),
                            command_hash.as_bytes().as_slice(),
                            occurred_at
                        ],
                    )
                    .map_err(|_| PortError::unavailable())?;
                let expected = AlertDeliveryStatus::Pending {
                    attempts: 0,
                    next_attempt_at_unix_ms: alert.occurred_at_unix_ms,
                };
                if load_status(
                    &transaction,
                    alert.idempotency_key.as_str(),
                    &canonical,
                    command_hash.as_bytes(),
                )? != Some(expected)
                {
                    return Err(PortError::integrity_failure());
                }
                expected
            }
        };
        transaction.commit().map_err(|_| PortError::unavailable())?;
        Ok(status)
    }

    fn load_alert_delivery(
        &self,
        query: &AlertDeliveryQuery,
    ) -> PortResult<Option<AlertDeliveryStatus>> {
        validate_alert(&query.alert)?;
        let canonical =
            canonical_json_bytes(&query.alert).map_err(|_| PortError::invalid_data())?;
        let command_hash = chio_core::sha256(&canonical);
        let connection = self.connection()?;
        load_status(
            &*connection,
            query.alert.idempotency_key.as_str(),
            &canonical,
            command_hash.as_bytes(),
        )
    }

    pub(super) fn load_persisted_alert_command(
        &self,
        tenant_id: &TenantId,
        idempotency_key: &RecordId,
    ) -> PortResult<Option<(SecurityAlert, AlertDeliveryStatus)>> {
        let connection = self.connection()?;
        let Some((command_json, command_hash, _, _, _, _)) =
            query_status_connection(&connection, idempotency_key.as_str())
                .map_err(|_| PortError::unavailable())?
        else {
            return Ok(None);
        };
        let alert: SecurityAlert =
            chio_core::canonical::UntrustedJsonText::from_wire(&command_json, 64 * 1024 * 1024)
                .and_then(|input| input.decode_signed())
                .map_err(|error| {
                    PortError::with_source(
                        chio_security_types::ports::PortErrorKind::IntegrityFailure,
                        error.code(),
                        error,
                    )
                })?;
        let canonical = canonical_json_bytes(&alert).map_err(|_| PortError::integrity_failure())?;
        let actual_hash = chio_core::sha256(&canonical);
        if canonical != command_json
            || actual_hash.as_bytes().as_slice() != command_hash
            || &alert.tenant_id != tenant_id
            || &alert.idempotency_key != idempotency_key
            || validate_alert(&alert).is_err()
        {
            return Err(PortError::integrity_failure());
        }
        let status = load_status(
            &*connection,
            idempotency_key.as_str(),
            &canonical,
            actual_hash.as_bytes(),
        )?
        .ok_or_else(PortError::integrity_failure)?;
        Ok(Some((alert, status)))
    }

    /// Per-backend outcome of a paged alert, keyed by backend name. A backend
    /// appears once it has been dispatched to: `Delivered` after it confirmed
    /// the alert, otherwise `Pending` with its dispatch count and the row's next
    /// attempt time (`i64::MAX` once the row is parked or no longer retried).
    pub fn load_backend_deliveries(
        &self,
        query: &AlertDeliveryQuery,
    ) -> PortResult<Option<BTreeMap<String, AlertDeliveryStatus>>> {
        validate_alert(&query.alert)?;
        let canonical =
            canonical_json_bytes(&query.alert).map_err(|_| PortError::invalid_data())?;
        let command_hash = chio_core::sha256(&canonical);
        let idempotency_key = query.alert.idempotency_key.as_str();
        let connection = self.connection()?;
        let Some(status) = load_status(
            &*connection,
            idempotency_key,
            &canonical,
            command_hash.as_bytes(),
        )?
        else {
            return Ok(None);
        };
        let retry_at_unix_ms = match status {
            AlertDeliveryStatus::Pending {
                next_attempt_at_unix_ms,
                ..
            } => next_attempt_at_unix_ms,
            AlertDeliveryStatus::Delivered { .. } => parked_at_unix_ms()?,
        };
        let records = load_backend_records(&connection, idempotency_key, command_hash.as_bytes())?;
        Ok(Some(
            records
                .into_iter()
                .map(|(backend, record)| {
                    let status = match record.delivered_at_unix_ms {
                        Some(delivered_at_unix_ms) => AlertDeliveryStatus::Delivered {
                            attempts: record.attempts,
                            delivered_at_unix_ms,
                        },
                        None => AlertDeliveryStatus::Pending {
                            attempts: record.attempts,
                            next_attempt_at_unix_ms: retry_at_unix_ms,
                        },
                    };
                    (backend, status)
                })
                .collect(),
        ))
    }

    /// Durable count of undelivered rows. A row is parked once it reached
    /// `max_attempts` or carries the parked retry time, so rows parked under an
    /// earlier configuration stay counted after a restart.
    pub fn backlog(&self) -> PortResult<AlertOutboxBacklog> {
        let connection = self.connection()?;
        delivery::store::backlog(&connection, self.config)
    }
}

impl SecurityAlertPort for SqliteSiemOutbox {
    fn ensure_alerts_ready(&self) -> PortResult<()> {
        self.ensure_ready()
    }

    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
        self.page_alert(alert)
    }

    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>> {
        self.load_alert_delivery(query)
    }
}

impl SchedulerHealthPort for SqliteSiemOutbox {
    fn ensure_scheduler_health_ready(&self) -> PortResult<()> {
        self.ensure_ready()
    }

    fn page_once(&self, request: &SchedulerHealthPageRequest) -> PortResult<AlertDeliveryStatus> {
        if request.event_id != request.alert.event_id
            || request.idempotency_key != request.alert.idempotency_key
            || request.first_failure_at_unix_ms != request.alert.occurred_at_unix_ms
            || request.tenant_id != request.alert.tenant_id
            || request.first_failure_at_unix_ms > request.occurred_at_unix_ms
            || request.attempts == 0
            || request.scheduler_fencing_token == 0
            || request.alert.action_id_hash.is_none()
        {
            return Err(PortError::integrity_failure());
        }
        self.page_alert(&request.alert)
    }

    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>> {
        self.load_alert_delivery(query)
    }
}

struct OutboxRow {
    alert: SecurityAlert,
    command_hash: Vec<u8>,
    attempts: u32,
}

struct BackendRecord {
    attempts: u32,
    delivered_at_unix_ms: Option<u64>,
}

fn load_backend_records(
    connection: &Connection,
    idempotency_key: &str,
    command_hash: &[u8],
) -> PortResult<BTreeMap<String, BackendRecord>> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT backend_name, command_hash, status, attempts, delivered_at_unix_ms
             FROM {BACKEND_DELIVERY_TABLE} WHERE idempotency_key = ?1"
        ))
        .map_err(|_| PortError::unavailable())?;
    let mut rows = statement
        .query([idempotency_key])
        .map_err(|_| PortError::unavailable())?;
    let mut records = BTreeMap::new();
    while let Some(row) = rows.next().map_err(|_| PortError::unavailable())? {
        let backend: String = row.get(0).map_err(|_| PortError::invalid_data())?;
        let stored_hash: Vec<u8> = row.get(1).map_err(|_| PortError::invalid_data())?;
        let status: String = row.get(2).map_err(|_| PortError::invalid_data())?;
        let attempts: i64 = row.get(3).map_err(|_| PortError::invalid_data())?;
        let delivered_at: Option<i64> = row.get(4).map_err(|_| PortError::invalid_data())?;
        if stored_hash != command_hash {
            return Err(PortError::integrity_failure());
        }
        let attempts = u32::try_from(attempts)
            .ok()
            .filter(|attempts| *attempts > 0)
            .ok_or_else(PortError::integrity_failure)?;
        let delivered_at_unix_ms = match (status.as_str(), delivered_at) {
            ("pending", None) => None,
            ("delivered", Some(delivered_at)) => {
                Some(u64::try_from(delivered_at).map_err(|_| PortError::integrity_failure())?)
            }
            _ => return Err(PortError::integrity_failure()),
        };
        if records
            .insert(
                backend,
                BackendRecord {
                    attempts,
                    delivered_at_unix_ms,
                },
            )
            .is_some()
        {
            return Err(PortError::integrity_failure());
        }
    }
    Ok(records)
}

type CatalogEntry = (String, String, String, Option<String>);

fn outbox_schema_sql() -> String {
    format!(
        "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 CREATE TABLE IF NOT EXISTS {OUTBOX_TABLE} (
                    idempotency_key TEXT PRIMARY KEY NOT NULL,
                    command_json BLOB NOT NULL,
                    command_hash BLOB NOT NULL CHECK(typeof(command_hash) = 'blob' AND length(command_hash) = 32),
                    status TEXT NOT NULL CHECK(status IN ('pending', 'delivered')),
                    attempts INTEGER NOT NULL CHECK(attempts >= 0),
                    next_attempt_at_unix_ms INTEGER NOT NULL CHECK(next_attempt_at_unix_ms >= 0),
                    delivered_at_unix_ms INTEGER,
                    CHECK((status = 'pending' AND delivered_at_unix_ms IS NULL)
                       OR (status = 'delivered' AND delivered_at_unix_ms IS NOT NULL))
                 );
                 CREATE INDEX IF NOT EXISTS idx_chio_security_alert_outbox_due
                 ON {OUTBOX_TABLE}(status, next_attempt_at_unix_ms, idempotency_key);
                 CREATE TABLE IF NOT EXISTS {BACKEND_DELIVERY_TABLE} (
                    idempotency_key TEXT NOT NULL
                        REFERENCES {OUTBOX_TABLE}(idempotency_key),
                    backend_name TEXT NOT NULL CHECK(typeof(backend_name) = 'text' AND length(backend_name) > 0 AND instr(backend_name, char(0)) = 0),
                    command_hash BLOB NOT NULL CHECK(typeof(command_hash) = 'blob' AND length(command_hash) = 32),
                    status TEXT NOT NULL CHECK(status IN ('pending', 'delivered')),
                    attempts INTEGER NOT NULL CHECK(attempts > 0),
                    delivered_at_unix_ms INTEGER,
                    PRIMARY KEY (idempotency_key, backend_name),
                    CHECK((status = 'pending' AND delivered_at_unix_ms IS NULL)
                       OR (status = 'delivered' AND delivered_at_unix_ms IS NOT NULL))
                 );"
    )
}

/// Reports whether the backend outcome table exists. Any schema object under
/// its name must match the declared table exactly (columns, composite key,
/// foreign key, checks and indexes), so a foreign table is refused before it
/// can hold confirmations.
fn verify_backend_table(connection: &Connection) -> PortResult<bool> {
    let catalog = backend_table_catalog(connection)?;
    if catalog.is_empty() {
        return Ok(false);
    }
    if catalog != expected_backend_table_catalog()? {
        return Err(PortError::integrity_failure());
    }
    Ok(true)
}

fn expected_backend_table_catalog() -> PortResult<&'static [CatalogEntry]> {
    static EXPECTED: OnceLock<PortResult<Vec<CatalogEntry>>> = OnceLock::new();
    EXPECTED
        .get_or_init(|| {
            let reference = Connection::open_in_memory().map_err(|_| PortError::unavailable())?;
            reference
                .execute_batch(&outbox_schema_sql())
                .map_err(|_| PortError::unavailable())?;
            backend_table_catalog(&reference)
        })
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}

fn backend_table_catalog(connection: &Connection) -> PortResult<Vec<CatalogEntry>> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_master
             WHERE lower(name) = ?1 OR lower(tbl_name) = ?1
             ORDER BY type, name, tbl_name
             LIMIT 8",
        )
        .map_err(|_| PortError::unavailable())?;
    let mut rows = statement
        .query([BACKEND_DELIVERY_TABLE])
        .map_err(|_| PortError::unavailable())?;
    let mut catalog = Vec::new();
    while let Some(row) = rows.next().map_err(|_| PortError::unavailable())? {
        catalog.push((
            row.get(0).map_err(|_| PortError::invalid_data())?,
            row.get(1).map_err(|_| PortError::invalid_data())?,
            row.get(2).map_err(|_| PortError::invalid_data())?,
            row.get(3).map_err(|_| PortError::invalid_data())?,
        ));
    }
    Ok(catalog)
}

fn parked_at_unix_ms() -> PortResult<u64> {
    u64::try_from(i64::MAX).map_err(|_| PortError::integrity_failure())
}

fn increment(counter: &mut usize) -> PortResult<()> {
    *counter = counter
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    Ok(())
}

fn validate_backends(backends: &[Arc<dyn AlertBackend>]) -> PortResult<()> {
    if backends.is_empty() {
        return Err(PortError::unavailable());
    }
    let mut names = BTreeSet::new();
    for backend in backends {
        let name = backend.name();
        if name.is_empty() || name.trim() != name || !names.insert(name.to_owned()) {
            return Err(PortError::invalid_data());
        }
    }
    Ok(())
}

fn validate_alert(alert: &SecurityAlert) -> PortResult<()> {
    if alert.occurred_at_unix_ms == 0
        || digest_is_zero(&alert.finding_id_hash)
        || digest_is_zero(&alert.evidence_hash)
        || alert.action_id_hash.as_ref().is_some_and(digest_is_zero)
    {
        return Err(PortError::invalid_data());
    }
    sqlite_time(alert.occurred_at_unix_ms)?;
    Ok(())
}

fn digest_is_zero(digest: &Digest32) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn sqlite_time(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

type AlertDeliveryStatusRow = (Vec<u8>, Vec<u8>, String, i64, i64, Option<i64>);

trait StatusConnection {
    fn query_status(
        &self,
        idempotency_key: &str,
    ) -> rusqlite::Result<Option<AlertDeliveryStatusRow>>;
}

impl StatusConnection for Connection {
    fn query_status(
        &self,
        idempotency_key: &str,
    ) -> rusqlite::Result<Option<AlertDeliveryStatusRow>> {
        query_status_connection(self, idempotency_key)
    }
}

impl<'connection> StatusConnection for Transaction<'connection> {
    fn query_status(
        &self,
        idempotency_key: &str,
    ) -> rusqlite::Result<Option<AlertDeliveryStatusRow>> {
        query_status_connection(self, idempotency_key)
    }
}

fn query_status_connection(
    connection: &Connection,
    idempotency_key: &str,
) -> rusqlite::Result<Option<AlertDeliveryStatusRow>> {
    connection
        .query_row(
            &format!(
                "SELECT command_json, command_hash, status, attempts,
                        next_attempt_at_unix_ms, delivered_at_unix_ms
                 FROM {OUTBOX_TABLE} WHERE idempotency_key = ?1"
            ),
            [idempotency_key],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
}

fn load_status(
    connection: &impl StatusConnection,
    idempotency_key: &str,
    expected_json: &[u8],
    expected_hash: &[u8],
) -> PortResult<Option<AlertDeliveryStatus>> {
    let Some((command_json, command_hash, status, attempts, next_attempt, delivered_at)) =
        connection
            .query_status(idempotency_key)
            .map_err(|_| PortError::unavailable())?
    else {
        return Ok(None);
    };
    if command_json != expected_json || command_hash != expected_hash {
        return Err(PortError::conflict());
    }
    let attempts = u32::try_from(attempts).map_err(|_| PortError::integrity_failure())?;
    match (status.as_str(), delivered_at) {
        ("pending", None) => Ok(Some(AlertDeliveryStatus::Pending {
            attempts,
            next_attempt_at_unix_ms: u64::try_from(next_attempt)
                .map_err(|_| PortError::integrity_failure())?,
        })),
        ("delivered", Some(delivered_at)) => Ok(Some(AlertDeliveryStatus::Delivered {
            attempts,
            delivered_at_unix_ms: u64::try_from(delivered_at)
                .map_err(|_| PortError::integrity_failure())?,
        })),
        _ => Err(PortError::integrity_failure()),
    }
}

fn retry_delay(config: AlertOutboxConfig, attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(63);
    let multiplier = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    config
        .base_retry_ms
        .saturating_mul(multiplier)
        .min(config.max_retry_ms)
}

fn backend_alert(alert: &SecurityAlert) -> PortResult<Alert> {
    let receipt_json = serde_json::to_value(alert).map_err(|_| PortError::invalid_data())?;
    Ok(Alert {
        summary: format!("Chio security alert: {}", alert.alert_type.as_str()),
        severity: AlertSeverity::Critical,
        dedup_key: alert.idempotency_key.as_str().to_owned(),
        guard: "chio.active-defense".to_owned(),
        tool_name: alert.alert_type.as_str().to_owned(),
        tool_server: "chio.kernel".to_owned(),
        receipt_id: alert.event_id.as_str().to_owned(),
        receipt_json: json!({
            "schema_version": ALERT_OUTBOX_SCHEMA_VERSION,
            "alert": receipt_json,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::scheduler_health_body;
    use super::*;
    use chio_quarantine::build_response_plan;
    use chio_security_types::ports::{
        ActionId, CanonicalBody, Digest32, ErrorCode, OpaqueReceiptRef, RecordId,
        SchedulerHealthPageRequest, SecurityAlert, TenantId,
    };
    use chio_security_types::{
        OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
        ResponseEffectSpec, ResponseMutationLog, ResponsePlanInput, ResponseSnapshot,
        ResponseState, ResponseTarget, RESPONSE_STATE_SCHEMA_VERSION,
    };

    fn digest(byte: u8) -> Digest32 {
        Digest32::new([byte; 32])
    }

    fn record(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
    }

    #[test]
    fn outbox_command_hash_refuses_nul_padded_text() -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(&outbox_schema_sql())?;
        let insert = format!(
            "INSERT INTO {OUTBOX_TABLE} (idempotency_key, command_json, command_hash, status, \
             attempts, next_attempt_at_unix_ms) VALUES ('key', x'7b7d', ?1, 'pending', 0, 0)"
        );
        let padded = connection.execute(
            &insert,
            [rusqlite::types::Value::Text(format!(
                "{}\0{}",
                "a".repeat(32),
                "a".repeat(1 << 20)
            ))],
        );
        assert!(
            matches!(
                &padded,
                Err(rusqlite::Error::SqliteFailure(error, Some(_)))
                    if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_CHECK
            ),
            "{padded:?}"
        );
        assert_eq!(
            connection.execute(&insert, [rusqlite::types::Value::Blob(vec![1; 32])])?,
            1
        );
        Ok(())
    }

    #[test]
    fn scheduler_health_page_projects_runtime_retry_and_plan_into_closed_receipt() {
        let tenant_id = TenantId::new("tenant-scheduler-native")
            .unwrap_or_else(|error| panic!("tenant: {error}"));
        let contribution_bytes = chio_core::canonical_json_bytes(&serde_json::json!({
            "severity": "critical",
        }))
        .unwrap_or_else(|error| panic!("contribution: {error}"));
        let contribution_hash = Digest32::new(*chio_core::sha256(&contribution_bytes).as_bytes());
        let plan = build_response_plan(ResponsePlanInput {
            execution: chio_security_types::ResponseExecutionBinding::new(
                chio_security_types::ResponseExecutionMode::Live,
            ),
            action_id: ActionId::new("action-scheduler-native")
                .unwrap_or_else(|error| panic!("action: {error}")),
            trigger_finding_id: record("finding-scheduler-native"),
            trigger_finding_hash: digest(2),
            trigger_finding_receipt_id: OpaqueReceiptRef::new("finding-receipt-scheduler-native")
                .unwrap_or_else(|error| panic!("finding receipt: {error}")),
            tenant_id: tenant_id.clone(),
            policy_version: record("policy-scheduler-native-v1"),
            policy_hash: digest(3),
            affected_ids: vec![record("affected-scheduler-native")],
            effects: vec![ResponseEffectSpec {
                kind: ResponseEffectKind::EscalateAlert,
                target: ResponseTarget::Tenant {
                    tenant_id: tenant_id.clone(),
                },
                canonical_contribution: CanonicalBody::new(contribution_bytes)
                    .unwrap_or_else(|error| panic!("canonical contribution: {error}")),
                contribution_hash,
                observed_base_version_hash: digest(4),
            }],
            ttl_ms: 60_000,
            created_at_unix_ms: 1_700_000_000_000,
            operator_capability: OperatorCapabilityBinding {
                capability_id: record("capability-scheduler-native"),
                capability_digest: digest(5),
                expires_at_unix_ms: 1_700_000_060_000,
                executor_subject: record("executor-scheduler-native"),
            },
            approval_requirement: ResponseApprovalRequirement::Automatic,
            submitter: record("submitter-scheduler-native"),
            reason_hash: digest(6),
        })
        .unwrap_or_else(|error| panic!("response plan: {error}"));
        let snapshot = ResponseSnapshot {
            schema_version: RESPONSE_STATE_SCHEMA_VERSION,
            plan: plan.clone(),
            execution_dispatch: None,
            dispatch_authorization_hash: None,
            state: ResponseState::Applying,
            generation: 4,
            applying_lease_expires_at_unix_ms: Some(1_700_000_050_000),
            due_at_unix_ms: Some(plan.expires_at_unix_ms),
            operator_page_required: true,
            mutations: ResponseMutationLog::new(Vec::new())
                .unwrap_or_else(|error| panic!("mutations: {error}")),
        };
        let event_id = record("scheduler-health-event-native");
        let idempotency_key = record("scheduler-health-page-native");
        let request = SchedulerHealthPageRequest {
            event_id: event_id.clone(),
            idempotency_key: idempotency_key.clone(),
            occurred_at_unix_ms: 1_700_000_020_000,
            tenant_id: tenant_id.clone(),
            action_id: plan.action_id.clone(),
            first_failure_at_unix_ms: 1_700_000_010_000,
            attempts: 4,
            scheduler_fencing_token: 19,
            error_code: ErrorCode::new(
                chio_security_types::DispatchRejection::CapabilityDigestMismatch.code(),
            )
            .unwrap_or_else(|error| panic!("error code: {error}")),
            alert: SecurityAlert {
                tenant_id,
                event_id,
                idempotency_key,
                occurred_at_unix_ms: 1_700_000_010_000,
                alert_type: record("response_scheduler_unavailable"),
                finding_id_hash: digest(7),
                action_id_hash: Some(digest(8)),
                evidence_hash: digest(9),
            },
        };

        let body = scheduler_health_body(
            &request,
            &snapshot,
            OpaqueReceiptRef::new("prior-response-native")
                .unwrap_or_else(|error| panic!("prior receipt: {error}")),
        )
        .unwrap_or_else(|error| panic!("scheduler health body: {error}"));
        let directory = chio_test_support::private_tempdir()
            .unwrap_or_else(|error| panic!("receipt directory: {error}"));
        let store = Arc::new(
            chio_store_sqlite::SqliteReceiptStore::open(directory.path().join("receipts.db"))
                .unwrap_or_else(|error| panic!("receipt store: {error}")),
        );
        let signer = Arc::new(chio_core::Ed25519Backend::new(
            chio_core::Keypair::from_seed(&[31; 32]),
        ));
        let sink = NativeSecurityReceiptSink::new(store.clone(), signer.clone());
        let append = active_defense_append_request(&body)
            .unwrap_or_else(|error| panic!("append request: {error}"));
        let evidence_id = sink
            .sign_and_append(&append)
            .unwrap_or_else(|error| panic!("signed receipt: {error}"));
        let signed = store
            .load_indexed_security_evidence(&evidence_id)
            .unwrap_or_else(|error| panic!("load receipt: {error}"))
            .unwrap_or_else(|| panic!("signed evidence missing"));
        verify_native_security_receipt(
            &evidence_id,
            &body,
            &signed,
            &[signer
                .public_key()
                .unwrap_or_else(|error| panic!("signer key: {error}"))],
        )
        .unwrap_or_else(|error| panic!("verify signed reason: {error}"));
        let mut changed = body.clone();
        if let ActiveDefenseReceiptBody::SchedulerHealth(ref mut health) = changed {
            health.error_code = ErrorCode::new("substituted.reason")
                .unwrap_or_else(|error| panic!("reason: {error}"));
        }
        assert!(matches!(
            verify_native_security_receipt(
                &evidence_id,
                &changed,
                &signed,
                &[signer
                    .public_key()
                    .unwrap_or_else(|error| panic!("signer key: {error}"))]
            ),
            Err(ActiveResponseFindingAuthorityError::Integrity(_))
        ));
        let chio_core::receipt::security::ActiveDefenseReceiptBody::SchedulerHealth(body) = body
        else {
            panic!("scheduler health page must emit a scheduler-health body");
        };
        assert_eq!(body.response.plan_hash, plan.plan_hash);
        assert_eq!(body.attempts, 4);
        assert_eq!(body.scheduler_fencing_token, 19);
        assert_eq!(
            body.error_code.as_str(),
            chio_security_types::DispatchRejection::CapabilityDigestMismatch.code()
        );
        assert_eq!(body.evidence_hash, digest(9));
        assert_eq!(
            body.header.prior_receipt_ids.as_slice()[0].as_str(),
            "prior-response-native"
        );
    }
}
