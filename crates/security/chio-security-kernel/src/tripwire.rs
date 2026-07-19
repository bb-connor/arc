// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::receipt::metadata::GuardEvidence;
use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    TripwireObservationReceiptBody,
};
use chio_core::sha256;
use chio_core::{canonical_json_bytes, SigningBackend};
use chio_core_types::SignedSecurityEvent;
use chio_decoy::{
    DecoyDetection, DecoyDetector, DetectionFailure, ObservationClass, TripwireObservation,
    WatermarkObservationContext, WatermarkScanError, WatermarkScanVerdict, WatermarkVerifier,
};
use chio_kernel::{
    Guard, GuardContext, GuardDecision, KernelError, PostInvocationContext,
    PostInvocationInspection, PostInvocationVerdict, SecurityInvocationContextV1, ToolCallRequest,
};
use chio_security_types::ports::{
    CanonicalBody, Digest32, EventAppend, EventId, OpaqueReceiptRef, PortError, PortResult,
    ProducerId, ProducerTrustClass, ReceiptAppendRequest, RecordId, RequestId, SecurityReceiptSink,
    TripwireDecision, TripwireInput, TripwireKind, UnverifiedSecurityEvent,
};
use chio_security_types::{
    DecoySurface, SecurityEventBody, SecurityEventBodyInput, SecurityEventKind, SecuritySeverity,
    SecuritySubject,
};
use serde::Serialize;
use serde_json::Value;

use crate::MissingContextPolicy;

const PRE_INVOCATION_GUARD_NAME: &str = "chio-tripwire-pre-invocation";
const POST_INVOCATION_HOOK_NAME: &str = "chio-watermark-tripwire";

pub trait SecurityClock: Send + Sync {
    fn now_unix_ms(&self) -> PortResult<u64>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSecurityClock;

impl SecurityClock for SystemSecurityClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PortError::unavailable())?;
        u64::try_from(duration.as_millis()).map_err(|_| PortError::invalid_data())
    }
}

/// Verification boundary for detector-signed events.
///
/// Implementations must authenticate `source_evidence` against independently
/// trusted producer configuration before appending any verified event state.
pub trait SecurityEventIngress: Send + Sync {
    fn verify_and_append(&self, event: &UnverifiedSecurityEvent) -> PortResult<EventAppend>;
}

pub struct TripwireEventPublisher {
    ingress: Arc<dyn SecurityEventIngress>,
    clock: Arc<dyn SecurityClock>,
    signer: Arc<dyn SigningBackend>,
    producer_id: ProducerId,
    producer_key_id: RecordId,
    policy_version: RecordId,
    receipt_evidence: Option<TripwireReceiptEvidence>,
}

struct TripwireReceiptEvidence {
    sink: Arc<dyn SecurityReceiptSink>,
    policy_hash: Digest32,
}

impl TripwireEventPublisher {
    pub fn new(
        ingress: Arc<dyn SecurityEventIngress>,
        clock: Arc<dyn SecurityClock>,
        signer: Arc<dyn SigningBackend>,
        producer_id: ProducerId,
        producer_key_id: RecordId,
        policy_version: RecordId,
    ) -> PortResult<Self> {
        if signer.public_key().algorithm() != signer.algorithm() {
            return Err(PortError::integrity_failure());
        }
        Ok(Self {
            ingress,
            clock,
            signer,
            producer_id,
            producer_key_id,
            policy_version,
            receipt_evidence: None,
        })
    }

    pub fn with_receipt_evidence(
        mut self,
        sink: Arc<dyn SecurityReceiptSink>,
        policy_hash: Digest32,
    ) -> PortResult<Self> {
        if policy_hash.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(PortError::invalid_data());
        }
        sink.ensure_receipts_ready()?;
        self.receipt_evidence = Some(TripwireReceiptEvidence { sink, policy_hash });
        Ok(self)
    }
}

pub struct DecoyTripwireDetectorPort {
    decoy: Option<Arc<DecoyDetector>>,
    watermark: Option<Arc<WatermarkVerifier>>,
    clock: Arc<dyn SecurityClock>,
}

impl DecoyTripwireDetectorPort {
    #[must_use]
    pub fn new(
        decoy: Arc<DecoyDetector>,
        watermark: Arc<WatermarkVerifier>,
        clock: Arc<dyn SecurityClock>,
    ) -> Self {
        Self {
            decoy: Some(decoy),
            watermark: Some(watermark),
            clock,
        }
    }

    #[must_use]
    pub fn decoy_only(decoy: Arc<DecoyDetector>, clock: Arc<dyn SecurityClock>) -> Self {
        Self {
            decoy: Some(decoy),
            watermark: None,
            clock,
        }
    }

    #[must_use]
    pub fn watermark_only(
        watermark: Arc<WatermarkVerifier>,
        clock: Arc<dyn SecurityClock>,
    ) -> Self {
        Self {
            decoy: None,
            watermark: Some(watermark),
            clock,
        }
    }

    fn detect_decoy(&self, input: &TripwireInput) -> PortResult<TripwireDecision> {
        let detector = self.decoy.as_ref().ok_or_else(PortError::unavailable)?;
        let surface = match input.kind {
            TripwireKind::CanaryCapability => DecoySurface::CanaryCapability,
            TripwireKind::HoneyTool => DecoySurface::HoneyTool,
            TripwireKind::CredentialArtifact => DecoySurface::CredentialArtifact,
            TripwireKind::FileMarker => DecoySurface::FileMarker,
            TripwireKind::BrowserCookie => DecoySurface::BrowserCookie,
            TripwireKind::InternalHostname => DecoySurface::InternalHostname,
            TripwireKind::SignedWatermark => return Err(PortError::invalid_data()),
        };
        let observation = TripwireObservation {
            tenant_id: &input.tenant_id,
            surface,
            presented: input.content.as_bytes(),
            class: ObservationClass::DirectPresentation,
            observed_at_unix_ms: self.clock.now_unix_ms()?,
        };
        match detector
            .detect(&observation)
            .map_err(map_detection_failure)?
        {
            DecoyDetection::ActiveMatch { evidence, .. } => Ok(TripwireDecision::Match {
                artifact_id_hash: evidence.artifact_id_hash,
                artifact_version_hash: evidence.version_hash,
            }),
            DecoyDetection::InactiveObservation { .. } | DecoyDetection::Clear => {
                Ok(TripwireDecision::Clear)
            }
        }
    }

    fn detect_watermark(&self, input: &TripwireInput) -> PortResult<TripwireDecision> {
        let verifier = self.watermark.as_ref().ok_or_else(PortError::unavailable)?;
        let text =
            std::str::from_utf8(input.content.as_bytes()).map_err(|_| PortError::invalid_data())?;
        let observed_at_unix_ms = self.clock.now_unix_ms()?;
        let observation_digest = domain_digest(
            b"chio.security.watermark-observation.v1\0",
            input.request_id.as_str().as_bytes(),
        );
        let observation_id = RecordId::new(format!(
            "watermark-observation-{}",
            hex_digest(observation_digest)
        ))
        .map_err(|_| PortError::invalid_data())?;
        let evidence_ref = RecordId::new(format!(
            "watermark-evidence-{}",
            hex_digest(input.canonical_context_digest)
        ))
        .map_err(|_| PortError::invalid_data())?;
        let report = verifier
            .scan_text(
                text,
                &WatermarkObservationContext {
                    observing_tenant_id: input.tenant_id.clone(),
                    observation_id,
                    evidence_ref,
                    observed_at_unix_ms,
                },
            )
            .map_err(map_watermark_error)?;
        if report.verdict != WatermarkScanVerdict::ActiveHit {
            return Ok(TripwireDecision::Clear);
        }
        let hit = report
            .active_hits
            .first()
            .ok_or_else(PortError::integrity_failure)?;
        Ok(TripwireDecision::Match {
            artifact_id_hash: hit.evidence.artifact_id_hash,
            artifact_version_hash: hit.evidence.version_hash,
        })
    }
}

impl chio_security_types::ports::TripwireDetectorPort for DecoyTripwireDetectorPort {
    fn detect(&self, input: &TripwireInput) -> PortResult<TripwireDecision> {
        if digest(input.content.as_bytes()) != input.content_digest {
            return Err(PortError::integrity_failure());
        }
        match input.kind {
            TripwireKind::SignedWatermark => self.detect_watermark(input),
            _ => self.detect_decoy(input),
        }
    }
}

pub struct TripwireGuard {
    detector: Arc<dyn chio_security_types::ports::TripwireDetectorPort>,
    publisher: Arc<TripwireEventPublisher>,
    missing_context: MissingContextPolicy,
}

impl TripwireGuard {
    #[must_use]
    pub fn new(
        detector: Arc<dyn chio_security_types::ports::TripwireDetectorPort>,
        publisher: Arc<TripwireEventPublisher>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            detector,
            publisher,
            missing_context,
        }
    }

    fn evaluate_input(
        &self,
        context: &SecurityInvocationContextV1,
        request: &ToolCallRequest,
        kind: TripwireKind,
        content: Vec<u8>,
    ) -> Result<Option<GuardDecision>, PortError> {
        let input = build_input(context, request, kind, content)?;
        match self.detector.detect(&input)? {
            TripwireDecision::Clear => Ok(None),
            decision @ TripwireDecision::Match { .. } => {
                let persistence = append_detection_event(
                    self.publisher.as_ref(),
                    context,
                    request,
                    &input,
                    &decision,
                    "pre_invocation",
                );
                Ok(Some(GuardDecision::deny(vec![tripwire_evidence(
                    PRE_INVOCATION_GUARD_NAME,
                    &input,
                    &decision,
                    &persistence,
                )])))
            }
        }
    }
}

impl Guard for TripwireGuard {
    fn name(&self) -> &str {
        PRE_INVOCATION_GUARD_NAME
    }

    fn evaluate(&self, guard_context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        let Some(security_context) = guard_context
            .security_context()
            .map(|context| context.as_v1())
        else {
            return Ok(if self.missing_context.denies() {
                denial_evidence(
                    PRE_INVOCATION_GUARD_NAME,
                    "authoritative security context is missing",
                )
            } else {
                GuardDecision::allow()
            });
        };
        let capability_content = guard_context.request.capability.id.as_bytes().to_vec();
        match self.evaluate_input(
            security_context,
            guard_context.request,
            TripwireKind::CanaryCapability,
            capability_content,
        ) {
            Ok(Some(decision)) => return Ok(decision),
            Ok(None) => {}
            Err(error) => {
                return Ok(denial_evidence(
                    PRE_INVOCATION_GUARD_NAME,
                    &format!("tripwire detector failed: {error}"),
                ));
            }
        }
        let tool_content = canonical_json_bytes(&ToolIdentity {
            server_id: &guard_context.request.server_id,
            tool_name: &guard_context.request.tool_name,
        })
        .map_err(|error| KernelError::Internal(error.to_string()))?;
        match self.evaluate_input(
            security_context,
            guard_context.request,
            TripwireKind::HoneyTool,
            tool_content,
        ) {
            Ok(Some(decision)) => Ok(decision),
            Ok(None) => Ok(GuardDecision::allow()),
            Err(error) => Ok(denial_evidence(
                PRE_INVOCATION_GUARD_NAME,
                &format!("tripwire detector failed: {error}"),
            )),
        }
    }
}

pub(crate) struct RawOutputTripwireEvaluator {
    detector: Arc<dyn chio_security_types::ports::TripwireDetectorPort>,
    publisher: Arc<TripwireEventPublisher>,
    missing_context: MissingContextPolicy,
}

impl RawOutputTripwireEvaluator {
    #[must_use]
    pub(crate) fn new(
        detector: Arc<dyn chio_security_types::ports::TripwireDetectorPort>,
        publisher: Arc<TripwireEventPublisher>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            detector,
            publisher,
            missing_context,
        }
    }

    pub(crate) fn inspect(
        &self,
        post_context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationInspection {
        let Some(security_context) = post_context
            .security_context()
            .map(|context| context.as_v1())
        else {
            return self.missing_post_context("authoritative security context is missing");
        };
        let Some(request) = post_context.request else {
            return self.missing_post_context("post-invocation request context is missing");
        };
        if post_context.agent_id.is_none() || post_context.server_id.is_none() {
            return self.missing_post_context("post-invocation identity context is missing");
        }
        let content = match canonical_json_bytes(response) {
            Ok(content) => content,
            Err(error) => {
                return post_block(&format!("watermark input serialization failed: {error}"));
            }
        };
        let input = match build_input(
            security_context,
            request,
            TripwireKind::SignedWatermark,
            content,
        ) {
            Ok(input) => input,
            Err(error) => return post_block(&format!("watermark input failed: {error}")),
        };
        match self.detector.detect(&input) {
            Ok(TripwireDecision::Clear) => {
                PostInvocationInspection::without_evidence(PostInvocationVerdict::Allow)
            }
            Ok(decision @ TripwireDecision::Match { .. }) => {
                let persistence = append_detection_event(
                    self.publisher.as_ref(),
                    security_context,
                    request,
                    &input,
                    &decision,
                    "post_invocation",
                );
                PostInvocationInspection::new(
                    PostInvocationVerdict::Block(
                        "signed watermark tripwire matched raw output".to_string(),
                    ),
                    vec![tripwire_evidence(
                        POST_INVOCATION_HOOK_NAME,
                        &input,
                        &decision,
                        &persistence,
                    )],
                )
            }
            Err(error) => post_block(&format!("watermark detector failed: {error}")),
        }
    }

    fn missing_post_context(&self, reason: &str) -> PostInvocationInspection {
        if self.missing_context.denies() {
            post_block(reason)
        } else {
            PostInvocationInspection::without_evidence(PostInvocationVerdict::Allow)
        }
    }
}

#[derive(Serialize)]
struct ToolIdentity<'a> {
    server_id: &'a str,
    tool_name: &'a str,
}

#[derive(Serialize)]
struct InvocationBinding<'a> {
    tenant_id: &'a str,
    session_id: &'a str,
    principal_id: &'a str,
    isolation_epoch_id: &'a str,
    lineage_root_id: &'a str,
    context_generation: u64,
    request_id_hash: String,
    server_id: &'a str,
    tool_name: &'a str,
}

#[derive(Serialize)]
struct DetectionEvidenceBinding<'a> {
    schema: &'static str,
    phase: &'a str,
    tenant_id: &'a str,
    subject_id: &'a str,
    agent_id: &'a str,
    session_id: &'a str,
    capability_id: &'a str,
    isolation_epoch_id: &'a str,
    lineage_seed: &'a str,
    context_generation: u64,
    request_id: &'a str,
    kind: TripwireKind,
    artifact_id_hash: Digest32,
    artifact_version_hash: Digest32,
    content_digest: Digest32,
    canonical_context_digest: Digest32,
    producer_id: &'a str,
    producer_key_id: &'a str,
    policy_version: &'a str,
}

fn build_input(
    context: &SecurityInvocationContextV1,
    request: &ToolCallRequest,
    kind: TripwireKind,
    content: Vec<u8>,
) -> PortResult<TripwireInput> {
    let context_bytes = canonical_json_bytes(&InvocationBinding {
        tenant_id: context.tenant_id().as_str(),
        session_id: context.session_id().as_str(),
        principal_id: context.principal_id().as_str(),
        isolation_epoch_id: context.isolation_epoch_id().as_str(),
        lineage_root_id: context.lineage_root_id().as_str(),
        context_generation: context.context_generation(),
        request_id_hash: sha256(request.request_id.as_bytes()).to_hex(),
        server_id: &request.server_id,
        tool_name: &request.tool_name,
    })
    .map_err(|_| PortError::invalid_data())?;
    let request_id = RequestId::new(format!(
        "request-{}",
        sha256(request.request_id.as_bytes()).to_hex()
    ))
    .map_err(|_| PortError::invalid_data())?;
    let content_digest = digest(&content);
    let content = CanonicalBody::new(content).map_err(|_| PortError::invalid_data())?;
    Ok(TripwireInput {
        tenant_id: context.tenant_id().clone(),
        request_id,
        kind,
        content,
        content_digest,
        canonical_context_digest: digest(&context_bytes),
    })
}

fn append_detection_event(
    publisher: &TripwireEventPublisher,
    context: &SecurityInvocationContextV1,
    request: &ToolCallRequest,
    input: &TripwireInput,
    decision: &TripwireDecision,
    phase: &str,
) -> DetectionPersistence {
    let prepared = match prepare_detection(publisher, context, request, input, decision, phase) {
        Ok(prepared) => prepared,
        Err(_) => return DetectionPersistence::preparation_failed(publisher),
    };
    let receipt = append_tripwire_receipt(publisher, context, input, decision, &prepared);
    let event = match &receipt {
        ReceiptPersistence::Appended(source_receipt_id) => build_detection_event_body(
            publisher,
            context,
            request,
            input,
            decision,
            &prepared,
            source_receipt_id.clone(),
        )
        .and_then(|body| append_security_event(publisher, context, &prepared, body)),
        ReceiptPersistence::NotConfigured => Err(PortError::unavailable()),
        ReceiptPersistence::Failed => Err(PortError::integrity_failure()),
    };
    DetectionPersistence { event, receipt }
}

struct PreparedDetection {
    now_unix_ms: u64,
    binding_hash: Digest32,
    event_id: EventId,
    request_hash: Digest32,
}

enum ReceiptPersistence {
    NotConfigured,
    Appended(OpaqueReceiptRef),
    Failed,
}

struct DetectionPersistence {
    event: PortResult<EventAppend>,
    receipt: ReceiptPersistence,
}

impl DetectionPersistence {
    fn preparation_failed(publisher: &TripwireEventPublisher) -> Self {
        Self {
            event: Err(PortError::invalid_data()),
            receipt: if publisher.receipt_evidence.is_some() {
                ReceiptPersistence::Failed
            } else {
                ReceiptPersistence::NotConfigured
            },
        }
    }
}

fn prepare_detection(
    publisher: &TripwireEventPublisher,
    context: &SecurityInvocationContextV1,
    request: &ToolCallRequest,
    input: &TripwireInput,
    decision: &TripwireDecision,
    phase: &str,
) -> PortResult<PreparedDetection> {
    let TripwireDecision::Match {
        artifact_id_hash,
        artifact_version_hash,
    } = decision
    else {
        return Err(PortError::invalid_data());
    };
    let now_unix_ms = publisher.clock.now_unix_ms()?;
    let binding_bytes = canonical_json_bytes(&DetectionEvidenceBinding {
        schema: "chio.security.tripwire-evidence-binding.v1",
        phase,
        tenant_id: context.tenant_id().as_str(),
        subject_id: context.principal_id().as_str(),
        agent_id: &request.agent_id,
        session_id: context.session_id().as_str(),
        capability_id: &request.capability.id,
        isolation_epoch_id: context.isolation_epoch_id().as_str(),
        lineage_seed: context.lineage_root_id().as_str(),
        context_generation: context.context_generation(),
        request_id: input.request_id.as_str(),
        kind: input.kind,
        artifact_id_hash: *artifact_id_hash,
        artifact_version_hash: *artifact_version_hash,
        content_digest: input.content_digest,
        canonical_context_digest: input.canonical_context_digest,
        producer_id: publisher.producer_id.as_str(),
        producer_key_id: publisher.producer_key_id.as_str(),
        policy_version: publisher.policy_version.as_str(),
    })
    .map_err(|_| PortError::invalid_data())?;
    let binding_hash = digest(&binding_bytes);
    let event_id = EventId::new(format!("tripwire-event-{}", hex_digest(binding_hash)))
        .map_err(|_| PortError::invalid_data())?;
    let request_hash =
        digest(&canonical_json_bytes(request).map_err(|_| PortError::invalid_data())?);
    Ok(PreparedDetection {
        now_unix_ms,
        binding_hash,
        event_id,
        request_hash,
    })
}

fn build_detection_event_body(
    publisher: &TripwireEventPublisher,
    context: &SecurityInvocationContextV1,
    request: &ToolCallRequest,
    input: &TripwireInput,
    decision: &TripwireDecision,
    prepared: &PreparedDetection,
    source_receipt_id: OpaqueReceiptRef,
) -> PortResult<SecurityEventBody> {
    let TripwireDecision::Match {
        artifact_id_hash,
        artifact_version_hash,
    } = decision
    else {
        return Err(PortError::invalid_data());
    };
    SecurityEventBody::new(SecurityEventBodyInput {
        event_id: prepared.event_id.clone(),
        event_time_unix_ms: prepared.now_unix_ms,
        ingest_time_unix_ms: prepared.now_unix_ms,
        tenant_id: context.tenant_id().clone(),
        subject: SecuritySubject {
            subject_id: RecordId::new(context.principal_id().as_str())
                .map_err(|_| PortError::invalid_data())?,
            agent_id: RecordId::new(request.agent_id.clone())
                .map_err(|_| PortError::invalid_data())?,
            session_id: context.session_id().clone(),
            capability_id: RecordId::new(request.capability.id.clone())
                .map_err(|_| PortError::invalid_data())?,
            lineage_seed: context.lineage_root_id().clone(),
        },
        source_receipt_id,
        event_kind: match input.kind {
            TripwireKind::CanaryCapability => SecurityEventKind::CanaryInvocation,
            TripwireKind::SignedWatermark => SecurityEventKind::WatermarkObservation,
            _ => SecurityEventKind::TripwireObservation,
        },
        severity: SecuritySeverity::High,
        evidence_references: vec![
            evidence_reference("tripwire-binding", prepared.binding_hash)?,
            evidence_reference("tripwire-artifact-id", *artifact_id_hash)?,
            evidence_reference("tripwire-artifact-version", *artifact_version_hash)?,
            evidence_reference("tripwire-content", input.content_digest)?,
            evidence_reference("tripwire-context", input.canonical_context_digest)?,
            OpaqueReceiptRef::new(format!("tripwire-request-{}", input.request_id.as_str()))
                .map_err(|_| PortError::invalid_data())?,
        ],
        producer_id: publisher.producer_id.clone(),
        producer_key_id: publisher.producer_key_id.clone(),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: publisher.policy_version.clone(),
    })
    .map_err(|_| PortError::invalid_data())
}

fn append_security_event(
    publisher: &TripwireEventPublisher,
    context: &SecurityInvocationContextV1,
    prepared: &PreparedDetection,
    body: SecurityEventBody,
) -> PortResult<EventAppend> {
    let body_bytes = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
    let body_hash = digest(&body_bytes);
    let signed = SignedSecurityEvent::sign_with_backend(body, publisher.signer.as_ref())
        .map_err(|_| PortError::integrity_failure())?;
    let source_evidence = canonical_json_bytes(&signed).map_err(|_| PortError::invalid_data())?;
    publisher
        .ingress
        .verify_and_append(&UnverifiedSecurityEvent {
            tenant_id: context.tenant_id().clone(),
            event_id: prepared.event_id.clone(),
            producer_id: publisher.producer_id.clone(),
            event_time_unix_ms: prepared.now_unix_ms,
            received_at_unix_ms: prepared.now_unix_ms,
            canonical_body: CanonicalBody::new(body_bytes)
                .map_err(|_| PortError::invalid_data())?,
            body_hash,
            source_evidence: CanonicalBody::new(source_evidence)
                .map_err(|_| PortError::invalid_data())?,
        })
}

fn append_tripwire_receipt(
    publisher: &TripwireEventPublisher,
    context: &SecurityInvocationContextV1,
    input: &TripwireInput,
    decision: &TripwireDecision,
    prepared: &PreparedDetection,
) -> ReceiptPersistence {
    let Some(receipt_evidence) = publisher.receipt_evidence.as_ref() else {
        return ReceiptPersistence::NotConfigured;
    };
    let TripwireDecision::Match {
        artifact_id_hash,
        artifact_version_hash,
    } = decision
    else {
        return ReceiptPersistence::Failed;
    };
    let transition_id = match RecordId::new(format!(
        "tripwire-observation-{}",
        hex_digest(prepared.binding_hash)
    )) {
        Ok(transition_id) => transition_id,
        Err(_) => return ReceiptPersistence::Failed,
    };
    let header = match ActiveDefenseReceiptHeader::new(
        prepared.now_unix_ms,
        context.tenant_id().clone(),
        transition_id,
        Vec::new(),
    ) {
        Ok(header) => header,
        Err(_) => return ReceiptPersistence::Failed,
    };
    let body = ActiveDefenseReceiptBody::TripwireObservation(TripwireObservationReceiptBody {
        header,
        policy: ActiveDefensePolicyBinding {
            policy_version: publisher.policy_version.clone(),
            policy_hash: receipt_evidence.policy_hash,
        },
        request_id: input.request_id.clone(),
        request_hash: prepared.request_hash,
        event_id: prepared.event_id.clone(),
        tripwire_kind: input.kind,
        artifact_id_hash: *artifact_id_hash,
        artifact_version_hash: *artifact_version_hash,
        observation_hash: prepared.binding_hash,
        severity: SecuritySeverity::High,
    });
    match tripwire_receipt_append_request(&body).and_then(|request| {
        receipt_evidence
            .sink
            .sign_and_append(&request)
            .map(|id| (request, id))
    }) {
        Ok((request, appended)) if appended == request.evidence_id => {
            ReceiptPersistence::Appended(appended)
        }
        _ => ReceiptPersistence::Failed,
    }
}

fn tripwire_receipt_append_request(
    body: &ActiveDefenseReceiptBody,
) -> PortResult<ReceiptAppendRequest> {
    body.validate().map_err(|_| PortError::invalid_data())?;
    let canonical_body = canonical_json_bytes(body).map_err(|_| PortError::invalid_data())?;
    Ok(ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: RecordId::new(body.kind().as_str())
            .map_err(|_| PortError::invalid_data())?,
        evidence_id: body.evidence_id().map_err(|_| PortError::invalid_data())?,
        canonical_body: CanonicalBody::new(canonical_body)
            .map_err(|_| PortError::invalid_data())?,
        body_hash: body.body_digest().map_err(|_| PortError::invalid_data())?,
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    })
}

fn evidence_reference(prefix: &str, digest: Digest32) -> PortResult<OpaqueReceiptRef> {
    OpaqueReceiptRef::new(format!("{prefix}-{}", hex_digest(digest)))
        .map_err(|_| PortError::invalid_data())
}

fn tripwire_evidence(
    name: &str,
    input: &TripwireInput,
    decision: &TripwireDecision,
    persistence: &DetectionPersistence,
) -> GuardEvidence {
    let TripwireDecision::Match {
        artifact_id_hash,
        artifact_version_hash,
    } = decision
    else {
        return GuardEvidence {
            guard_name: name.to_string(),
            verdict: false,
            details: Some("tripwire decision integrity failure".to_string()),
        };
    };
    let event_persistence = match &persistence.event {
        Ok(EventAppend::Inserted) => "inserted",
        Ok(EventAppend::Duplicate) => "duplicate",
        Err(_) => "failed",
    };
    let receipt_persistence = match &persistence.receipt {
        ReceiptPersistence::NotConfigured => "not_configured",
        ReceiptPersistence::Appended(_) => "appended",
        ReceiptPersistence::Failed => "failed",
    };
    let details = serde_json::json!({
        "artifact_id_hash": artifact_id_hash,
        "artifact_version_hash": artifact_version_hash,
        "event_persistence": event_persistence,
        "kind": input.kind,
        "receipt_persistence": receipt_persistence,
    });
    GuardEvidence {
        guard_name: name.to_string(),
        verdict: false,
        details: Some(details.to_string()),
    }
}

fn denial_evidence(name: &str, reason: &str) -> GuardDecision {
    GuardDecision::deny(vec![GuardEvidence {
        guard_name: name.to_string(),
        verdict: false,
        details: Some(reason.to_string()),
    }])
}

fn post_block(reason: &str) -> PostInvocationInspection {
    PostInvocationInspection::new(
        PostInvocationVerdict::Block(reason.to_string()),
        vec![GuardEvidence {
            guard_name: POST_INVOCATION_HOOK_NAME.to_string(),
            verdict: false,
            details: Some(reason.to_string()),
        }],
    )
}

fn map_detection_failure(error: DetectionFailure) -> PortError {
    match error {
        DetectionFailure::InvalidObservation => PortError::invalid_data(),
        DetectionFailure::RegistryUnavailable => PortError::unavailable(),
        DetectionFailure::RegistryIntegrityFailure | DetectionFailure::LifecycleError => {
            PortError::integrity_failure()
        }
    }
}

fn map_watermark_error(error: WatermarkScanError) -> PortError {
    match error {
        WatermarkScanError::DetectorUnavailable => PortError::unavailable(),
        WatermarkScanError::InvalidObservationContext
        | WatermarkScanError::CandidateLimitExceeded
        | WatermarkScanError::TextTooLarge => PortError::invalid_data(),
    }
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*sha256(bytes).as_bytes())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut preimage = Vec::with_capacity(domain.len().saturating_add(bytes.len()));
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    digest(&preimage)
}

fn hex_digest(value: Digest32) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
