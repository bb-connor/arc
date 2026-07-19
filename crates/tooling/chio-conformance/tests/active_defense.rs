use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::security::adapters::effect_port::{
    ActiveResponseEffectPort, SessionSuspensionOverlayBackend,
};
use chio_control_plane::security::{
    NativeSecurityEventVerifier, SecurityEventReceiptProjection, TrustedSecurityEventProducer,
    TrustedSecurityEventReceiptProducer, VerifiedSecurityEventIngress,
    SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::receipt::security::{
    ActiveDefenseEffectOutcome, ActiveDefensePolicyBinding, ActiveDefenseReceiptBody,
    ActiveDefenseReceiptHeader, DeclassificationConsumptionReceiptBody,
};
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::ToolCallAction,
    kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    },
};
use chio_core::{
    canonical_json_bytes, sha256, Ed25519Backend, Keypair, SignedDeclassificationGrant,
    SignedSecurityEvent,
};
use chio_decoy::{
    DecoyCreateRequest, DecoyDetector, PrivateDecoyRegistry, PrivilegedExportCredential,
    RegistryError, RegistryExportAuthorizer, RegistryExportGrant, RegistryKey, RegistryKeyProvider,
    SecretMaterial,
};
use chio_flow::{
    canonical_request_hash, evaluate_pre_invocation, evaluate_pre_invocation_with_declassification,
    information_label_hash, verify_declassification, DeclassificationVerificationRequest,
    FlowDenial, ResolvedFlowRequest,
};
use chio_kernel::{
    ChioKernel, Guard, GuardContext, KernelConfig, KernelError, MemoryBudgetConfig,
    NestedFlowBridge, SecurityInvocationContext, SecurityInvocationContextV1, ToolCallRequest,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{
    sign_manifest, AuthoritativeToolPolicy, RuntimeToolTopology, VerifiedManifestRegistry,
};
use chio_openapi_mcp_bridge::{BridgeConfig, OpenApiMcpBridge};
use chio_quarantine::{
    build_response_plan, decode_response_record, prepare_response_dispatch,
    CausalBlastRadiusResolver, CorrelationPolicy, CorrelationStatus, FenceValidationOutcome,
    ResponseDispatchPreparationRequest, ResponseExecutor, RuleLimits, TemporalCorrelator,
    TemporalRule,
};
use chio_security_kernel::{
    ContainmentGuard, DecoyTripwireDetectorPort, MissingContextPolicy, SecurityClock,
    SecurityEventIngress, TripwireEventPublisher, TripwireGuard,
};
use chio_security_types::flow::{DeclassificationPurpose, ToolFlowDeclaration};
use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, derive_declassification_event_id,
    derive_declassification_transition_id, predict_containment_overlay_apply,
    predict_containment_overlay_remove, ActionId, AlertDeliveryQuery, AlertDeliveryStatus,
    ArtifactId, BlastRadiusIncompleteReason, BlastRadiusQueryBounds, BlastRadiusRequest,
    BlastRadiusResult, BlastRadiusSeeds, BoundedVec, CanonicalBody, CausalLineageCommitMetadata,
    CausalLineageCommitRequest, CausalLineageCommitStore, CausalLineageEdge, CausalLineageEdgeKind,
    CausalLineageEdges, CausalLineageNode, CausalLineageNodeKind, CausalLineageNodes,
    ContainmentOverlayCommand, ContainmentOverlayStore, DeclassificationConsume,
    DeclassificationConsumeRequest, DeclassificationConsumptionEvidenceCommit,
    DeclassificationEvidenceCommitStore, DeclassificationOutcomeRequest,
    DeclassificationTransitionBinding, DeclassificationUseState, DeclassificationUseStore,
    DestinationId, Digest32, EffectExecutionStatus, EffectId, EffectOperation, EffectRequest,
    EffectResult, EffectResultQuery, EventAppend, EventId, FlowJoinRequest, FlowStateKey,
    FlowStateSnapshot, FlowStateStore, GrantId, IsolationEpochId, LeaseOwnerId, LineageId,
    OpaqueReceiptRef, OverlayApplyRequest, OverlayContribution, OverlayContributions,
    OverlayRemoveRequest, OverlaySnapshot, PortError, PortErrorKind, PortResult, ProducerId,
    ProducerTrustClass, ReceiptAppendRequest, RecordId, RequestId, ResponseDispatchApproval,
    ResponseDispatchCommitOutcome, ResponseDispatchLease, ResponseDispatchStore, ResponsePlanKey,
    ResponsePlanRecord, ResponseSchedulerStore, ResponseStore, SchedulerClaimRequest,
    SchedulerLeaseRenewRequest, SecurityAlert, SecurityAlertPort, SecurityEventVerifierPort,
    SecurityReceiptSink, SessionId, TenantId, TenantScopedId, TripwireDecision,
    TripwireDetectorPort, TripwireInput, TripwireKind, UnverifiedSecurityEvent,
    VerifiedSecurityEvent,
};
use chio_security_types::{
    Compartment, DeclassificationGrantBody, DeclassificationGrantClaims, DecoyOperationAttempt,
    DecoyOperationKind, DecoySurface, DecoyVersion, InformationLabel, OperatorCapabilityBinding,
    PrincipalId, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectProgress,
    ResponseEffectSpec, ResponsePlanInput, ResponseState, ResponseTarget, ResponseTransitionCause,
    SecurityEventBody, SecurityEventBodyInput, SecurityEventKind, SecuritySeverity,
    SecuritySubject,
};
use chio_store_sqlite::{
    SqliteReceiptStore, SqliteSealedDecoyRegistryStore, SqliteSecurityStateStore,
};
use chio_test_support::prelude::*;
use tempfile::tempdir;

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).test_expect("tenant id")
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).test_expect("record id")
}

fn action(value: &str) -> ActionId {
    ActionId::new(value).test_expect("action id")
}

fn effect(value: &str) -> EffectId {
    EffectId::new(value).test_expect("effect id")
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*sha256(bytes).as_bytes())
}

fn current_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system clock after epoch");
    u64::try_from(elapsed.as_millis()).test_expect("clock fits u64")
}

fn principal(value: &str) -> PrincipalId {
    PrincipalId::new(value).test_expect("principal id")
}

fn compartment(value: &str) -> Compartment {
    Compartment::new(value).test_expect("compartment")
}

fn label(compartments: &[&str]) -> InformationLabel {
    InformationLabel::try_known(
        BTreeMap::new(),
        compartments
            .iter()
            .map(|value| compartment(value))
            .collect(),
    )
    .test_expect("information label")
}

fn flow_key(session: &str, epoch: &str) -> FlowStateKey {
    FlowStateKey {
        tenant_id: tenant("tenant-active-defense"),
        principal_id: principal("principal-active-defense"),
        lineage_id: LineageId::new("lineage-active-defense").test_expect("lineage id"),
        session_id: SessionId::new(session).test_expect("session id"),
        isolation_epoch_id: IsolationEpochId::new(epoch).test_expect("isolation epoch id"),
    }
}

fn empty_snapshot(session: &str) -> FlowStateSnapshot {
    FlowStateSnapshot {
        key: flow_key(session, "epoch-active-defense"),
        principal_label: InformationLabel::bottom(),
        lineage_label: InformationLabel::bottom(),
        session_label: InformationLabel::bottom(),
        context_generation: 1,
    }
}

fn resolved_flow(
    state: FlowStateSnapshot,
    payload_label: InformationLabel,
    policy_clearance: InformationLabel,
    manifest: ToolFlowDeclaration,
) -> ResolvedFlowRequest {
    ResolvedFlowRequest {
        request_id: RequestId::new("request-active-defense-flow").test_expect("request id"),
        request_hash: digest(b"active-defense-flow-request"),
        transition_id: record("active-defense-flow-transition"),
        state,
        payload_label,
        operator_input_floor: InformationLabel::bottom(),
        runtime_egress: true,
        capability_id: record("capability-active-defense"),
        agent_id: record("agent-active-defense"),
        tool_name: record("export-records"),
        destination_id: DestinationId::new("server-active-defense").test_expect("destination id"),
        purpose: DeclassificationPurpose::new("support").test_expect("purpose"),
        effective_declassification_purposes: BTreeSet::new(),
        trusted_declassification_authorities: BTreeMap::new(),
        now_unix_ms: 150_000,
        declassification: None,
        policy_clearances: BoundedVec::new(vec![policy_clearance]).test_expect("policy clearances"),
        manifest,
        fence_expires_at_unix_ms: 300_000,
    }
}

fn egress_manifest(clearance: InformationLabel) -> ToolFlowDeclaration {
    ToolFlowDeclaration::new(None, Some(clearance), true, BTreeSet::new())
        .test_expect("flow manifest")
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "server-active-defense".to_string(),
            tool_name: "export_records".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn request() -> ToolCallRequest {
    let keypair = Keypair::from_seed(&[61; 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-active-defense".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: scope(),
            issued_at: 1,
            expires_at: u64::MAX,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &keypair,
    )
    .test_expect("sign active-defense capability");
    ToolCallRequest {
        request_id: "request-active-defense".to_string(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "export_records".to_string(),
        server_id: "server-active-defense".to_string(),
        arguments: serde_json::json!({"batch": 1}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

fn security_context(request: &ToolCallRequest) -> SecurityInvocationContext {
    let lineage_root = request
        .capability
        .delegation_chain
        .first()
        .map_or(request.capability.id.as_str(), |link| {
            link.capability_id.as_str()
        });
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        tenant("tenant-active-defense"),
        SessionId::new("session-active-defense").test_expect("session id"),
        PrincipalId::new(request.agent_id.clone()).test_expect("principal id"),
        IsolationEpochId::new("epoch-active-defense").test_expect("isolation epoch id"),
        LineageId::new(lineage_root).test_expect("lineage id"),
        7,
    ))
}

#[test]
fn slow_cumulative_exfiltration() {
    let directory = tempdir().test_expect("temporary directory");
    let store = SqliteSecurityStateStore::open(directory.path().join("flow-state.db"))
        .test_expect("open flow store");
    let key = flow_key("session-cumulative", "epoch-active-defense");
    let first = store
        .join(&FlowJoinRequest {
            key: key.clone(),
            principal_join: label(&["pii"]),
            lineage_join: label(&["pii"]),
            session_join: InformationLabel::bottom(),
            transition_id: record("cumulative-pii"),
        })
        .test_expect("persist first taint");
    assert!(first.principal_label.flows_to(&label(&["pii"])));
    let cumulative = store
        .join(&FlowJoinRequest {
            key,
            principal_join: label(&["phi"]),
            lineage_join: label(&["phi"]),
            session_join: InformationLabel::bottom(),
            transition_id: record("cumulative-phi"),
        })
        .test_expect("persist cumulative taint");
    let compartments = cumulative
        .session_label
        .compartments()
        .test_expect("known cumulative label");
    assert!(compartments.contains(&compartment("pii")));
    assert!(compartments.contains(&compartment("phi")));

    let pii_only = label(&["pii"]);
    assert_eq!(
        evaluate_pre_invocation(resolved_flow(
            cumulative,
            InformationLabel::bottom(),
            pii_only.clone(),
            egress_manifest(pii_only),
        )),
        Err(FlowDenial::PolicyFlowViolation)
    );
}

#[test]
fn pii_phi_adapter_round_trip() {
    let signer = Keypair::from_seed(&[63; 32]);
    let flow = serde_json::json!({
        "output_label": {
            "kind": "known",
            "owners": {},
            "compartments": ["phi", "pii"]
        },
        "input_clearance": {
            "kind": "known",
            "owners": {},
            "compartments": ["phi", "pii"]
        },
        "egress": true
    });
    let spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "Clinical Export", "version": "1.0.0"},
        "paths": {
            "/records": {
                "post": {
                    "operationId": "exportRecords",
                    "x-chio-flow": flow,
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    });
    let bridge = OpenApiMcpBridge::from_spec(
        &spec.to_string(),
        BridgeConfig {
            server_id: "clinical-export".to_string(),
            server_name: "Clinical Export".to_string(),
            server_version: "1.0.0".to_string(),
            public_key: signer.public_key().to_hex(),
            base_url: "https://clinical.invalid".to_string(),
            egress_contract: None,
        },
    )
    .test_expect("build OpenAPI to MCP bridge");
    let signed = sign_manifest(bridge.manifest(), &signer).test_expect("sign bridge manifest");
    let mut registry = VerifiedManifestRegistry::default();
    let policies = BTreeMap::from([(
        "exportRecords".to_string(),
        AuthoritativeToolPolicy::new(
            vec![label(&["pii", "phi"])],
            InformationLabel::bottom(),
            BTreeSet::new(),
        )
        .test_expect("construct clinical export flow policy"),
    )]);
    let topologies = BTreeMap::from([("exportRecords".to_string(), RuntimeToolTopology::remote())]);
    registry
        .register(signed, &signer.public_key(), &policies, &topologies)
        .test_expect("admit bridge manifest");
    let bindings = bridge
        .registry_bound_mcp_tools(&registry)
        .test_expect("export registry-bound MCP tools");
    let binding = bindings.first().test_expect("one bridged tool");
    let round_tripped = binding
        .security()
        .flow()
        .test_expect("flow sidecar survived OpenAPI and MCP adapters")
        .clone();
    let output_label = round_tripped
        .output_label
        .clone()
        .test_expect("adapter output label");
    let compartments = output_label
        .compartments()
        .test_expect("known adapter output label");
    assert!(compartments.contains(&compartment("pii")));
    assert!(compartments.contains(&compartment("phi")));
    assert_eq!(binding.server_id(), "clinical-export");
    assert_eq!(binding.tool_name(), "exportRecords");

    assert_eq!(
        evaluate_pre_invocation(resolved_flow(
            empty_snapshot("session-adapter"),
            output_label,
            label(&["pii"]),
            round_tripped,
        )),
        Err(FlowDenial::PolicyFlowViolation)
    );
}

struct FixedClock(u64);

impl SecurityClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(self.0)
    }
}

struct RecordingEvents(AtomicUsize);

fn verify_tripwire_event(event: &UnverifiedSecurityEvent) -> PortResult<()> {
    let signed: SignedSecurityEvent = serde_json::from_slice(event.source_evidence.as_bytes())
        .map_err(|_| PortError::invalid_data())?;
    let valid = signed
        .verify_trusted_producer(
            &ProducerId::new("active-defense-conformance")?,
            &record("active-defense-conformance-key-v1"),
            &tripwire_keypair().public_key(),
        )
        .map_err(|_| PortError::integrity_failure())?;
    if !valid {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

impl SecurityEventIngress for RecordingEvents {
    fn verify_and_append(&self, event: &UnverifiedSecurityEvent) -> PortResult<EventAppend> {
        verify_tripwire_event(event)?;
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(EventAppend::Inserted)
    }
}

struct FailingEvents(AtomicUsize);

impl SecurityEventIngress for FailingEvents {
    fn verify_and_append(&self, event: &UnverifiedSecurityEvent) -> PortResult<EventAppend> {
        verify_tripwire_event(event)?;
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(PortError::unavailable())
    }
}

struct ValidatingReceipts;

fn validate_receipt_request(request: &ReceiptAppendRequest) -> PortResult<()> {
    let body: ActiveDefenseReceiptBody = serde_json::from_slice(request.canonical_body.as_bytes())
        .map_err(|_| PortError::invalid_data())?;
    body.validate().map_err(|_| PortError::invalid_data())?;
    if body.body_digest().map_err(|_| PortError::invalid_data())? != request.body_hash
        || body.evidence_id().map_err(|_| PortError::invalid_data())? != request.evidence_id
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

impl SecurityReceiptSink for ValidatingReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        validate_receipt_request(request)?;
        Ok(request.evidence_id.clone())
    }
}

struct SecretScanningReceipts {
    forbidden: Vec<Vec<u8>>,
    appends: AtomicUsize,
}

impl SecretScanningReceipts {
    fn new(forbidden: Vec<Vec<u8>>) -> Self {
        Self {
            forbidden,
            appends: AtomicUsize::new(0),
        }
    }
}

impl SecurityReceiptSink for SecretScanningReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        validate_receipt_request(request)?;
        let canonical = request.canonical_body.as_bytes();
        if self.forbidden.iter().any(|needle| {
            !needle.is_empty()
                && canonical
                    .windows(needle.len())
                    .any(|window| window == needle.as_slice())
        }) {
            return Err(PortError::integrity_failure());
        }
        self.appends.fetch_add(1, Ordering::SeqCst);
        Ok(request.evidence_id.clone())
    }
}

fn tripwire_keypair() -> Keypair {
    Keypair::from_seed(&[62; 32])
}

struct DecoyKeys;

impl RegistryKeyProvider for DecoyKeys {
    fn key_for(&self, tenant_id: &TenantId) -> Result<RegistryKey, RegistryError> {
        if tenant_id.as_str() != "tenant-active-defense" {
            return Err(RegistryError::KeyUnavailable);
        }
        Ok(RegistryKey::from_bytes([41; 64]))
    }
}

struct NoDecoyExports;

impl RegistryExportAuthorizer for NoDecoyExports {
    fn authorize(
        &self,
        _: &PrivilegedExportCredential,
        _: u64,
    ) -> Result<RegistryExportGrant, RegistryError> {
        Err(RegistryError::AuthorizationDenied)
    }
}

fn create_and_arm_decoy(
    registry: &PrivateDecoyRegistry,
    artifact_id_value: &str,
    surface: DecoySurface,
    operation_prefix: &str,
    marker: &[u8],
) {
    let artifact_id = ArtifactId::new(artifact_id_value).test_expect("artifact id");
    registry
        .create(
            DecoyCreateRequest {
                tenant_id: tenant("tenant-active-defense"),
                artifact_id: artifact_id.clone(),
                surface,
                scope_id: record(&format!("{operation_prefix}-scope")),
                creation_policy_id: record(&format!("{operation_prefix}-policy")),
                version: DecoyVersion::new(1).test_expect("decoy version"),
                expires_at_unix_ms: 100_000,
                predecessor_artifact_id: None,
                marker: SecretMaterial::new(marker.to_vec()).test_expect("decoy marker"),
                materialization_payload: None,
            },
            record(&format!("{operation_prefix}-create")),
        )
        .test_expect("create decoy");
    let planned = registry
        .load_private(&tenant("tenant-active-defense"), &artifact_id)
        .test_expect("load planned decoy")
        .test_expect("planned decoy");
    let materializing = registry
        .apply_transition(
            &tenant("tenant-active-defense"),
            &artifact_id,
            &DecoyOperationAttempt {
                operation_id: record(&format!("{operation_prefix}-materialize")),
                kind: DecoyOperationKind::BeginMaterialization,
                expected_generation: planned.generation,
                expected_version: planned.version,
                successor_artifact_id: None,
            },
        )
        .test_expect("begin decoy materialization");
    registry
        .apply_transition(
            &tenant("tenant-active-defense"),
            &artifact_id,
            &DecoyOperationAttempt {
                operation_id: record(&format!("{operation_prefix}-arm")),
                kind: DecoyOperationKind::Arm,
                expected_generation: materializing.generation,
                expected_version: materializing.version,
                successor_artifact_id: None,
            },
        )
        .test_expect("arm decoy");
}

fn create_and_arm_canary(registry: &PrivateDecoyRegistry, marker: &[u8]) {
    create_and_arm_decoy(
        registry,
        "capability-canary",
        DecoySurface::CanaryCapability,
        "active-defense-canary",
        marker,
    );
}

struct RecordingTripwireDetector {
    inner: DecoyTripwireDetectorPort,
    lookups: Arc<Mutex<Vec<(TripwireKind, bool)>>>,
}

impl TripwireDetectorPort for RecordingTripwireDetector {
    fn detect(&self, input: &TripwireInput) -> PortResult<TripwireDecision> {
        let decision = self.inner.detect(input)?;
        let matched = matches!(&decision, TripwireDecision::Match { .. });
        self.lookups
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push((input.kind, matched));
        Ok(decision)
    }
}

struct CountingServer(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "server-active-defense"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["export_records".to_string()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"dispatched": true}))
    }
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::from_seed(&[64; 32]),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "active-defense-kernel-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: MemoryBudgetConfig::defaults(),
    }
}

include!("active_defense/deception_dispatch.rs");

fn temporal_rule(rule_id: &str) -> TemporalRule {
    let document = serde_json::json!({
        "rule_id": rule_id,
        "policy_version": "active-defense-correlation-policy",
        "group_by": "session_id",
        "max_groups": 8,
        "max_partial_matches_per_group": 8,
        "allow_event_reuse": false,
        "stages": [
            {
                "name": "credential",
                "event_kind": "credential_access",
                "minimum_severity": "low"
            },
            {
                "name": "egress",
                "event_kind": "egress_attempt",
                "minimum_severity": "low",
                "after": "credential",
                "within_ms": 50
            }
        ]
    });
    TemporalRule::parse_json(
        &canonical_json_bytes(&document).test_expect("canonical rule"),
        &RuleLimits::default(),
    )
    .test_expect("temporal rule")
}

fn security_event_body(
    event_id_value: &str,
    kind: SecurityEventKind,
    event_time_unix_ms: u64,
    ingest_time_unix_ms: u64,
    trust_class: ProducerTrustClass,
) -> SecurityEventBody {
    SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new(event_id_value).test_expect("event id"),
        event_time_unix_ms,
        ingest_time_unix_ms,
        tenant_id: tenant("tenant-active-defense"),
        subject: SecuritySubject {
            subject_id: record("subject-active-defense"),
            agent_id: record("agent-active-defense"),
            session_id: SessionId::new("session-temporal").test_expect("session id"),
            capability_id: record("capability-active-defense"),
            lineage_seed: LineageId::new("lineage-active-defense").test_expect("lineage id"),
        },
        source_receipt_id: OpaqueReceiptRef::new(format!("receipt-{event_id_value}"))
            .test_expect("source receipt id"),
        event_kind: kind,
        severity: SecuritySeverity::High,
        evidence_references: vec![
            OpaqueReceiptRef::new(format!("evidence-{event_id_value}")).test_expect("evidence id")
        ],
        producer_id: ProducerId::new("detector-active-defense").test_expect("producer id"),
        producer_key_id: record("detector-active-defense-key"),
        trust_class,
        policy_version: record("active-defense-correlation-policy"),
    })
    .test_expect("security event body")
}

fn verified_event(
    event_id_value: &str,
    kind: SecurityEventKind,
    event_time_unix_ms: u64,
    ingest_time_unix_ms: u64,
    trust_class: ProducerTrustClass,
) -> VerifiedSecurityEvent {
    let body = security_event_body(
        event_id_value,
        kind,
        event_time_unix_ms,
        ingest_time_unix_ms,
        trust_class,
    );
    let canonical = canonical_json_bytes(&body).test_expect("canonical event body");
    VerifiedSecurityEvent {
        tenant_id: body.tenant_id.clone(),
        event_id: body.event_id.clone(),
        producer_id: body.producer_id.clone(),
        trust_class,
        event_time_unix_ms,
        received_at_unix_ms: ingest_time_unix_ms,
        canonical_body: CanonicalBody::new(canonical.clone()).test_expect("canonical event"),
        body_hash: digest(&canonical),
        evidence_hash: digest(format!("evidence:{event_id_value}").as_bytes()),
    }
}

fn unverified_event_with_evidence(
    body: &SecurityEventBody,
    source_evidence: Vec<u8>,
) -> UnverifiedSecurityEvent {
    let canonical_body = canonical_json_bytes(body).test_expect("canonical security event body");
    UnverifiedSecurityEvent {
        tenant_id: body.tenant_id.clone(),
        event_id: body.event_id.clone(),
        producer_id: body.producer_id.clone(),
        event_time_unix_ms: body.event_time_unix_ms,
        received_at_unix_ms: body.ingest_time_unix_ms,
        canonical_body: CanonicalBody::new(canonical_body.clone())
            .test_expect("bound security event body"),
        body_hash: digest(&canonical_body),
        source_evidence: CanonicalBody::new(source_evidence)
            .test_expect("bound security event evidence"),
    }
}

fn signed_unverified_event(body: &SecurityEventBody, key: &Keypair) -> UnverifiedSecurityEvent {
    let signed =
        SignedSecurityEvent::sign_with_backend(body.clone(), &Ed25519Backend::new(key.clone()))
            .test_expect("sign security event");
    let evidence = canonical_json_bytes(&signed).test_expect("canonical signed security event");
    unverified_event_with_evidence(body, evidence)
}

fn receipt_unverified_event(body: &SecurityEventBody, key: &Keypair) -> UnverifiedSecurityEvent {
    let canonical_body = canonical_json_bytes(body).test_expect("canonical receipt event body");
    let body_hash = digest(&canonical_body);
    let projection = SecurityEventReceiptProjection {
        version: SECURITY_EVENT_RECEIPT_PROJECTION_VERSION.to_string(),
        body: body.clone(),
    };
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "event_id": body.event_id.as_str(),
        "producer_id": body.producer_id.as_str(),
        "projection_version": SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
    }))
    .test_expect("security event receipt action");
    let receipt = ChioReceipt::sign_with_backend(
        ChioReceiptBody {
            id: String::new(),
            timestamp: body.ingest_time_unix_ms / 1_000,
            capability_id: "chio.security-event.projection".to_string(),
            tool_server: "chio.kernel".to_string(),
            tool_name: "security_event".to_string(),
            action,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
            content_hash: hex::encode(body_hash.as_bytes()),
            policy_hash: hex::encode([9_u8; 32]),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({"security_event_projection": projection})),
            trust_level: TrustLevel::Verified,
            tenant_id: Some(body.tenant_id.as_str().to_string()),
            kernel_key: key.public_key(),
            bbs_projection_version: None,
        },
        &Ed25519Backend::new(key.clone()),
    )
    .test_expect("sign security event receipt");
    let evidence = canonical_json_bytes(&receipt).test_expect("canonical security event receipt");
    unverified_event_with_evidence(body, evidence)
}

fn correlation_policy() -> CorrelationPolicy {
    CorrelationPolicy::new(0, 4_096, 8, false).test_expect("correlation policy")
}

#[test]
fn temporal_within_boundary() {
    let rule = temporal_rule("active-defense-temporal-boundary");
    let inside_directory = tempdir().test_expect("inside directory");
    let inside_store = Arc::new(
        SqliteSecurityStateStore::open(inside_directory.path().join("events.db"))
            .test_expect("inside event store"),
    );
    let inside = TemporalCorrelator::new(inside_store, correlation_policy());
    let first = verified_event(
        "inside-first",
        SecurityEventKind::CredentialAccess,
        100,
        1_000,
        ProducerTrustClass::InternalDetector,
    );
    let boundary = verified_event(
        "inside-boundary",
        SecurityEventKind::EgressAttempt,
        150,
        9_000,
        ProducerTrustClass::InternalDetector,
    );
    assert_eq!(
        inside.ingest(&rule, &first).status,
        CorrelationStatus::Accepted
    );
    let matched = inside.ingest(&rule, &boundary);
    assert_eq!(matched.status, CorrelationStatus::Matched);
    assert_eq!(matched.findings.len(), 1);
    let ordered: Vec<&str> = matched.findings[0]
        .ordered_event_ids
        .as_slice()
        .iter()
        .map(EventId::as_str)
        .collect();
    assert_eq!(ordered, vec!["inside-first", "inside-boundary"]);

    let outside_directory = tempdir().test_expect("outside directory");
    let outside_store = Arc::new(
        SqliteSecurityStateStore::open(outside_directory.path().join("events.db"))
            .test_expect("outside event store"),
    );
    let outside = TemporalCorrelator::new(outside_store, correlation_policy());
    let first = verified_event(
        "outside-first",
        SecurityEventKind::CredentialAccess,
        100,
        5_000,
        ProducerTrustClass::InternalDetector,
    );
    let beyond = verified_event(
        "outside-beyond",
        SecurityEventKind::EgressAttempt,
        151,
        5_001,
        ProducerTrustClass::InternalDetector,
    );
    assert_eq!(
        outside.ingest(&rule, &first).status,
        CorrelationStatus::Accepted
    );
    let not_matched = outside.ingest(&rule, &beyond);
    assert_eq!(not_matched.status, CorrelationStatus::Accepted);
    assert!(not_matched.findings.is_empty());
}

fn declassification_receipt_request(body: &ActiveDefenseReceiptBody) -> ReceiptAppendRequest {
    body.validate()
        .test_expect("valid declassification receipt");
    let canonical = canonical_json_bytes(body).test_expect("canonical declassification receipt");
    ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: record(body.kind().as_str()),
        evidence_id: body
            .evidence_id()
            .test_expect("declassification evidence id"),
        canonical_body: CanonicalBody::new(canonical).test_expect("canonical receipt body"),
        body_hash: body
            .body_digest()
            .test_expect("declassification body digest"),
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    }
}

struct EvidenceBackedDeclassificationUse<'a> {
    store: &'a SqliteSecurityStateStore,
    commit: &'a DeclassificationConsumptionEvidenceCommit,
}

impl DeclassificationUseStore for EvidenceBackedDeclassificationUse<'_> {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume> {
        if request != &self.commit.consumption {
            return Err(PortError::conflict());
        }
        self.store
            .commit_declassification_consumption_evidence(self.commit)
    }

    fn record_outcome(&self, _: &DeclassificationOutcomeRequest) -> PortResult<()> {
        Err(PortError::unavailable())
    }
}

#[test]
fn declassification_replay() {
    let authority = Keypair::from_seed(&[66; 32]);
    let authority_id = record("active-defense-declassification-authority");
    let purpose = DeclassificationPurpose::new("support").test_expect("purpose");
    let source = label(&["phi", "pii"]);
    let target = InformationLabel::bottom();
    let canonical_request =
        CanonicalBody::new(br#"{"export":"patient"}"#.to_vec()).test_expect("canonical request");
    let request_hash = canonical_request_hash(&canonical_request).test_expect("request hash");
    let verification = DeclassificationVerificationRequest {
        capability_id: record("capability-active-defense"),
        tenant_id: tenant("tenant-active-defense"),
        subject_id: principal("principal-active-defense"),
        agent_id: record("agent-active-defense"),
        session_id: SessionId::new("session-declassification").test_expect("session id"),
        source_label: source.clone(),
        destination_id: DestinationId::new("server-active-defense").test_expect("destination id"),
        tool_name: record("export-records"),
        purpose: purpose.clone(),
        policy_purposes: BTreeSet::from([purpose.clone()]),
        manifest_purposes: BTreeSet::from([purpose.clone()]),
        canonical_request: canonical_request.clone(),
        now_unix_ms: 150_000,
        trusted_authorities: BTreeMap::from([(authority_id.clone(), authority.public_key())]),
    };
    let grant = SignedDeclassificationGrant::sign(
        DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("grant-active-defense").test_expect("grant id"),
            capability_id: verification.capability_id.clone(),
            tenant_id: verification.tenant_id.clone(),
            subject_id: verification.subject_id.clone(),
            agent_id: verification.agent_id.clone(),
            session_id: verification.session_id.clone(),
            source_label_hash: information_label_hash(&source).test_expect("source label hash"),
            target_label: target.clone(),
            destination_id: verification.destination_id.clone(),
            tool_name: verification.tool_name.clone(),
            purpose: purpose.clone(),
            request_hash,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            authority_key_id: authority_id,
        })
        .test_expect("declassification grant body"),
        &authority,
    )
    .test_expect("sign declassification grant");
    let verified = verify_declassification(&grant, &verification)
        .test_expect("verify grant for durable consumption evidence");

    let binding = DeclassificationTransitionBinding::Consumption {
        tenant_id: verified.tenant_id().clone(),
        grant_id: verified.grant_id().clone(),
        request_hash: verified.request_hash(),
        request_id: RequestId::new("request-declassification").test_expect("request id"),
    };
    let transition_id =
        derive_declassification_transition_id(&binding).test_expect("transition id");
    let event_id = derive_declassification_event_id(&binding).test_expect("event id");
    let grant_bytes = canonical_json_bytes(&grant).test_expect("canonical grant");
    let body = ActiveDefenseReceiptBody::DeclassificationConsumption(
        DeclassificationConsumptionReceiptBody {
            header: ActiveDefenseReceiptHeader::new(
                150_000,
                verified.tenant_id().clone(),
                transition_id,
                Vec::new(),
            )
            .test_expect("receipt header"),
            policy: ActiveDefensePolicyBinding {
                policy_version: record("active-defense-declassification-policy"),
                policy_hash: digest(b"declassification-policy"),
            },
            grant_id: verified.grant_id().clone(),
            grant_hash: digest(&grant_bytes),
            request_hash: verified.request_hash(),
            event_id,
            state: DeclassificationUseState::ConsumedPendingDispatch,
        },
    );
    let commit = DeclassificationConsumptionEvidenceCommit {
        consumption: DeclassificationConsumeRequest {
            tenant_id: verified.tenant_id().clone(),
            grant_id: verified.grant_id().clone(),
            request_hash: verified.request_hash(),
            consumed_at_unix_ms: 150_000,
            grant_expires_at_unix_ms: 200_000,
        },
        transition_binding: binding,
        receipt: declassification_receipt_request(&body),
    };
    let directory = tempdir().test_expect("temporary directory");
    let evaluated_store =
        SqliteSecurityStateStore::open(directory.path().join("evaluated-declassification.db"))
            .test_expect("open evaluated declassification store");
    evaluated_store
        .ensure_declassification_evidence_ready()
        .test_expect("evaluated declassification evidence ready");
    evaluated_store
        .seal_declassification_live_dispatch()
        .test_expect("seal evaluated live declassification dispatch");
    let evaluated_use = EvidenceBackedDeclassificationUse {
        store: &evaluated_store,
        commit: &commit,
    };
    let flow_request = || {
        let mut flow = resolved_flow(
            FlowStateSnapshot {
                key: FlowStateKey {
                    session_id: verification.session_id.clone(),
                    ..flow_key("session-declassification", "epoch-active-defense")
                },
                ..empty_snapshot("session-declassification")
            },
            source.clone(),
            target.clone(),
            ToolFlowDeclaration::new(
                None,
                Some(target.clone()),
                true,
                BTreeSet::from([purpose.clone()]),
            )
            .test_expect("declassification manifest"),
        );
        flow.request_hash = request_hash;
        flow.request_id = RequestId::new("request-declassification").test_expect("request id");
        flow.purpose = purpose.clone();
        flow.effective_declassification_purposes = verification.policy_purposes.clone();
        flow.trusted_declassification_authorities = verification.trusted_authorities.clone();
        flow.declassification = Some(
            verify_declassification(&grant, &verification)
                .test_expect("verify signed declassification grant"),
        );
        flow
    };
    let first_admission =
        evaluate_pre_invocation_with_declassification(flow_request(), &evaluated_use)
            .test_expect("consume grant through production flow evaluation");
    assert!(first_admission.declassification.is_some());
    assert_eq!(
        evaluate_pre_invocation_with_declassification(flow_request(), &evaluated_use),
        Err(FlowDenial::DeclassificationReplay)
    );

    let store = SqliteSecurityStateStore::open(directory.path().join("declassification.db"))
        .test_expect("open declassification store");
    store
        .ensure_declassification_evidence_ready()
        .test_expect("declassification evidence ready");
    store
        .seal_declassification_live_dispatch()
        .test_expect("seal live declassification dispatch");
    assert_eq!(
        store
            .commit_declassification_consumption_evidence(&commit)
            .test_expect("consume grant once"),
        DeclassificationConsume::Consumed
    );
    assert_eq!(
        store
            .commit_declassification_consumption_evidence(&commit)
            .test_expect("observe replay"),
        DeclassificationConsume::AlreadyConsumed {
            request_hash: verified.request_hash(),
            state: DeclassificationUseState::ConsumedPendingDispatch,
        }
    );
}

#[test]
fn session_isolation_epoch() {
    let directory = tempdir().test_expect("temporary directory");
    let store = SqliteSecurityStateStore::open(directory.path().join("session-state.db"))
        .test_expect("open flow store");
    let original_key = flow_key("session-original", "epoch-active-defense");
    store
        .join(&FlowJoinRequest {
            key: original_key.clone(),
            principal_join: label(&["pii"]),
            lineage_join: label(&["phi"]),
            session_join: label(&["session-secret"]),
            transition_id: record("session-original-taint"),
        })
        .test_expect("persist original taint");
    let replacement_key = FlowStateKey {
        session_id: SessionId::new("session-replacement").test_expect("replacement session"),
        ..original_key.clone()
    };
    let inherited = store
        .join(&FlowJoinRequest {
            key: replacement_key,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("session-replacement-without-isolation"),
        })
        .test_expect("replace session inside existing isolation epoch");
    assert!(inherited
        .principal_label
        .compartments()
        .is_some_and(|values| values.contains(&compartment("pii"))));
    assert!(inherited
        .lineage_label
        .compartments()
        .is_some_and(|values| values.contains(&compartment("phi"))));
    assert_eq!(
        evaluate_pre_invocation(resolved_flow(
            inherited,
            InformationLabel::bottom(),
            label(&["pii"]),
            egress_manifest(label(&["pii"])),
        )),
        Err(FlowDenial::PolicyFlowViolation)
    );

    let unverified_epoch = FlowStateKey {
        session_id: SessionId::new("session-unverified-epoch").test_expect("session id"),
        isolation_epoch_id: IsolationEpochId::new("epoch-unverified").test_expect("epoch id"),
        ..original_key
    };
    let error = store
        .join(&FlowJoinRequest {
            key: unverified_epoch,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("session-unverified-epoch"),
        })
        .test_expect_err("unverified isolation transition must fail");
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
}

#[test]
fn event_producer_trust() {
    let trusted_key = Keypair::from_seed(&[67; 32]);
    let wrong_key = Keypair::from_seed(&[68; 32]);
    let receipt_key = Keypair::from_seed(&[69; 32]);
    let verifier = Arc::new(
        NativeSecurityEventVerifier::new(
            Arc::new(FixedClock(10_000)),
            vec![TrustedSecurityEventProducer {
                tenant_id: tenant("tenant-active-defense"),
                producer_id: ProducerId::new("detector-active-defense").test_expect("producer id"),
                producer_key_id: record("detector-active-defense-key"),
                policy_version: record("active-defense-correlation-policy"),
                producer_key: trusted_key.public_key(),
            }],
            vec![TrustedSecurityEventReceiptProducer {
                tenant_id: tenant("tenant-active-defense"),
                producer_id: ProducerId::new("detector-active-defense")
                    .test_expect("receipt producer id"),
                signer_key_id: record("detector-active-defense-key"),
                signer_key: receipt_key.public_key(),
            }],
            1_000,
            100,
        )
        .test_expect("native security event verifier"),
    );
    let ingress_directory = tempdir().test_expect("verified ingress directory");
    let ingress_store = Arc::new(
        SqliteSecurityStateStore::open(ingress_directory.path().join("producer-ingress.db"))
            .test_expect("verified ingress store"),
    );
    let ingress =
        VerifiedSecurityEventIngress::new(Arc::clone(&verifier), Arc::clone(&ingress_store))
            .test_expect("verified security event ingress");
    let correlation_directory = tempdir().test_expect("correlation directory");
    let correlation_store = Arc::new(
        SqliteSecurityStateStore::open(correlation_directory.path().join("producer-events.db"))
            .test_expect("correlation event store"),
    );
    let correlator = TemporalCorrelator::new(correlation_store, correlation_policy());
    let rule = temporal_rule("active-defense-producer-trust");

    let first_body = security_event_body(
        "trusted-first",
        SecurityEventKind::CredentialAccess,
        9_900,
        9_900,
        ProducerTrustClass::InternalDetector,
    );
    let first_input = signed_unverified_event(&first_body, &trusted_key);
    assert_eq!(
        ingress
            .verify_and_append(&first_input)
            .test_expect("verify and append trusted first event"),
        EventAppend::Inserted
    );
    let first_verified = SecurityEventVerifierPort::verify(verifier.as_ref(), &first_input)
        .test_expect("production verifier returns trusted first event");
    assert_eq!(
        correlator.ingest(&rule, &first_verified).status,
        CorrelationStatus::Accepted
    );

    let second_body = security_event_body(
        "trusted-second",
        SecurityEventKind::EgressAttempt,
        9_930,
        9_930,
        ProducerTrustClass::InternalDetector,
    );
    let second_input = signed_unverified_event(&second_body, &trusted_key);
    assert_eq!(
        ingress
            .verify_and_append(&second_input)
            .test_expect("verify and append trusted second event"),
        EventAppend::Inserted
    );
    let second_verified = SecurityEventVerifierPort::verify(verifier.as_ref(), &second_input)
        .test_expect("production verifier returns trusted second event");
    let matched = correlator.ingest(&rule, &second_verified);
    assert_eq!(matched.status, CorrelationStatus::Matched);
    assert_eq!(matched.findings.len(), 1);

    let unsigned_body = security_event_body(
        "unsigned-event",
        SecurityEventKind::CredentialAccess,
        9_940,
        9_940,
        ProducerTrustClass::InternalDetector,
    );
    let unsigned = unverified_event_with_evidence(
        &unsigned_body,
        canonical_json_bytes(&unsigned_body).test_expect("canonical unsigned event"),
    );
    assert_eq!(
        ingress
            .verify_and_append(&unsigned)
            .test_expect_err("unsigned event must not enter verified ingress")
            .kind(),
        PortErrorKind::InvalidData
    );

    let wrong_key_body = security_event_body(
        "wrong-key-event",
        SecurityEventKind::CredentialAccess,
        9_950,
        9_950,
        ProducerTrustClass::InternalDetector,
    );
    let wrong_key_event = signed_unverified_event(&wrong_key_body, &wrong_key);
    assert_eq!(
        ingress
            .verify_and_append(&wrong_key_event)
            .test_expect_err("wrong-key event must not enter verified ingress")
            .kind(),
        PortErrorKind::IntegrityFailure
    );

    let external_body = security_event_body(
        "receipt-backed-external-event",
        SecurityEventKind::EgressAttempt,
        9_960,
        9_960,
        ProducerTrustClass::VerifiedReceipt,
    );
    let external = receipt_unverified_event(&external_body, &receipt_key);
    assert_eq!(
        ingress
            .verify_and_append(&external)
            .test_expect("verify receipt-backed external event"),
        EventAppend::Inserted
    );
    let external_verified = SecurityEventVerifierPort::verify(verifier.as_ref(), &external)
        .test_expect("production verifier returns receipt-backed external event");
    let advisory = correlator.ingest(&rule, &external_verified);
    assert_eq!(advisory.status, CorrelationStatus::AdvisoryOnly);
    assert!(advisory.automatic_response_suppressed);
    assert!(advisory.findings.is_empty());

    let stale_body = security_event_body(
        "stale-internal-event",
        SecurityEventKind::CredentialAccess,
        8_000,
        8_000,
        ProducerTrustClass::InternalDetector,
    );
    let stale = signed_unverified_event(&stale_body, &trusted_key);
    assert_eq!(
        ingress
            .verify_and_append(&stale)
            .test_expect_err("stale event must not enter verified ingress")
            .kind(),
        PortErrorKind::InvalidData
    );
}

fn causal_node(
    tenant_id: &TenantId,
    node_id: &str,
    kind: CausalLineageNodeKind,
) -> CausalLineageNode {
    CausalLineageNode {
        tenant_id: tenant_id.clone(),
        node_id: record(node_id),
        kind,
    }
}

fn causal_edge(
    tenant_id: &TenantId,
    parent_id: &str,
    child_id: &str,
    kind: CausalLineageEdgeKind,
) -> CausalLineageEdge {
    CausalLineageEdge {
        tenant_id: tenant_id.clone(),
        parent_id: record(parent_id),
        child_id: record(child_id),
        kind,
    }
}

#[test]
fn truncated_lineage_no_containment() {
    let directory = tempdir().test_expect("temporary directory");
    let store = Arc::new(
        SqliteReceiptStore::open(directory.path().join("lineage.db"))
            .test_expect("open lineage store"),
    );
    let tenant_id = tenant("tenant-active-defense");
    store
        .commit_causal_lineage(&CausalLineageCommitRequest {
            tenant_id: tenant_id.clone(),
            metadata: CausalLineageCommitMetadata {
                source_lineage_version: 1,
                observed_commit_index: 1,
                authoritative_commit_index: 1,
                completeness_watermark: Some(1),
            },
            nodes: CausalLineageNodes::new(vec![
                causal_node(&tenant_id, "cap-root", CausalLineageNodeKind::Capability),
                causal_node(&tenant_id, "cap-child", CausalLineageNodeKind::Capability),
                causal_node(&tenant_id, "receipt-child", CausalLineageNodeKind::Receipt),
            ])
            .test_expect("causal nodes"),
            edges: CausalLineageEdges::new(vec![
                causal_edge(
                    &tenant_id,
                    "cap-root",
                    "cap-child",
                    CausalLineageEdgeKind::CapabilityDelegation,
                ),
                causal_edge(
                    &tenant_id,
                    "cap-child",
                    "receipt-child",
                    CausalLineageEdgeKind::CapabilityReceipt,
                ),
            ])
            .test_expect("causal edges"),
        })
        .test_expect("commit causal lineage");
    let resolver = CausalBlastRadiusResolver::new(store.clone(), store);
    let request = BlastRadiusRequest {
        tenant_id,
        action_id: action("truncated-lineage-action"),
        seed_ids: BlastRadiusSeeds::new(vec![record("cap-root")]).test_expect("blast seeds"),
        query_bounds: BlastRadiusQueryBounds {
            max_depth: 8,
            max_nodes: 1,
            max_edges: 8,
        },
    };
    let result = resolver.resolve(&request);
    assert!(matches!(
        result,
        BlastRadiusResult::Incomplete {
            reason: BlastRadiusIncompleteReason::TruncatedSnapshot,
            ..
        }
    ));
    let rejected = resolver.acquire_validated_fence(
        &request,
        &result,
        current_unix_ms().saturating_add(60_000),
        &chio_security_types::ports::LineageFenceRequest {
            tenant_id: request.tenant_id.clone(),
            action_id: request.action_id.clone(),
            expected_commit_index: 1,
            expected_affected_set_hash: digest(b"truncated-affected-set"),
            scheduler_lease_owner_id: LeaseOwnerId::new("truncated-lineage-worker")
                .test_expect("lease owner"),
            scheduler_fencing_token: 1,
            expires_at_unix_ms: current_unix_ms().saturating_add(60_000),
        },
    );
    assert_eq!(rejected, Err(FenceValidationOutcome::InvalidApprovedResult));
}

fn overlay_target(session_id: &str) -> TenantScopedId {
    containment_session_target(
        &tenant("tenant-active-defense"),
        &SessionId::new(session_id).test_expect("session id"),
    )
    .test_expect("containment target")
}

fn empty_overlay(target: TenantScopedId) -> OverlaySnapshot {
    OverlaySnapshot {
        target,
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())
            .test_expect("empty contributions"),
        highest_fencing_token: 0,
    }
}

fn claimed_overlay_store(
    path: &std::path::Path,
    action_id: &ActionId,
) -> (SqliteSecurityStateStore, u64) {
    let store = SqliteSecurityStateStore::open(path).test_expect("open overlay store");
    let now = current_unix_ms();
    let canonical_body = CanonicalBody::new(b"{}".to_vec()).test_expect("response body");
    store
        .create(&ResponsePlanRecord {
            tenant_id: tenant("tenant-active-defense"),
            action_id: action_id.clone(),
            generation: 0,
            state: record("active"),
            body_hash: digest(canonical_body.as_bytes()),
            canonical_body,
            due_at_unix_ms: Some(now.saturating_sub(1)),
        })
        .test_expect("create response plan");
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant("tenant-active-defense"),
            claim_id: record("active-defense-overlay-claim"),
            lease_owner_id: LeaseOwnerId::new("active-defense-overlay-worker")
                .test_expect("lease owner"),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(120_000),
            max_claims: 1,
        })
        .test_expect("claim response plan");
    (store, work[0].fencing_token)
}

struct OverlayApplyFixture<'a> {
    session_id: &'a str,
    action_id: ActionId,
    effect_id: EffectId,
    posture_rank: u32,
    expires_at_unix_ms: u64,
    scheduler_fencing_token: u64,
    idempotency_suffix: &'a str,
}

fn overlay_apply_request(
    current: &OverlaySnapshot,
    fixture: OverlayApplyFixture<'_>,
) -> OverlayApplyRequest {
    let OverlayApplyFixture {
        session_id,
        action_id,
        effect_id,
        posture_rank,
        expires_at_unix_ms,
        scheduler_fencing_token,
        idempotency_suffix,
    } = fixture;
    let contribution_bytes = format!("{{\"posture_rank\":{posture_rank}}}").into_bytes();
    let contribution_hash = digest(&contribution_bytes);
    let request = EffectRequest {
        tenant_id: current.target.tenant_id.clone(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("plan:{}", action_id.as_str()).as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendSession,
        target: ResponseTarget::Session {
            session_id: SessionId::new(session_id).test_expect("session id"),
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(&format!("response_effect_command:{idempotency_suffix}")),
        expected_version_hash: containment_overlay_version_hash(current)
            .test_expect("overlay base hash"),
        scheduler_lease_owner_id: LeaseOwnerId::new("active-defense-overlay-worker")
            .test_expect("lease owner"),
        scheduler_fencing_token,
        canonical_contribution: CanonicalBody::new(contribution_bytes)
            .test_expect("contribution body"),
        contribution_hash,
    };
    let contribution = OverlayContribution {
        effect_id: effect_id.clone(),
        posture_rank,
        contribution_hash,
        expires_at_unix_ms: Some(expires_at_unix_ms),
    };
    let resulting_snapshot =
        predict_containment_overlay_apply(current, &contribution, scheduler_fencing_token)
            .test_expect("predict overlay apply");
    OverlayApplyRequest {
        target: current.target.clone(),
        action_id,
        contribution: contribution.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: ContainmentOverlayCommand {
            request,
            result: EffectResult {
                effect_id,
                resulting_version_hash: containment_installed_version_hash(
                    &current.target,
                    &contribution,
                )
                .test_expect("installed contribution hash"),
                applied: true,
            },
            resulting_snapshot,
        },
    }
}

fn overlay_remove_request(
    apply: &OverlayApplyRequest,
    current: &OverlaySnapshot,
    scheduler_fencing_token: u64,
    idempotency_suffix: &str,
) -> OverlayRemoveRequest {
    let mut request = apply.command.request.clone();
    request.operation = EffectOperation::Remove;
    request.idempotency_key = record(&format!("response_effect_command:{idempotency_suffix}"));
    request.expected_version_hash = apply.command.result.resulting_version_hash;
    request.scheduler_fencing_token = scheduler_fencing_token;
    let resulting_snapshot = predict_containment_overlay_remove(
        current,
        &apply.contribution.effect_id,
        scheduler_fencing_token,
    )
    .test_expect("predict overlay removal");
    OverlayRemoveRequest {
        target: apply.target.clone(),
        action_id: apply.action_id.clone(),
        effect_id: apply.contribution.effect_id.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: ContainmentOverlayCommand {
            request,
            result: EffectResult {
                effect_id: apply.contribution.effect_id.clone(),
                resulting_version_hash: containment_overlay_version_hash(&resulting_snapshot)
                    .test_expect("removed overlay hash"),
                applied: false,
            },
            resulting_snapshot,
        },
    }
}

fn overlay_guard_verdict(store: Arc<SqliteSecurityStateStore>, session_id: &str) -> Verdict {
    let guard = ContainmentGuard::new(store, MissingContextPolicy::Deny);
    let request = request();
    let security = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        tenant("tenant-active-defense"),
        SessionId::new(session_id).test_expect("session id"),
        principal("principal-active-defense"),
        IsolationEpochId::new("epoch-active-defense").test_expect("epoch id"),
        LineageId::new("lineage-active-defense").test_expect("lineage id"),
        7,
    ));
    guard
        .evaluate(
            &GuardContext::new(&request, &request.capability.scope)
                .with_security_context(Some(&security)),
        )
        .test_expect("containment guard decision")
        .verdict
}

#[test]
fn overlapping_ttl_lift() {
    let directory = tempdir().test_expect("temporary directory");
    let action_id = action("overlapping-ttl-action");
    let (store, token) = claimed_overlay_store(&directory.path().join("overlap.db"), &action_id);
    let session_id = "session-overlapping-ttl";
    let empty = empty_overlay(overlay_target(session_id));
    let now = current_unix_ms();
    let long = overlay_apply_request(
        &empty,
        OverlayApplyFixture {
            session_id,
            action_id: action_id.clone(),
            effect_id: effect("overlap-long"),
            posture_rank: 3,
            expires_at_unix_ms: now.saturating_add(90_000),
            scheduler_fencing_token: token,
            idempotency_suffix: "overlap-apply-long",
        },
    );
    let one = store
        .apply_contribution(&long)
        .test_expect("apply long TTL");
    let short = overlay_apply_request(
        &one,
        OverlayApplyFixture {
            session_id,
            action_id,
            effect_id: effect("overlap-short"),
            posture_rank: 8,
            expires_at_unix_ms: now.saturating_add(30_000),
            scheduler_fencing_token: token,
            idempotency_suffix: "overlap-apply-short",
        },
    );
    let both = store
        .apply_contribution(&short)
        .test_expect("apply short TTL");
    assert_eq!(both.active_contributions.len(), 2);
    assert_eq!(
        overlay_guard_verdict(Arc::new(store), session_id),
        Verdict::Deny
    );

    let store = SqliteSecurityStateStore::open(directory.path().join("overlap.db"))
        .test_expect("reopen overlap store");
    let lift_short = overlay_remove_request(&short, &both, token, "overlap-lift-short");
    let long_remaining = store
        .remove_contribution(&lift_short)
        .test_expect("lift shorter TTL contribution first");
    assert_eq!(long_remaining.active_contributions.len(), 1);
    assert_eq!(long_remaining.effective_posture_rank, 3);
    assert_eq!(
        overlay_guard_verdict(Arc::new(store), session_id),
        Verdict::Deny
    );

    let store = SqliteSecurityStateStore::open(directory.path().join("overlap.db"))
        .test_expect("reopen overlap store after first lift");
    let lift_long = overlay_remove_request(&long, &long_remaining, token, "overlap-lift-long");
    let lifted = store
        .remove_contribution(&lift_long)
        .test_expect("lift remaining long TTL contribution");
    assert!(lifted.active_contributions.is_empty());
    assert_eq!(
        overlay_guard_verdict(Arc::new(store), session_id),
        Verdict::Allow
    );
}

include!("active_defense/partial_rollback.rs");
