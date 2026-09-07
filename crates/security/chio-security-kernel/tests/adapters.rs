use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chio_core::capability::caveat::{
    CapabilitySecurityBinding, CAPABILITY_SECURITY_BINDING_SCHEMA,
};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::receipt::security::ActiveDefenseReceiptBody;
use chio_core::{
    canonical_json_bytes, sha256, Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm,
    SigningBackend,
};
use chio_core_types::{SignedDeclassificationGrant, SignedSecurityEvent};
use chio_flow::{
    canonical_request_hash, information_label_hash, verify_declassification,
    DeclassificationDispatchOutcome, DeclassificationVerificationRequest, FlowDenial,
    PostInvocationFlow, ResolvedFlowRequest,
};
use chio_kernel::{
    CapabilityAuthority, CapabilityAuthorityWorkloadBinding, ChioKernel, Guard, GuardContext,
    KernelConfig, MemoryBudgetConfig, NestedFlowBridge, PostInvocationContext, PostInvocationHook,
    PostInvocationPipeline, PostInvocationVerdict, SecurityInvocationContext,
    SecurityInvocationContextV1, SecurityPreDispatchContext, SecurityPreDispatchHook,
    SecurityPreDispatchPolicy, SecurityRequestLifecyclePermit, ToolCallRequest,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_security_kernel::{
    ContainmentGuard, EngineFlowPostInvocationPort, EngineFlowPreInvocationPort,
    FlowDispatchOutcomeRecorder, FlowPostInvocationHook, FlowPostInvocationInput,
    FlowPostInvocationPort, FlowPostInvocationResolver, FlowPreDispatchHook, FlowPreDispatchInput,
    FlowPreDispatchPort, FlowPreInvocationGuard, FlowPreInvocationInput, FlowPreInvocationPort,
    FlowPreInvocationResolver, MissingContextPolicy, RawOutputTripwireHook, SecurityClock,
    SecurityEventIngress, TripwireEventPublisher, TripwireGuard,
};
use chio_security_types::flow::{DeclassificationPurpose, ToolFlowDeclaration};
use chio_security_types::ports::{
    BoundedVec, CanonicalBody, ContainmentOverlayStore, DestinationId, Digest32,
    EffectExecutionStatus, EffectId, EffectResultQuery, EventAppend, FlowJoinRequest, FlowStateKey,
    FlowStateSnapshot, GrantId, OpaqueReceiptRef, OverlayApplyRequest, OverlayContribution,
    OverlayContributions, OverlayRemoveRequest, OverlaySnapshot, PortError, PortResult, ProducerId,
    ReceiptAppendRequest, RecordId, RequestId, SecurityReceiptSink, TenantId, TenantScopedId,
    TripwireDecision, TripwireDetectorPort, TripwireInput, TripwireKind, UnverifiedSecurityEvent,
};
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId};
use chio_security_types::{
    Compartment, DeclassificationGrantBody, DeclassificationGrantClaims, InformationLabel,
    PrincipalId, SecurityEventBody, SecurityEventKind,
};
use chio_test_support::prelude::*;

const FLOW_DENIALS: [FlowDenial; 19] = [
    FlowDenial::StateOverflow,
    FlowDenial::StateChanged,
    FlowDenial::InvalidManifest,
    FlowDenial::DeclassificationBindingMismatch,
    FlowDenial::DeclassificationPurposeDenied,
    FlowDenial::DeclassificationNotYetValid,
    FlowDenial::DeclassificationExpired,
    FlowDenial::DeclassificationUntrustedAuthority,
    FlowDenial::UnexpectedDeclassification,
    FlowDenial::DeclassificationReplay,
    FlowDenial::DeclassificationStoreFailure,
    FlowDenial::ClassifierFailure,
    FlowDenial::ClassifierBindingMismatch,
    FlowDenial::MissingPolicyClearance,
    FlowDenial::MissingManifestClearance,
    FlowDenial::TopSource,
    FlowDenial::TopClearance,
    FlowDenial::PolicyFlowViolation,
    FlowDenial::ManifestFlowViolation,
];

#[derive(Clone, Copy)]
enum DetectorBehavior {
    Clear,
    Match(Digest32, Digest32),
    ContentBoundMatch,
    Fail,
}

struct FakeDetector {
    behavior: DetectorBehavior,
}

impl TripwireDetectorPort for FakeDetector {
    fn detect(&self, input: &TripwireInput) -> PortResult<TripwireDecision> {
        match self.behavior {
            DetectorBehavior::Clear => Ok(TripwireDecision::Clear),
            DetectorBehavior::Match(artifact_id_hash, artifact_version_hash) => {
                Ok(TripwireDecision::Match {
                    artifact_id_hash,
                    artifact_version_hash,
                })
            }
            DetectorBehavior::ContentBoundMatch => Ok(TripwireDecision::Match {
                artifact_id_hash: input.content_digest,
                artifact_version_hash: input.canonical_context_digest,
            }),
            DetectorBehavior::Fail => Err(PortError::unavailable()),
        }
    }
}

struct FixedClock(u64);

impl SecurityClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(self.0)
    }
}

struct FakeEvents {
    fail: bool,
    appends: AtomicUsize,
    events: Mutex<Vec<UnverifiedSecurityEvent>>,
}

struct FakeSecurityReceipts {
    append_fails: bool,
    bodies: Mutex<Vec<ActiveDefenseReceiptBody>>,
}

impl FakeSecurityReceipts {
    fn new(append_fails: bool) -> Self {
        Self {
            append_fails,
            bodies: Mutex::new(Vec::new()),
        }
    }

    fn bodies(&self) -> Vec<ActiveDefenseReceiptBody> {
        self.bodies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl SecurityReceiptSink for FakeSecurityReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        if self.append_fails {
            return Err(PortError::unavailable());
        }
        let body: ActiveDefenseReceiptBody =
            serde_json::from_slice(request.canonical_body.as_bytes())
                .map_err(|_| PortError::invalid_data())?;
        if body.evidence_id().map_err(|_| PortError::invalid_data())? != request.evidence_id {
            return Err(PortError::integrity_failure());
        }
        self.bodies
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(body);
        Ok(request.evidence_id.clone())
    }
}

impl FakeEvents {
    fn new(fail: bool) -> Self {
        Self {
            fail,
            appends: AtomicUsize::new(0),
            events: Mutex::new(Vec::new()),
        }
    }

    fn last_event(&self) -> UnverifiedSecurityEvent {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .cloned()
            .unwrap_or_else(|| panic!("tripwire event was not appended"))
    }

    fn events(&self) -> Vec<UnverifiedSecurityEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl SecurityEventIngress for FakeEvents {
    fn verify_and_append(&self, event: &UnverifiedSecurityEvent) -> PortResult<EventAppend> {
        let body: SecurityEventBody = serde_json::from_slice(event.canonical_body.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
        let signed: SignedSecurityEvent = serde_json::from_slice(event.source_evidence.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
        let canonical_body = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
        let signature_valid = signed
            .verify_trusted_producer(
                &producer(),
                &RecordId::new("security-kernel-test-key-v1")
                    .map_err(|_| PortError::invalid_data())?,
                &tripwire_keypair().public_key(),
            )
            .map_err(|_| PortError::integrity_failure())?;
        if !signature_valid
            || signed.body() != &body
            || canonical_body.as_slice() != event.canonical_body.as_bytes()
            || Digest32::new(*sha256(&canonical_body).as_bytes()) != event.body_hash
        {
            return Err(PortError::integrity_failure());
        }
        self.appends.fetch_add(1, Ordering::SeqCst);
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event.clone());
        if self.fail {
            Err(PortError::unavailable())
        } else {
            Ok(EventAppend::Inserted)
        }
    }
}

struct FailingSigner {
    key: Keypair,
}

impl SigningBackend for FailingSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    fn sign_bytes(&self, _: &[u8]) -> Result<Signature, chio_core::Error> {
        Err(chio_core::Error::InvalidSignature(
            "injected tripwire signing failure".to_string(),
        ))
    }
}

struct FailingPreFlow(FlowDenial);

impl FlowPreInvocationPort for FailingPreFlow {
    fn evaluate(&self, _input: &FlowPreInvocationInput<'_>) -> Result<(), FlowDenial> {
        Err(self.0)
    }
}

struct FailingPostFlow(FlowDenial);

impl FlowPostInvocationPort for FailingPostFlow {
    fn evaluate(&self, _input: &FlowPostInvocationInput<'_>) -> Result<(), FlowDenial> {
        Err(self.0)
    }
}

struct RecordingPreDispatchFlow {
    calls: Arc<AtomicUsize>,
    reject: bool,
}

impl FlowPreDispatchPort for RecordingPreDispatchFlow {
    fn commit(
        &self,
        input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(input.request.request_id, "request-a");
        assert_eq!(
            input.canonical_request,
            canonical_json_bytes(input.request).test_unwrap()
        );
        assert_eq!(input.security_context.context_generation(), 7);
        assert_eq!(
            input.dispatch_commitment_id.as_str(),
            "dispatch-commitment:test"
        );
        if self.reject {
            Err(FlowDenial::StateChanged)
        } else {
            Ok(None)
        }
    }
}

struct FailingFlowDispatchOutcomeRecorder;

impl FlowDispatchOutcomeRecorder for FailingFlowDispatchOutcomeRecorder {
    fn record(
        &mut self,
        _outcome: chio_flow::DeclassificationDispatchOutcome,
    ) -> Result<(), FlowDenial> {
        Err(FlowDenial::DeclassificationStoreFailure)
    }
}

struct FailingOutcomePreDispatchFlow;

impl FlowPreDispatchPort for FailingOutcomePreDispatchFlow {
    fn commit(
        &self,
        _input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        Ok(Some(Box::new(FailingFlowDispatchOutcomeRecorder)))
    }
}

struct KernelBoundaryPreDispatchFlow {
    calls: Arc<AtomicUsize>,
    outcomes: Arc<Mutex<Vec<DeclassificationDispatchOutcome>>>,
    reject: bool,
}

impl FlowPreDispatchPort for KernelBoundaryPreDispatchFlow {
    fn commit(
        &self,
        input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            input.canonical_request,
            canonical_json_bytes(input.request).test_unwrap()
        );
        assert_eq!(input.security_context.context_generation(), 7);
        assert!(input
            .dispatch_commitment_id
            .as_str()
            .starts_with("dispatch-commitment:"));
        if self.reject {
            return Err(FlowDenial::StateChanged);
        }
        Ok(Some(Box::new(RecordingFlowDispatchOutcome {
            outcomes: Arc::clone(&self.outcomes),
        })))
    }
}

struct RecordingFlowDispatchOutcome {
    outcomes: Arc<Mutex<Vec<DeclassificationDispatchOutcome>>>,
}

impl FlowDispatchOutcomeRecorder for RecordingFlowDispatchOutcome {
    fn record(&mut self, outcome: DeclassificationDispatchOutcome) -> Result<(), FlowDenial> {
        self.outcomes
            .lock()
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?
            .push(outcome);
        Ok(())
    }
}

struct FinalReleasePermit {
    releases: Arc<AtomicUsize>,
}

impl SecurityRequestLifecyclePermit for FinalReleasePermit {
    fn ensure_final_release(self: Box<Self>) -> Result<(), chio_kernel::KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct LifecyclePreDispatchFlow {
    releases: Arc<AtomicUsize>,
}

impl FlowPreDispatchPort for LifecyclePreDispatchFlow {
    fn acquire_request_lifecycle(
        &self,
        _input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, FlowDenial> {
        Ok(Some(Box::new(FinalReleasePermit {
            releases: Arc::clone(&self.releases),
        })))
    }

    fn commit(
        &self,
        _input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        Ok(None)
    }
}

struct BlockingPostInvocationHook;

impl PostInvocationHook for BlockingPostInvocationHook {
    fn name(&self) -> &str {
        "blocking-post-invocation"
    }

    fn inspect(
        &self,
        _context: &PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> PostInvocationVerdict {
        PostInvocationVerdict::Block("blocked after connector execution".to_string())
    }
}

struct CompilePreResolver;

impl FlowPreInvocationResolver for CompilePreResolver {
    fn resolve(
        &self,
        _input: &FlowPreInvocationInput<'_>,
    ) -> Result<ResolvedFlowRequest, FlowDenial> {
        Err(FlowDenial::ClassifierFailure)
    }

    fn persist(&self, _admission: &chio_flow::FlowAdmission) -> Result<(), FlowDenial> {
        Err(FlowDenial::StateChanged)
    }
}

struct PersistFailingPreResolver;

impl FlowPreInvocationResolver for PersistFailingPreResolver {
    fn resolve(
        &self,
        _input: &FlowPreInvocationInput<'_>,
    ) -> Result<ResolvedFlowRequest, FlowDenial> {
        Ok(resolved_flow_request())
    }

    fn persist(&self, _admission: &chio_flow::FlowAdmission) -> Result<(), FlowDenial> {
        Err(FlowDenial::DeclassificationStoreFailure)
    }
}

struct DeclassifyingPreResolver {
    persist_calls: Arc<AtomicUsize>,
}

impl FlowPreInvocationResolver for DeclassifyingPreResolver {
    fn resolve(
        &self,
        _input: &FlowPreInvocationInput<'_>,
    ) -> Result<ResolvedFlowRequest, FlowDenial> {
        Ok(declassifying_resolved_flow_request())
    }

    fn persist(&self, _admission: &chio_flow::FlowAdmission) -> Result<(), FlowDenial> {
        self.persist_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn resolved_flow_request() -> ResolvedFlowRequest {
    let bottom = InformationLabel::bottom();
    ResolvedFlowRequest {
        request_id: RequestId::new("request-a").test_unwrap(),
        request_hash: Digest32::new([7; 32]),
        transition_id: RecordId::new("flow-request-a").test_unwrap(),
        state: FlowStateSnapshot {
            key: FlowStateKey {
                tenant_id: TenantId::new("tenant-a").test_unwrap(),
                principal_id: PrincipalId::new("subject-a").test_unwrap(),
                lineage_id: LineageId::new("lineage-a").test_unwrap(),
                session_id: SessionId::new("session-a").test_unwrap(),
                isolation_epoch_id: IsolationEpochId::new("epoch-a").test_unwrap(),
            },
            principal_label: bottom.clone(),
            lineage_label: bottom.clone(),
            session_label: bottom.clone(),
            context_generation: 7,
        },
        payload_label: bottom.clone(),
        operator_input_floor: bottom.clone(),
        runtime_egress: true,
        capability_id: RecordId::new("capability-a").test_unwrap(),
        agent_id: RecordId::new("agent-a").test_unwrap(),
        tool_name: RecordId::new("tool-a").test_unwrap(),
        destination_id: DestinationId::new("server-a").test_unwrap(),
        purpose: DeclassificationPurpose::new("support").test_unwrap(),
        effective_declassification_purposes: BTreeSet::new(),
        trusted_declassification_authorities: BTreeMap::new(),
        now_unix_ms: 100,
        declassification: None,
        policy_clearances: BoundedVec::new(vec![bottom]).test_unwrap(),
        manifest: ToolFlowDeclaration::public_egress(),
        fence_expires_at_unix_ms: 1_000,
    }
}

fn declassifying_resolved_flow_request() -> ResolvedFlowRequest {
    let mut flow = resolved_flow_request();
    let owner = PrincipalId::new("owner-a").test_unwrap();
    let source = InformationLabel::try_known(
        BTreeMap::from([(owner.clone(), BTreeSet::from([owner]))]),
        BTreeSet::from([Compartment::new("restricted-a").test_unwrap()]),
    )
    .test_unwrap();
    let target = InformationLabel::bottom();
    let purpose = DeclassificationPurpose::new("support").test_unwrap();
    let canonical_request = CanonicalBody::new(br#"{"operation":"read"}"#.to_vec()).test_unwrap();
    let authority_id = RecordId::new("authority-a").test_unwrap();
    let authority = Keypair::from_seed(&[91; 32]);

    flow.payload_label = source.clone();
    flow.request_hash = canonical_request_hash(&canonical_request).test_unwrap();
    flow.purpose = purpose.clone();
    flow.effective_declassification_purposes = BTreeSet::from([purpose.clone()]);
    flow.trusted_declassification_authorities =
        BTreeMap::from([(authority_id.clone(), authority.public_key())]);
    flow.now_unix_ms = 150_000;
    flow.policy_clearances = BoundedVec::new(vec![target.clone()]).test_unwrap();
    flow.manifest = ToolFlowDeclaration::new(
        None,
        Some(target.clone()),
        true,
        BTreeSet::from([purpose.clone()]),
    )
    .test_unwrap();

    let verification = DeclassificationVerificationRequest {
        capability_id: flow.capability_id.clone(),
        tenant_id: flow.state.key.tenant_id.clone(),
        subject_id: flow.state.key.principal_id.clone(),
        agent_id: flow.agent_id.clone(),
        session_id: flow.state.key.session_id.clone(),
        source_label: source.clone(),
        destination_id: flow.destination_id.clone(),
        tool_name: flow.tool_name.clone(),
        purpose: purpose.clone(),
        policy_purposes: flow.effective_declassification_purposes.clone(),
        manifest_purposes: flow.manifest.declassification_purposes.clone(),
        canonical_request,
        now_unix_ms: flow.now_unix_ms,
        trusted_authorities: flow.trusted_declassification_authorities.clone(),
    };
    let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
        grant_id: GrantId::new("grant-adapter-a").test_unwrap(),
        capability_id: verification.capability_id.clone(),
        tenant_id: verification.tenant_id.clone(),
        subject_id: verification.subject_id.clone(),
        agent_id: verification.agent_id.clone(),
        session_id: verification.session_id.clone(),
        source_label_hash: information_label_hash(&source).test_unwrap(),
        target_label: target,
        destination_id: verification.destination_id.clone(),
        tool_name: verification.tool_name.clone(),
        purpose,
        request_hash: flow.request_hash,
        issued_at_unix_seconds: 100,
        expires_at_unix_seconds: 200,
        authority_key_id: authority_id,
    })
    .test_unwrap();
    let grant = SignedDeclassificationGrant::sign(body, &authority).test_unwrap();
    flow.declassification = Some(verify_declassification(&grant, &verification).test_unwrap());
    flow
}

struct CompilePostResolver;

impl FlowPostInvocationResolver for CompilePostResolver {
    fn resolve(
        &self,
        _input: &FlowPostInvocationInput<'_>,
    ) -> Result<PostInvocationFlow, FlowDenial> {
        Err(FlowDenial::ClassifierFailure)
    }

    fn persist(&self, _transition: &FlowJoinRequest) -> Result<(), FlowDenial> {
        Err(FlowDenial::StateChanged)
    }
}

#[derive(Clone, Copy)]
enum OverlayBehavior {
    Clear,
    Active,
    Fail,
}

struct FakeOverlays {
    behavior: OverlayBehavior,
}

impl ContainmentOverlayStore for FakeOverlays {
    fn ensure_containment_overlays_ready(&self) -> PortResult<()> {
        match self.behavior {
            OverlayBehavior::Fail => Err(PortError::unavailable()),
            OverlayBehavior::Clear | OverlayBehavior::Active => Ok(()),
        }
    }

    fn apply_contribution(&self, _request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        Err(PortError::conflict())
    }

    fn remove_contribution(&self, _request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot> {
        Err(PortError::conflict())
    }

    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        match self.behavior {
            OverlayBehavior::Clear => Ok(None),
            OverlayBehavior::Fail => Err(PortError::unavailable()),
            OverlayBehavior::Active => {
                let contributions = OverlayContributions::new(vec![OverlayContribution {
                    effect_id: EffectId::new("effect-a").test_unwrap(),
                    posture_rank: 1,
                    contribution_hash: Digest32::new([4; 32]),
                    expires_at_unix_ms: None,
                }])
                .test_unwrap();
                Ok(Some(OverlaySnapshot {
                    target: target.clone(),
                    generation: 1,
                    effective_posture_rank: 1,
                    active_contributions: contributions,
                    highest_fencing_token: 1,
                }))
            }
        }
    }

    fn load_containment_overlay_result(
        &self,
        _query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        Err(PortError::unavailable())
    }
}

struct CountingServer {
    invocations: Arc<AtomicUsize>,
}

struct PinnedWorkloadAuthority {
    issuer: Keypair,
    workload: CapabilityAuthorityWorkloadBinding,
}

impl CapabilityAuthority for PinnedWorkloadAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.issuer.public_key()
    }

    fn workload_binding(&self) -> Option<CapabilityAuthorityWorkloadBinding> {
        Some(self.workload.clone())
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "unused-pinned-workload-capability".to_string(),
                issuer: self.issuer.public_key(),
                subject: subject.clone(),
                scope,
                issued_at: 1,
                expires_at: 1_u64.saturating_add(ttl_seconds),
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &self.issuer,
        )
        .map_err(|error| chio_kernel::KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "server-a"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["tool-a".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"secret": "output"}))
    }
}

struct ContextProbeGuard;

impl Guard for ContextProbeGuard {
    fn name(&self) -> &str {
        "context-probe-pre"
    }

    fn evaluate(
        &self,
        context: &GuardContext<'_>,
    ) -> Result<chio_kernel::GuardDecision, chio_kernel::KernelError> {
        Ok(match context.security_context() {
            Some(security) if security.as_v1().context_generation() == 7 => {
                chio_kernel::GuardDecision::allow()
            }
            _ => chio_kernel::GuardDecision::deny(Vec::new()),
        })
    }
}

struct ContextProbeHook;

impl PostInvocationHook for ContextProbeHook {
    fn name(&self) -> &str {
        "context-probe-post"
    }

    fn inspect(
        &self,
        context: &PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> PostInvocationVerdict {
        match context.security_context() {
            Some(security) if security.as_v1().context_generation() == 7 => {
                PostInvocationVerdict::Allow
            }
            _ => PostInvocationVerdict::Block("context missing".to_string()),
        }
    }
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "server-a".to_string(),
            tool_name: "tool-a".to_string(),
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
    let keypair = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-a".to_string(),
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
    .test_unwrap();
    ToolCallRequest {
        request_id: "request-a".to_string(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "tool-a".to_string(),
        server_id: "server-a".to_string(),
        arguments: serde_json::json!({"value": "input"}),
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
    let lineage_root_id = request
        .capability
        .delegation_chain
        .first()
        .map_or(request.capability.id.as_str(), |link| {
            link.capability_id.as_str()
        });
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("tenant-a").test_unwrap(),
        SessionId::new("session-a").test_unwrap(),
        PrincipalId::new(request.agent_id.clone()).test_unwrap(),
        IsolationEpochId::new("epoch-a").test_unwrap(),
        LineageId::new(lineage_root_id).test_unwrap(),
        7,
    ))
}

fn kernel_with_server() -> (ChioKernel, ToolCallRequest, Arc<AtomicUsize>) {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "policy-a".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingServer {
        invocations: Arc::clone(&invocations),
    }));
    let subject = Keypair::generate();
    let capability = kernel
        .issue_capability(&subject.public_key(), scope(), 300)
        .test_unwrap();
    let request = ToolCallRequest {
        request_id: "kernel-request-a".to_string(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "tool-a".to_string(),
        server_id: "server-a".to_string(),
        arguments: serde_json::json!({"value": "input"}),
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
    };
    (kernel, request, invocations)
}

fn producer() -> ProducerId {
    ProducerId::new("security-kernel-test").test_unwrap()
}

fn tripwire_keypair() -> Keypair {
    Keypair::from_seed(&[41_u8; 32])
}

fn tripwire_publisher(events: Arc<FakeEvents>) -> Arc<TripwireEventPublisher> {
    Arc::new(
        TripwireEventPublisher::new(
            events,
            Arc::new(FixedClock(100)),
            Arc::new(Ed25519Backend::new(tripwire_keypair())),
            producer(),
            RecordId::new("security-kernel-test-key-v1").test_unwrap(),
            RecordId::new("security-kernel-test-policy-v1").test_unwrap(),
        )
        .test_unwrap()
        .with_receipt_evidence(
            Arc::new(FakeSecurityReceipts::new(false)),
            Digest32::new([31; 32]),
        )
        .test_unwrap(),
    )
}

fn tripwire_publisher_with_receipts(
    events: Arc<FakeEvents>,
    receipts: Arc<FakeSecurityReceipts>,
) -> Arc<TripwireEventPublisher> {
    Arc::new(
        TripwireEventPublisher::new(
            events,
            Arc::new(FixedClock(100)),
            Arc::new(Ed25519Backend::new(tripwire_keypair())),
            producer(),
            RecordId::new("security-kernel-test-key-v1").test_unwrap(),
            RecordId::new("security-kernel-test-policy-v1").test_unwrap(),
        )
        .test_unwrap()
        .with_receipt_evidence(receipts, Digest32::new([31; 32]))
        .test_unwrap(),
    )
}

#[test]
fn trait_conformance_compiles_against_kernel_hooks() {
    fn guard<T: Guard>() {}
    fn hook<T: PostInvocationHook>() {}
    fn pre_dispatch_hook<T: SecurityPreDispatchHook>() {}
    guard::<FlowPreInvocationGuard>();
    guard::<TripwireGuard>();
    guard::<ContainmentGuard>();
    hook::<FlowPostInvocationHook>();
    hook::<RawOutputTripwireHook>();
    pre_dispatch_hook::<FlowPreDispatchHook>();

    let pre = EngineFlowPreInvocationPort::new(Arc::new(CompilePreResolver));
    let post = EngineFlowPostInvocationPort::new(Arc::new(CompilePostResolver));
    let _: &dyn FlowPreInvocationPort = &pre;
    let _: &dyn FlowPostInvocationPort = &post;
}

#[test]
fn generic_pre_invocation_adapter_fails_closed_without_declassification_store() {
    let persist_calls = Arc::new(AtomicUsize::new(0));
    let engine = EngineFlowPreInvocationPort::new(Arc::new(DeclassifyingPreResolver {
        persist_calls: Arc::clone(&persist_calls),
    }));
    let request = request();
    let security = security_context(&request);
    let input = FlowPreInvocationInput {
        security_context: security.as_v1(),
        request: &request,
    };

    assert_eq!(
        engine.evaluate(&input),
        Err(FlowDenial::DeclassificationStoreFailure)
    );
    assert_eq!(persist_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn flow_pre_dispatch_hook_commits_canonical_authoritative_input() {
    let calls = Arc::new(AtomicUsize::new(0));
    let hook = FlowPreDispatchHook::new(Arc::new(RecordingPreDispatchFlow {
        calls: Arc::clone(&calls),
        reject: false,
    }));
    let request = request();
    let security = security_context(&request);
    let canonical = canonical_json_bytes(&request).test_unwrap();
    let commitment = RecordId::new("dispatch-commitment:test").test_unwrap();
    let context = SecurityPreDispatchContext {
        request: &request,
        canonical_request: &canonical,
        security_context: &security,
        dispatch_commitment_id: &commitment,
    };

    hook.commit(&context).test_unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn flow_pre_dispatch_hook_maps_flow_rejection_without_domain_details() {
    let calls = Arc::new(AtomicUsize::new(0));
    let hook = FlowPreDispatchHook::new(Arc::new(RecordingPreDispatchFlow {
        calls: Arc::clone(&calls),
        reject: true,
    }));
    let request = request();
    let security = security_context(&request);
    let canonical = canonical_json_bytes(&request).test_unwrap();
    let commitment = RecordId::new("dispatch-commitment:test").test_unwrap();
    let context = SecurityPreDispatchContext {
        request: &request,
        canonical_request: &canonical,
        security_context: &security,
        dispatch_commitment_id: &commitment,
    };

    let error = hook.commit(&context).test_unwrap_err();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!error.to_string().contains("StateChanged"));
}

#[test]
fn flow_pre_dispatch_hook_maps_outcome_persistence_to_non_retryable_recovery() {
    let hook = FlowPreDispatchHook::new(Arc::new(FailingOutcomePreDispatchFlow));
    let request = request();
    let security = security_context(&request);
    let canonical = canonical_json_bytes(&request).test_unwrap();
    let commitment = RecordId::new("dispatch-commitment:test").test_unwrap();
    let context = SecurityPreDispatchContext {
        request: &request,
        canonical_request: &canonical,
        security_context: &security,
        dispatch_commitment_id: &commitment,
    };
    let outcome = hook
        .commit(&context)
        .test_unwrap()
        .unwrap_or_else(|| panic!("flow authority omitted its outcome recorder"));

    let error = outcome.record_released().test_unwrap_err();

    assert!(matches!(
        &error,
        chio_kernel::KernelError::SecurityDispatchOutcomeRecoveryRequired(_)
    ));
    assert!(!matches!(&error, chio_kernel::KernelError::GuardDenied(_)));
    let report = error.report();
    assert_eq!(report.context["retryable"], false);
    assert!(report.suggested_fix.contains("Do not retry or redispatch"));
}

#[test]
fn public_entrypoint_propagates_authoritative_context_pre_and_post() {
    let (mut kernel, request, invocations) = kernel_with_server();
    kernel.add_guard(Box::new(ContextProbeGuard));
    kernel.add_post_invocation_hook(Box::new(ContextProbeHook));
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn pinned_workload_capability_requires_exact_signed_live_context() {
    let (mut kernel, mut request, invocations) = kernel_with_server();
    let issuer = Keypair::generate();
    let workload_signer = Keypair::generate();
    let workload = CapabilityAuthorityWorkloadBinding {
        tenant_id: "tenant-a".to_string(),
        workload_id: "authority-workload-a".to_string(),
        server_id: "authority-server-a".to_string(),
        signer_public_key: workload_signer.public_key(),
    };
    let capability_id = "bound-capability-a";
    let binding = CapabilitySecurityBinding {
        schema: CAPABILITY_SECURITY_BINDING_SCHEMA.to_string(),
        tenant_id: workload.tenant_id.clone(),
        lineage_id: capability_id.to_string(),
        session_id: "session-a".to_string(),
        principal_id: request.agent_id.clone(),
        isolation_epoch_id: "epoch-a".to_string(),
        context_generation: 7,
        workload_id: workload.workload_id.clone(),
        server_id: workload.server_id.clone(),
        workload_signer_public_key: workload.signer_public_key.to_hex(),
    };
    request.capability = CapabilityToken::sign_with_security_binding(
        CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer.public_key(),
            subject: request.capability.subject.clone(),
            scope: scope(),
            issued_at: 1,
            expires_at: u64::MAX,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        binding,
        &issuer,
    )
    .test_unwrap();
    kernel.set_capability_authority(Box::new(PinnedWorkloadAuthority { issuer, workload }));

    let missing_context = kernel
        .evaluate_tool_call_blocking(&request)
        .test_unwrap_err();
    assert!(matches!(
        missing_context,
        chio_kernel::KernelError::GuardDenied(_)
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    let context = security_context(&request);
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context)
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let wrong_epoch = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("tenant-a").test_unwrap(),
        SessionId::new("session-a").test_unwrap(),
        PrincipalId::new(request.agent_id.clone()).test_unwrap(),
        IsolationEpochId::new("epoch-b").test_unwrap(),
        LineageId::new(capability_id).test_unwrap(),
        7,
    ));
    let error = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &wrong_epoch)
        .test_unwrap_err();
    assert!(matches!(error, chio_kernel::KernelError::GuardDenied(_)));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn enforced_pre_dispatch_hook_commits_and_records_release_at_connector_boundary() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let calls = Arc::new(AtomicUsize::new(0));
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(FlowPreDispatchHook::new(Arc::new(
        KernelBoundaryPreDispatchFlow {
            calls: Arc::clone(&calls),
            outcomes: Arc::clone(&outcomes),
            reject: false,
        },
    ))));

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec![DeclassificationDispatchOutcome::Released]
    );
}

#[test]
fn enforced_pre_dispatch_missing_or_rejected_authority_denies_before_connector() {
    let (mut missing_hook_kernel, request, invocations) = kernel_with_server();
    missing_hook_kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let response = missing_hook_kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(response
        .receipt
        .evidence
        .iter()
        .any(|item| item.guard_name == "chio-security-pre-dispatch"));

    let (mut rejecting_kernel, request, invocations) = kernel_with_server();
    let calls = Arc::new(AtomicUsize::new(0));
    rejecting_kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    rejecting_kernel.set_security_pre_dispatch_hook(Arc::new(FlowPreDispatchHook::new(Arc::new(
        KernelBoundaryPreDispatchFlow {
            calls: Arc::clone(&calls),
            outcomes: Arc::new(Mutex::new(Vec::new())),
            reject: true,
        },
    ))));
    let response = rejecting_kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn request_lifecycle_linearizes_release_after_post_invocation_block() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let releases = Arc::new(AtomicUsize::new(0));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(FlowPreDispatchHook::new(Arc::new(
        LifecyclePreDispatchFlow {
            releases: Arc::clone(&releases),
        },
    ))));
    kernel.add_post_invocation_hook(Box::new(BlockingPostInvocationHook));

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();

    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
}

#[test]
fn synthetic_and_missing_context_block_under_enforcement() {
    let flow = Arc::new(FailingPostFlow(FlowDenial::ClassifierFailure));
    let hook = FlowPostInvocationHook::new(flow, MissingContextPolicy::Deny);
    let synthetic = PostInvocationContext::synthetic("tool-a");
    let inspection = hook.inspect_with_evidence(&synthetic, &serde_json::json!({"ok": true}));
    assert!(matches!(
        inspection.verdict,
        PostInvocationVerdict::Block(_)
    ));
    assert_eq!(inspection.evidence.len(), 1);

    let request = request();
    let guard = FlowPreInvocationGuard::new(
        Arc::new(FailingPreFlow(FlowDenial::ClassifierFailure)),
        MissingContextPolicy::Deny,
    );
    let context = GuardContext::new(&request, &request.capability.scope);
    let decision = guard.evaluate(&context).test_unwrap();
    assert_eq!(decision.verdict, Verdict::Deny);
}

#[test]
fn every_flow_domain_error_is_fail_closed_pre_and_post() {
    let request = request();
    let security = security_context(&request);
    let engine = EngineFlowPreInvocationPort::new(Arc::new(PersistFailingPreResolver));
    let pre = FlowPreInvocationGuard::new(Arc::new(engine), MissingContextPolicy::Deny);
    let context = GuardContext::new(&request, &request.capability.scope)
        .with_security_context(Some(&security));
    let decision = pre.evaluate(&context).test_unwrap();
    assert_eq!(decision.verdict, Verdict::Deny);
    assert!(decision.evidence.iter().any(|evidence| {
        evidence
            .details
            .as_deref()
            .is_some_and(|details| details.contains("declassification state store failed"))
    }));

    for error in FLOW_DENIALS {
        let pre = FlowPreInvocationGuard::new(
            Arc::new(FailingPreFlow(error)),
            MissingContextPolicy::Deny,
        );
        let context = GuardContext::new(&request, &request.capability.scope)
            .with_security_context(Some(&security));
        let decision = pre.evaluate(&context).test_unwrap();
        assert_eq!(decision.verdict, Verdict::Deny, "pre error {error:?}");
        assert_eq!(decision.evidence.len(), 1, "pre error {error:?}");

        let post = FlowPostInvocationHook::new(
            Arc::new(FailingPostFlow(error)),
            MissingContextPolicy::Deny,
        );
        let context = PostInvocationContext::from_request_with_security_context(
            &request,
            Some(0),
            Some(&security),
        );
        let inspection = post.inspect_with_evidence(&context, &serde_json::json!({"output": true}));
        assert!(
            matches!(inspection.verdict, PostInvocationVerdict::Block(_)),
            "post error {error:?}"
        );
        assert_eq!(inspection.evidence.len(), 1, "post error {error:?}");
    }
}

#[test]
fn tripwire_event_store_outage_preserves_pre_dispatch_deny() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let events = Arc::new(FakeEvents::new(true));
    kernel.add_guard(Box::new(TripwireGuard::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Match(Digest32::new([9; 32]), Digest32::new([10; 32])),
        }),
        tripwire_publisher(events.clone()),
        MissingContextPolicy::Deny,
    )));
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.output, None);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(events.appends.load(Ordering::SeqCst), 1);
    let evidence = response.receipt.evidence.first().test_unwrap();
    let details = evidence.details.as_deref().test_unwrap();
    assert!(details.contains("\"event_persistence\":\"failed\""));
    assert!(details.contains('9'));
}

#[test]
fn tripwire_event_outage_still_emits_closed_native_observation_receipt() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let events = Arc::new(FakeEvents::new(true));
    let receipts = Arc::new(FakeSecurityReceipts::new(false));
    kernel.add_guard(Box::new(TripwireGuard::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Match(Digest32::new([21; 32]), Digest32::new([22; 32])),
        }),
        tripwire_publisher_with_receipts(events.clone(), receipts.clone()),
        MissingContextPolicy::Deny,
    )));

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(events.appends.load(Ordering::SeqCst), 1);
    let bodies = receipts.bodies();
    assert_eq!(bodies.len(), 1);
    let ActiveDefenseReceiptBody::TripwireObservation(observation) = &bodies[0] else {
        panic!("tripwire match must emit a tripwire-observation receipt");
    };
    assert_eq!(observation.header.tenant_id.as_str(), "tenant-a");
    assert_eq!(observation.tripwire_kind, TripwireKind::CanaryCapability);
    assert_eq!(observation.artifact_id_hash, Digest32::new([21; 32]));
    assert_eq!(observation.artifact_version_hash, Digest32::new([22; 32]));
    assert_ne!(observation.request_hash, Digest32::new([0; 32]));
    let details = response.receipt.evidence[0]
        .details
        .as_deref()
        .test_unwrap();
    assert!(details.contains("\"event_persistence\":\"failed\""));
    assert!(details.contains("\"receipt_persistence\":\"appended\""));
}

#[test]
fn tripwire_receipt_outage_is_explicit_and_never_allows_dispatch() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let events = Arc::new(FakeEvents::new(false));
    let receipts = Arc::new(FakeSecurityReceipts::new(true));
    let publisher = Arc::new(
        TripwireEventPublisher::new(
            events.clone(),
            Arc::new(FixedClock(100)),
            Arc::new(Ed25519Backend::new(tripwire_keypair())),
            producer(),
            RecordId::new("security-kernel-test-key-v1").test_unwrap(),
            RecordId::new("security-kernel-test-policy-v1").test_unwrap(),
        )
        .test_unwrap()
        .with_receipt_evidence(receipts, Digest32::new([31; 32]))
        .test_unwrap(),
    );
    kernel.add_guard(Box::new(TripwireGuard::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Match(Digest32::new([23; 32]), Digest32::new([24; 32])),
        }),
        publisher,
        MissingContextPolicy::Deny,
    )));

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(events.appends.load(Ordering::SeqCst), 0);
    let details = response.receipt.evidence[0]
        .details
        .as_deref()
        .test_unwrap();
    assert!(details.contains("\"event_persistence\":\"failed\""));
    assert!(details.contains("\"receipt_persistence\":\"failed\""));
}

#[test]
fn tripwire_signing_failure_is_fail_closed_before_unverified_ingress() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let events = Arc::new(FakeEvents::new(false));
    let publisher = Arc::new(
        TripwireEventPublisher::new(
            events.clone(),
            Arc::new(FixedClock(100)),
            Arc::new(FailingSigner {
                key: tripwire_keypair(),
            }),
            producer(),
            RecordId::new("security-kernel-test-key-v1").test_unwrap(),
            RecordId::new("security-kernel-test-policy-v1").test_unwrap(),
        )
        .test_unwrap()
        .with_receipt_evidence(
            Arc::new(FakeSecurityReceipts::new(false)),
            Digest32::new([31; 32]),
        )
        .test_unwrap(),
    );
    kernel.add_guard(Box::new(TripwireGuard::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Match(Digest32::new([11; 32]), Digest32::new([12; 32])),
        }),
        publisher,
        MissingContextPolicy::Deny,
    )));

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(events.appends.load(Ordering::SeqCst), 0);
    assert!(response
        .receipt
        .evidence
        .iter()
        .filter_map(|evidence| evidence.details.as_deref())
        .any(|details| details.contains("\"event_persistence\":\"failed\"")));
}

#[test]
fn tripwire_emits_canonical_event_with_existing_observation_receipt_lineage() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let events = Arc::new(FakeEvents::new(false));
    let receipts = Arc::new(FakeSecurityReceipts::new(false));
    kernel.add_guard(Box::new(TripwireGuard::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Match(Digest32::new([19; 32]), Digest32::new([20; 32])),
        }),
        tripwire_publisher_with_receipts(events.clone(), receipts.clone()),
        MissingContextPolicy::Deny,
    )));

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    let event = events.last_event();
    let body: SecurityEventBody = serde_json::from_slice(event.canonical_body.as_bytes())
        .unwrap_or_else(|error| panic!("tripwire event is not a SecurityEventBody: {error}"));
    body.validate()
        .unwrap_or_else(|error| panic!("tripwire event body is invalid: {error}"));
    assert_eq!(
        canonical_json_bytes(&body).test_unwrap(),
        event.canonical_body.as_bytes()
    );
    assert_eq!(
        event.body_hash,
        Digest32::new(*sha256(event.canonical_body.as_bytes()).as_bytes())
    );
    assert_eq!(body.event_kind, SecurityEventKind::CanaryInvocation);
    assert_eq!(body.event_id, event.event_id);
    assert_eq!(body.tenant_id, event.tenant_id);
    assert_eq!(body.producer_id, event.producer_id);
    assert_eq!(body.event_time_unix_ms, event.event_time_unix_ms);
    assert_eq!(body.ingest_time_unix_ms, event.received_at_unix_ms);
    assert_eq!(body.subject.subject_id.as_str(), request.agent_id);
    assert_eq!(body.subject.agent_id.as_str(), request.agent_id);
    assert_eq!(body.subject.session_id.as_str(), "session-a");
    assert_eq!(body.subject.capability_id.as_str(), request.capability.id);
    assert_eq!(body.subject.lineage_seed.as_str(), request.capability.id);
    assert_eq!(body.producer_key_id.as_str(), "security-kernel-test-key-v1");
    assert_eq!(
        body.policy_version.as_str(),
        "security-kernel-test-policy-v1"
    );
    assert_eq!(body.evidence_references.len(), 6);
    let evidence_references = body
        .evidence_references
        .as_slice()
        .iter()
        .map(|reference| reference.as_str())
        .collect::<Vec<_>>();
    let artifact_id_reference = format!("tripwire-artifact-id-{}", "13".repeat(32));
    let artifact_version_reference = format!("tripwire-artifact-version-{}", "14".repeat(32));
    let content_reference = format!(
        "tripwire-content-{}",
        sha256(request.capability.id.as_bytes()).to_hex()
    );
    assert!(evidence_references.contains(&artifact_id_reference.as_str()));
    assert!(evidence_references.contains(&artifact_version_reference.as_str()));
    assert!(evidence_references.contains(&content_reference.as_str()));
    let receipt_bodies = receipts.bodies();
    assert_eq!(receipt_bodies.len(), 1);
    let emitted_receipt_id = receipt_bodies[0].evidence_id().test_unwrap();
    assert_eq!(body.source_receipt_id, emitted_receipt_id);
    assert!(!body
        .source_receipt_id
        .as_str()
        .starts_with("tripwire-source-"));
    let signed: SignedSecurityEvent = serde_json::from_slice(event.source_evidence.as_bytes())
        .unwrap_or_else(|error| panic!("tripwire provenance is not signed: {error}"));
    assert_eq!(signed.body(), &body);
    assert!(signed
        .verify_trusted_producer(
            &producer(),
            &RecordId::new("security-kernel-test-key-v1").test_unwrap(),
            &tripwire_keypair().public_key(),
        )
        .test_unwrap());
}

#[test]
fn tripwire_content_digest_separates_identity_and_replays_exactly() {
    let events = Arc::new(FakeEvents::new(false));
    let receipts = Arc::new(FakeSecurityReceipts::new(false));
    let hook = RawOutputTripwireHook::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Match(Digest32::new([25; 32]), Digest32::new([26; 32])),
        }),
        tripwire_publisher_with_receipts(events.clone(), receipts.clone()),
        MissingContextPolicy::Deny,
    );
    let request = request();
    let security = security_context(&request);
    let context = PostInvocationContext::from_request_with_security_context(
        &request,
        Some(0),
        Some(&security),
    );

    for response in [
        serde_json::json!({"marker": "first"}),
        serde_json::json!({"marker": "second"}),
        serde_json::json!({"marker": "first"}),
    ] {
        let inspection = hook.inspect_with_evidence(&context, &response);
        assert!(matches!(
            inspection.verdict,
            PostInvocationVerdict::Block(_)
        ));
    }

    let event_bodies = events
        .events()
        .into_iter()
        .map(|event| {
            serde_json::from_slice::<SecurityEventBody>(event.canonical_body.as_bytes())
                .unwrap_or_else(|error| panic!("tripwire event body: {error}"))
        })
        .collect::<Vec<_>>();
    let receipt_bodies = receipts.bodies();
    assert_eq!(event_bodies.len(), 3);
    assert_eq!(receipt_bodies.len(), 3);
    assert_ne!(event_bodies[0].event_id, event_bodies[1].event_id);
    assert_eq!(event_bodies[0].event_id, event_bodies[2].event_id);
    assert_eq!(event_bodies[0], event_bodies[2]);

    let observations = receipt_bodies
        .iter()
        .map(|body| {
            let ActiveDefenseReceiptBody::TripwireObservation(observation) = body else {
                panic!("tripwire match must emit a tripwire-observation receipt");
            };
            observation
        })
        .collect::<Vec<_>>();
    assert_ne!(
        observations[0].observation_hash,
        observations[1].observation_hash
    );
    assert_eq!(
        observations[0].observation_hash,
        observations[2].observation_hash
    );
    assert_ne!(
        receipt_bodies[0].evidence_id().test_unwrap(),
        receipt_bodies[1].evidence_id().test_unwrap()
    );
    assert_eq!(
        receipt_bodies[0].evidence_id().test_unwrap(),
        receipt_bodies[2].evidence_id().test_unwrap()
    );
    assert_eq!(receipt_bodies[0], receipt_bodies[2]);
    for (event, receipt) in event_bodies.iter().zip(receipt_bodies.iter()) {
        assert_eq!(event.source_receipt_id, receipt.evidence_id().test_unwrap());
    }
}

#[test]
fn containment_active_and_store_error_both_prevent_dispatch() {
    for behavior in [OverlayBehavior::Active, OverlayBehavior::Fail] {
        let (mut kernel, request, invocations) = kernel_with_server();
        kernel.add_guard(Box::new(ContainmentGuard::new(
            Arc::new(FakeOverlays { behavior }),
            MissingContextPolicy::Deny,
        )));
        let response = kernel
            .evaluate_tool_call_blocking_with_security_context(
                &request,
                &security_context(&request),
            )
            .test_unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(response.receipt.evidence.len(), 1);
    }
}

#[test]
fn post_output_match_blocks_delivery_after_server_execution() {
    let (mut kernel, request, invocations) = kernel_with_server();
    let events = Arc::new(FakeEvents::new(false));
    kernel.add_post_invocation_hook(Box::new(RawOutputTripwireHook::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Match(Digest32::new([7; 32]), Digest32::new([8; 32])),
        }),
        tripwire_publisher(events.clone()),
        MissingContextPolicy::Deny,
    )));
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .test_unwrap();
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.output, None);
    assert_eq!(events.appends.load(Ordering::SeqCst), 1);
    assert!(response
        .receipt
        .evidence
        .iter()
        .any(|evidence| evidence.guard_name == "chio-watermark-tripwire"));
}

#[test]
fn detector_failure_is_fail_closed() {
    let request = request();
    let security = security_context(&request);
    let events = Arc::new(FakeEvents::new(false));
    let guard = TripwireGuard::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Fail,
        }),
        tripwire_publisher(events),
        MissingContextPolicy::Deny,
    );
    let context = GuardContext::new(&request, &request.capability.scope)
        .with_security_context(Some(&security));
    assert_eq!(
        guard.evaluate(&context).test_unwrap().verdict,
        Verdict::Deny
    );
}

#[test]
fn atomic_post_evidence_remains_bound_to_each_concurrent_response() {
    let events = Arc::new(FakeEvents::new(false));
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(RawOutputTripwireHook::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::ContentBoundMatch,
        }),
        tripwire_publisher(events),
        MissingContextPolicy::Deny,
    )));
    let pipeline = Arc::new(pipeline);
    let mut workers = Vec::new();
    for index in 0..16_u8 {
        let pipeline = Arc::clone(&pipeline);
        workers.push(std::thread::spawn(move || {
            let request = request();
            let security = security_context(&request);
            let response = serde_json::json!({"marker": index});
            let canonical = canonical_json_bytes(&response).test_unwrap();
            let expected = Digest32::new(*sha256(&canonical).as_bytes());
            let context = PostInvocationContext::from_request_with_security_context(
                &request,
                Some(0),
                Some(&security),
            );
            let outcome = pipeline.evaluate_with_context_and_evidence(&context, &response);
            assert!(matches!(outcome.verdict, PostInvocationVerdict::Block(_)));
            let evidence = outcome.evidence.first().test_unwrap();
            let details: serde_json::Value =
                serde_json::from_str(evidence.details.as_deref().test_unwrap()).test_unwrap();
            assert_eq!(
                details.get("artifact_id_hash"),
                Some(&serde_json::to_value(expected).test_unwrap())
            );
        }));
    }
    for worker in workers {
        match worker.join() {
            Ok(()) => {}
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}

#[test]
fn clear_paths_preserve_allow_decisions() {
    let request = request();
    let security = security_context(&request);
    let events = Arc::new(FakeEvents::new(false));
    let tripwire = TripwireGuard::new(
        Arc::new(FakeDetector {
            behavior: DetectorBehavior::Clear,
        }),
        tripwire_publisher(events),
        MissingContextPolicy::Deny,
    );
    let context = GuardContext::new(&request, &request.capability.scope)
        .with_security_context(Some(&security));
    assert_eq!(
        tripwire.evaluate(&context).test_unwrap().verdict,
        Verdict::Allow
    );

    let containment = ContainmentGuard::new(
        Arc::new(FakeOverlays {
            behavior: OverlayBehavior::Clear,
        }),
        MissingContextPolicy::Deny,
    );
    assert_eq!(
        containment.evaluate(&context).test_unwrap().verdict,
        Verdict::Allow
    );
}
