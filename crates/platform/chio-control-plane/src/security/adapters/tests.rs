
use super::test_clocks::{AdvancingClock, FixedClock};

mod native_flow;

mod prepared_dispatch;

use super::{FlowResolverConfig, PersistentFlowResolver, StructuredClassificationAdapter};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_core_types::SignedDeclassificationGrant;
use chio_data_guards::{
    ClassifierIdentity, RegexClassificationRule, RegexStructuredClassifier,
    StructuredClassificationError, StructuredClassificationResult, StructuredClassifier,
};
use chio_flow::{
    canonical_request_hash, evaluate_post_invocation, evaluate_pre_invocation,
    information_label_hash, CategoryLabelMap, DeclassificationDispatchOutcome,
};
use chio_kernel::{SecurityInvocationContextV1, ToolCallRequest};
use chio_manifest::{
    sign_manifest, AuthoritativeToolPolicy, RuntimeToolTopology, ServerTool, ToolAnnotations,
    ToolDefinition, ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry,
    TOOL_MANIFEST_SCHEMA,
};
use chio_security_kernel::{
    Clock, FlowPostInvocationInput, FlowPostInvocationResolver, FlowPreDispatchInput,
    FlowPreDispatchPort, FlowPreInvocationInput, FlowPreInvocationPort, FlowPreInvocationResolver,
};
use chio_security_types::flow::DeclassificationPurpose;
use chio_security_types::ports::{
    derive_declassification_transition_id, CanonicalBody, ClassificationPort,
    ClassificationRequest, ClassificationResult, ClassifierId, ClassifierVersion,
    CommittedEgressFence, DeclassificationEvidenceCommitStore, DeclassificationEvidencePhase,
    DeclassificationEvidenceQuery, DeclassificationTransitionBinding, DeclassificationUseQuery,
    DeclassificationUseState, DestinationId, Digest32, EgressFence, EgressFenceCommit,
    EgressFenceRequest, ExactReceiptRecord, ExactSecurityReceiptSink, FlowJoinRequest,
    FlowStateKey, FlowStateSnapshot, FlowStateStore, GrantId, IsolationEpochTransition, LineageId,
    OpaqueReceiptRef, PortError, PortErrorKind, PortResult, ReceiptAppendRequest, RecordId,
    RequestId, SecurityReceiptSink, SessionId, TenantId,
};
use chio_security_types::{
    Compartment, DeclassificationGrantBody, DeclassificationGrantClaims, InformationLabel,
    PrincipalId,
};
use chio_store_sqlite::SqliteSecurityStateStore;
use rusqlite::Connection;
use tempfile::tempdir;

fn require_error<T>(result: PortResult<T>) -> chio_security_types::ports::PortError {
    match result {
        Ok(_) => panic!("classification unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn request(payload: &[u8]) -> ClassificationRequest {
    ClassificationRequest {
        tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
        request_id: RequestId::new("classification-a")
            .unwrap_or_else(|error| panic!("request: {error}")),
        payload: CanonicalBody::new(payload.to_vec())
            .unwrap_or_else(|error| panic!("payload: {error}")),
        payload_digest: Digest32::new(*chio_core::sha256(payload).as_bytes()),
    }
}
mod adapter_preserves_identity_locations_and_payload_binding;

mod declared_request_digest_mismatch_fails_before_classification;

struct WrongRepresentation;

impl StructuredClassifier for WrongRepresentation {
    fn classify(
        &self,
        _: &[u8],
    ) -> Result<StructuredClassificationResult, StructuredClassificationError> {
        StructuredClassificationResult::from_payload(
            ClassifierIdentity::new("classifier.external", "1")?,
            b"other",
            vec![],
        )
    }
}
mod classifier_result_for_another_representation_fails_closed;

mod declassification_transition_ids_bind_tenant_and_replay_exactly;

fn open_declassification_test_store(
    path: impl AsRef<std::path::Path>,
) -> PortResult<SqliteSecurityStateStore> {
    SqliteSecurityStateStore::open_with_trusted_clock(path, Arc::new(FixedClock(150_000)))
}

struct CountingEmptyClassifier {
    calls: AtomicUsize,
}

impl CountingEmptyClassifier {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl ClassificationPort for CountingEmptyClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: request.payload_digest,
            classifier_id: ClassifierId::new("classifier.empty").map_err(PortError::from)?,
            classifier_version: ClassifierVersion::new("1").map_err(PortError::from)?,
            findings: chio_security_types::ports::BoundedVec::new(Vec::new())
                .map_err(|_| PortError::invalid_data())?,
        })
    }
}

struct FakeFlowStore {
    snapshot: Mutex<FlowStateSnapshot>,
    acquired: AtomicUsize,
    committed: AtomicUsize,
    fail_join: bool,
}

impl FakeFlowStore {
    fn new(snapshot: FlowStateSnapshot) -> Self {
        Self {
            snapshot: Mutex::new(snapshot),
            acquired: AtomicUsize::new(0),
            committed: AtomicUsize::new(0),
            fail_join: false,
        }
    }

    fn with_join_failure(snapshot: FlowStateSnapshot) -> Self {
        Self {
            snapshot: Mutex::new(snapshot),
            acquired: AtomicUsize::new(0),
            committed: AtomicUsize::new(0),
            fail_join: true,
        }
    }
}

impl FlowStateStore for FakeFlowStore {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
        Ok((snapshot.key == *key).then(|| snapshot.clone()))
    }

    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
        if self.fail_join {
            return Err(PortError::unavailable());
        }
        let mut snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
        if snapshot.key != request.key {
            return Err(PortError::invalid_data());
        }
        snapshot.principal_label = snapshot
            .principal_label
            .join_restrictions(&request.principal_join)
            .map_err(|_| PortError::invalid_data())?;
        snapshot.lineage_label = snapshot
            .lineage_label
            .join_restrictions(&request.lineage_join)
            .map_err(|_| PortError::invalid_data())?;
        snapshot.session_label = snapshot
            .session_label
            .join_restrictions(&request.session_join)
            .map_err(|_| PortError::invalid_data())?;
        snapshot.context_generation = snapshot
            .context_generation
            .checked_add(1)
            .ok_or_else(PortError::invalid_data)?;
        Ok(snapshot.clone())
    }

    fn open_isolation_epoch(&self, _: &IsolationEpochTransition) -> PortResult<FlowStateSnapshot> {
        Err(PortError::invalid_data())
    }

    fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence> {
        let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
        if snapshot.key != request.key
            || snapshot.context_generation != request.expected_context_generation
        {
            return Err(PortError::conflict());
        }
        self.acquired.fetch_add(1, Ordering::SeqCst);
        Ok(EgressFence {
            fence_id: RecordId::new("fence-a").map_err(PortError::from)?,
            key: request.key.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash,
            context_generation: request.expected_context_generation,
            expires_at_unix_ms: request.expires_at_unix_ms,
        })
    }

    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()> {
        let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
        if snapshot.key == fence.key && snapshot.context_generation == fence.context_generation {
            Ok(())
        } else {
            Err(PortError::conflict())
        }
    }

    fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
    ) -> PortResult<CommittedEgressFence> {
        self.validate_egress_fence(&commitment.fence)?;
        self.committed.fetch_add(1, Ordering::SeqCst);
        Ok(CommittedEgressFence {
            fence_id: commitment.fence.fence_id.clone(),
            request_id: commitment.fence.request_id.clone(),
            request_hash: commitment.fence.request_hash,
            context_generation: commitment.fence.context_generation,
            dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
            committed_at_unix_ms: commitment.committed_at_unix_ms,
        })
    }
}

#[derive(Default)]
struct RecordingSecurityReceipts {
    bodies: Mutex<Vec<chio_core::receipt::security::ActiveDefenseReceiptBody>>,
    records: Mutex<BTreeMap<OpaqueReceiptRef, ExactReceiptRecord>>,
}

#[derive(Default)]
struct ToggleSecurityReceipts {
    inner: RecordingSecurityReceipts,
    rejecting: AtomicBool,
}

struct RejectingSecurityReceipts;

impl RecordingSecurityReceipts {
    fn bodies(&self) -> Vec<chio_core::receipt::security::ActiveDefenseReceiptBody> {
        self.bodies
            .lock()
            .unwrap_or_else(|_| panic!("security receipt lock"))
            .clone()
    }
}

impl SecurityReceiptSink for RecordingSecurityReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        let body = serde_json::from_slice(request.canonical_body.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
        let canonical =
            chio_core::canonical_json_bytes(request).map_err(|_| PortError::invalid_data())?;
        let exact = ExactReceiptRecord {
            receipt: request.clone(),
            durable_record_hash: Digest32::new(*chio_core::sha256(&canonical).as_bytes()),
        };
        let mut records = self.records.lock().map_err(|_| PortError::unavailable())?;
        if let Some(existing) = records.get(&request.evidence_id) {
            return if existing == &exact {
                Ok(request.evidence_id.clone())
            } else {
                Err(PortError::conflict())
            };
        }
        records.insert(request.evidence_id.clone(), exact);
        self.bodies
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(body);
        Ok(request.evidence_id.clone())
    }
}

impl ExactSecurityReceiptSink for RecordingSecurityReceipts {
    fn load_exact(&self, evidence_id: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| PortError::unavailable())?
            .get(evidence_id)
            .cloned())
    }
}

impl SecurityReceiptSink for ToggleSecurityReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        self.inner.ensure_receipts_ready()
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        if self.rejecting.load(Ordering::Acquire) {
            Err(PortError::unavailable())
        } else {
            self.inner.sign_and_append(request)
        }
    }
}

impl ExactSecurityReceiptSink for ToggleSecurityReceipts {
    fn load_exact(&self, evidence_id: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>> {
        if self.rejecting.load(Ordering::Acquire) {
            Err(PortError::unavailable())
        } else {
            self.inner.load_exact(evidence_id)
        }
    }
}

impl SecurityReceiptSink for RejectingSecurityReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, _: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        Err(PortError::unavailable())
    }
}

impl ExactSecurityReceiptSink for RejectingSecurityReceipts {
    fn load_exact(&self, _: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>> {
        Err(PortError::unavailable())
    }
}

fn flow_key() -> FlowStateKey {
    FlowStateKey {
        tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
        principal_id: PrincipalId::new("principal-a")
            .unwrap_or_else(|error| panic!("principal: {error}")),
        lineage_id: LineageId::new("lineage-a").unwrap_or_else(|error| panic!("lineage: {error}")),
        session_id: SessionId::new("session-a").unwrap_or_else(|error| panic!("session: {error}")),
        isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("epoch-a")
            .unwrap_or_else(|error| panic!("epoch: {error}")),
    }
}

fn flow_snapshot(generation: u64) -> FlowStateSnapshot {
    FlowStateSnapshot {
        key: flow_key(),
        principal_label: InformationLabel::bottom(),
        lineage_label: InformationLabel::bottom(),
        session_label: InformationLabel::bottom(),
        context_generation: generation,
    }
}

fn flow_registry() -> Arc<VerifiedManifestRegistry> {
    let signer = Keypair::from_seed(&[73; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "server-a".to_string(),
        name: "Flow server".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "send".to_string(),
            description: "Send".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "object"})),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: false,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow: Some(ToolFlowDeclaration::public_egress()),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed =
        sign_manifest(&manifest, &signer).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .unwrap_or_else(|error| panic!("register manifest: {error}"));
    Arc::new(registry)
}

fn server_tool_flow_registry() -> Arc<VerifiedManifestRegistry> {
    let signer = Keypair::from_seed(&[72; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "server-a".to_string(),
        name: "Anthropic flow server".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "send".to_string(),
            description: "Regular control tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "object"})),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: vec![ServerTool::Bash],
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign server-tool manifest: {error}"));
    let server_tool_policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        restricted_label(),
        BTreeSet::new(),
    )
    .unwrap_or_else(|error| panic!("server-tool policy: {error}"));
    let policies = BTreeMap::from([
        ("send".to_string(), AuthoritativeToolPolicy::public_only()),
        (ServerTool::Bash.as_str().to_string(), server_tool_policy),
    ]);
    let topologies = BTreeMap::from([
        ("send".to_string(), RuntimeToolTopology::local()),
        (
            ServerTool::Bash.as_str().to_string(),
            RuntimeToolTopology::remote(),
        ),
    ]);
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(signed, &signer.public_key(), &policies, &topologies)
        .unwrap_or_else(|error| panic!("register server-tool manifest: {error}"));
    Arc::new(registry)
}

fn restricted_label() -> InformationLabel {
    InformationLabel::try_known(
        BTreeMap::new(),
        BTreeSet::from([
            Compartment::new("restricted").unwrap_or_else(|error| panic!("compartment: {error}"))
        ]),
    )
    .unwrap_or_else(|error| panic!("label: {error}"))
}

fn declassification_registry(purpose: &DeclassificationPurpose) -> Arc<VerifiedManifestRegistry> {
    let signer = Keypair::from_seed(&[73; 32]);
    let flow = ToolFlowDeclaration::new(
        None,
        Some(InformationLabel::bottom()),
        true,
        BTreeSet::from([purpose.clone()]),
    )
    .unwrap_or_else(|error| panic!("flow: {error}"));
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "server-a".to_string(),
        name: "Flow server".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "send".to_string(),
            description: "Send".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "object"})),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: false,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow: Some(flow),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed =
        sign_manifest(&manifest, &signer).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    let policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        InformationLabel::bottom(),
        BTreeSet::from([purpose.clone()]),
    )
    .unwrap_or_else(|error| panic!("policy: {error}"));
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(
            signed,
            &signer.public_key(),
            &BTreeMap::from([("send".to_string(), policy)]),
            &BTreeMap::from([("send".to_string(), RuntimeToolTopology::remote())]),
        )
        .unwrap_or_else(|error| panic!("register manifest: {error}"));
    Arc::new(registry)
}

fn flow_request() -> ToolCallRequest {
    let keypair = Keypair::from_seed(&[74; 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-a".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: ChioScope::default(),
            issued_at: 1,
            expires_at: u64::MAX,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &keypair,
    )
    .unwrap_or_else(|error| panic!("capability: {error}"));
    ToolCallRequest {
        request_id: "request-a".to_string(),
        capability,
        tool_name: "send".to_string(),
        server_id: "server-a".to_string(),
        agent_id: "agent-a".to_string(),
        arguments: serde_json::json!({"safe": true}),
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

fn server_tool_flow_request() -> ToolCallRequest {
    let mut request = flow_request();
    request.tool_name = "bash_20241022".to_string();
    request
}

fn declassifying_flow_request(
    authority: &Keypair,
    purpose: &DeclassificationPurpose,
) -> ToolCallRequest {
    let mut request = flow_request();
    let canonical = CanonicalBody::new(
        chio_core::canonical_json_bytes(&request.arguments)
            .unwrap_or_else(|error| panic!("canonical request: {error}")),
    )
    .unwrap_or_else(|error| panic!("canonical body: {error}"));
    let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
        grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
        capability_id: RecordId::new("capability-a")
            .unwrap_or_else(|error| panic!("capability: {error}")),
        tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
        subject_id: PrincipalId::new("principal-a")
            .unwrap_or_else(|error| panic!("subject: {error}")),
        agent_id: RecordId::new("agent-a").unwrap_or_else(|error| panic!("agent: {error}")),
        session_id: SessionId::new("session-a").unwrap_or_else(|error| panic!("session: {error}")),
        source_label_hash: information_label_hash(&restricted_label())
            .unwrap_or_else(|error| panic!("source label hash: {error}")),
        target_label: InformationLabel::bottom(),
        destination_id: DestinationId::new("server-a")
            .unwrap_or_else(|error| panic!("destination: {error}")),
        tool_name: RecordId::new("send").unwrap_or_else(|error| panic!("tool: {error}")),
        purpose: purpose.clone(),
        request_hash: canonical_request_hash(&canonical)
            .unwrap_or_else(|error| panic!("request hash: {error}")),
        issued_at_unix_seconds: 100,
        expires_at_unix_seconds: 200,
        authority_key_id: RecordId::new("authority-a")
            .unwrap_or_else(|error| panic!("authority: {error}")),
    })
    .unwrap_or_else(|error| panic!("grant body: {error}"));
    request.declassification_grant = Some(
        SignedDeclassificationGrant::sign(body, authority)
            .unwrap_or_else(|error| panic!("sign grant: {error}")),
    );
    request
}

fn flow_config() -> FlowResolverConfig {
    FlowResolverConfig::new(
        InformationLabel::bottom(),
        CategoryLabelMap::new(
            ClassifierId::new("classifier.empty")
                .unwrap_or_else(|error| panic!("classifier: {error}")),
            ClassifierVersion::new("1")
                .unwrap_or_else(|error| panic!("classifier version: {error}")),
            BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("category map: {error}")),
        BTreeMap::new(),
        10_000,
    )
    .unwrap_or_else(|error| panic!("flow config: {error}"))
}

fn declassifying_evidence_flow_config(
    authority: &Keypair,
    declassification_store: Arc<dyn DeclassificationEvidenceCommitStore>,
    receipt_sink: Arc<dyn ExactSecurityReceiptSink>,
) -> FlowResolverConfig {
    FlowResolverConfig::new(
        restricted_label(),
        CategoryLabelMap::new(
            ClassifierId::new("classifier.empty")
                .unwrap_or_else(|error| panic!("classifier: {error}")),
            ClassifierVersion::new("1")
                .unwrap_or_else(|error| panic!("classifier version: {error}")),
            BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("category map: {error}")),
        BTreeMap::from([(
            RecordId::new("authority-a").unwrap_or_else(|error| panic!("authority: {error}")),
            authority.public_key(),
        )]),
        10_000,
    )
    .unwrap_or_else(|error| panic!("flow config: {error}"))
    .with_declassification_evidence(declassification_store, receipt_sink, receipt_policy())
    .unwrap_or_else(|error| panic!("declassification evidence config: {error}"))
}

fn receipt_policy() -> chio_core::receipt::security::ActiveDefensePolicyBinding {
    chio_core::receipt::security::ActiveDefensePolicyBinding {
        policy_version: RecordId::new("flow-policy-v1")
            .unwrap_or_else(|error| panic!("policy version: {error}")),
        policy_hash: Digest32::new([91; 32]),
    }
}
mod production_flow_denial_path_emits_closed_native_receipt_from_resolved_runtime_facts;

mod production_flow_denial_path_surfaces_receipt_persistence_failure;

mod production_declassification_path_attests_consumption_and_exact_dispatch_outcome;

mod production_declassification_path_attests_live_unknown_dispatch_outcome;

mod consumption_sink_failure_durably_terminalizes_at_failure_time;

mod pre_dispatch_state_failure_durably_terminalizes_at_failure_time;

mod outcome_sink_failure_leaves_a_durable_terminal_outcome;

mod outcome_store_failure_leaves_reconciliation_required;

mod persistent_flow_resolver_binds_verified_manifest_state_and_final_bytes;

mod persistent_flow_resolver_accepts_exact_server_tool_in_pre_and_post_stages;

mod persistent_flow_resolver_rejects_server_tool_coordinate_mismatches_pre_and_post;

mod pre_dispatch_port_commits_the_authoritative_fence_for_exact_kernel_bytes;

mod pre_dispatch_port_rejects_bytes_from_another_request_before_classification;

mod flow_transition_identity_binds_the_canonical_payload;

mod stale_authoritative_generation_denies_before_classification;
