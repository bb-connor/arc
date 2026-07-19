use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

use crate::security::adapters::effect_port::{IssuanceFreezeBackend, ResponseEffectBackend};
use crate::security::{
    install_security_runtime as install_security_runtime_with_governance, ActiveDefenseMode,
    AuthorityDurability, SecurityDurability, SecurityInstallError, SecurityRuntime,
    SecurityRuntimeAuthorityBundleBuilder, SecurityRuntimeBuildError, SecurityRuntimeParts,
};
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequest, ThresholdApprovalResolutionError,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_guards::{GuardPipeline, RuntimeGuardProfile};
use chio_kernel::admission_operation::InMemoryAdmissionOperationStore;
use chio_kernel::approval::InMemoryApprovalStore;
use chio_kernel::budget_store::InMemoryBudgetStore;
use chio_kernel::{
    ActiveResponseExecutionEvidence, ActiveResponseExecutionRequest,
    ActiveResponseExecutorAuthority, ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseExecutorError, ActiveResponseFindingAuthority,
    ActiveResponseFindingAuthorityError, ActiveResponsePolicyRequest,
    ActiveResponsePolicyResolutionError, AdmissionCaptureAuthority, AdmissionCaptureDecision,
    AdmissionCaptureError, AdmissionCaptureRequest, AuthoritativeCorrelatedFindingEvidence,
    BlockingToolServerAdapter, BlockingToolServerConnection, ChioKernel, Guard, GuardContext,
    GuardDecision, IndexedSecurityEvidenceStore, KernelConfig, KernelError, MemoryBudgetConfig,
    OpaqueSignedSupplementalQuota, PostInvocationContext, PostInvocationHook,
    PostInvocationPipeline, PostInvocationVerdict, ReceiptStoreError, SecurityInvocationContext,
    SecurityInvocationContextV1, SecurityPreDispatchContext, SecurityPreDispatchHook,
    SecurityPreDispatchPolicy, SupplementalAdmissionAuthorization, SupplementalAdmissionPlan,
    SupplementalAdmissionPrepareRequest, SupplementalAdmissionRegistrar, SupplementalQuotaError,
    SupplementalQuotaVerificationContext, SupplementalQuotaVerifier, ToolCallOutput,
    ToolCallRequest, Verdict, VerifiedSupplementalQuotaClaimBody, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{
    sign_manifest, RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration,
    ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_mcp_edge::{ChioMcpEdge, McpEdgeConfig, SecurityInvocationContextAuthority};
use chio_quarantine::{
    build_response_plan, prepare_response_dispatch, CausalBlastRadiusResolver,
    ResponseDispatchPreparationRequest,
};
use chio_security_types::ports::{
    empty_issuance_freeze_snapshot, issuance_freeze_version_hash, ActionId,
    BlastRadiusFenceAcquisition, BlastRadiusPort, BlastRadiusQueryBounds, BlastRadiusRequest,
    BlastRadiusResult, BlastRadiusSeeds, CanonicalBody, CausalLineageCommitMetadata,
    CausalLineageCommitRequest, CausalLineageCommitStore, CausalLineageEdges, CausalLineageNode,
    CausalLineageNodeKind, CausalLineageNodes, Digest32, EffectOperation, EffectRequest,
    IsolationEpochId, IssuanceFreezeKey, IssuanceFreezeSpec, IssuanceFreezeStore, LeaseOwnerId,
    LineageId, OpaqueReceiptRef, RecordId, ResponseDispatchApproval, ResponseDispatchCommitOutcome,
    ResponseDispatchLease, ResponseDispatchStore, ResponseSchedulerStore, SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, PrincipalId, ResponseApprovalRequirement, ResponseEffectKind,
    ResponseEffectSpec, ResponsePlanInput, ResponseTarget,
};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use chio_store_sqlite::{
    SqliteAdmissionOperationStore, SqliteApprovalStore, SqliteBudgetStore, SqliteReceiptStore,
};
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;

fn rejected<T: std::fmt::Debug, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(value) => panic!("{message}: {value:?}"),
        Err(error) => error,
    }
}

struct NamedGuard(&'static str);

impl Guard for NamedGuard {
    fn name(&self) -> &str {
        self.0
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }
}

struct NamedHook(&'static str);

impl PostInvocationHook for NamedHook {
    fn name(&self) -> &str {
        self.0
    }

    fn inspect(&self, _: &PostInvocationContext<'_>, _: &Value) -> PostInvocationVerdict {
        PostInvocationVerdict::Allow
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct TraceGuard {
    name: &'static str,
    verdict: Verdict,
    trace: Arc<Mutex<Vec<&'static str>>>,
}

impl Guard for TraceGuard {
    fn name(&self) -> &str {
        self.name
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        lock_unpoisoned(&self.trace).push(self.name);
        Ok(GuardDecision::from_verdict(self.verdict))
    }
}

struct RecordingHook {
    name: &'static str,
    observations: Arc<Mutex<Vec<Value>>>,
}

impl PostInvocationHook for RecordingHook {
    fn name(&self) -> &str {
        self.name
    }

    fn inspect(&self, _: &PostInvocationContext<'_>, response: &Value) -> PostInvocationVerdict {
        lock_unpoisoned(&self.observations).push(response.clone());
        PostInvocationVerdict::Allow
    }
}

struct FixedRedactionHook;

impl PostInvocationHook for FixedRedactionHook {
    fn name(&self) -> &str {
        "configured-sanitizer"
    }

    fn inspect(&self, _: &PostInvocationContext<'_>, _: &Value) -> PostInvocationVerdict {
        PostInvocationVerdict::Redact(serde_json::json!({
            "kind": "value",
            "value": { "marker": "[REDACTED]" }
        }))
    }
}

struct NamedPreDispatchHook(&'static str);

struct InstalledMcpSecurityContextAuthority;

impl SecurityInvocationContextAuthority for InstalledMcpSecurityContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        context: &chio_core::session::OperationContext,
        operation: &chio_core::session::ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        Ok(SecurityInvocationContext::v1(
            SecurityInvocationContextV1::new(
                TenantId::new("tenant-installed-mcp")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                SessionId::new(context.session_id.as_str())
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                PrincipalId::new(context.agent_id.clone())
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                IsolationEpochId::new("epoch-installed-mcp")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                LineageId::new(
                    operation
                        .capability
                        .delegation_chain
                        .first()
                        .map_or(operation.capability.id.as_str(), |link| {
                            link.capability_id.as_str()
                        }),
                )
                .map_err(|error| KernelError::Internal(error.to_string()))?,
                1,
            ),
        ))
    }
}

impl SecurityPreDispatchHook for NamedPreDispatchHook {
    fn name(&self) -> &str {
        self.0
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<chio_kernel::SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

struct RejectingSupplementalQuotaVerifier;

impl SupplementalQuotaVerifier for RejectingSupplementalQuotaVerifier {
    fn verifier_id(&self) -> &str {
        "replacement-verifier"
    }

    fn verify(
        &self,
        _: &OpaqueSignedSupplementalQuota,
        _: &SupplementalQuotaVerificationContext,
    ) -> Result<VerifiedSupplementalQuotaClaimBody, SupplementalQuotaError> {
        Err(SupplementalQuotaError::Verification(
            "replacement verifier must never execute".to_string(),
        ))
    }
}

struct RejectingSupplementalAdmissionRegistrar;

impl SupplementalAdmissionRegistrar for RejectingSupplementalAdmissionRegistrar {
    fn prepare_admission(
        &self,
        _: SupplementalAdmissionPrepareRequest<'_>,
    ) -> Result<SupplementalAdmissionPlan, SupplementalQuotaError> {
        Err(SupplementalQuotaError::Verification(
            "replacement registrar must never execute".to_string(),
        ))
    }

    fn register_admission(
        &self,
        _: &SupplementalAdmissionPlan,
        _: SupplementalAdmissionAuthorization<'_>,
    ) -> Result<(), SupplementalQuotaError> {
        Err(SupplementalQuotaError::Verification(
            "replacement registrar must never execute".to_string(),
        ))
    }

    fn prepare_dispatch(&self, _: &str) -> Result<(), SupplementalQuotaError> {
        Err(SupplementalQuotaError::Verification(
            "replacement registrar must never execute".to_string(),
        ))
    }

    fn release_admission(&self, _: &str) -> Result<(), SupplementalQuotaError> {
        Err(SupplementalQuotaError::Verification(
            "replacement registrar must never execute".to_string(),
        ))
    }

    fn finalize_admission(&self, _: &str) -> Result<(), SupplementalQuotaError> {
        Err(SupplementalQuotaError::Verification(
            "replacement registrar must never execute".to_string(),
        ))
    }
}

struct RejectingAdmissionCaptureAuthority;

impl AdmissionCaptureAuthority for RejectingAdmissionCaptureAuthority {
    fn capture_admission(
        &self,
        _: AdmissionCaptureRequest,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        Err(AdmissionCaptureError::Unavailable(
            "replacement capture authority must never execute".to_string(),
        ))
    }
}

struct RejectingActiveResponseFindingAuthority;

impl ActiveResponseFindingAuthority for RejectingActiveResponseFindingAuthority {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
        Err(ActiveResponseFindingAuthorityError::Unavailable(
            "replacement finding authority must never execute".to_string(),
        ))
    }

    fn load_correlated_finding(
        &self,
        _: &OpaqueReceiptRef,
    ) -> Result<Option<AuthoritativeCorrelatedFindingEvidence>, ActiveResponseFindingAuthorityError>
    {
        Err(ActiveResponseFindingAuthorityError::Unavailable(
            "replacement finding authority must never execute".to_string(),
        ))
    }
}

struct MarkerToolServer {
    marker: &'static str,
}

impl BlockingToolServerConnection for MarkerToolServer {
    fn server_id(&self) -> &str {
        "frozen-route"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["marker".to_string()]
    }

    fn invoke_blocking(&self, _: &str, _: Value) -> Result<Value, KernelError> {
        Ok(serde_json::json!({ "marker": self.marker }))
    }
}

struct RecordingActiveResponseExecutor {
    identity: ActiveResponseExecutorAuthorityIdentity,
    ready: AtomicBool,
    readiness_checks: AtomicUsize,
}

impl RecordingActiveResponseExecutor {
    fn new(ready: bool) -> Self {
        Self::with_generation(ready, 1)
    }

    fn with_generation(ready: bool, generation: u64) -> Self {
        Self {
            identity: ActiveResponseExecutorAuthorityIdentity::new(
                Keypair::generate().public_key(),
                generation,
            )
            .unwrap_or_else(|error| panic!("executor identity: {error}")),
            ready: AtomicBool::new(ready),
            readiness_checks: AtomicUsize::new(0),
        }
    }

    fn readiness_checks(&self) -> usize {
        self.readiness_checks.load(Ordering::SeqCst)
    }

    fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }
}

impl ActiveResponseExecutorAuthority for RecordingActiveResponseExecutor {
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
        self.identity.clone()
    }

    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        self.readiness_checks.fetch_add(1, Ordering::SeqCst);
        if self.ready.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ActiveResponseExecutorError::NotReady(
                "test executor is unavailable".to_string(),
            ))
        }
    }

    fn execute_active_response(
        &self,
        _: &ActiveResponseExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        Err(ActiveResponseExecutorError::RejectedBeforeCommit(
            "test executor does not dispatch".to_string(),
        ))
    }
}

struct RecordingIndexedFindingStore {
    ready: AtomicBool,
    readiness_checks: AtomicUsize,
}

impl RecordingIndexedFindingStore {
    fn new(ready: bool) -> Self {
        Self {
            ready: AtomicBool::new(ready),
            readiness_checks: AtomicUsize::new(0),
        }
    }

    fn readiness_checks(&self) -> usize {
        self.readiness_checks.load(Ordering::SeqCst)
    }

    fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }
}

impl IndexedSecurityEvidenceStore for RecordingIndexedFindingStore {
    fn ensure_indexed_security_evidence_ready(&self) -> Result<(), ReceiptStoreError> {
        self.readiness_checks.fetch_add(1, Ordering::SeqCst);
        if self.ready.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ReceiptStoreError::Pool(
                "test indexed finding store is unavailable".to_string(),
            ))
        }
    }

    fn append_indexed_security_evidence(
        &self,
        _: &OpaqueReceiptRef,
        _: &ChioReceipt,
    ) -> Result<ChioReceipt, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "test indexed store does not append".to_string(),
        ))
    }

    fn load_indexed_security_evidence(
        &self,
        _: &OpaqueReceiptRef,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(None)
    }
}

fn kernel_with_keypair(keypair: Keypair) -> ChioKernel {
    ChioKernel::new(KernelConfig {
        keypair,
        ca_public_keys: vec![],
        max_delegation_depth: 4,
        policy_hash: "security-runtime-test".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: 64,
        retention_config: None,
        memory_budget: MemoryBudgetConfig::defaults(),
    })
}

fn kernel() -> ChioKernel {
    let mut kernel = kernel_with_keypair(Keypair::generate());
    kernel
        .set_active_response_submission_authority(
            Keypair::from_seed(&[97_u8; 32]).public_key(),
        )
        .unwrap_or_else(|error| panic!("install active-response submission authority: {error}"));
    kernel
}

fn install_contextual_receipt_store(kernel: &mut ChioKernel) -> TempDir {
    let directory =
        tempfile::tempdir().unwrap_or_else(|error| panic!("create receipt directory: {error}"));
    let store = Arc::new(
        SqliteReceiptStore::open(directory.path().join("receipts.sqlite3"))
            .unwrap_or_else(|error| panic!("open receipt store: {error}")),
    );
    kernel
        .set_receipt_store_handle(store)
        .unwrap_or_else(|error| panic!("install receipt store: {error}"));
    directory
}

fn profile() -> RuntimeGuardProfile {
    let mut post = PostInvocationPipeline::new();
    post.add(Box::new(NamedHook("default-post")));
    RuntimeGuardProfile {
        pre_invocation_guards: vec![Box::new(NamedGuard("default-pre"))],
        post_invocation_pipeline: post,
    }
}

fn configured() -> (GuardPipeline, PostInvocationPipeline) {
    let mut pre = GuardPipeline::new();
    pre.add(Box::new(NamedGuard("configured-pre")));
    let mut post = PostInvocationPipeline::new();
    post.add(Box::new(NamedHook("configured-post")));
    (pre, post)
}

fn register_marker_route(kernel: &mut ChioKernel, marker: &'static str) {
    let inner: Arc<dyn BlockingToolServerConnection> = Arc::new(MarkerToolServer { marker });
    let server = BlockingToolServerAdapter::new(inner)
        .unwrap_or_else(|error| panic!("build marker route: {error}"));
    kernel.register_tool_server(Box::new(server));
}

fn marker_request(kernel: &ChioKernel, request_id: &str) -> ToolCallRequest {
    marker_request_with_optional_security_context(kernel, request_id, None)
}

fn contextual_marker_request(
    kernel: &ChioKernel,
    request_id: &str,
    security_context: &SecurityInvocationContext,
) -> ToolCallRequest {
    marker_request_with_optional_security_context(kernel, request_id, Some(security_context))
}

fn marker_request_with_optional_security_context(
    kernel: &ChioKernel,
    request_id: &str,
    security_context: Option<&SecurityInvocationContext>,
) -> ToolCallRequest {
    let subject = Keypair::generate().public_key();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "frozen-route".to_string(),
            tool_name: "marker".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let capability = match security_context {
        Some(security_context) => {
            let context = security_context.as_v1();
            let issuance_context = SecurityInvocationContext::v1(
                SecurityInvocationContextV1::new(
                    context.tenant_id().clone(),
                    context.session_id().clone(),
                    PrincipalId::new(subject.to_hex())
                        .unwrap_or_else(|error| panic!("capability principal id: {error}")),
                    context.isolation_epoch_id().clone(),
                    context.lineage_root_id().clone(),
                    context.context_generation(),
                )
                .with_flow_state_generation(
                    context
                        .flow_state_generation()
                        .unwrap_or_else(|| context.context_generation()),
                ),
            );
            kernel.issue_capability_with_security_context(&subject, scope, 300, &issuance_context)
        }
        None => kernel.issue_capability(&subject, scope, 300),
    }
    .unwrap_or_else(|error| panic!("issue marker capability: {error}"));
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability,
        tool_name: "marker".to_string(),
        server_id: "frozen-route".to_string(),
        agent_id: subject.to_hex(),
        arguments: serde_json::json!({}),
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

fn security_context(label: &str) -> SecurityInvocationContext {
    SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            TenantId::new(format!("tenant-{label}"))
                .unwrap_or_else(|error| panic!("tenant id: {error}")),
            SessionId::new(format!("session-{label}"))
                .unwrap_or_else(|error| panic!("session id: {error}")),
            PrincipalId::new(format!("principal-{label}"))
                .unwrap_or_else(|error| panic!("principal id: {error}")),
            IsolationEpochId::new(format!("epoch-{label}"))
                .unwrap_or_else(|error| panic!("isolation epoch id: {error}")),
            LineageId::new(format!("lineage-{label}"))
                .unwrap_or_else(|error| panic!("lineage id: {error}")),
            1,
        )
        .with_flow_state_generation(1),
    )
}

fn bind_security_context_to_request(
    context: &SecurityInvocationContext,
    request: &ToolCallRequest,
) -> SecurityInvocationContext {
    let context = context.as_v1();
    let security_binding = request
        .capability
        .security_binding()
        .unwrap_or_else(|error| panic!("capability security binding: {error}"));
    let lineage_root = security_binding.as_ref().map_or_else(
        || context.lineage_root_id().as_str(),
        |binding| binding.lineage_id.as_str(),
    );
    SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            context.tenant_id().clone(),
            context.session_id().clone(),
            PrincipalId::new(request.agent_id.clone())
                .unwrap_or_else(|error| panic!("request principal id: {error}")),
            context.isolation_epoch_id().clone(),
            LineageId::new(lineage_root)
                .unwrap_or_else(|error| panic!("request lineage id: {error}")),
            context.context_generation(),
        )
        .with_flow_state_generation(
            context
                .flow_state_generation()
                .unwrap_or_else(|| context.context_generation()),
        ),
    )
}

fn runtime_parts() -> SecurityRuntimeParts {
    SecurityRuntimeParts::new(
        Box::new(NamedGuard("caller-session-throttle")),
        Box::new(NamedGuard("tripwire")),
        Box::new(NamedGuard("containment")),
        Box::new(NamedGuard("flow-pre")),
        Arc::new(NamedPreDispatchHook("flow-pre-dispatch")),
        Box::new(NamedHook("raw-tripwire")),
        Box::new(NamedHook("flow-post")),
    )
}

struct ProductionAuthorityFixture {
    _database_directory: TempDir,
    active_response_requirement_resolver: Arc<dyn chio_kernel::ActiveResponseRequirementResolver>,
    admission_operation_store: Arc<SqliteAdmissionOperationStore>,
    approval_store: Arc<SqliteApprovalStore>,
    budget_store: Arc<SqliteBudgetStore>,
    session_throttle_store: Arc<SqliteSecurityStateStore>,
    indexed_finding_store: Arc<RecordingIndexedFindingStore>,
    trusted_receipt_signer: chio_core::PublicKey,
    executor_authority: Arc<RecordingActiveResponseExecutor>,
}

impl ProductionAuthorityFixture {
    fn new(finding_ready: bool, executor_ready: bool, executor_generation: u64) -> Self {
        let database_directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create security authority directory: {error}"));
        let admission_operation_store = Arc::new(
            SqliteAdmissionOperationStore::open(
                database_directory
                    .path()
                    .join("admission-operation.sqlite3"),
            )
            .unwrap_or_else(|error| panic!("open admission operation store: {error}")),
        );
        let approval_store = Arc::new(
            SqliteApprovalStore::open(database_directory.path().join("approval.sqlite3"))
                .unwrap_or_else(|error| panic!("open approval store: {error}")),
        );
        let budget_store = Arc::new(
            SqliteBudgetStore::open(database_directory.path().join("budget.sqlite3"))
                .unwrap_or_else(|error| panic!("open budget store: {error}")),
        );
        let session_throttle_store = Arc::new(
            SqliteSecurityStateStore::open(
                database_directory.path().join("session-throttle.sqlite3"),
            )
            .unwrap_or_else(|error| panic!("open session-throttle store: {error}")),
        );
        Self {
            _database_directory: database_directory,
            active_response_requirement_resolver: Arc::new(
                |_: &ActiveResponsePolicyRequest, _: &str| {
                    Err(ActiveResponsePolicyResolutionError::Unavailable(
                        "resolution is outside this installation test".to_string(),
                    ))
                },
            ),
            admission_operation_store,
            approval_store,
            budget_store,
            session_throttle_store,
            indexed_finding_store: Arc::new(RecordingIndexedFindingStore::new(finding_ready)),
            trusted_receipt_signer: Keypair::generate().public_key(),
            executor_authority: Arc::new(RecordingActiveResponseExecutor::with_generation(
                executor_ready,
                executor_generation,
            )),
        }
    }

    fn builder(&self) -> SecurityRuntimeAuthorityBundleBuilder {
        SecurityRuntimeAuthorityBundleBuilder::new()
            .with_active_response_requirement_resolver(Arc::clone(
                &self.active_response_requirement_resolver,
            ))
            .with_admission_operation_store(self.admission_operation_store.clone())
            .with_approval_store(self.approval_store.clone())
            .with_budget_store(self.budget_store.clone())
            .with_session_throttle_store(self.session_throttle_store.clone())
            .with_indexed_finding_store(self.indexed_finding_store.clone())
            .with_trusted_receipt_signers(vec![self.trusted_receipt_signer.clone()])
            .with_executor_authority(self.executor_authority.clone())
    }

    fn invalidate_session_throttle_schema(&self) {
        let connection = Connection::open(
            self._database_directory
                .path()
                .join("session-throttle.sqlite3"),
        )
        .unwrap_or_else(|error| panic!("open session-throttle database: {error}"));
        connection
            .execute_batch("DROP TABLE security_session_throttle_effects;")
            .unwrap_or_else(|error| panic!("invalidate session-throttle schema: {error}"));
    }
}

fn digest32(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn apply_contextual_issuance_freeze(
    authorities: &ProductionAuthorityFixture,
    receipt_store: &Arc<SqliteReceiptStore>,
    tenant_id: TenantId,
    lineage_id: LineageId,
) {
    let now_unix_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("trusted clock before Unix epoch: {error}"))
            .as_millis(),
    )
    .unwrap_or_else(|error| panic!("trusted clock exceeds u64: {error}"));
    let action_id = ActionId::new("freeze-kernel-issuance")
        .unwrap_or_else(|error| panic!("freeze action id: {error}"));
    let root_id = RecordId::new(lineage_id.as_str())
        .unwrap_or_else(|error| panic!("freeze lineage root id: {error}"));
    let query_bounds = BlastRadiusQueryBounds {
        max_depth: 8,
        max_nodes: 32,
        max_edges: 32,
    };
    let blast_request = BlastRadiusRequest {
        tenant_id: tenant_id.clone(),
        action_id: action_id.clone(),
        seed_ids: BlastRadiusSeeds::new(vec![root_id])
            .unwrap_or_else(|error| panic!("freeze blast-radius seed: {error}")),
        query_bounds,
    };
    let blast_radius: Arc<dyn BlastRadiusPort> = Arc::new(CausalBlastRadiusResolver::new(
        Arc::clone(receipt_store),
        Arc::clone(receipt_store),
    ));
    let approved_result = blast_radius
        .resolve(&blast_request)
        .unwrap_or_else(|error| panic!("resolve issuance-freeze blast radius: {error:?}"));
    let affected_ids = match &approved_result {
        BlastRadiusResult::Exact {
            sorted_affected_ids,
            ..
        } => sorted_affected_ids.as_slice().to_vec(),
        BlastRadiusResult::Incomplete { .. } => {
            panic!("issuance-freeze blast radius was incomplete");
        }
    };
    let acquisition_expires_at_unix_ms = now_unix_ms.saturating_add(30_000);
    let plan_expires_at_unix_ms = now_unix_ms.saturating_add(120_000);
    let spec = IssuanceFreezeSpec {
        lineage_id: lineage_id.clone(),
        acquisition: BlastRadiusFenceAcquisition {
            request: blast_request,
            approved_result,
            expires_at_unix_ms: acquisition_expires_at_unix_ms,
        },
    };
    let canonical_contribution = canonical_json_bytes(&spec)
        .unwrap_or_else(|error| panic!("canonicalize issuance-freeze spec: {error}"));
    let canonical_contribution = CanonicalBody::new(canonical_contribution)
        .unwrap_or_else(|error| panic!("issuance-freeze contribution: {error}"));
    let contribution_hash = digest32(canonical_contribution.as_bytes());
    let key = IssuanceFreezeKey {
        tenant_id: tenant_id.clone(),
        lineage_id: lineage_id.clone(),
    };
    let empty = empty_issuance_freeze_snapshot(key)
        .unwrap_or_else(|error| panic!("empty issuance-freeze snapshot: {error:?}"));
    let expected_version_hash = issuance_freeze_version_hash(&empty)
        .unwrap_or_else(|error| panic!("empty issuance-freeze version: {error:?}"));
    let plan = build_response_plan(ResponsePlanInput {
        action_id,
        trigger_finding_id: RecordId::new("freeze-kernel-finding")
            .unwrap_or_else(|error| panic!("freeze finding id: {error}")),
        trigger_finding_hash: digest32(b"freeze-kernel-finding"),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("freeze-kernel-finding-receipt")
            .unwrap_or_else(|error| panic!("freeze finding receipt: {error}")),
        tenant_id,
        policy_version: RecordId::new("freeze-kernel-policy")
            .unwrap_or_else(|error| panic!("freeze policy version: {error}")),
        policy_hash: digest32(b"freeze-kernel-policy"),
        affected_ids,
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::FreezeIssuance,
            target: ResponseTarget::Lineage { lineage_id },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: expected_version_hash,
        }],
        ttl_ms: 120_000,
        created_at_unix_ms: now_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: RecordId::new("freeze-kernel-operator-capability")
                .unwrap_or_else(|error| panic!("freeze operator capability: {error}")),
            capability_digest: digest32(b"freeze-kernel-operator-capability"),
            expires_at_unix_ms: plan_expires_at_unix_ms.saturating_add(60_000),
            executor_subject: RecordId::new("freeze-kernel-executor")
                .unwrap_or_else(|error| panic!("freeze executor subject: {error}")),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: RecordId::new("freeze-kernel-submitter")
            .unwrap_or_else(|error| panic!("freeze submitter: {error}")),
        reason_hash: digest32(b"freeze-kernel-reason"),
    })
    .unwrap_or_else(|error| panic!("build issuance-freeze response plan: {error}"));
    let planned_effect = plan
        .effects
        .as_slice()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("issuance-freeze effect missing"));
    let dispatch = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        authorization_capability_hash: plan.operator_capability.capability_digest,
        plan: plan.clone(),
        dispatch_id: RecordId::new("freeze-kernel-dispatch")
            .unwrap_or_else(|error| panic!("freeze dispatch id: {error}")),
        governed_intent_hash: digest32(b"freeze-kernel-governed-intent"),
        policy_decision_hash: digest32(b"freeze-kernel-policy-decision"),
        executor_authority_id: RecordId::new("freeze-kernel-executor-authority")
            .unwrap_or_else(|error| panic!("freeze executor authority: {error}")),
        executor_authority_generation: 1,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms: now_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("freeze-kernel-worker")
                .unwrap_or_else(|error| panic!("freeze lease owner: {error}")),
            lease_expires_at_unix_ms: acquisition_expires_at_unix_ms,
        },
        commit_mode: chio_security_types::ports::ResponseDispatchCommitMode::Fresh,
    })
    .unwrap_or_else(|error| panic!("prepare issuance-freeze dispatch: {error}"));
    let committed = authorities
        .session_throttle_store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("commit issuance-freeze dispatch: {error:?}"));
    let ResponseDispatchCommitOutcome::Committed(committed) = committed else {
        panic!("new issuance-freeze dispatch already existed");
    };
    let request = EffectRequest {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        effect_id: planned_effect.effect_id,
        effect_kind: planned_effect.kind,
        target: planned_effect.target,
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: RecordId::new("response_effect_command:freeze-kernel-issuance")
            .unwrap_or_else(|error| panic!("freeze idempotency key: {error}")),
        expected_version_hash: planned_effect.observed_base_version_hash,
        scheduler_lease_owner_id: committed.initial_work.lease_owner_id,
        scheduler_fencing_token: committed.initial_work.fencing_token,
        canonical_contribution: planned_effect.canonical_contribution,
        contribution_hash: planned_effect.contribution_hash,
    };
    let freeze_store: Arc<dyn IssuanceFreezeStore> = authorities.session_throttle_store.clone();
    let scheduler_store: Arc<dyn ResponseSchedulerStore> =
        authorities.session_throttle_store.clone();
    IssuanceFreezeBackend::new_with_scheduler(freeze_store, blast_radius, scheduler_store)
        .execute(&request)
        .unwrap_or_else(|error| panic!("apply contextual issuance freeze: {error:?}"));
}

fn authority_builder_through(
    fixture: &ProductionAuthorityFixture,
    stage: usize,
) -> SecurityRuntimeAuthorityBundleBuilder {
    let mut builder = SecurityRuntimeAuthorityBundleBuilder::new();
    if stage >= 1 {
        builder = builder.with_active_response_requirement_resolver(Arc::clone(
            &fixture.active_response_requirement_resolver,
        ));
    }
    if stage >= 2 {
        builder = builder.with_admission_operation_store(fixture.admission_operation_store.clone());
    }
    if stage >= 3 {
        builder = builder.with_approval_store(fixture.approval_store.clone());
    }
    if stage >= 4 {
        builder = builder.with_budget_store(fixture.budget_store.clone());
    }
    if stage >= 5 {
        builder = builder.with_session_throttle_store(fixture.session_throttle_store.clone());
    }
    if stage >= 6 {
        builder = builder.with_indexed_finding_store(fixture.indexed_finding_store.clone());
    }
    if stage >= 7 {
        builder =
            builder.with_trusted_receipt_signers(vec![fixture.trusted_receipt_signer.clone()]);
    }
    if stage >= 8 {
        builder = builder.with_executor_authority(fixture.executor_authority.clone());
    }
    builder
}

fn production_runtime(
    durability: SecurityDurability,
    authorities: &ProductionAuthorityFixture,
) -> Result<SecurityRuntime, SecurityRuntimeBuildError> {
    production_runtime_with_parts(durability, authorities, runtime_parts())
}

fn production_runtime_with_parts(
    durability: SecurityDurability,
    authorities: &ProductionAuthorityFixture,
    parts: SecurityRuntimeParts,
) -> Result<SecurityRuntime, SecurityRuntimeBuildError> {
    let bundle = authorities.builder().build()?;
    SecurityRuntime::production(
        Arc::new(VerifiedManifestRegistry::default()),
        durability,
        parts,
        bundle,
    )
}

fn runtime(durability: SecurityDurability) -> SecurityRuntime {
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    production_runtime(durability, &authorities)
        .unwrap_or_else(|error| panic!("build production security runtime: {error}"))
}

fn shadow_runtime(durability: SecurityDurability) -> SecurityRuntime {
    SecurityRuntime::new(
        Arc::new(VerifiedManifestRegistry::default()),
        durability,
        runtime_parts(),
    )
}

fn threshold_resolver(
) -> Arc<dyn chio_kernel::threshold_approval::ThresholdApprovalRequirementResolver> {
    Arc::new(|_: &ThresholdApprovalRequest, _: &str| {
        Err(ThresholdApprovalResolutionError::Unavailable(
            "resolution is outside this installation test".to_string(),
        ))
    })
}

fn install_security_runtime(
    kernel: &mut ChioKernel,
    mode: ActiveDefenseMode,
    runtime: Option<SecurityRuntime>,
    default_profile: RuntimeGuardProfile,
    configured_pre: GuardPipeline,
    configured_post: PostInvocationPipeline,
) -> Result<(), SecurityInstallError> {
    let policy_authority = kernel.public_key();
    install_security_runtime_with_governance(
        kernel,
        mode,
        runtime,
        Some(threshold_resolver()),
        vec![policy_authority],
        default_profile,
        configured_pre,
        configured_post,
    )
}

fn require_install_error(result: Result<(), SecurityInstallError>) -> SecurityInstallError {
    match result {
        Ok(()) => panic!("security runtime installation unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn installed_production_kernel() -> (ChioKernel, ProductionAuthorityFixture) {
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(
            production_runtime(SecurityDurability::persistent(), &authorities)
                .unwrap_or_else(|error| panic!("build production runtime: {error}")),
        ),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install production runtime: {error}"));
    (kernel, authorities)
}

fn installed_mcp_manifest_registry() -> VerifiedManifestRegistry {
    let signer = Keypair::from_seed(&[82; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "frozen-route".to_string(),
        name: "Installed MCP flow route".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "marker".to_string(),
            description: "Marker".to_string(),
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
            flow: Some(ToolFlowDeclaration::public_egress()),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign installed MCP manifest: {error}"));
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .unwrap_or_else(|error| panic!("register installed MCP manifest: {error}"));
    registry
}

fn assert_publication_freeze(result: Result<(), KernelError>, operation: &str) {
    let error = match result {
        Ok(()) => panic!("{operation} bypassed governed publication freeze"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("partial security authority mutation is disabled"),
        "{operation} returned a non-freeze error: {error}"
    );
}

#[test]
fn disabled_mode_preserves_existing_pipeline_order() {
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Disabled,
        None,
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install disabled runtime: {error}"));

    assert_eq!(kernel.guard_names(), ["default-pre", "guard-pipeline"]);
    assert_eq!(
        kernel.post_invocation_hook_names(),
        ["configured-post", "default-post"]
    );
}

#[test]
fn disabled_mode_preserves_canonical_receipt_bytes() {
    let keypair = Keypair::generate();
    let mut baseline = kernel_with_keypair(keypair.clone());
    let mut disabled = kernel_with_keypair(keypair);
    register_marker_route(&mut baseline, "byte-identical");
    register_marker_route(&mut disabled, "byte-identical");
    let request = marker_request(&baseline, "disabled-byte-identity");
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut disabled,
        ActiveDefenseMode::Disabled,
        None,
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install disabled runtime: {error}"));

    let baseline_response = {
        let _fixed_runtime = chio_kernel::scope_fixed_runtime_for_current_thread(
            request.capability.issued_at,
            ["rcpt-disabled-byte-identity".to_string()],
        );
        baseline
            .evaluate_tool_call_blocking(&request)
            .unwrap_or_else(|error| panic!("evaluate baseline call: {error}"))
    };
    let disabled_response = {
        let _fixed_runtime = chio_kernel::scope_fixed_runtime_for_current_thread(
            request.capability.issued_at,
            ["rcpt-disabled-byte-identity".to_string()],
        );
        disabled
            .evaluate_tool_call_blocking(&request)
            .unwrap_or_else(|error| panic!("evaluate disabled-mode call: {error}"))
    };
    let baseline_bytes = chio_core::canonical::canonical_json_bytes(&baseline_response.receipt)
        .unwrap_or_else(|error| panic!("canonicalize baseline receipt: {error}"));
    let disabled_bytes = chio_core::canonical::canonical_json_bytes(&disabled_response.receipt)
        .unwrap_or_else(|error| panic!("canonicalize disabled-mode receipt: {error}"));

    assert_eq!(disabled_response.output, baseline_response.output);
    assert_eq!(disabled_bytes, baseline_bytes);
}

#[test]
fn enforce_tripwire_denial_stops_later_allowing_guards() {
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let mut kernel = kernel();
    let _receipt_directory = install_contextual_receipt_store(&mut kernel);
    register_marker_route(&mut kernel, "must-not-dispatch");
    let security_context = security_context("tripwire-first");
    let trace = Arc::new(Mutex::new(Vec::new()));
    let parts = SecurityRuntimeParts::new(
        Box::new(NamedGuard("caller-session-throttle")),
        Box::new(TraceGuard {
            name: "tripwire",
            verdict: Verdict::Deny,
            trace: Arc::clone(&trace),
        }),
        Box::new(TraceGuard {
            name: "containment",
            verdict: Verdict::Allow,
            trace: Arc::clone(&trace),
        }),
        Box::new(TraceGuard {
            name: "flow-pre",
            verdict: Verdict::Allow,
            trace: Arc::clone(&trace),
        }),
        Arc::new(NamedPreDispatchHook("flow-pre-dispatch")),
        Box::new(NamedHook("raw-tripwire")),
        Box::new(NamedHook("flow-post")),
    );
    let security_runtime =
        production_runtime_with_parts(SecurityDurability::persistent(), &authorities, parts)
            .unwrap_or_else(|error| panic!("build tripwire runtime: {error}"));
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(security_runtime),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install tripwire runtime: {error}"));
    let request = contextual_marker_request(&kernel, "tripwire-first", &security_context);
    let invocation_context = bind_security_context_to_request(&security_context, &request);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &invocation_context)
        .unwrap_or_else(|error| panic!("evaluate tripwire denial: {error}"));

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        *lock_unpoisoned(&trace),
        vec!["tripwire"],
        "response: {response:#?}"
    );
}

#[test]
fn enforce_post_pipeline_observes_raw_then_sanitized_response() {
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let mut kernel = kernel();
    let _receipt_directory = install_contextual_receipt_store(&mut kernel);
    register_marker_route(&mut kernel, "raw-secret");
    let security_context = security_context("post-security-order");
    let raw_observations = Arc::new(Mutex::new(Vec::new()));
    let flow_observations = Arc::new(Mutex::new(Vec::new()));
    let parts = SecurityRuntimeParts::new(
        Box::new(NamedGuard("caller-session-throttle")),
        Box::new(NamedGuard("tripwire")),
        Box::new(NamedGuard("containment")),
        Box::new(NamedGuard("flow-pre")),
        Arc::new(NamedPreDispatchHook("flow-pre-dispatch")),
        Box::new(RecordingHook {
            name: "raw-tripwire",
            observations: Arc::clone(&raw_observations),
        }),
        Box::new(RecordingHook {
            name: "flow-post",
            observations: Arc::clone(&flow_observations),
        }),
    );
    let security_runtime =
        production_runtime_with_parts(SecurityDurability::persistent(), &authorities, parts)
            .unwrap_or_else(|error| panic!("build post-order runtime: {error}"));
    let mut configured_post = PostInvocationPipeline::new();
    configured_post.add(Box::new(FixedRedactionHook));
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(security_runtime),
        RuntimeGuardProfile {
            pre_invocation_guards: Vec::new(),
            post_invocation_pipeline: PostInvocationPipeline::new(),
        },
        GuardPipeline::new(),
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install post-order runtime: {error}"));
    let request = contextual_marker_request(&kernel, "post-security-order", &security_context);
    let invocation_context = bind_security_context_to_request(&security_context, &request);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &invocation_context)
        .unwrap_or_else(|error| panic!("evaluate post-order call: {error}"));

    let raw = lock_unpoisoned(&raw_observations);
    assert_eq!(raw.len(), 1, "response: {response:#?}");
    assert!(raw[0].to_string().contains("raw-secret"));
    drop(raw);
    let flow = lock_unpoisoned(&flow_observations);
    assert_eq!(flow.len(), 1);
    assert!(!flow[0].to_string().contains("raw-secret"));
    assert_eq!(
        flow[0],
        serde_json::json!({
            "kind": "value",
            "value": { "marker": "[REDACTED]" }
        })
    );
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({ "marker": "[REDACTED]" })
        ))
    );
    assert!(response
        .receipt
        .verify_signature()
        .unwrap_or_else(|error| panic!("verify sanitized receipt: {error}")));
}

#[test]
fn enforce_mode_installs_exact_security_order() {
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(runtime(SecurityDurability::persistent())),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install enforced runtime: {error}"));

    assert_eq!(
        kernel.guard_names(),
        [
            "tripwire",
            "containment",
            "flow-pre",
            "chio-capability-set-suspension",
            "chio-session-throttle",
            "default-pre",
            "guard-pipeline"
        ]
    );
    assert_eq!(
        kernel.post_invocation_hook_names(),
        [
            "raw-tripwire",
            "configured-post",
            "default-post",
            "flow-post"
        ]
    );
}

#[test]
fn enforce_mode_installs_the_authoritative_pre_dispatch_hook() {
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(runtime(SecurityDurability::persistent())),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install enforced runtime: {error}"));

    assert_eq!(
        kernel.security_pre_dispatch_policy(),
        SecurityPreDispatchPolicy::Enforce
    );
    assert_eq!(
        kernel.security_pre_dispatch_hook_name(),
        Some("flow-pre-dispatch")
    );
}

#[test]
fn governed_runtime_mcp_dispatch_uses_authoritative_context_and_exact_manifest_registry() {
    let registry = Arc::new(installed_mcp_manifest_registry());
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let mut kernel = kernel();
    let _receipt_directory = install_contextual_receipt_store(&mut kernel);
    register_marker_route(&mut kernel, "installed-mcp-marker");
    let request = marker_request(&kernel, "installed-mcp-request");
    let security_runtime = SecurityRuntime::production(
        Arc::clone(&registry),
        SecurityDurability::persistent(),
        runtime_parts(),
        authorities
            .builder()
            .build()
            .unwrap_or_else(|error| panic!("build installed MCP authority bundle: {error}")),
    )
    .unwrap_or_else(|error| panic!("build installed MCP security runtime: {error}"));
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(security_runtime),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install MCP security runtime: {error}"));

    assert!(registry.requires_flow_runtime());
    assert!(kernel.has_installed_flow_runtime());
    assert_eq!(
        kernel.security_pre_dispatch_policy(),
        SecurityPreDispatchPolicy::Enforce
    );

    let mut edge = ChioMcpEdge::new_with_manifest_registry_arc_and_security_context_authority(
        McpEdgeConfig::default(),
        kernel,
        request.agent_id.clone(),
        vec![request.capability.clone()],
        Arc::clone(&registry),
        Arc::new(InstalledMcpSecurityContextAuthority),
    )
    .unwrap_or_else(|error| panic!("construct installed MCP edge: {error}"));
    let initialize = edge
        .handle_jsonrpc(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap_or_else(|| panic!("installed MCP initialize returned no response"));
    assert!(initialize.get("result").is_some());
    assert!(edge
        .handle_jsonrpc(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }))
        .is_none());

    let response = edge
        .handle_jsonrpc(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "marker",
                "arguments": {}
            }
        }))
        .unwrap_or_else(|| panic!("installed MCP dispatch returned no response"));

    assert_eq!(response["result"]["isError"], false);
    assert!(response["result"]["content"]
        .to_string()
        .contains("installed-mcp-marker"));
}

#[test]
fn enforce_mode_atomically_activates_the_complete_authority_bundle() {
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(
            production_runtime(SecurityDurability::persistent(), &authorities)
                .unwrap_or_else(|error| panic!("build production runtime: {error}")),
        ),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install enforced runtime: {error}"));

    assert_eq!(authorities.indexed_finding_store.readiness_checks(), 2);
    assert_eq!(authorities.executor_authority.readiness_checks(), 2);
    let status = kernel.governed_security_runtime_status();
    assert_eq!(status.publication_generation, 1);
    assert!(status.active_response_enabled);
    assert!(status.threshold_approval_enabled);
    assert!(status.capability_issuance_admission_enabled);
    assert_eq!(
        status.executor_authority,
        Some(authorities.executor_authority.identity())
    );
    assert_eq!(status.threshold_policy_authorities, [kernel.public_key()]);
}

#[test]
fn enforce_runtime_routes_real_issuance_through_freeze_admission_and_contextual_store() {
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let receipt_directory =
        tempfile::tempdir().unwrap_or_else(|error| panic!("create receipt directory: {error}"));
    let receipt_store = Arc::new(
        SqliteReceiptStore::open(receipt_directory.path().join("receipts.sqlite3"))
            .unwrap_or_else(|error| panic!("open receipt store: {error}")),
    );
    let receipt_store_handle: Arc<dyn chio_kernel::ReceiptStore> = receipt_store.clone();
    let mut kernel = kernel();
    kernel
        .set_receipt_store_handle(receipt_store_handle)
        .unwrap_or_else(|error| panic!("install receipt store: {error}"));
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(
            production_runtime(SecurityDurability::persistent(), &authorities)
                .unwrap_or_else(|error| panic!("build production runtime: {error}")),
        ),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install enforced runtime: {error}"));

    let subject = Keypair::generate().public_key();
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("tenant-issuance")
            .unwrap_or_else(|error| panic!("invalid issuance tenant: {error}")),
        SessionId::new("session-issuance")
            .unwrap_or_else(|error| panic!("invalid issuance session: {error}")),
        PrincipalId::new("principal-issuance")
            .unwrap_or_else(|error| panic!("invalid issuance principal: {error}")),
        IsolationEpochId::new("epoch-issuance")
            .unwrap_or_else(|error| panic!("invalid issuance isolation epoch: {error}")),
        LineageId::new("lineage-issuance")
            .unwrap_or_else(|error| panic!("invalid issuance lineage: {error}")),
        1,
    ));
    let context_free = kernel.issue_capability(&subject, ChioScope::default(), 300);
    assert!(matches!(
        context_free,
        Err(KernelError::CapabilityIssuanceDenied(_))
    ));
    kernel
        .issue_capability_with_security_context(&subject, ChioScope::default(), 300, &context)
        .unwrap_or_else(|error| panic!("contextual issuance: {error}"));
    let tenant_id = context.as_v1().tenant_id().clone();
    let lineage_id = context.as_v1().lineage_root_id().clone();
    let root_id = RecordId::new(lineage_id.as_str())
        .unwrap_or_else(|error| panic!("invalid issuance lineage record: {error}"));
    receipt_store
        .commit_causal_lineage(&CausalLineageCommitRequest {
            tenant_id: tenant_id.clone(),
            metadata: CausalLineageCommitMetadata {
                source_lineage_version: 1,
                observed_commit_index: 1,
                authoritative_commit_index: 1,
                completeness_watermark: Some(1),
            },
            nodes: CausalLineageNodes::new(vec![CausalLineageNode {
                tenant_id: tenant_id.clone(),
                node_id: root_id.clone(),
                kind: CausalLineageNodeKind::Capability,
            }])
            .unwrap_or_else(|error| panic!("invalid issuance lineage nodes: {error}")),
            edges: CausalLineageEdges::new(Vec::new())
                .unwrap_or_else(|error| panic!("invalid issuance lineage edges: {error}")),
        })
        .unwrap_or_else(|error| panic!("failed to commit issuance lineage: {error}"));
    apply_contextual_issuance_freeze(&authorities, &receipt_store, tenant_id, lineage_id);
    let frozen = kernel.issue_capability_with_security_context(
        &subject,
        ChioScope::default(),
        300,
        &context,
    );
    assert!(matches!(
        frozen,
        Err(KernelError::CapabilityIssuanceDenied(_))
    ));
}

#[test]
fn authority_bundle_builder_rejects_each_missing_dependency() {
    let fixture = ProductionAuthorityFixture::new(true, true, 1);
    let expected = [
        SecurityRuntimeBuildError::ActiveResponseRequirementResolverMissing,
        SecurityRuntimeBuildError::AdmissionOperationStoreMissing,
        SecurityRuntimeBuildError::ApprovalStoreMissing,
        SecurityRuntimeBuildError::BudgetStoreMissing,
        SecurityRuntimeBuildError::SessionThrottleStoreMissing,
        SecurityRuntimeBuildError::IndexedFindingStoreMissing,
        SecurityRuntimeBuildError::TrustedReceiptSignerMissing,
        SecurityRuntimeBuildError::ExecutorMissing,
    ];

    for (stage, expected_error) in expected.into_iter().enumerate() {
        let error = authority_builder_through(&fixture, stage)
            .build()
            .err()
            .unwrap_or_else(|| panic!("stage {stage} unexpectedly built a partial bundle"));
        assert_eq!(error, expected_error);
    }
}

#[test]
fn authority_bundle_builder_rejects_ephemeral_stores() {
    let fixture = ProductionAuthorityFixture::new(true, true, 1);
    let ephemeral_operation = fixture
        .builder()
        .with_admission_operation_store(Arc::new(InMemoryAdmissionOperationStore::new()))
        .build()
        .err()
        .unwrap_or_else(|| panic!("ephemeral operation store unexpectedly accepted"));
    assert_eq!(
        ephemeral_operation,
        SecurityRuntimeBuildError::AdmissionOperationStoreEphemeral
    );

    let ephemeral_approval = fixture
        .builder()
        .with_approval_store(Arc::new(InMemoryApprovalStore::new()))
        .build()
        .err()
        .unwrap_or_else(|| panic!("ephemeral approval store unexpectedly accepted"));
    assert_eq!(
        ephemeral_approval,
        SecurityRuntimeBuildError::ApprovalStoreEphemeral
    );

    let ephemeral_budget = fixture
        .builder()
        .with_budget_store(Arc::new(InMemoryBudgetStore::new()))
        .build()
        .err()
        .unwrap_or_else(|| panic!("ephemeral budget store unexpectedly accepted"));
    assert_eq!(
        ephemeral_budget,
        SecurityRuntimeBuildError::BudgetStoreEphemeral
    );
}

#[test]
fn authority_bundle_and_atomic_install_reject_unavailable_session_throttle_store() {
    let unavailable_at_build = ProductionAuthorityFixture::new(true, true, 1);
    unavailable_at_build.invalidate_session_throttle_schema();
    let error = unavailable_at_build
        .builder()
        .build()
        .err()
        .unwrap_or_else(|| panic!("unavailable session-throttle store unexpectedly accepted"));
    assert_eq!(
        error,
        SecurityRuntimeBuildError::SessionThrottleStoreUnavailable
    );

    let unavailable_at_install = ProductionAuthorityFixture::new(true, true, 1);
    let runtime = production_runtime(SecurityDurability::persistent(), &unavailable_at_install)
        .unwrap_or_else(|error| panic!("build production runtime: {error}"));
    unavailable_at_install.invalidate_session_throttle_schema();
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    let error = require_install_error(install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(runtime),
        profile(),
        configured_pre,
        configured_post,
    ));
    assert_eq!(error, SecurityInstallError::SessionThrottleStoreUnavailable);
    assert_eq!(kernel.guard_count(), 0);
    assert_eq!(kernel.post_invocation_hook_count(), 0);
    assert_eq!(
        kernel
            .governed_security_runtime_status()
            .publication_generation,
        0
    );
}

#[test]
fn authority_bundle_builder_rejects_unready_finding_and_executor_authorities() {
    let finding_unready = ProductionAuthorityFixture::new(false, true, 1);
    let error = finding_unready
        .builder()
        .build()
        .err()
        .unwrap_or_else(|| panic!("unready finding authority unexpectedly accepted"));
    assert_eq!(
        error,
        SecurityRuntimeBuildError::FindingAuthorityUnavailable
    );
    assert_eq!(finding_unready.indexed_finding_store.readiness_checks(), 1);
    assert_eq!(finding_unready.executor_authority.readiness_checks(), 0);

    let executor_unready = ProductionAuthorityFixture::new(true, false, 1);
    let error = executor_unready
        .builder()
        .build()
        .err()
        .unwrap_or_else(|| panic!("unready executor authority unexpectedly accepted"));
    assert_eq!(error, SecurityRuntimeBuildError::ExecutorUnavailable);
    assert_eq!(executor_unready.indexed_finding_store.readiness_checks(), 1);
    assert_eq!(executor_unready.executor_authority.readiness_checks(), 1);

    let empty_trust = ProductionAuthorityFixture::new(true, true, 1);
    let error = empty_trust
        .builder()
        .with_trusted_receipt_signers(Vec::new())
        .build()
        .err()
        .unwrap_or_else(|| panic!("empty receipt signer trust unexpectedly accepted"));
    assert_eq!(
        error,
        SecurityRuntimeBuildError::TrustedReceiptSignerMissing
    );
}
