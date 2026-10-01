//! Original kernel authority for the existing broker process boundary fixture.
use super::*;
use crate::kernel_admission::{
    BrokerAdmissionParticipant, BrokerKernelAuthorityHandler, BrokerKernelConnection,
    BrokerMcpConnection, BrokerNativeCaptureReader, BrokerQuotaVerifier, BrokerQuotaVerifierConfig,
};
use chio_control_plane::security::adapters::{FlowResolverConfig, NativeFlowResolver};
use chio_control_plane::DurableAdmissionRuntime;
use chio_core_types::capability::aggregate_invocation::{
    AggregateInvocationBudget, AggregateInvocationScope,
};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_flow::CategoryLabelMap;
use chio_kernel::admission_operation::{AdmissionIdentifier, NativeSecurityAuthorityBindingV1};
use chio_kernel::{
    BlockingToolServerAdapter, ChioKernel, KernelConfig, SecurityInvocationContext,
    SecurityInvocationContextV1, SecurityPreDispatchPolicy, ToolCallRequest,
};
use chio_manifest::{
    sign_manifest, AuthoritativeToolPolicy, RuntimeToolTopology, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_security_kernel::SystemSecurityClock;
use chio_security_types::ports::{
    BoundedVec, ClassificationPort, ClassificationRequest, ClassificationResult, ClassifierId,
    ClassifierVersion, IsolationEpochId, LineageId, PortError, PortResult, SessionId, TenantId,
};
use chio_security_types::{InformationLabel, PrincipalId};
use chio_store_sqlite::security_state::SqliteSecurityParticipantSource;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore, SqliteSecurityStateStore};
use std::collections::{BTreeMap, BTreeSet};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(super) const SERVER: &str = "native-broker";
pub(super) const TOOL: &str = "send";

pub(super) fn parent_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: SERVER.into(),
            tool_name: TOOL.into(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

pub(super) struct NativeAuthority<'a> {
    pub issuer: &'a Keypair,
    pub caller: &'a Keypair,
    pub authority_signer: &'a Keypair,
    pub parent: Option<CapabilityToken>,
    pub cutpoint: Option<Arc<cutpoints::Control>>,
    #[cfg(feature = "real-linux-enforcement")]
    pub confined_router: Option<crate::native_mcp::NativeBrokerMcpTool>,
}

pub(super) struct NativeHost {
    pub kernel: Arc<ChioKernel>,
    pub authority: Arc<SqliteAuthorityStore>,
    pub handler: Arc<BrokerKernelAuthorityHandler>,
    pub reader: BrokerNativeCaptureReader,
    pub participant: Arc<BrokerAdmissionParticipant>,
    pub request: ToolCallRequest,
    pub context: SecurityInvocationContext,
    pub execute: BrokerExecuteRequest,
}

impl NativeHost {
    pub fn new(
        directory: &Path,
        config: &BrokerDaemonConfig,
        broker_pid: u32,
        keys: NativeAuthority<'_>,
        mut execute: BrokerExecuteRequest,
        tool: Option<Arc<dyn crate::kernel_admission::BrokerMcpToolConnection>>,
        manifest_registry: Arc<VerifiedManifestRegistry>,
    ) -> TestResult<Self> {
        let NativeAuthority {
            issuer,
            caller,
            authority_signer,
            parent,
            cutpoint,
            #[cfg(feature = "real-linux-enforcement")]
            confined_router,
        } = keys;
        let database = directory.join("kernel-authority.sqlite3");
        let runtime = DurableAdmissionRuntime::open(&database)?;
        let authority = runtime
            .local_authority_store()
            .ok_or("native broker requires the host's local admission authority")?;
        let mut kernel = ChioKernel::new(KernelConfig {
            ca_public_keys: vec![parent.as_ref().map_or_else(
                || authority_signer.public_key(),
                |parent| parent.issuer.clone(),
            )],
            keypair: runtime.kernel_keypair(),
            max_delegation_depth: 5,
            policy_hash: chio_core_types::crypto::sha256_hex(b"native-broker-process-policy"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            allow_ephemeral_revocation_store: false,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        });
        let receipts = SqliteReceiptStore::open(directory.join("kernel-receipts.sqlite3"))?;
        receipts.wait_for_writer_ready(Duration::from_secs(30))?;
        kernel.set_receipt_store_handle(Arc::new(receipts))?;
        runtime.attach(&mut kernel)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let parent = match parent {
            Some(parent) => parent,
            None => CapabilityToken::sign(
                CapabilityTokenBody {
                    id: "native-parent-process-boundary".into(),
                    issuer: authority_signer.public_key(),
                    subject: caller.public_key(),
                    issued_at: now.saturating_sub(1),
                    expires_at: now + 300,
                    delegation_chain: Vec::new(),
                    scope: parent_scope(),
                    aggregate_invocation_budget: Some(AggregateInvocationBudget {
                        scope: AggregateInvocationScope::Capability,
                        max_invocations: 1,
                        root_binding: None,
                    }),
                },
                authority_signer,
            )?,
        };
        kernel.register_delegation_parent(&parent)?;
        execute.capability.body.parent_capability_id = parent.id.clone();
        execute.capability = issue_capability(
            execute.capability.body,
            &Ed25519Backend::new(issuer.clone()),
            true,
        )?;
        execute.proof = issue_request_proof(
            &execute.capability,
            &execute.request,
            execute.proof.body.nonce,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            caller,
        )?;
        let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            TenantId::new(TENANT_SCOPE)?,
            SessionId::new("native-broker-session")?,
            PrincipalId::new(caller.public_key().to_hex())?,
            IsolationEpochId::new("native-broker-epoch")?,
            LineageId::new(&parent.id)?,
            1,
        ));
        let request = ToolCallRequest {
            request_id: execute.invocation_id.clone(),
            capability: parent,
            tool_name: TOOL.into(),
            server_id: SERVER.into(),
            agent_id: caller.public_key().to_hex(),
            arguments: serde_json::to_value(&execute)?,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: Some(serde_json::from_value(
                serde_json::json!({"signed_extension": String::from_utf8(canonical_json_bytes(&execute)?)?}),
            )?),
            federated_origin_kernel_id: None,
            declassification_grant: None,
        };
        let native = initialize_native(&authority, directory)?;
        let resolver = NativeFlowResolver::new(
            native.clone(),
            manifest_registry,
            Arc::new(EmptyClassifier),
            Arc::new(SystemSecurityClock),
            FlowResolverConfig::new(
                InformationLabel::bottom(),
                CategoryLabelMap::new(
                    ClassifierId::new("classifier.empty")?,
                    ClassifierVersion::new("1")?,
                    BTreeMap::new(),
                )?,
                BTreeMap::new(),
                10_000,
            )?,
        )?
        .with_captured_lifecycle();
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(resolver));
        let verifier = BrokerQuotaVerifier::new(
            BrokerQuotaVerifierConfig {
                issuer: issuer.public_key(),
                audience: config.broker_audience.clone(),
                server_id: SERVER.into(),
                tool_name: TOOL.into(),
                provider_adapter_id: config.provider_adapter_id.clone(),
                provider_adapter_version: 1,
                credential_placement: config.provider_placement,
            },
            Arc::new(crate::daemon::SystemDaemonClock),
        )?;
        let participant = Arc::new(BrokerAdmissionParticipant::new(
            BrokerIpcClientConfig {
                socket_path: config.ipc_socket_path.clone(),
                tenant_scope: config.tenant_scope.clone(),
                timeout_ms: config.ipc_read_timeout_ms,
                expected_peer: BrokerPeerIdentity {
                    process_id: broker_pid,
                    user_id: config.trusted_service_uid,
                    group_id: rustix::process::getegid().as_raw(),
                },
                trusted_receipt_signer: config.broker_identity.clone(),
            },
            Arc::new(Ed25519Backend::new(authority_signer.clone())),
            AUTHORITY_DOMAIN.into(),
            &verifier,
        )?);
        let selected = verifier.binding().clone();
        kernel.set_supplemental_quota_verifier(Arc::new(verifier), selected)?;
        kernel.set_supplemental_admission_participant(
            cutpoints::wrap_participant(participant.clone(), cutpoint),
            participant.binding().clone(),
        )?;
        let connection = Arc::new(BrokerKernelConnection::new(
            BrokerNativeCaptureReader::new(
                &authority,
                native.clone(),
                participant.binding().clone(),
            )?,
            participant.clone(),
        )?);
        #[cfg(feature = "real-linux-enforcement")]
        let routed = confined_router
            .map(|template| {
                crate::native_mcp::NativeBrokerMcpRouter::new(connection.clone(), template)
                    .map(|router| Box::new(router) as Box<dyn chio_kernel::ToolServerConnection>)
            })
            .transpose()?;
        #[cfg(not(feature = "real-linux-enforcement"))]
        let routed: Option<Box<dyn chio_kernel::ToolServerConnection>> = None;
        let connection: Box<dyn chio_kernel::ToolServerConnection> = match routed {
            Some(router) => router,
            None => match tool {
                Some(tool) => Box::new(BrokerMcpConnection::new(connection, tool)?),
                None => Box::new(BlockingToolServerAdapter::new(connection)?),
            },
        };
        kernel.register_tool_server(connection);
        let kernel = Arc::new(kernel);
        let handler = Arc::new(BrokerKernelAuthorityHandler::new(
            &authority,
            native.clone(),
            participant.clone(),
            kernel.clone(),
        )?);
        let reader =
            BrokerNativeCaptureReader::new(&authority, native, participant.binding().clone())?;
        Ok(Self {
            kernel,
            authority,
            handler,
            reader,
            participant,
            request,
            context,
            execute,
        })
    }
}

fn initialize_native(
    authority: &SqliteAuthorityStore,
    directory: &Path,
) -> TestResult<NativeSecurityAuthorityBindingV1> {
    let source_path = directory.join("native-source.sqlite3");
    drop(SqliteSecurityStateStore::open(&source_path)?);
    let source = SqliteSecurityParticipantSource::open(source_path)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let selected = AdmissionIdentifier::try_new("authority", "native-broker-process")?;
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let expected =
        store.expect_security_participant_source(&selected, &selected, &source, &fence, now)?;
    store.import_security_participant_source(
        &selected,
        expected.expectation_id(),
        &source,
        &fence,
        now,
    )?;
    Ok(store
        .hydrate_security_participant_state(&selected, expected.expectation_id(), &fence, now)?
        .admission_binding()?)
}

pub(super) fn manifests(
    signer: &Keypair,
    confined: bool,
) -> TestResult<Arc<VerifiedManifestRegistry>> {
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.into(),
        server_id: SERVER.into(),
        name: "Native broker".into(),
        description: confined.then(|| "MCP server adapted to Chio protocol".into()),
        version: "1.0.0".into(),
        tools: vec![ToolDefinition {
            name: TOOL.into(),
            description: if confined {
                "Execute one originally admitted request through the credential broker"
            } else {
                "Send through the broker"
            }
            .into(),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: None,
            pricing: None,
            annotations: if confined {
                ToolAnnotations {
                    read_only: false,
                    destructive: true,
                    idempotent: false,
                    requires_approval: true,
                }
            } else {
                ToolAnnotations::default()
            },
            latency_hint: None,
            flow: Some(ToolFlowDeclaration::new(
                Some(InformationLabel::bottom()),
                Some(InformationLabel::bottom()),
                true,
                BTreeSet::new(),
            )?),
        }],
        server_tools: Vec::new(),
        required_permissions: confined.then_some(chio_manifest::RequiredPermissions {
            read_paths: None,
            write_paths: None,
            network_destinations: None,
            environment_variables: None,
            native_syscall_profile: chio_manifest::NativeSyscallProfile::BrokeredNativeV1,
        }),
        public_key: signer.public_key().to_hex(),
    };
    let policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        InformationLabel::bottom(),
        BTreeSet::new(),
    )?;
    let mut registry = VerifiedManifestRegistry::default();
    registry.register(
        sign_manifest(&manifest, signer)?,
        &signer.public_key(),
        &BTreeMap::from([(TOOL.into(), policy)]),
        &BTreeMap::from([(
            TOOL.into(),
            if confined {
                RuntimeToolTopology::brokered()
            } else {
                RuntimeToolTopology::remote()
            },
        )]),
    )?;
    Ok(Arc::new(registry))
}

struct EmptyClassifier;
impl ClassificationPort for EmptyClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        Ok(ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: request.payload_digest,
            classifier_id: ClassifierId::new("classifier.empty").map_err(PortError::from)?,
            classifier_version: ClassifierVersion::new("1").map_err(PortError::from)?,
            findings: BoundedVec::new(Vec::new()).map_err(|_| PortError::invalid_data())?,
        })
    }
}
