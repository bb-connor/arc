use super::*;
use chio_core::capability::{
    governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedToolInvocationIntentBody, GovernedTransactionIntent,
    },
    scope::{ChioScope, Constraint, ModelSafetyTier, MonetaryAmount, Operation, ToolGrant},
    threshold_approval::{ThresholdApprovalProposal, ThresholdApprovalProposalBody},
};
use chio_core::crypto::Keypair;
use chio_core::message::OpaqueSupplementalAuthorization;
use chio_kernel::{
    ChioKernel, ExecutionNonceConfig, InMemoryExecutionNonceStore, KernelConfig, KernelError,
    NestedFlowBridge, RuntimeAdmissionContext, RuntimeAdmissionDecision, RuntimeAdmissionHook,
    ToolCallRequest, ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct IncrementingSecurityContextAuthority {
    generations: Arc<Mutex<Vec<u64>>>,
}

impl SecurityInvocationContextAuthority for IncrementingSecurityContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        let mut generations = self.generations.lock().unwrap();
        let generation = u64::try_from(generations.len())
            .map_err(|error| KernelError::Internal(error.to_string()))?
            .saturating_add(1);
        generations.push(generation);
        let lineage_root = operation
            .capability
            .delegation_chain
            .first()
            .map_or(operation.capability.id.as_str(), |link| {
                link.capability_id.as_str()
            });
        Ok(SecurityInvocationContext::v1(
            chio_kernel::SecurityInvocationContextV1::new(
                chio_security_types::ports::TenantId::new("tenant-openai-batch")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::SessionId::new(context.session_id.as_str())
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::PrincipalId::new(context.agent_id.clone())
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::IsolationEpochId::new("epoch-openai-batch")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::LineageId::new(lineage_root)
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                generation,
            ),
        ))
    }
}

struct WrongSessionSecurityContextAuthority;

impl SecurityInvocationContextAuthority for WrongSessionSecurityContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        let lineage_root = operation
            .capability
            .delegation_chain
            .first()
            .map_or(operation.capability.id.as_str(), |link| {
                link.capability_id.as_str()
            });
        Ok(SecurityInvocationContext::v1(
            chio_kernel::SecurityInvocationContextV1::new(
                chio_security_types::ports::TenantId::new("tenant-openai-wrong-session")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::SessionId::new("openai-foreign-session")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::PrincipalId::new(context.agent_id.clone())
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::IsolationEpochId::new("epoch-openai-wrong-session")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::LineageId::new(lineage_root)
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                1,
            ),
        ))
    }
}

struct MockToolServer {
    response: Value,
}

fn valid_test_public_key() -> String {
    Keypair::from_seed(&[23u8; 32]).public_key().to_hex()
}

#[async_trait::async_trait]
impl ToolServerConnection for MockToolServer {
    fn server_id(&self) -> &str {
        "test-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["get_weather".to_string(), "search".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(self.response.clone())
    }
}

struct FailingServer;

#[async_trait::async_trait]
impl ToolServerConnection for FailingServer {
    fn server_id(&self) -> &str {
        "fail-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["fail".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(KernelError::ToolServerError("simulated failure".into()))
    }
}

struct CountingToolServer {
    invocations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingToolServer {
    fn server_id(&self) -> &str {
        "test-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["get_weather".to_string(), "search".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"temperature": 72, "conditions": "sunny"}))
    }
}

struct DenyingOpenAiRuntimeAdmissionHook;

impl RuntimeAdmissionHook for DenyingOpenAiRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "openai-denying-runtime-admission"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Ok(RuntimeAdmissionDecision::deny(
            "openai runtime admission denied",
            Some(json!({
                "chio_runtime": {
                    "accepted": false,
                    "failure_code": "openai_runtime_admission_denied"
                }
            })),
        ))
    }
}

fn test_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "test-srv".to_string(),
        name: "Test".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![
            ToolDefinition {
                name: "get_weather".to_string(),
                description: "Get the weather for a location".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "location": {"type": "string"}
                    },
                    "required": ["location"]
                }),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: None,
                flow: None,
            },
            ToolDefinition {
                name: "search".to_string(),
                description: "Search the web".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"}
                    },
                    "required": ["query"]
                }),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: None,
                flow: None,
            },
        ],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: valid_test_public_key(),
    }
}

fn test_config() -> OpenAiAdapterConfig {
    OpenAiAdapterConfig {
        server_id: "openai-test".to_string(),
        server_name: "OpenAI Test".to_string(),
        server_version: "1.0.0".to_string(),
        public_key: valid_test_public_key(),
    }
}

fn verified_test_registry_with_topology(
    topology: chio_manifest::RuntimeToolTopology,
) -> chio_manifest::VerifiedManifestRegistry {
    let signer = Keypair::from_seed(&[23u8; 32]);
    let signed = chio_manifest::sign_manifest(&test_manifest(), &signer)
        .unwrap_or_else(|error| panic!("sign OpenAI test manifest: {error}"));
    let mut registry = chio_manifest::VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), topology)
        .unwrap_or_else(|error| panic!("admit OpenAI test manifest: {error}"));
    registry
}

fn verified_test_registry() -> chio_manifest::VerifiedManifestRegistry {
    verified_test_registry_with_topology(chio_manifest::RuntimeToolTopology::local())
}

fn test_server() -> MockToolServer {
    MockToolServer {
        response: json!({"temperature": 72, "conditions": "sunny"}),
    }
}

fn weather_tool_call() -> OpenAiToolCall {
    OpenAiToolCall {
        id: "call_abc123".to_string(),
        call_type: "function".to_string(),
        function: OpenAiFunctionCall {
            name: "get_weather".to_string(),
            arguments: r#"{"location": "San Francisco"}"#.to_string(),
        },
    }
}

#[test]
fn denied_tool_call_result_preserves_call_identity_without_receipt() {
    let call = weather_tool_call();
    let result = denied_tool_call_result(&call, "Error: blocked");

    assert_eq!(result.tool_call_id, "call_abc123");
    assert_eq!(result.name, "get_weather");
    assert_eq!(result.content, "Error: blocked");
    assert!(result.denied);
    assert!(result.receipt_ref.is_none());
    assert!(result.receipt.is_none());
}

fn test_kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 8,
        policy_hash: "test-policy".to_string(),
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
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    }
}

fn test_execution_context(
    kernel: &ChioKernel,
    agent_kp: &Keypair,
    server_id: &str,
    tool_name: &str,
) -> OpenAiExecutionContext {
    let capability = kernel
        .issue_capability(
            &agent_kp.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.to_string(),
                    tool_name: tool_name.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            3600,
        )
        .expect("capability should issue");
    OpenAiExecutionContext {
        capability,
        agent_id: agent_kp.public_key().to_hex(),
        dpop_proof: None,
        execution_nonces: BTreeMap::new(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        security_context: None,
    }
}

fn adapter_authorization_artifacts(
    subject: &Keypair,
    request_id: &str,
) -> (
    Vec<GovernedApprovalToken>,
    ThresholdApprovalProposal,
    OpaqueSupplementalAuthorization,
) {
    let authority = Keypair::from_seed(&[92; 32]);
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody::new(
            "proposal-openai-preservation",
            request_id,
            "11".repeat(32),
            subject.public_key(),
            "22".repeat(32),
            "33".repeat(32),
            1,
            "44".repeat(32),
            1_000,
            300,
            1_500,
            1_400,
        )
        .unwrap(),
        &authority,
    )
    .unwrap();
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval-openai-preservation".to_string(),
            approver: authority.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "11".repeat(32),
            threshold_proposal_hash: Some(proposal.proposal_hash().unwrap()),
            request_id: request_id.to_string(),
            issued_at: 1_000,
            expires_at: 1_300,
            decision: GovernedApprovalDecision::Approved,
        },
        &authority,
    )
    .unwrap();
    let supplemental = OpaqueSupplementalAuthorization::new(
        "supplemental-openai-preservation",
        vec![0x43, 0x48, 0x49, 0x4f],
    )
    .unwrap();
    (vec![token], proposal, supplemental)
}

#[test]
fn openai_kernel_request_preserves_complete_authorization_context() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let kernel = ChioKernel::new(test_kernel_config());
    let subject = Keypair::generate();
    let tool_call = weather_tool_call();
    let mut execution = test_execution_context(&kernel, &subject, "test-srv", "get_weather");
    let request_id = format!("openai-{}", tool_call.id);
    let (approval_tokens, proposal, supplemental) =
        adapter_authorization_artifacts(&subject, &request_id);
    execution.approval_tokens = approval_tokens.clone();
    execution.threshold_approval_proposal = Some(proposal.clone());
    execution.supplemental_authorization = Some(supplemental.clone());

    let request = adapter
        .build_tool_call_request(&tool_call, &execution)
        .expect("valid OpenAI tool call should map to a kernel request");

    assert_eq!(request.approval_tokens, approval_tokens);
    assert_eq!(request.threshold_approval_proposal, Some(proposal));
    assert_eq!(request.supplemental_authorization, Some(supplemental));
}

// ---- Adapter creation tests ----

#[test]
fn adapter_creates_from_manifest() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    assert_eq!(adapter.manifest().server_id, "openai-test");
}

#[test]
fn adapter_empty_manifests_errors() {
    let empty_manifest = ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "empty".to_string(),
        name: "Empty".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: valid_test_public_key(),
    };
    let err = ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![empty_manifest])
        .unwrap_err();
    assert!(matches!(err, OpenAiAdapterError::InvalidRequest(_)));
}

#[test]
fn adapter_function_names() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let names = adapter.function_names();
    assert!(names.contains(&"get_weather".to_string()));
    assert!(names.contains(&"search".to_string()));
}

#[test]
fn adapter_function_def_lookup() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let def = adapter.function_def("get_weather").unwrap();
    assert_eq!(def.description, "Get the weather for a location");
}

#[test]
fn adapter_unknown_function_def_returns_none() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    assert!(adapter.function_def("nonexistent").is_none());
}

// ---- OpenAI tools generation tests ----

#[test]
fn openai_tools_format() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let tools = adapter.openai_tools();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].tool_type, "function");
    assert_eq!(tools[0].function.name, "get_weather");
}

#[test]
fn openai_tools_json_is_valid() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let json = adapter.openai_tools_json();
    assert!(json.is_array());
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["type"], "function");
}

#[test]
fn openai_tool_has_parameters_schema() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let tools = adapter.openai_tools();
    let weather = &tools[0];
    assert!(weather.function.parameters.get("properties").is_some());
}

// ---- Tool call execution tests ----

#[test]
fn production_adapter_executes_with_exact_verified_registry_sidecar() {
    let registry = verified_test_registry();
    let expected_security = registry
        .bridge_security("test-srv", "get_weather")
        .unwrap_or_else(|| panic!("verified registry must expose get_weather security"));
    let adapter = ChioOpenAiAdapter::new(test_config(), &registry)
        .unwrap_or_else(|error| panic!("build production OpenAI adapter: {error}"));
    let mut kernel = ChioKernel::new(test_kernel_config());
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingToolServer {
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");

    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);

    assert!(
        !result.denied,
        "production execution denied: {}",
        result.content
    );
    let manifest_security = result
        .receipt
        .as_ref()
        .and_then(|receipt| receipt.metadata.as_ref())
        .and_then(|metadata| metadata.get("chio_manifest_security_v1"))
        .unwrap_or_else(|| panic!("receipt must preserve manifest security"));
    let expected_security = serde_json::to_value(expected_security)
        .unwrap_or_else(|error| panic!("serialize expected manifest security: {error}"));
    assert_eq!(
        chio_core::canonical_json_bytes(manifest_security)
            .unwrap_or_else(|error| panic!("canonicalize receipt manifest security: {error}")),
        chio_core::canonical_json_bytes(&expected_security)
            .unwrap_or_else(|error| panic!("canonicalize expected manifest security: {error}"))
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn production_adapter_rejects_flow_required_registry_without_governed_runtime() {
    let registry =
        verified_test_registry_with_topology(chio_manifest::RuntimeToolTopology::remote());
    let adapter = ChioOpenAiAdapter::new(test_config(), &registry)
        .unwrap_or_else(|error| panic!("build production OpenAI adapter: {error}"));
    let mut kernel = ChioKernel::new(test_kernel_config());
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingToolServer {
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");

    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);

    assert!(result.denied);
    assert!(result.content.contains(
        "admitted manifest flow policy or topology requires an installed active defense runtime"
    ));
    assert!(result.receipt.is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn production_adapter_rejects_forged_manifest_security_sidecar() {
    let registry = verified_test_registry();
    let mut adapter = ChioOpenAiAdapter::new(test_config(), &registry)
        .unwrap_or_else(|error| panic!("build production OpenAI adapter: {error}"));
    adapter.function_security.insert(
        "get_weather".to_string(),
        BridgeSecurityMetadata::from_tool(&test_manifest().tools[0]),
    );
    let mut kernel = ChioKernel::new(test_kernel_config());
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingToolServer {
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");

    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);

    assert!(result.denied);
    assert!(result
        .content
        .contains("bridge security does not match live registry entry"));
    assert!(!result.content.contains("is reserved"));
    assert!(result.receipt.is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn execute_tool_call_success() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
    assert!(!result.denied);
    assert_eq!(result.tool_call_id, "call_abc123");
    assert!(result.content.contains("72"));
    assert!(result.receipt_ref.is_some());
    assert!(result.receipt.is_some());
    let route_selection = result
        .receipt
        .as_ref()
        .and_then(|receipt| receipt.metadata.as_ref())
        .and_then(|metadata| metadata.get("route_selection"));
    assert_eq!(
        route_selection
            .and_then(|value| value.get("selectedTargetProtocol"))
            .and_then(Value::as_str),
        Some("native")
    );
    assert_eq!(
        route_selection
            .and_then(|value| value.get("decision"))
            .and_then(Value::as_str),
        Some("select")
    );
}

#[test]
fn execute_tool_call_runtime_admission_denies_before_tool_server_dispatch() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingToolServer {
        invocations: Arc::clone(&invocations),
    }));
    kernel.set_runtime_admission_hook(Arc::new(DenyingOpenAiRuntimeAdmissionHook));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");

    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);

    assert!(result.denied);
    assert!(result.content.contains("openai runtime admission denied"));
    assert_eq!(
        result
            .receipt
            .as_ref()
            .and_then(|receipt| receipt.metadata.as_ref())
            .and_then(|metadata| metadata.pointer("/chio_runtime/failure_code"))
            .and_then(Value::as_str),
        Some("openai_runtime_admission_denied")
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn execute_tool_call_preserves_model_metadata_for_model_constrained_grant() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let agent_kp = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent_kp.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "test-srv".to_string(),
                    tool_name: "get_weather".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![Constraint::ModelConstraint {
                        allowed_model_ids: vec!["gpt-5".to_string()],
                        min_safety_tier: Some(ModelSafetyTier::High),
                    }],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            3600,
        )
        .expect("capability should issue");
    let execution = OpenAiExecutionContext {
        capability,
        agent_id: agent_kp.public_key().to_hex(),
        dpop_proof: None,
        execution_nonces: BTreeMap::new(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: Some(ModelMetadata {
            model_id: "gpt-5".to_string(),
            safety_tier: Some(ModelSafetyTier::High),
            provider: Some("openai".to_string()),
            provenance_class: chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
        }),
        supplemental_authorization: None,
        security_context: None,
    };

    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
    assert!(!result.denied);
    assert!(result.receipt.is_some());
}

#[test]
fn execute_tool_call_treats_pending_approval_as_denied() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let agent_kp = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent_kp.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "test-srv".to_string(),
                    tool_name: "get_weather".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![Constraint::RequireApprovalAbove {
                        threshold_units: 50,
                    }],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            3600,
        )
        .expect("capability should issue");
    let execution = OpenAiExecutionContext {
        capability,
        agent_id: agent_kp.public_key().to_hex(),
        dpop_proof: None,
        execution_nonces: BTreeMap::new(),
        governed_intent: Some(GovernedTransactionIntent::tool_invocation(
            GovernedToolInvocationIntentBody {
                id: "intent-openai-approval-1".to_string(),
                server_id: "test-srv".to_string(),
                tool_name: "get_weather".to_string(),
                purpose: "require human approval".to_string(),
                max_amount: Some(MonetaryAmount {
                    units: 100,
                    currency: "USD".to_string(),
                }),
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: None,
            },
        )),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        security_context: None,
    };

    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
    assert!(result.denied);
    assert!(result.content.contains("approval"));
    assert!(result.receipt.is_some());
    assert!(result.receipt_ref.is_some());
}

#[test]
fn execute_tool_call_fails_closed_on_nonce_preflight() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .unwrap();
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");

    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);

    assert!(result.denied);
    assert!(result.preflight);
    assert!(result.content.contains("execution nonce preflight"));
    assert!(result.content.contains("did not execute the tool"));
    assert!(result.execution_nonce.is_some());
    assert!(result.receipt_ref.is_some());
    assert!(result.receipt.is_some());
}

#[test]
fn execute_tool_call_unknown_function() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
    let call = OpenAiToolCall {
        id: "call_unknown".to_string(),
        call_type: "function".to_string(),
        function: OpenAiFunctionCall {
            name: "nonexistent".to_string(),
            arguments: "{}".to_string(),
        },
    };
    let result = adapter.execute_tool_call(&call, &kernel, &execution);
    assert!(result.denied);
    assert!(result.content.contains("not found"));
    assert!(result.receipt.is_none());
}

#[test]
fn execute_tool_call_invalid_arguments() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
    let call = OpenAiToolCall {
        id: "call_bad".to_string(),
        call_type: "function".to_string(),
        function: OpenAiFunctionCall {
            name: "get_weather".to_string(),
            arguments: "not valid json".to_string(),
        },
    };
    let result = adapter.execute_tool_call(&call, &kernel, &execution);
    assert!(result.denied);
    assert!(result.content.contains("parse arguments"));
    assert!(result.receipt.is_none());
}

#[test]
fn execute_tool_call_server_error() {
    let manifest = ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "fail-srv".to_string(),
        name: "Fail".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "fail".to_string(),
            description: "Fails".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: valid_test_public_key(),
    };
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![manifest]).unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(FailingServer));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "fail-srv", "fail");
    let call = OpenAiToolCall {
        id: "call_fail".to_string(),
        call_type: "function".to_string(),
        function: OpenAiFunctionCall {
            name: "fail".to_string(),
            arguments: "{}".to_string(),
        },
    };
    let result = adapter.execute_tool_call(&call, &kernel, &execution);
    assert!(result.denied);
    assert!(result.receipt_ref.is_some());
    assert!(result.receipt.is_some());
}

#[test]
fn execute_tool_call_generates_unique_receipts() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
    let r1 = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
    let r2 = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
    assert_ne!(r1.receipt_ref, r2.receipt_ref);
}

// ---- Batch execution tests ----

#[test]
fn execute_tool_calls_batch() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "*");
    let calls = vec![
        weather_tool_call(),
        OpenAiToolCall {
            id: "call_search".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "search".to_string(),
                arguments: r#"{"query": "test"}"#.to_string(),
            },
        },
    ];
    let results = adapter.execute_tool_calls(&calls, &kernel, &execution);
    assert_eq!(results.len(), 2);
    assert!(!results[0].denied);
    assert!(!results[1].denied);
    assert!(!results[0].preflight);
    assert!(!results[1].preflight);
}

#[test]
fn execute_tool_calls_rejects_one_security_snapshot_for_multiple_calls() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingToolServer {
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = Keypair::generate();
    let mut execution = test_execution_context(&kernel, &agent_kp, "test-srv", "*");
    execution.security_context = Some(SecurityInvocationContext::v1(
        chio_kernel::SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("tenant-openai-snapshot").unwrap(),
            chio_security_types::ports::SessionId::new("session-openai-snapshot").unwrap(),
            chio_security_types::PrincipalId::new(execution.agent_id.clone()).unwrap(),
            chio_security_types::ports::IsolationEpochId::new("epoch-openai-snapshot").unwrap(),
            chio_security_types::ports::LineageId::new(execution.capability.id.clone()).unwrap(),
            1,
        ),
    ));
    let calls = vec![
        weather_tool_call(),
        OpenAiToolCall {
            id: "call_search_snapshot".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "search".to_string(),
                arguments: r#"{"query": "test"}"#.to_string(),
            },
        },
    ];

    let results = adapter.execute_tool_calls(&calls, &kernel, &execution);

    assert!(results.iter().all(|result| result.denied));
    assert!(results.iter().all(|result| result
        .content
        .contains("must be resolved separately for each tool call")));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn authority_backed_openai_batch_resolves_each_dispatch_generation() {
    let registry = verified_test_registry();
    let adapter = ChioOpenAiAdapter::new(test_config(), &registry).unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "*");
    let authenticated_context = OperationContext::new(
        chio_core::session::SessionId::new("openai-authority-batch"),
        RequestId::new("openai-authority-template"),
        execution.agent_id.clone(),
    );
    let generations = Arc::new(Mutex::new(Vec::new()));
    let authority = IncrementingSecurityContextAuthority {
        generations: Arc::clone(&generations),
    };
    let calls = vec![
        weather_tool_call(),
        OpenAiToolCall {
            id: "call_search_authority".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "search".to_string(),
                arguments: r#"{"query": "test"}"#.to_string(),
            },
        },
    ];

    let results = adapter.execute_tool_calls_with_security_context_authority(
        &calls,
        &kernel,
        &execution,
        &authenticated_context,
        &authority,
    );

    assert!(results.iter().all(|result| !result.denied));
    assert_eq!(*generations.lock().unwrap(), vec![1, 2]);
}

#[test]
fn authority_backed_openai_batch_rejects_wrong_session_before_dispatch() {
    let registry = verified_test_registry();
    let adapter = ChioOpenAiAdapter::new(test_config(), &registry).unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingToolServer {
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "*");
    let authenticated_context = OperationContext::new(
        chio_core::session::SessionId::new("openai-authenticated-session"),
        RequestId::new("openai-wrong-session-template"),
        execution.agent_id.clone(),
    );

    let results = adapter.execute_tool_calls_with_security_context_authority(
        &[weather_tool_call()],
        &kernel,
        &execution,
        &authenticated_context,
        &WrongSessionSecurityContextAuthority,
    );

    assert_eq!(results.len(), 1);
    assert!(results[0].denied);
    assert!(results[0]
        .content
        .contains("authoritative security context does not match the authenticated session"));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn execute_tool_calls_uses_per_call_execution_nonces() {
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(test_server()));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .unwrap();
    let agent_kp = Keypair::generate();
    let mut execution = test_execution_context(&kernel, &agent_kp, "test-srv", "*");
    let calls = vec![
        weather_tool_call(),
        OpenAiToolCall {
            id: "call_search".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "search".to_string(),
                arguments: r#"{"query": "test"}"#.to_string(),
            },
        },
    ];

    for call in &calls {
        let (server_id, tool_name) = adapter
            .function_bindings
            .get(&call.function.name)
            .expect("fixture function is bound");
        let request = ToolCallRequest {
            request_id: format!("openai-{}", call.id),
            capability: execution.capability.clone(),
            tool_name: tool_name.clone(),
            server_id: server_id.clone(),
            agent_id: execution.agent_id.clone(),
            arguments: serde_json::from_str(&call.function.arguments).unwrap(),
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
        let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
        execution.execution_nonces.insert(
            call.id.clone(),
            *preflight
                .execution_nonce
                .expect("strict preflight returns a nonce"),
        );
    }

    let results = adapter.execute_tool_calls(&calls, &kernel, &execution);

    assert_eq!(results.len(), 2);
    assert!(!results[0].denied);
    assert!(!results[1].denied);
}

// ---- Message conversion tests ----

#[test]
fn results_to_messages_format() {
    let results = vec![ToolCallResult {
        tool_call_id: "call_123".to_string(),
        name: "get_weather".to_string(),
        content: "sunny".to_string(),
        denied: false,
        preflight: false,
        execution_nonce: None,
        receipt_ref: Some("receipt-1".to_string()),
        receipt: None,
    }];
    let messages = ChioOpenAiAdapter::results_to_messages(&results);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["role"], "tool");
    assert_eq!(messages[0]["tool_call_id"], "call_123");
    assert_eq!(messages[0]["content"], "sunny");
}

#[test]
fn results_to_messages_multiple() {
    let results = vec![
        ToolCallResult {
            tool_call_id: "c1".to_string(),
            name: "a".to_string(),
            content: "r1".to_string(),
            denied: false,
            preflight: false,
            execution_nonce: None,
            receipt_ref: None,
            receipt: None,
        },
        ToolCallResult {
            tool_call_id: "c2".to_string(),
            name: "b".to_string(),
            content: "r2".to_string(),
            denied: false,
            preflight: false,
            execution_nonce: None,
            receipt_ref: None,
            receipt: None,
        },
    ];
    let messages = ChioOpenAiAdapter::results_to_messages(&results);
    assert_eq!(messages.len(), 2);
}

// ---- Responses API conversion tests ----

#[test]
fn results_to_responses_api_format() {
    let results = vec![ToolCallResult {
        tool_call_id: "call_123".to_string(),
        name: "get_weather".to_string(),
        content: "sunny".to_string(),
        denied: false,
        preflight: false,
        execution_nonce: None,
        receipt_ref: Some("receipt-1".to_string()),
        receipt: None,
    }];
    let outputs = ChioOpenAiAdapter::results_to_responses_api(&results);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].output_type, "function_call_output");
    assert_eq!(outputs[0].call_id, "call_123");
    assert_eq!(outputs[0].output, "sunny");
}

// ---- Extract tool calls tests ----

#[test]
fn extract_tool_calls_from_chat_completions() {
    let message = json!({
        "role": "assistant",
        "tool_calls": [{
            "id": "call_abc",
            "type": "function",
            "function": {
                "name": "get_weather",
                "arguments": "{\"location\": \"NYC\"}"
            }
        }]
    });
    let calls = ChioOpenAiAdapter::extract_tool_calls(&message).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].function.name, "get_weather");
    assert_eq!(calls[0].id, "call_abc");
}

#[test]
fn extract_tool_calls_empty_when_no_calls() {
    let message = json!({"role": "assistant", "content": "hello"});
    let calls = ChioOpenAiAdapter::extract_tool_calls(&message).unwrap();
    assert!(calls.is_empty());
}

#[test]
fn extract_tool_calls_multiple() {
    let message = json!({
        "role": "assistant",
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "arguments": "{}"
                }
            },
            {
                "id": "call_2",
                "type": "function",
                "function": {
                    "name": "search",
                    "arguments": "{\"query\": \"test\"}"
                }
            }
        ]
    });
    let calls = ChioOpenAiAdapter::extract_tool_calls(&message).unwrap();
    assert_eq!(calls.len(), 2);
}

// ---- Responses API extraction tests ----

#[test]
fn extract_responses_api_calls() {
    let output = json!({
        "output": [
            {
                "type": "function_call",
                "call_id": "fc_123",
                "name": "get_weather",
                "arguments": "{\"location\": \"LA\"}"
            }
        ]
    });
    let calls = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].function.name, "get_weather");
    assert_eq!(calls[0].id, "fc_123");
}

#[test]
fn extract_responses_api_filters_non_function_calls() {
    let output = json!({
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "hello"}]
            },
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "search",
                "arguments": "{}"
            }
        ]
    });
    let calls = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].function.name, "search");
}

#[test]
fn extract_responses_api_empty_output() {
    let output = json!({"output": []});
    let calls = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap();
    assert!(calls.is_empty());
}

#[test]
fn extract_responses_api_rejects_missing_call_id() {
    let output = json!({
        "output": [
            {
                "type": "function_call",
                "name": "search",
                "arguments": "{}"
            }
        ]
    });

    let err = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap_err();
    assert!(err.to_string().contains("missing non-empty call_id"));
}

#[test]
fn extract_responses_api_rejects_malformed_function_call_in_mixed_output() {
    let output = json!({
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "hello"}]
            },
            {
                "type": "function_call",
                "call_id": "fc_valid",
                "name": "search",
                "arguments": "{}"
            },
            {
                "type": "function_call",
                "call_id": "fc_bad",
                "name": "",
                "arguments": "{}"
            }
        ]
    });

    let err = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap_err();
    assert!(err.to_string().contains("missing non-empty name"));
}

// ---- Deduplication tests ----

#[test]
fn duplicate_tools_across_manifests_deduplicated() {
    let m1 = test_manifest();
    let m2 = test_manifest();
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![m1, m2]).unwrap();
    assert_eq!(adapter.function_names().len(), 2);
}

// ---- Error display tests ----

#[test]
fn error_display_function_not_found() {
    let err = OpenAiAdapterError::FunctionNotFound("x".into());
    assert!(format!("{err}").contains("x"));
}

#[test]
fn error_display_invalid_request() {
    let err = OpenAiAdapterError::InvalidRequest("bad".into());
    assert!(format!("{err}").contains("bad"));
}

#[test]
fn error_display_kernel() {
    let err = OpenAiAdapterError::Kernel("denied".into());
    assert!(format!("{err}").contains("denied"));
}

// ---- Serde tests ----

#[test]
fn tool_call_result_serializes() {
    let result = ToolCallResult {
        tool_call_id: "call_1".to_string(),
        name: "test".to_string(),
        content: "ok".to_string(),
        denied: false,
        preflight: false,
        execution_nonce: None,
        receipt_ref: Some("receipt-1".to_string()),
        receipt: None,
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["tool_call_id"], "call_1");
    assert_eq!(json["denied"], false);
}

#[test]
fn tool_call_result_omits_receipt_ref_when_none() {
    let result = ToolCallResult {
        tool_call_id: "call_1".to_string(),
        name: "test".to_string(),
        content: "ok".to_string(),
        denied: false,
        preflight: false,
        execution_nonce: None,
        receipt_ref: None,
        receipt: None,
    };
    let json = serde_json::to_value(&result).unwrap();
    assert!(json.get("receipt_ref").is_none());
}

#[test]
fn openai_tool_def_roundtrips() {
    let def = OpenAiToolDef {
        tool_type: "function".to_string(),
        function: OpenAiFunctionDef {
            name: "test".to_string(),
            description: "A test function".to_string(),
            parameters: json!({"type": "object"}),
        },
    };
    let json = serde_json::to_value(&def).unwrap();
    let roundtripped: OpenAiToolDef = serde_json::from_value(json).unwrap();
    assert_eq!(roundtripped.function.name, "test");
}

#[test]
fn openai_function_call_roundtrips() {
    let call = OpenAiFunctionCall {
        name: "get_weather".to_string(),
        arguments: r#"{"location":"NYC"}"#.to_string(),
    };
    let json = serde_json::to_value(&call).unwrap();
    let roundtripped: OpenAiFunctionCall = serde_json::from_value(json).unwrap();
    assert_eq!(roundtripped.name, "get_weather");
}

// ---- String result handling ----

#[test]
fn execute_tool_call_with_string_result() {
    let server = MockToolServer {
        response: json!("hello world"),
    };
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(server));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
    assert_eq!(result.content, "hello world");
}

#[test]
fn execute_tool_call_with_object_result() {
    let server = MockToolServer {
        response: json!({"temp": 72}),
    };
    let adapter =
        ChioOpenAiAdapter::new_from_unverified_internal(test_config(), vec![test_manifest()])
            .unwrap();
    let mut kernel = ChioKernel::new(test_kernel_config());
    kernel.register_tool_server(Box::new(server));
    let agent_kp = Keypair::generate();
    let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
    let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
    assert!(result.content.contains("72"));
}
