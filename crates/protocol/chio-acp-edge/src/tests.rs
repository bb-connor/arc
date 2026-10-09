use crate::bridge::{
    current_unix_timestamp, execute_orchestrated_acp_request, AcpRequestIds, CapabilityBinding,
};
use crate::edge::validate_execution_context;
use crate::error::AcpEdgeError;
use crate::metrics::{render_acp_edge_metrics_prometheus, CHIO_RECEIPT_WRITE_TOTAL};
use crate::request_error::AcpRequestError;
use crate::types::AcpTaskStatus;
use crate::{AcpEdgeConfig, AcpKernelExecutionContext, ChioAcpEdge};
use chio_core::capability::token::CapabilityToken;
use chio_cross_protocol::discovery::DiscoveryProtocol;
use chio_cross_protocol::error::BridgeError;
use chio_cross_protocol::semantic_hints::BridgeFidelity;
use chio_manifest::{
    BridgeSecurityMetadata, ToolDefinition, ToolManifest, VerifiedManifestRegistry,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[path = "../../../../tests/bindings/support/authorization_projection.rs"]
mod authorization_projection;

fn test_registry_from_unverified_manifests(
    manifests: &[ToolManifest],
) -> Result<VerifiedManifestRegistry, AcpEdgeError> {
    let mut registry = VerifiedManifestRegistry::default();
    for manifest in manifests {
        let signer = (0..=u8::MAX)
            .map(|seed| chio_core::crypto::Keypair::from_seed(&[seed; 32]))
            .find(|candidate| candidate.public_key().to_hex() == manifest.public_key)
            .ok_or_else(|| AcpEdgeError::InvalidRequest(AcpRequestError::UnsupportedTarget))?;
        let signed = chio_manifest::sign_manifest(manifest, &signer)?;
        registry
            .register_public_only(
                signed,
                &signer.public_key(),
                chio_manifest::RuntimeToolTopology::local(),
            )
            .map_err(AcpEdgeError::Admission)?;
    }
    Ok(registry)
}

pub(super) fn new_test_edge(
    config: AcpEdgeConfig,
    manifests: Vec<ToolManifest>,
) -> Result<ChioAcpEdge, AcpEdgeError> {
    ChioAcpEdge::new(
        config,
        &test_registry_from_unverified_manifests(&manifests)?,
    )
}
fn kernel_execution(
    server: Box<dyn ToolServerConnection>,
    server_id: &str,
    tool: &str,
) -> (ChioKernel, AcpKernelExecutionContext) {
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let subject = Keypair::generate();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(server);
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, server_id, tool),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    (kernel, execution)
}

fn authorization_context(request: &chio_kernel::ToolCallRequest) -> AcpKernelExecutionContext {
    AcpKernelExecutionContext {
        capability: request.capability.clone(),
        agent_id: request.agent_id.clone(),
        dpop_proof: request.dpop_proof.clone(),
        execution_nonce: request.execution_nonce.clone(),
        governed_intent: request.governed_intent.clone(),
        approval_token: request.approval_token.clone(),
        approval_tokens: request.approval_tokens.clone(),
        threshold_approval_proposal: request.threshold_approval_proposal.clone(),
        supplemental_authorization: request.supplemental_authorization.clone(),
        model_metadata: request.model_metadata.clone(),
    }
}

#[test]
fn deferred_failure_is_terminal_and_retains_the_same_local_cause() {
    use std::error::Error;
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(
        Box::new(MockToolServer {
            server_id: "streaming-srv".into(),
            tools: vec!["search_stream".into()],
            response: json!({"ok": true}),
        }),
        "streaming-srv",
        "search_stream",
    );
    let task = edge
        .start_stream_task("search_stream", json!({}), &execution, &kernel)
        .test_unwrap();
    edge.tasks
        .borrow_mut()
        .get_mut(&task.id)
        .test_unwrap()
        .request
        .target_server_id = "private_missing_server".into();
    let first = edge
        .resume_stream_task(&task.id, &kernel, &execution)
        .test_unwrap_err();
    let AcpEdgeError::Deferred(first) = first else {
        panic!("deferred cause was lost")
    };
    assert!(first.source().is_some());
    assert_eq!(
        edge.tasks.borrow()[&task.id].task.status,
        AcpTaskStatus::Failed
    );
    // Restoring a valid target cannot make a failed task execute again.
    edge.tasks
        .borrow_mut()
        .get_mut(&task.id)
        .test_unwrap()
        .request
        .target_server_id = "streaming-srv".into();
    let second = edge
        .resume_stream_task(&task.id, &kernel, &execution)
        .test_unwrap_err();
    let AcpEdgeError::Deferred(second) = second else {
        panic!("failure was not retained")
    };
    assert!(std::sync::Arc::ptr_eq(&first, &second));
    assert!(!format!("{second:?} {second}").contains("private_missing_server"));
}

#[test]
fn acp_execution_request_preserves_complete_authorization_context() {
    let expected = authorization_projection::complete_wire_request();
    let execution = authorization_context(&expected);
    validate_execution_context(
        &execution,
        &chio_mcp_edge::authorization::authorization_capabilities(),
    )
    .test_unwrap();
    let projected = ChioAcpEdge::build_execution_request(
        &expected.tool_name,
        expected.arguments.clone(),
        &execution,
        &CapabilityBinding {
            target_protocol: DiscoveryProtocol::Native,
            server_id: expected.server_id.clone(),
            tool_name: expected.tool_name.clone(),
            security: BridgeSecurityMetadata::unconstrained(),
        },
        DiscoveryProtocol::Native,
        AcpRequestIds {
            origin_request_id: "wire-origin".to_string(),
            kernel_request_id: expected.request_id.clone(),
        },
    )
    .test_unwrap();
    authorization_projection::assert_authorization_preserved(
        &expected,
        &chio_cross_protocol::execution::kernel_tool_call_request(&projected),
    );
}

#[test]
fn acp_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    kernel.register_tool_server(Box::new(authorization_projection::CountedToolServer {
        server: "test-srv".to_string(),
        tool: "read_file".to_string(),
        calls: calls.clone(),
    }));
    let baseline: chio_kernel::ToolCallRequest = serde_json::from_value(json!({
        "request_id":"ordinary-positive", "capability":capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        "agent_id":subject.public_key().to_hex(), "server_id":"test-srv", "tool_name":"read_file", "arguments":{}
    })).test_unwrap();
    let positive = edge
        .invoke_with_request_id(
            &baseline.request_id,
            "read_file",
            json!({}),
            &kernel,
            &authorization_context(&baseline),
        )
        .test_unwrap();
    assert!(positive.success, "{positive:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let receipts = kernel.receipt_log().receipts().len();
    for (feature, request) in authorization_projection::extension_cases(&baseline) {
        let error = edge
            .invoke_with_request_id(
                &request.request_id,
                "read_file",
                json!({
                    "chioAuthorization":chio_mcp_edge::authorization::authorization_capabilities()
                }),
                &kernel,
                &authorization_context(&request),
            )
            .test_unwrap_err();
        assert!(
            std::error::Error::source(&error)
                .test_expect("local feature cause")
                .to_string()
                .contains(&format!("invocation feature {feature} was not negotiated")),
            "{error}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(kernel.receipt_log().receipts().len(), receipts);
    }
}
use chio_test_support::prelude::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, MutexGuard,
};

use chio_core::capability::{
    governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        ThresholdApprovalProposal, ThresholdApprovalProposalBody,
        THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
    },
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityTokenBody,
};
use chio_core::crypto::Keypair;
use chio_kernel::{
    dpop, ChioKernel, KernelConfig, KernelError, NestedFlowBridge, RuntimeAdmissionContext,
    RuntimeAdmissionDecision, RuntimeAdmissionHook, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::LatencyHint;
static METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());
fn metrics_test_guard() -> MutexGuard<'static, ()> {
    match METRICS_TEST_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn manifest_public_key(seed: u8) -> String {
    Keypair::from_seed(&[seed; 32]).public_key().to_hex()
}

struct MockToolServer {
    server_id: String,
    tools: Vec<String>,
    response: Value,
}

#[async_trait::async_trait]
impl ToolServerConnection for MockToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
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

struct FailingToolServer;

#[async_trait::async_trait]
impl ToolServerConnection for FailingToolServer {
    fn server_id(&self) -> &str {
        "fail-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["fail_tool".to_string()]
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
    calls: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingToolServer {
    fn server_id(&self) -> &str {
        "streaming-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["search_stream".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"content": [{"text": "should-not-run"}]}))
    }
}

struct DenyingAcpRuntimeAdmissionHook {
    calls: Arc<AtomicU64>,
}

impl RuntimeAdmissionHook for DenyingAcpRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "acp-denying-runtime-admission"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::deny(
            "acp runtime admission denied",
            Some(json!({
                "chio_runtime": {
                    "accepted": false,
                    "failure_code": "acp_runtime_admission_denied"
                }
            })),
        ))
    }
}

pub(super) fn test_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "test-srv".to_string(),
        name: "Test Server".to_string(),
        description: Some("Test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![
            ToolDefinition {
                name: "read_file".to_string(),
                description: "Read a file".to_string(),
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
            },
            ToolDefinition {
                name: "write_file".to_string(),
                description: "Write a file".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: false,
                    destructive: true,
                    idempotent: false,
                    requires_approval: true,
                },
                latency_hint: None,
                flow: None,
            },
            ToolDefinition {
                name: "exec_command".to_string(),
                description: "Execute a shell command".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: false,
                    destructive: true,
                    idempotent: false,
                    requires_approval: true,
                },
                latency_hint: None,
                flow: None,
            },
            ToolDefinition {
                name: "search".to_string(),
                description: "Search documents".to_string(),
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
            },
        ],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(1),
    }
}

fn nontrivial_registry_flow() -> chio_manifest::ToolFlowDeclaration {
    serde_json::from_value(json!({
        "output_label": {
            "kind": "known",
            "owners": {},
            "compartments": ["audit", "pii"]
        },
        "input_clearance": {
            "kind": "known",
            "owners": {},
            "compartments": ["customer", "restricted"]
        },
        "egress": true,
        "declassification_purposes": ["audit", "support"]
    }))
    .test_unwrap()
}

fn registry_with_nontrivial_flow() -> (VerifiedManifestRegistry, chio_manifest::ToolFlowDeclaration)
{
    let signer = Keypair::from_seed(&[1; 32]);
    let flow = nontrivial_registry_flow();
    let mut manifest = test_manifest();
    manifest.tools[0].flow = Some(flow.clone());
    let signed = chio_manifest::sign_manifest(&manifest, &signer).test_unwrap();
    let flow_policy = chio_manifest::AuthoritativeToolPolicy::new(
        vec![flow
            .input_clearance
            .clone()
            .test_expect("flow fixture input clearance")],
        flow.output_label
            .clone()
            .test_expect("flow fixture output label"),
        flow.declassification_purposes.clone(),
    )
    .test_unwrap();
    let policies = BTreeMap::from([
        ("read_file".to_string(), flow_policy),
        (
            "write_file".to_string(),
            chio_manifest::AuthoritativeToolPolicy::public_only(),
        ),
        (
            "exec_command".to_string(),
            chio_manifest::AuthoritativeToolPolicy::public_only(),
        ),
        (
            "search".to_string(),
            chio_manifest::AuthoritativeToolPolicy::public_only(),
        ),
    ]);
    let topologies = BTreeMap::from([
        (
            "read_file".to_string(),
            chio_manifest::RuntimeToolTopology::remote(),
        ),
        (
            "write_file".to_string(),
            chio_manifest::RuntimeToolTopology::remote(),
        ),
        (
            "exec_command".to_string(),
            chio_manifest::RuntimeToolTopology::remote(),
        ),
        (
            "search".to_string(),
            chio_manifest::RuntimeToolTopology::remote(),
        ),
    ]);
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(signed, &signer.public_key(), &policies, &topologies)
        .test_unwrap();
    (registry, flow)
}

fn browser_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "browser-srv".to_string(),
        name: "Browser Server".to_string(),
        description: Some("Browser test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "browser_navigate".to_string(),
            description: "Navigate browser".to_string(),
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
        public_key: manifest_public_key(2),
    }
}

fn generic_side_effect_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "tool-srv".to_string(),
        name: "Generic Tool Server".to_string(),
        description: Some("Generic side effect test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "mutate_records".to_string(),
            description: "Mutate records".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: false,
                destructive: true,
                idempotent: false,
                requires_approval: true,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(3),
    }
}

fn approval_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "approval-srv".to_string(),
        name: "Approval Server".to_string(),
        description: Some("Approval test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "read_secret".to_string(),
            description: "Read secret".to_string(),
            input_schema: json!({
                "type": "object",
                "x-chio-approval-required": true
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
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(4),
    }
}

fn streaming_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "streaming-srv".to_string(),
        name: "Streaming Server".to_string(),
        description: Some("Streaming test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "search_stream".to_string(),
            description: "Stream search results".to_string(),
            input_schema: json!({
                "type": "object",
                "x-chio-streaming": true,
                "x-chio-partial-output": true,
                "x-chio-cancellation": true
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
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(5),
    }
}

fn mcp_target_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "test-srv".to_string(),
        name: "MCP Target Server".to_string(),
        description: Some("MCP target binding".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "read_file".to_string(),
            description: "Read file via MCP target executor".to_string(),
            input_schema: json!({
                "type": "object",
                "x-chio-target-protocol": "mcp"
            }),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: Some(LatencyHint::Fast),
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(6),
    }
}

fn openai_target_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "test-srv".to_string(),
        name: "OpenAI Target Server".to_string(),
        description: Some("OpenAI target binding".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "read_file".to_string(),
            description: "Read file via OpenAI target executor".to_string(),
            input_schema: json!({
                "type": "object",
                "x-chio-target-protocol": "open_ai"
            }),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: Some(LatencyHint::Fast),
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(7),
    }
}

fn invalid_target_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "test-srv".to_string(),
        name: "Invalid Target Server".to_string(),
        description: Some("Invalid protocol binding".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "read_file".to_string(),
            description: "Invalid binding".to_string(),
            input_schema: json!({
                "type": "object",
                "x-chio-target-protocol": "smtp"
            }),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: Some(LatencyHint::Fast),
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(8),
    }
}

fn hidden_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "hidden-srv".to_string(),
        name: "Hidden Server".to_string(),
        description: Some("Hidden test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "hidden_tool".to_string(),
            description: "Hidden tool".to_string(),
            input_schema: json!({
                "type": "object",
                "x-chio-publish": false
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
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(9),
    }
}

fn colliding_search_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "other-srv".to_string(),
        name: "Other Search Server".to_string(),
        description: Some("Collision test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "search".to_string(),
            description: "Search somewhere else".to_string(),
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
        public_key: manifest_public_key(10),
    }
}

fn test_server() -> MockToolServer {
    MockToolServer {
        server_id: "test-srv".to_string(),
        tools: vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "exec_command".to_string(),
            "search".to_string(),
        ],
        response: json!({"result": "ok"}),
    }
}

pub(super) fn test_kernel_config() -> KernelConfig {
    let keypair = Keypair::generate();
    KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 8,
        policy_hash: "policy-acp-test".to_string(),
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
    }
}

pub(super) fn capability_for_tool(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    tool_name: &str,
) -> chio_core::capability::token::CapabilityToken {
    capability_for_tool_with_dpop_requirement(issuer, subject, server_id, tool_name, None)
}

fn capability_for_tool_with_dpop_requirement(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    tool_name: &str,
    dpop_required: Option<bool>,
) -> chio_core::capability::token::CapabilityToken {
    let now = current_unix_timestamp();
    chio_core::capability::token::CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("cap-{server_id}-{tool_name}"),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.to_string(),
                    tool_name: tool_name.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: now.saturating_sub(30),
            expires_at: now + 300,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .test_expect("capability should sign")
}

pub(super) fn threshold_artifacts(
    subject: &Keypair,
    request_id: &str,
) -> (Vec<GovernedApprovalToken>, ThresholdApprovalProposal) {
    let policy_authority = Keypair::generate();
    let approvers = [Keypair::generate(), Keypair::generate()];
    let intent_hash = "a".repeat(64);
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: format!("proposal-{request_id}"),
            request_id: request_id.to_string(),
            governed_intent_hash: intent_hash.clone(),
            subject: subject.public_key(),
            authorizing_capability_digest: "b".repeat(64),
            policy_hash: "c".repeat(64),
            threshold: 2,
            eligible_set_digest: "d".repeat(64),
            proposal_created_at: 100,
            proposal_deadline: 200,
            policy_authority: policy_authority.public_key(),
        },
        &policy_authority,
    )
    .test_expect("threshold proposal should sign");
    let proposal_hash = proposal
        .artifact_digest()
        .test_expect("threshold proposal should hash");
    let approvals = approvers
        .iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("approval-{request_id}-{index}"),
                    approver: approver.public_key(),
                    subject: subject.public_key(),
                    governed_intent_hash: intent_hash.clone(),
                    request_id: request_id.to_string(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    issued_at: 100,
                    expires_at: 200,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .test_expect("approval should sign")
        })
        .collect();
    (approvals, proposal)
}

#[test]
fn acp_projection_preserves_complete_approval_set_and_opaque_extension() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_for_tool(&issuer, &subject, "srv", "run");
    let (approvals, proposal) = threshold_artifacts(&subject, "acp-auth-set");
    let supplemental =
        chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
            signed_extension: "opaque-acp-extension".to_string(),
        };
    let execution = AcpKernelExecutionContext {
        capability,
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: approvals.clone(),
        threshold_approval_proposal: Some(proposal.clone()),
        supplemental_authorization: Some(supplemental.clone()),
        model_metadata: None,
    };
    let projected = ChioAcpEdge::build_execution_request(
        "run",
        serde_json::json!({"value": 7}),
        &execution,
        &CapabilityBinding {
            target_protocol: DiscoveryProtocol::Native,
            server_id: "srv".to_string(),
            tool_name: "run".to_string(),
            security: BridgeSecurityMetadata::unconstrained(),
        },
        DiscoveryProtocol::Native,
        AcpRequestIds {
            origin_request_id: "acp-auth-set".to_string(),
            kernel_request_id: "acp-auth-set".to_string(),
        },
    )
    .test_expect("ACP request should project");

    assert_eq!(projected.approval_tokens, approvals);
    assert_eq!(projected.threshold_approval_proposal, Some(proposal));
    assert_eq!(projected.supplemental_authorization, Some(supplemental));
    assert_eq!(projected.kernel_request_id, "acp-auth-set");
}

#[test]
fn registry_admitted_flow_survives_acp_execution_projection_canonically() {
    let (registry, expected_flow) = registry_with_nontrivial_flow();
    let edge = ChioAcpEdge::new_with_registry(AcpEdgeConfig::default(), &registry).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let binding = edge.capability_binding("read_file").test_unwrap();
    let request = ChioAcpEdge::build_execution_request(
        "read_file",
        json!({"path":"/tmp/preserve-flow"}),
        &execution,
        &binding,
        binding.target_protocol,
        AcpRequestIds {
            origin_request_id: "acp-flow-origin".to_string(),
            kernel_request_id: "acp-flow-kernel".to_string(),
        },
    )
    .test_unwrap();
    let projected_flow = request
        .bridge_security
        .flow()
        .test_expect("registry-admitted ACP binding must retain flow");

    assert_eq!(
        chio_core::canonical_json_bytes(projected_flow).test_unwrap(),
        chio_core::canonical_json_bytes(&expected_flow).test_unwrap()
    );
    assert!(request.bridge_security.has_registry_coordinates());
    assert!(request.bridge_security.effective_egress());
    assert_eq!(projected_flow.declassification_purposes.len(), 2);
}

#[test]
fn acp_execution_boundary_rejects_removed_or_mismatched_flow_sidecar() {
    let (registry, _) = registry_with_nontrivial_flow();
    let edge = ChioAcpEdge::new_with_registry(AcpEdgeConfig::default(), &registry).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let binding = edge.capability_binding("read_file").test_unwrap();
    let request = ChioAcpEdge::build_execution_request(
        "read_file",
        json!({"path":"/tmp/reject-flow-drift"}),
        &execution,
        &binding,
        binding.target_protocol,
        AcpRequestIds {
            origin_request_id: "acp-flow-reject-origin".to_string(),
            kernel_request_id: "acp-flow-reject-kernel".to_string(),
        },
    )
    .test_unwrap();

    let runtime_error =
        execute_orchestrated_acp_request(&Default::default(), &kernel, &registry, request.clone())
            .test_expect_err("flow-required ACP registry must reject an unprotected kernel");
    assert!(matches!(
        runtime_error,
        AcpEdgeError::Bridge(BridgeError::Kernel(KernelError::FlowRuntimeUnavailable))
    ));

    let mut removed = request.clone();
    removed.bridge_security = BridgeSecurityMetadata::unconstrained();
    let removed_error =
        execute_orchestrated_acp_request(&Default::default(), &kernel, &registry, removed)
            .test_expect_err("removed ACP flow sidecar must fail before dispatch");
    assert!(std::error::Error::source(&removed_error)
        .test_expect("local bridge cause")
        .to_string()
        .contains("bridge security does not match live registry entry for test-srv/read_file"));

    let mut mismatched = request;
    mismatched.target_tool_name = "different-tool".to_string();
    let mismatch_error =
        execute_orchestrated_acp_request(&Default::default(), &kernel, &registry, mismatched)
            .test_expect_err("mismatched ACP flow sidecar must fail before dispatch");
    assert!(std::error::Error::source(&mismatch_error)
        .test_expect("local bridge cause")
        .to_string()
        .contains(
            "bridge security does not match live registry entry for test-srv/different-tool"
        ));
}

fn dpop_proof_for_request(
    agent: &Keypair,
    capability: &CapabilityToken,
    server_id: &str,
    tool_name: &str,
    arguments: &Value,
    nonce: &str,
) -> dpop::DpopProof {
    dpop_proof_for_request_issued_at(
        agent,
        capability,
        server_id,
        tool_name,
        arguments,
        nonce,
        current_unix_timestamp(),
    )
}

fn dpop_proof_for_request_issued_at(
    agent: &Keypair,
    capability: &CapabilityToken,
    server_id: &str,
    tool_name: &str,
    arguments: &Value,
    nonce: &str,
    issued_at: u64,
) -> dpop::DpopProof {
    let args_bytes = chio_core::canonical::canonical_json_bytes(arguments)
        .test_expect("arguments should serialize to canonical JSON");
    let action_hash = chio_core::crypto::sha256_hex(&args_bytes);
    let body = dpop::DpopProofBody {
        replay_authority: None,
        schema: dpop::DPOP_SCHEMA.to_string(),
        capability_id: capability.id.clone(),
        tool_server: server_id.to_string(),
        tool_name: tool_name.to_string(),
        action_hash,
        nonce: nonce.to_string(),
        issued_at,
        agent_key: agent.public_key(),
    };
    dpop::DpopProof::sign(body, agent).test_expect("DPoP proof should sign")
}

fn assert_receipt_write_prometheus_sample_at_least(outcome: &str, minimum: u64) {
    let body = render_acp_edge_metrics_prometheus(chio_kernel::ReceiptWriterLiveness::Healthy);
    let prefix = format!("{CHIO_RECEIPT_WRITE_TOTAL}{{outcome=\"{outcome}\"}} ");
    let sample = body
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .test_expect("Prometheus sample should exist")
        .parse::<u64>()
        .test_expect("Prometheus sample should be an integer");
    assert!(
        sample >= minimum,
        "Prometheus sample for {outcome} must include the pending projection counter"
    );
}

// ---- Capability generation tests ----

#[test]
fn edge_rejects_manifest_with_unsupported_schema_version() {
    let mut manifest = test_manifest();
    manifest.schema = "chio.manifest.v0".to_string();
    manifest.public_key = manifest_public_key(99);

    let error = match new_test_edge(AcpEdgeConfig::default(), vec![manifest]) {
        Ok(_) => panic!("ACP edge must reject unsupported manifest schema versions"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        AcpEdgeError::Manifest(chio_manifest::ManifestError::UnsupportedSchema(schema))
            if schema == "chio.manifest.v0"
    ));
}

#[test]
fn edge_generates_capabilities_from_manifest() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    assert_eq!(edge.capabilities().len(), 4);
}

#[test]
fn edge_capability_ids_match_tool_names() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let ids = edge.capability_ids();
    assert!(ids.contains(&"read_file".to_string()));
    assert!(ids.contains(&"write_file".to_string()));
    assert!(ids.contains(&"exec_command".to_string()));
    assert!(ids.contains(&"search".to_string()));
}

#[test]
fn edge_capability_lookup() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("read_file").test_unwrap();
    assert_eq!(cap.description, "Read a file");
}

#[test]
fn edge_unknown_capability_returns_none() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    assert!(edge.capability("nonexistent").is_none());
}

// ---- BridgeFidelity tests ----

#[test]
fn filesystem_tools_have_lossless_fidelity() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("read_file").test_unwrap();
    assert_eq!(cap.bridge_fidelity, BridgeFidelity::Lossless);
}

#[test]
fn terminal_tools_have_lossless_fidelity() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("exec_command").test_unwrap();
    assert_eq!(cap.bridge_fidelity, BridgeFidelity::Lossless);
}

#[test]
fn generic_readonly_tool_is_adapted_with_category_caveat() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let cap = edge.capability("search").test_unwrap();
    let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
        panic!("expected adapted fidelity");
    };
    assert!(caveats
        .iter()
        .any(|c| c.contains("tool category") || c.contains("native ACP primitive")));
}

#[test]
fn browser_tools_are_not_auto_published() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![browser_manifest()]).test_unwrap();
    assert!(edge.capability("browser_navigate").is_none());
    assert_eq!(
        edge.bridge_fidelity("browser_navigate"),
        Some(&BridgeFidelity::Unsupported {
            reason: "browser/session automation semantics are not yet truthfully projected on the ACP edge".to_string()
        })
    );
}

#[test]
fn generic_side_effectful_tools_are_not_auto_published() {
    let edge = new_test_edge(
        AcpEdgeConfig::default(),
        vec![generic_side_effect_manifest()],
    )
    .test_unwrap();
    assert!(edge.capability("mutate_records").is_none());
    assert_eq!(
        edge.bridge_fidelity("mutate_records"),
        Some(&BridgeFidelity::Unsupported {
            reason: "generic side-effectful tools do not map honestly to ACP capability classes on this edge".to_string()
        })
    );
}

#[test]
fn approval_required_capability_is_adapted_with_permission_caveat() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![approval_manifest()]).test_unwrap();
    let cap = edge.capability("read_secret").test_unwrap();
    let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
        panic!("expected adapted fidelity");
    };
    assert!(caveats
        .iter()
        .any(|c| c.contains("permission preview is advisory")));
}

#[test]
fn streaming_capability_is_adapted_with_stream_and_cancellation_caveats() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
    let cap = edge.capability("search_stream").test_unwrap();
    let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
        panic!("expected adapted fidelity");
    };
    assert!(caveats
        .iter()
        .any(|c| c.contains("deferred `tool/stream` tasks")));
    assert!(caveats
        .iter()
        .any(|c| c.contains("partial output is preserved")));
    assert!(caveats
        .iter()
        .any(|c| c.contains("cancellation is available")));
}

#[test]
fn hidden_capability_is_not_auto_published() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![hidden_manifest()]).test_unwrap();
    assert!(edge.capability("hidden_tool").is_none());
    assert_eq!(
        edge.bridge_fidelity("hidden_tool"),
        Some(&BridgeFidelity::Unsupported {
            reason: "publication disabled by x-chio-publish=false".to_string()
        })
    );
}

mod config_and_serde;
mod document_input;
mod invocation;
mod jsonrpc;
mod nonce_preflight;
mod original_input;
mod permissions;
