use crate::bridge::{execute_orchestrated_a2a_request, SkillBinding};
use crate::config::A2aEdgeConfig;
use crate::edge::{validate_execution_context, ChioA2aEdge};
use crate::error::A2aEdgeError;
use crate::metrics::{render_a2a_edge_metrics_prometheus, CHIO_RECEIPT_WRITE_TOTAL};
use crate::types::{
    A2aKernelExecutionContext, A2aMessage, A2aPart, SendMessageRequest, TaskStatus,
};
use chio_cross_protocol::discovery::DiscoveryProtocol;
use chio_cross_protocol::error::BridgeError;
use chio_kernel::ToolServerConnection;
use chio_manifest::{
    BridgeSecurityMetadata, ToolDefinition, ToolManifest, VerifiedManifestRegistry,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[path = "../../../../tests/bindings/support/authorization_projection.rs"]
pub(super) mod authorization_projection;

fn authorization_context(request: &chio_kernel::ToolCallRequest) -> A2aKernelExecutionContext {
    A2aKernelExecutionContext {
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
fn a2a_execution_request_preserves_complete_authorization_context() {
    let expected = authorization_projection::complete_wire_request();
    let execution = authorization_context(&expected);
    validate_execution_context(
        &execution,
        &chio_mcp_edge::authorization::authorization_capabilities(),
    )
    .test_unwrap();
    let source = SendMessageRequest {
        message: A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: expected.arguments.clone(),
            }],
            metadata: None,
        },
        metadata: None,
    };
    let projected = ChioA2aEdge::build_execution_request(
        SkillBinding {
            target_protocol: DiscoveryProtocol::Native,
            server_id: expected.server_id.clone(),
            tool_name: expected.tool_name.clone(),
            security: BridgeSecurityMetadata::unconstrained(),
        },
        &expected.tool_name,
        &source,
        expected.arguments.clone(),
        &execution,
        "wire-origin".to_string(),
        expected.request_id.clone(),
    )
    .test_unwrap();
    authorization_projection::assert_authorization_preserved(
        &expected,
        &chio_cross_protocol::execution::kernel_tool_call_request(&projected),
    );
}

#[test]
fn a2a_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    kernel.register_tool_server(Box::new(authorization_projection::CountedToolServer {
        server: "test-srv".to_string(),
        tool: "echo".to_string(),
        calls: calls.clone(),
    }));
    let baseline: chio_kernel::ToolCallRequest = serde_json::from_value(json!({
        "request_id":"ordinary-positive", "capability":capability_for_tool(&issuer, &subject, "test-srv", "echo"),
        "agent_id":subject.public_key().to_hex(), "server_id":"test-srv", "tool_name":"echo", "arguments":{}
    })).test_unwrap();
    let source = SendMessageRequest {
        message: A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data { data: json!({}) }],
            metadata: None,
        },
        metadata: Some(
            json!({"chioAuthorization":chio_mcp_edge::authorization::authorization_capabilities()}),
        ),
    };
    let positive = edge
        .handle_send_message_with_request_id(
            &baseline.request_id,
            "echo",
            &source,
            &kernel,
            &authorization_context(&baseline),
        )
        .test_unwrap();
    assert_eq!(positive.status, TaskStatus::Completed);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let receipts = kernel.receipt_log().receipts().len();
    for (feature, request) in authorization_projection::extension_cases(&baseline) {
        let error = edge
            .handle_send_message_with_request_id(
                &request.request_id,
                "echo",
                &source,
                &kernel,
                &authorization_context(&request),
            )
            .test_unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("invocation feature {feature} was not negotiated")),
            "{error}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(kernel.receipt_log().receipts().len(), receipts);
    }
}
use chio_test_support::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

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
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, RuntimeAdmissionContext,
    RuntimeAdmissionDecision, RuntimeAdmissionHook, ToolCallChunk, ToolCallStream,
    ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
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

struct StreamingToolServer;

#[async_trait::async_trait]
impl ToolServerConnection for StreamingToolServer {
    fn server_id(&self) -> &str {
        "stream-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["stream".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({"result": "fallback"}))
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![
                ToolCallChunk {
                    data: json!("chunk-1"),
                },
                ToolCallChunk {
                    data: json!({"content": [{"type": "text", "text": "chunk-2"}]}),
                },
            ],
        })))
    }
}

struct CountingStreamingToolServer {
    invocations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingStreamingToolServer {
    fn server_id(&self) -> &str {
        "stream-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["stream".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"result": "fallback"}))
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![ToolCallChunk {
                data: json!("should-not-dispatch"),
            }],
        })))
    }
}

struct DenyingRuntimeAdmissionHook;

impl RuntimeAdmissionHook for DenyingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "a2a-edge-denying-runtime-admission"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Ok(RuntimeAdmissionDecision::deny(
            "a2a edge runtime admission denied",
            Some(json!({
                "chio_runtime": {
                    "accepted": false,
                    "failure_code": "a2a_edge_runtime_admission_denied"
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
                name: "echo".to_string(),
                description: "Echo input".to_string(),
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
                name: "write".to_string(),
                description: "Write data".to_string(),
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
        ],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(1),
    }
}

fn test_server() -> MockToolServer {
    MockToolServer {
        server_id: "test-srv".to_string(),
        tools: vec!["echo".to_string(), "write".to_string()],
        response: json!({"result": "ok"}),
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
        ("echo".to_string(), flow_policy),
        (
            "write".to_string(),
            chio_manifest::AuthoritativeToolPolicy::public_only(),
        ),
    ]);
    let topologies = BTreeMap::from([
        (
            "echo".to_string(),
            chio_manifest::RuntimeToolTopology::remote(),
        ),
        (
            "write".to_string(),
            chio_manifest::RuntimeToolTopology::remote(),
        ),
    ]);
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(signed, &signer.public_key(), &policies, &topologies)
        .test_unwrap();
    (registry, flow)
}

fn stream_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "stream-srv".to_string(),
        name: "Stream Server".to_string(),
        description: Some("Streaming test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "stream".to_string(),
            description: "Stream output".to_string(),
            input_schema: json!({
                "type": "object",
                "x-chio-streaming": true,
                "x-chio-partial-output": true
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
        public_key: manifest_public_key(2),
    }
}

fn approval_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "approve-srv".to_string(),
        name: "Approval Server".to_string(),
        description: Some("Approval test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "approve".to_string(),
            description: "Approval-gated operation".to_string(),
            input_schema: json!({
                "type": "object",
                "x-chio-approval-required": true
            }),
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

fn cancellation_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "cancel-srv".to_string(),
        name: "Cancellation Server".to_string(),
        description: Some("Cancel test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "cancel_me".to_string(),
            description: "Requires cancellation".to_string(),
            input_schema: json!({
                "type": "object",
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
        public_key: manifest_public_key(4),
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
            name: "echo".to_string(),
            description: "Echo via MCP target executor".to_string(),
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
        public_key: manifest_public_key(5),
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
            name: "echo".to_string(),
            description: "Echo via OpenAI target executor".to_string(),
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
        public_key: manifest_public_key(6),
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
            name: "echo".to_string(),
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
        public_key: manifest_public_key(7),
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
            name: "hidden".to_string(),
            description: "Hidden from publication".to_string(),
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
        public_key: manifest_public_key(8),
    }
}

pub(super) fn text_message(text: &str) -> SendMessageRequest {
    SendMessageRequest {
        message: A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Text {
                text: text.to_string(),
            }],
            metadata: None,
        },
        metadata: None,
    }
}

pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system time should be after unix epoch")
        .as_secs()
}

pub(super) fn test_kernel_config() -> KernelConfig {
    let keypair = Keypair::generate();
    KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 8,
        policy_hash: "policy-a2a-test".to_string(),
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
    let now = unix_now();
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
                    dpop_required: None,
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

fn threshold_artifacts(
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
fn a2a_projection_preserves_complete_approval_set_and_opaque_extension() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_for_tool(&issuer, &subject, "srv", "run");
    let (approvals, proposal) = threshold_artifacts(&subject, "a2a-auth-set");
    let supplemental =
        chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
            signed_extension: "opaque-a2a-extension".to_string(),
        };
    let execution = A2aKernelExecutionContext {
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
    let source = SendMessageRequest {
        message: A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: serde_json::json!({"value": 7}),
            }],
            metadata: None,
        },
        metadata: None,
    };

    let projected = ChioA2aEdge::build_execution_request(
        SkillBinding {
            target_protocol: DiscoveryProtocol::Native,
            server_id: "srv".to_string(),
            tool_name: "run".to_string(),
            security: BridgeSecurityMetadata::unconstrained(),
        },
        "run",
        &source,
        serde_json::json!({"value": 7}),
        &execution,
        "a2a-auth-set".to_string(),
        "a2a-kernel-auth-set".to_string(),
    )
    .test_expect("A2A request should project");

    assert_eq!(projected.approval_tokens, approvals);
    assert_eq!(projected.threshold_approval_proposal, Some(proposal));
    assert_eq!(projected.supplemental_authorization, Some(supplemental));
}

#[test]
fn registry_admitted_flow_survives_a2a_execution_projection_canonically() {
    let (registry, expected_flow) = registry_with_nontrivial_flow();
    let edge = ChioA2aEdge::new_with_registry(A2aEdgeConfig::default(), &registry).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
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
    let binding = edge.resolve_skill_binding("echo").test_unwrap();
    let source = text_message("preserve admitted flow");
    let request = ChioA2aEdge::build_execution_request(
        binding,
        "echo",
        &source,
        json!({"message":"preserve admitted flow"}),
        &execution,
        "a2a-flow-origin".to_string(),
        "a2a-flow-kernel".to_string(),
    )
    .test_unwrap();
    let projected_flow = request
        .bridge_security
        .flow()
        .test_expect("registry-admitted A2A binding must retain flow");

    assert_eq!(
        chio_core::canonical_json_bytes(projected_flow).test_unwrap(),
        chio_core::canonical_json_bytes(&expected_flow).test_unwrap()
    );
    assert!(request.bridge_security.has_registry_coordinates());
    assert!(request.bridge_security.effective_egress());
    assert_eq!(projected_flow.declassification_purposes.len(), 2);
}

#[test]
fn a2a_execution_boundary_rejects_removed_or_mismatched_flow_sidecar() {
    let (registry, _) = registry_with_nontrivial_flow();
    let edge = ChioA2aEdge::new_with_registry(A2aEdgeConfig::default(), &registry).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let kernel = ChioKernel::new(config);
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
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
    let binding = edge.resolve_skill_binding("echo").test_unwrap();
    let source = text_message("reject sidecar drift");
    let request = ChioA2aEdge::build_execution_request(
        binding,
        "echo",
        &source,
        json!({"message":"reject sidecar drift"}),
        &execution,
        "a2a-flow-reject-origin".to_string(),
        "a2a-flow-reject-kernel".to_string(),
    )
    .test_unwrap();

    let runtime_error =
        execute_orchestrated_a2a_request(&Default::default(), &kernel, &registry, request.clone())
            .test_expect_err("flow-required A2A registry must reject an unprotected kernel");
    assert!(matches!(
        runtime_error,
        A2aEdgeError::Bridge(BridgeError::Kernel(KernelError::FlowRuntimeUnavailable))
    ));

    let mut removed = request.clone();
    removed.bridge_security = BridgeSecurityMetadata::unconstrained();
    let removed_error =
        execute_orchestrated_a2a_request(&Default::default(), &kernel, &registry, removed)
            .test_expect_err("removed A2A flow sidecar must fail before dispatch");
    assert!(removed_error
        .to_string()
        .contains("bridge security does not match live registry entry for test-srv/echo"));

    let mut mismatched = request;
    mismatched.target_tool_name = "different-tool".to_string();
    let mismatch_error =
        execute_orchestrated_a2a_request(&Default::default(), &kernel, &registry, mismatched)
            .test_expect_err("mismatched A2A flow sidecar must fail before dispatch");
    assert!(mismatch_error.to_string().contains(
        "bridge security does not match live registry entry for test-srv/different-tool"
    ));
}

fn assert_receipt_write_prometheus_sample_at_least(outcome: &str, minimum: u64) {
    let body = render_a2a_edge_metrics_prometheus(chio_kernel::ReceiptWriterLiveness::Healthy);
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

fn kernel_for_server(
    server: impl ToolServerConnection + 'static,
) -> (ChioKernel, A2aKernelExecutionContext) {
    let config = test_kernel_config();
    let subject = Keypair::generate();
    let capability = capability_for_tool(
        &config.keypair,
        &subject,
        server.server_id(),
        &server.tool_names()[0],
    );
    let execution = A2aKernelExecutionContext {
        capability,
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
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(server));
    (kernel, execution)
}

mod agent_card;
mod boundaries;
mod errors_and_defaults;
mod jsonrpc;
mod message_conversion;
mod nonce_preflight;
mod send_message;
