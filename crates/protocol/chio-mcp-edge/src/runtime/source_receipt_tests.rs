#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::McpTargetExecutor;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_cross_protocol::capability_bridge::{
    CrossProtocolCapabilityEnvelope, CrossProtocolCapabilityRef,
};
use chio_cross_protocol::discovery::DiscoveryProtocol;
use chio_cross_protocol::error::BridgeError;
use chio_cross_protocol::execution::{
    CrossProtocolExecutionRequest, CrossProtocolTargetExecution, CrossProtocolTargetRequest,
    TargetProtocolExecutor,
};
use chio_cross_protocol::routing::{
    RouteCandidateEvidence, RouteSelectionDecision, RouteSelectionEvidence,
};
use chio_kernel::{ChioKernel, KernelConfig, KernelError, ToolServerConnection, Verdict};
use serde_json::{json, Value};

struct CountingEchoServer {
    invocations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingEchoServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(json!({
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

struct DirectExecutorFixture {
    kernel: ChioKernel,
    manifest_registry: chio_manifest::VerifiedManifestRegistry,
    execution: CrossProtocolExecutionRequest,
    invocations: Arc<AtomicUsize>,
}

impl DirectExecutorFixture {
    fn new(input_schema: Value) -> Self {
        let mut kernel = make_kernel();
        let invocations = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingEchoServer {
            invocations: Arc::clone(&invocations),
        }));
        let agent = Keypair::generate();
        let capability = kernel
            .issue_capability(
                &agent.public_key(),
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv".to_string(),
                        tool_name: "read_file".to_string(),
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
                300,
            )
            .unwrap();
        let manifest_signer = Keypair::from_seed(&[71; 32]);
        let manifest = chio_manifest::ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "srv".to_string(),
            name: "MCP source receipt test".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![chio_manifest::ToolDefinition {
                name: "read_file".to_string(),
                description: "Read file".to_string(),
                input_schema,
                output_schema: Some(json!({"type": "object"})),
                pricing: None,
                annotations: chio_manifest::ToolAnnotations::default(),
                latency_hint: None,
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: manifest_signer.public_key().to_hex(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &manifest_signer).unwrap();
        let mut manifest_registry = chio_manifest::VerifiedManifestRegistry::default();
        manifest_registry
            .register_public_only(
                signed,
                &manifest_signer.public_key(),
                chio_manifest::RuntimeToolTopology::local(),
            )
            .unwrap();
        let execution = CrossProtocolExecutionRequest {
            origin_request_id: "source-1".to_string(),
            kernel_request_id: "mcp-target-source-context".to_string(),
            target_protocol: DiscoveryProtocol::Mcp,
            target_server_id: "srv".to_string(),
            target_tool_name: "read_file".to_string(),
            agent_id: agent.public_key().to_hex(),
            arguments: json!({}),
            capability,
            source_envelope: json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            authenticated_session_id: None,
            security_context: None,
            bridge_security: manifest_registry
                .bridge_security("srv", "read_file")
                .unwrap(),
        };
        Self {
            kernel,
            manifest_registry,
            execution,
            invocations,
        }
    }

    fn execute(
        &self,
        source_protocol: DiscoveryProtocol,
        request_suffix: &str,
        arguments: Value,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        let mut execution = self.execution.clone();
        execution.origin_request_id = format!("{source_protocol}-{request_suffix}");
        execution.kernel_request_id = format!("mcp-target-{source_protocol}-{request_suffix}");
        execution.arguments = arguments;
        execution.source_envelope = json!({
            "receipt_context": {
                "sourceReceiptId": format!("source-receipt-{request_suffix}"),
                "sourceProtocol": source_protocol,
            }
        });
        let capability_ref = CrossProtocolCapabilityRef {
            chio_capability_id: execution.capability.id.clone(),
            origin_protocol: source_protocol,
            protocol_context: None,
            parent_capability_hash: "parent-hash".to_string(),
        };
        let capability_envelope = CrossProtocolCapabilityEnvelope {
            schema: "test.capability-envelope".to_string(),
            capability_ref: capability_ref.clone(),
            target_protocol: DiscoveryProtocol::Mcp,
            attenuated_scope: execution.capability.scope.clone(),
            bridged_at: 1,
            bridge_id: "bridge-test".to_string(),
        };
        let route_id = format!("{source_protocol}-mcp-native");
        let route_selection = RouteSelectionEvidence {
            route_selection_id: format!("route-{request_suffix}"),
            decision: RouteSelectionDecision::Select,
            source_protocol,
            requested_target_protocol: DiscoveryProtocol::Mcp,
            selected_route_id: Some(route_id.clone()),
            selected_target_protocol: Some(DiscoveryProtocol::Mcp),
            selected_protocols: vec![source_protocol, DiscoveryProtocol::Mcp],
            reason: None,
            governed_intent_id: None,
            candidates: vec![RouteCandidateEvidence {
                route_id,
                target_protocol: DiscoveryProtocol::Mcp,
                selected_protocols: vec![source_protocol, DiscoveryProtocol::Mcp],
                available: true,
                availability_reason: None,
            }],
        };
        let projected_request = json!({"jsonrpc": "2.0"});
        McpTargetExecutor {
            peer_supports_chio_tool_streaming: false,
        }
        .execute(CrossProtocolTargetRequest {
            kernel: &self.kernel,
            manifest_registry: &self.manifest_registry,
            execution: &execution,
            source_protocol,
            bridge_id: "bridge-test",
            capability_ref: &capability_ref,
            capability_envelope: &capability_envelope,
            route_selection: &route_selection,
            projected_request: &projected_request,
        })
    }
}

#[test]
fn mcp_target_executor_carries_source_receipt_context_into_kernel_receipt_metadata() {
    let fixture = DirectExecutorFixture::new(json!({"type": "object"}));

    let result = fixture
        .execute(
            DiscoveryProtocol::Acp,
            "context",
            json!({"path": "/tmp/demo.txt"}),
        )
        .unwrap();
    let metadata = result.response.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        metadata["receipt_context"]["sourceReceiptId"],
        "source-receipt-context"
    );
    assert_eq!(metadata["receipt_context"]["sourceProtocol"], "acp");
    assert_eq!(
        metadata["chio_manifest_security_v1"]["effective_egress"],
        false
    );
}

#[test]
fn mcp_target_executor_rejects_invalid_signed_schema_arguments_before_effects_and_recovers() {
    let fixture = DirectExecutorFixture::new(json!({
        "$defs": {
            "message": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4
            }
        },
        "type": "object",
        "properties": {
            "message": {"$ref": "#/$defs/message"}
        },
        "required": ["message"],
        "additionalProperties": false
    }));

    for source_protocol in [DiscoveryProtocol::A2a, DiscoveryProtocol::Acp] {
        for (case, invalid_arguments) in [
            ("non-object", json!([])),
            ("missing", json!({})),
            ("wrong-type", json!({"message": true})),
            ("too-long", json!({"message": "abcde"})),
            ("additional", json!({"message": "ok", "extra": true})),
        ] {
            let receipt_count = fixture.kernel.receipt_log().len();
            let invocation_count = fixture.invocations.load(Ordering::SeqCst);
            let error = match fixture.execute(
                source_protocol,
                &format!("invalid-{case}"),
                invalid_arguments,
            ) {
                Ok(_) => panic!("{source_protocol} {case} must reject invalid arguments"),
                Err(error) => error,
            };
            assert!(matches!(error, BridgeError::InvalidRequest(_)), "{error}");
            assert_eq!(
                fixture.kernel.receipt_log().len(),
                receipt_count,
                "{source_protocol} {case} must not create a receipt"
            );
            assert_eq!(
                fixture.invocations.load(Ordering::SeqCst),
                invocation_count,
                "{source_protocol} {case} must not invoke the tool"
            );
        }

        let receipt_count = fixture.kernel.receipt_log().len();
        let invocation_count = fixture.invocations.load(Ordering::SeqCst);
        let result = fixture
            .execute(
                source_protocol,
                "valid-after-rejections",
                json!({"message": "🧪🧪🧪🧪"}),
            )
            .unwrap();
        assert_eq!(result.response.verdict, Verdict::Allow);
        assert_eq!(fixture.kernel.receipt_log().len(), receipt_count + 1);
        assert_eq!(
            fixture.invocations.load(Ordering::SeqCst),
            invocation_count + 1
        );
    }
}

fn make_kernel() -> ChioKernel {
    ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    })
}
