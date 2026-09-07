#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::capability_bridge::*;
use crate::discovery::*;
use crate::error::*;
use crate::execution::*;
use crate::lifecycle::*;
use crate::orchestrator::*;
use crate::routing::*;
use crate::semantic_hints::*;
use crate::validation::schema_extension;

use std::collections::BTreeMap;

use chio_core::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Constraint, ModelMetadata, ModelSafetyTier, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::session::SessionId;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolServerConnection,
    Verdict as KernelVerdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{
    sign_manifest, BridgeSecurityMetadata, LatencyHint, RuntimeToolTopology, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use serde_json::{json, Value};

struct MockBridge;

impl CapabilityBridge for MockBridge {
    fn source_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::A2a
    }

    fn extract_capability_ref(
        &self,
        request: &Value,
    ) -> Result<Option<CrossProtocolCapabilityRef>, BridgeError> {
        request
            .pointer("/metadata/chio/capabilityRef")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| BridgeError::InvalidRequest(error.to_string()))
    }

    fn inject_capability_ref(
        &self,
        envelope: &mut Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError> {
        let Some(object) = envelope.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "request envelope must be a JSON object".to_string(),
            ));
        };
        let metadata = object
            .entry("metadata".to_string())
            .or_insert_with(|| json!({}));
        let Some(metadata_obj) = metadata.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "metadata must be a JSON object".to_string(),
            ));
        };
        let chio = metadata_obj
            .entry("chio".to_string())
            .or_insert_with(|| json!({}));
        let Some(chio_obj) = chio.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "metadata.chio must be a JSON object".to_string(),
            ));
        };
        chio_obj.insert(
            "capabilityRef".to_string(),
            serde_json::to_value(cap_ref)
                .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?,
        );
        Ok(())
    }

    fn protocol_context(&self, request: &Value) -> Result<Option<Value>, BridgeError> {
        Ok(request
            .pointer("/metadata/chio/targetSkillId")
            .and_then(Value::as_str)
            .map(|skill| json!({ "targetSkillId": skill })))
    }
}

struct MockToolServer;

struct MockMcpExecutor;

impl TargetProtocolExecutor for MockMcpExecutor {
    fn target_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Mcp
    }

    fn execute(
        &self,
        request: CrossProtocolTargetRequest<'_>,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        let route_metadata = route_selection_metadata(request.route_selection)?;
        let response = request
            .kernel
            .evaluate_tool_call_blocking_with_manifest_security(
                &kernel_tool_call_request(request.execution),
                request.manifest_registry,
                &request.execution.bridge_security,
                Some(route_metadata),
            )
            .map_err(BridgeError::Kernel)?;
        let receipt_id = response.receipt.id.clone();

        Ok(CrossProtocolTargetExecution {
            response,
            protocol_result: Some(json!({
                "content": [{"type": "text", "text": "projected"}],
                "structuredContent": {"mode": "mcp"},
                "isError": false
            })),
            protocol_notifications: vec![json!({"jsonrpc": "2.0", "method": "notifications/test"})],
            route_hops: vec![
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Mcp,
                    request_id: format!("{}:mcp", request.execution.kernel_request_id),
                    receipt_id: None,
                },
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Native,
                    request_id: request.execution.kernel_request_id.clone(),
                    receipt_id: Some(receipt_id),
                },
            ],
        })
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MockToolServer {
    fn server_id(&self) -> &str {
        "test-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({"result":"ok"}))
    }
}

fn unix_now() -> u64 {
    current_unix_timestamp()
}

fn test_kernel() -> (Keypair, ChioKernel) {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair: keypair.clone(),
        max_delegation_depth: 8,
        policy_hash: "policy-cross-protocol-test".to_string(),
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
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(MockToolServer));
    (keypair, kernel)
}

fn test_manifest_registry() -> VerifiedManifestRegistry {
    let signer = Keypair::from_seed(&[61; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "test-srv".to_string(),
        name: "Cross-protocol test server".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: ["echo", "write"]
            .into_iter()
            .map(|name| semantic_tool(name, None, json!({"type":"object"}), None))
            .collect(),
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, &signer).unwrap();
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::local())
        .unwrap();
    registry
}

fn flow_manifest_registry() -> VerifiedManifestRegistry {
    let signer = Keypair::from_seed(&[41; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "test-srv".to_string(),
        name: "Cross-protocol flow server".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "echo".to_string(),
            description: "Cross-protocol flow test tool".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: Some(json!({"type": "object"})),
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
                estimated_duration_ms: None,
            },
            latency_hint: Some(LatencyHint::Fast),
            flow: Some(ToolFlowDeclaration::public_egress()),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, &signer).unwrap();
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .unwrap();
    registry
}

fn boundary_request(bridge_security: BridgeSecurityMetadata) -> CrossProtocolExecutionRequest {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    CrossProtocolExecutionRequest {
        origin_request_id: "cross-protocol-security-origin".to_string(),
        kernel_request_id: "cross-protocol-security-kernel".to_string(),
        target_protocol: DiscoveryProtocol::Native,
        target_server_id: "test-srv".to_string(),
        target_tool_name: "echo".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: json!({"message": "security boundary"}),
        capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
        source_envelope: json!({"message": {"role": "user"}}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        authenticated_session_id: None,
        security_context: None,
        bridge_security,
    }
}

#[test]
fn execution_boundary_rejects_unadmitted_bridge_security() {
    let registry = flow_manifest_registry();
    let request = boundary_request(BridgeSecurityMetadata::unconstrained());

    let error = crate::validation::validate_execution_request_boundary(&request, &registry)
        .expect_err("unadmitted bridge metadata must fail closed");

    assert_eq!(
        error.to_string(),
        "invalid request envelope: bridge security does not match live registry entry for test-srv/echo"
    );
}

#[test]
fn execution_boundary_rejects_authenticated_session_without_security_context() {
    let registry = flow_manifest_registry();
    let bridge_security = registry.bridge_security("test-srv", "echo").unwrap();
    let mut request = boundary_request(bridge_security);
    request.authenticated_session_id = Some(SessionId::new("authenticated-session"));

    let error = crate::validation::validate_execution_request_boundary(&request, &registry)
        .expect_err("authenticated session without its security context must fail closed");

    assert_eq!(
        error.to_string(),
        "invalid request envelope: authenticated session requires an authoritative security context"
    );
}

#[test]
fn execution_boundary_rejects_forged_digest_flow_and_topology_fields() {
    let registry = flow_manifest_registry();
    let exact = registry.bridge_security("test-srv", "echo").unwrap();
    let exact_value = serde_json::to_value(exact).unwrap();

    let mut forged_cases = Vec::new();
    let mut forged_digest = exact_value.clone();
    forged_digest["manifest_digest"] = Value::String("00".repeat(32));
    forged_cases.push(("manifest digest", forged_digest));

    let mut forged_topology = exact_value.clone();
    forged_topology["effective_egress"] = Value::Bool(false);
    forged_cases.push(("effective topology", forged_topology));

    let mut forged_flow = exact_value;
    forged_flow["flow"]["egress"] = Value::Bool(false);
    forged_cases.push(("flow egress", forged_flow));

    for (field, value) in forged_cases {
        let forged: BridgeSecurityMetadata = serde_json::from_value(value).unwrap();
        let request = boundary_request(forged);
        let error = crate::validation::validate_execution_request_boundary(&request, &registry)
            .expect_err("forged bridge metadata must fail closed");
        assert_eq!(
            error.to_string(),
            "invalid request envelope: bridge security does not match live registry entry for test-srv/echo",
            "forged {field} must fail closed"
        );
    }
}

#[test]
fn cross_protocol_routing_preserves_registry_admitted_flow_canonical_bytes() {
    let (_, kernel) = test_kernel();
    let registry = flow_manifest_registry();
    let bridge_security = registry.bridge_security("test-srv", "echo").unwrap();
    let expected_flow = chio_core::canonical_json_bytes(
        bridge_security
            .flow()
            .expect("registry-admitted sidecar must retain flow"),
    )
    .unwrap();
    let mut request = boundary_request(bridge_security.clone());
    request.target_protocol = DiscoveryProtocol::Mcp;

    let result = CrossProtocolOrchestrator::new(&kernel, &registry)
        .execute(&MockBridge, request)
        .expect("route denial must retain registry-admitted security evidence");
    assert!(matches!(result.response.verdict, KernelVerdict::Deny));

    let metadata = result.metadata();
    let routed_sidecar = metadata
        .pointer("/chio/receipt/metadata/chio_manifest_security_v1")
        .expect("signed route receipt must retain the complete admitted sidecar");
    assert_eq!(
        chio_core::canonical_json_bytes(routed_sidecar).unwrap(),
        chio_core::canonical_json_bytes(&serde_json::to_value(&bridge_security).unwrap()).unwrap()
    );
    let routed_flow = routed_sidecar
        .get("flow")
        .expect("signed route receipt must retain admitted flow");
    assert_eq!(
        chio_core::canonical_json_bytes(routed_flow).unwrap(),
        expected_flow
    );
}

fn capability_for_tool(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    tool_name: &str,
) -> CapabilityToken {
    capability_for_tool_with_constraints(issuer, subject, server_id, tool_name, vec![])
}

fn capability_for_tool_with_constraints(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    tool_name: &str,
    constraints: Vec<Constraint>,
) -> CapabilityToken {
    let now = unix_now();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("cap-{server_id}-{tool_name}"),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.to_string(),
                    tool_name: tool_name.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints,
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
    .unwrap()
}

#[test]
fn attenuate_scope_for_tool_narrows_wildcard_parent_grants() {
    let parent = ChioScope {
        grants: vec![ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::MaxLength(1024)],
            max_invocations: Some(3),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };

    let child = attenuate_scope_for_tool(&parent, "test-srv", "echo");

    assert_eq!(child.grants.len(), 1);
    assert_eq!(child.grants[0].server_id, "test-srv");
    assert_eq!(child.grants[0].tool_name, "echo");
    assert_eq!(child.grants[0].operations, vec![Operation::Invoke]);
    assert_eq!(
        child.grants[0].constraints,
        vec![Constraint::MaxLength(1024)]
    );
    assert_eq!(child.grants[0].max_invocations, Some(3));
    assert_eq!(child.grants[0].dpop_required, Some(true));
}

#[test]
fn parent_capability_hash_commits_to_signed_token_not_id_only() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let first = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let mut second = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    second.expires_at = second.expires_at.saturating_add(1);

    assert_eq!(first.id, second.id);
    assert_ne!(
        parent_capability_hash(&first).unwrap(),
        parent_capability_hash(&second).unwrap()
    );
}

#[test]
fn capability_envelope_serializes_without_parent_capability_token() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let capability_ref =
        CrossProtocolCapabilityRef::from_capability(&capability, DiscoveryProtocol::A2a, None)
            .unwrap();
    let envelope = CrossProtocolCapabilityEnvelope {
        schema: CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA.to_string(),
        capability_ref,
        target_protocol: DiscoveryProtocol::Native,
        attenuated_scope: capability.scope.clone(),
        bridged_at: 1,
        bridge_id: "bridge-no-token".to_string(),
    };

    let serialized = serde_json::to_value(envelope).unwrap();
    assert!(serialized.get("capability").is_none());
    assert_eq!(
        serialized["capabilityRef"]["chioCapabilityId"].as_str(),
        Some("cap-test-srv-echo")
    );
    assert!(serialized["capabilityRef"]["parentCapabilityHash"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
}

fn semantic_tool(
    name: &str,
    latency_hint: Option<LatencyHint>,
    input_schema: Value,
    output_schema: Option<Value>,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: format!("semantic tool {name}"),
        input_schema,
        output_schema,
        pricing: None,
        annotations: chio_manifest::ToolAnnotations {
            read_only: true,
            destructive: false,
            idempotent: false,
            requires_approval: false,
            estimated_duration_ms: None,
        },
        latency_hint,
        flow: None,
    }
}

#[test]
fn target_protocol_defaults_to_native() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({"type": "object"}),
        None,
    );
    assert_eq!(
        target_protocol_for_tool(&tool).unwrap(),
        DiscoveryProtocol::Native
    );
}

#[test]
fn target_protocol_can_be_registry_derived() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({"type": "object"}),
        None,
    );
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::OpenAi);
    assert_eq!(
        target_protocol_for_tool_with_registry(&tool, &registry).unwrap(),
        DiscoveryProtocol::OpenAi
    );
}

#[test]
fn target_protocol_reads_schema_extension() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({
            "type": "object",
            "x-chio-target-protocol": "mcp"
        }),
        None,
    );
    assert_eq!(
        target_protocol_for_tool(&tool).unwrap(),
        DiscoveryProtocol::Mcp
    );
}

#[test]
fn target_protocol_rejects_unknown_extension_value() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({
            "type": "object",
            "x-chio-target-protocol": "smtp"
        }),
        None,
    );
    assert!(target_protocol_for_tool(&tool).is_err());
}

#[test]
fn target_protocol_rejects_non_string_extension_value() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({
            "type": "object",
            "x-chio-target-protocol": 42
        }),
        None,
    );
    let err = target_protocol_for_tool(&tool).unwrap_err();

    assert!(err.contains("x-chio-target-protocol must be a string"));
}

#[test]
fn source_receipt_context_is_preserved_as_non_authoritative_metadata() {
    let metadata = metadata_with_source_receipt_context(
        json!({"route_selection": {"decision": "allow"}}),
        &json!({
            "receipt_context": {
                "request_id": "source-request",
                "session_id": "source-session"
            }
        }),
    )
    .expect("source receipt context should project");

    assert!(metadata.get("receipt_context").is_none());
    assert_eq!(
        metadata.pointer("/source_receipt_context/request_id"),
        Some(&json!("source-request"))
    );
    assert_eq!(
        metadata.pointer("/source_receipt_context/session_id"),
        Some(&json!("source-session"))
    );
}

#[test]
fn orchestrator_rejects_empty_origin_request_id_before_signed_lineage() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let err = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: " ".to_string(),
                kernel_request_id: "a2a-empty-origin-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "invalid request envelope: origin_request_id must be a non-empty string"
    );
}

#[test]
fn orchestrator_rejects_padded_or_control_execution_identity_before_signed_lineage() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let agent_id = subject.public_key().to_hex();

    let cases = [
        ("origin_request_id", " a2a-padded-origin "),
        ("kernel_request_id", "kernel\ncontrol"),
        ("target_server_id", " test-srv "),
        ("target_tool_name", "echo\rcontrol"),
        ("agent_id", " agent-padded "),
    ];

    for (field_name, malformed_value) in cases {
        let mut request = CrossProtocolExecutionRequest {
            origin_request_id: "a2a-valid-origin".to_string(),
            kernel_request_id: "a2a-valid-kernel".to_string(),
            target_protocol: DiscoveryProtocol::Native,
            target_server_id: "test-srv".to_string(),
            target_tool_name: "echo".to_string(),
            bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
            agent_id: agent_id.clone(),
            arguments: json!({"message":"hello"}),
            capability: capability.clone(),
            source_envelope: json!({
                "message": {"role":"user"},
                "metadata": { "chio": { "targetSkillId": "echo" } }
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            authenticated_session_id: None,
            security_context: None,
        };

        match field_name {
            "origin_request_id" => request.origin_request_id = malformed_value.to_string(),
            "kernel_request_id" => request.kernel_request_id = malformed_value.to_string(),
            "target_server_id" => request.target_server_id = malformed_value.to_string(),
            "target_tool_name" => request.target_tool_name = malformed_value.to_string(),
            "agent_id" => request.agent_id = malformed_value.to_string(),
            _ => unreachable!("test case uses only request identity fields"),
        }

        let err = orchestrator.execute(&MockBridge, request).unwrap_err();

        assert_eq!(
                err.to_string(),
                format!(
                    "invalid request envelope: {field_name} must be unpadded and contain no control characters"
                )
            );
    }
}

#[test]
fn orchestrator_rejects_forged_capability_ref_parent_hash() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");

    let err = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-forged-cap-ref".to_string(),
                kernel_request_id: "a2a-forged-cap-ref-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability,
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": {
                        "chio": {
                            "targetSkillId": "echo",
                            "capabilityRef": {
                                "chioCapabilityId": "cap-test-srv-echo",
                                "originProtocol": "a2a",
                                "protocolContext": {"targetSkillId": "echo"},
                                "parentCapabilityHash": "forged-parent-hash"
                            }
                        }
                    }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap_err();

    assert_eq!(
            err.to_string(),
            "invalid request envelope: capabilityRef parentCapabilityHash does not match active capability lineage"
        );
}

#[test]
fn orchestrator_rejects_capability_ref_origin_protocol_drift() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let parent_hash = parent_capability_hash(&capability).unwrap();

    let err = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-drifted-cap-ref".to_string(),
                kernel_request_id: "a2a-drifted-cap-ref-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability,
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": {
                        "chio": {
                            "targetSkillId": "echo",
                            "capabilityRef": {
                                "chioCapabilityId": "cap-test-srv-echo",
                                "originProtocol": "acp",
                                "protocolContext": {"targetSkillId": "echo"},
                                "parentCapabilityHash": parent_hash
                            }
                        }
                    }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap_err();

    assert_eq!(
            err.to_string(),
            "invalid request envelope: capabilityRef originProtocol acp does not match source protocol a2a"
        );
}

#[test]
fn orchestrator_executes_and_preserves_bridge_lineage() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-1".to_string(),
                kernel_request_id: "a2a-a2a-task-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap();

    assert_eq!(result.source_protocol, DiscoveryProtocol::A2a);
    assert_eq!(result.target_protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result.capability_ref.chio_capability_id,
        "cap-test-srv-echo"
    );
    assert_eq!(
        result.projected_request["metadata"]["chio"]["capabilityRef"]["chioCapabilityId"].as_str(),
        Some("cap-test-srv-echo")
    );
    assert_eq!(result.trace.hops.len(), 2);
    assert!(result.trace.hops[1].receipt_id.is_some());

    let metadata = result.metadata();
    assert_eq!(
        metadata["chio"]["authorityPath"].as_str(),
        Some(CROSS_PROTOCOL_AUTHORITY_PATH)
    );
    assert_eq!(
        metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
        Some("a2a")
    );
    assert_eq!(
        metadata["chio"]["bridge"]["targetProtocol"].as_str(),
        Some("native")
    );
    assert_eq!(
        metadata["chio"]["bridge"]["terminalProtocol"].as_str(),
        Some("native")
    );
    assert_eq!(
        metadata["chio"]["routeSelection"]["decision"].as_str(),
        Some("select")
    );
    assert_eq!(
        metadata["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        Some("native")
    );
    assert!(metadata["chio"]["bridge"]["capabilityEnvelope"]
        .get("capability")
        .is_none());
    assert_eq!(
        metadata["chio"]["bridge"]["capabilityEnvelope"]["capabilityRef"]["chioCapabilityId"]
            .as_str(),
        Some("cap-test-srv-echo")
    );
}

#[test]
fn orchestrator_fail_closes_with_empty_attenuation_on_out_of_scope_target() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-2".to_string(),
                kernel_request_id: "a2a-a2a-task-2".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "write".to_string(),
                bridge_security: registry.bridge_security("test-srv", "write").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"nope"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "write" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap();

    assert!(result
        .capability_envelope
        .attenuated_scope
        .grants
        .is_empty());
    assert!(matches!(result.response.verdict, KernelVerdict::Deny));
    assert_eq!(result.metadata()["chio"]["decision"].as_str(), Some("deny"));
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["decision"].as_str(),
        Some("select")
    );
}

#[test]
fn pending_approval_metadata_is_not_labeled_allow() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let mut result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-pending".to_string(),
                kernel_request_id: "a2a-a2a-task-pending".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap();
    result.response.verdict = KernelVerdict::PendingApproval;
    result.response.reason = Some("approval required".to_string());

    let metadata = result.metadata();
    assert_eq!(
        metadata["chio"]["decision"].as_str(),
        Some("pending_approval")
    );
    assert_eq!(
        metadata["chio"]["reason"].as_str(),
        Some("approval required")
    );
}

#[test]
fn orchestrator_dispatches_to_registered_target_executor() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let executor = MockMcpExecutor;
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry).with_executor(&executor);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-mcp".to_string(),
                kernel_request_id: "a2a-mcp-1".to_string(),
                target_protocol: DiscoveryProtocol::Mcp,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap();

    assert_eq!(result.target_protocol, DiscoveryProtocol::Mcp);
    assert_eq!(
        result
            .protocol_result
            .as_ref()
            .and_then(|value| value["isError"].as_bool()),
        Some(false)
    );
    assert_eq!(result.protocol_notifications.len(), 1);
    assert_eq!(
        result.metadata()["chio"]["targetExecution"]["projectedResult"],
        Value::Bool(true)
    );
    assert_eq!(result.trace.hops.len(), 3);
    assert_eq!(result.trace.hops[1].protocol, DiscoveryProtocol::Mcp);
    assert_eq!(result.trace.hops[2].protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result.metadata()["chio"]["bridge"]["route"]["multiHop"],
        Value::Bool(true)
    );
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        Some("mcp")
    );
}

#[test]
fn orchestrator_capability_envelope_uses_selected_native_fallback_target() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let executor = MockMcpExecutor;
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry)
        .with_executor(&executor)
        .with_protocol_availability(
            DiscoveryProtocol::Mcp,
            RouteAvailabilityStatus::unavailable("mcp route unavailable"),
        );

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-mcp-fallback".to_string(),
                kernel_request_id: "a2a-mcp-fallback-1".to_string(),
                target_protocol: DiscoveryProtocol::Mcp,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: Some(governed_intent_with_control_plane(json!({
                    "allowNativeFallback": true
                }))),
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap();

    assert_eq!(result.target_protocol, DiscoveryProtocol::Native);
    assert_eq!(result.terminal_protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result.capability_envelope.target_protocol,
        DiscoveryProtocol::Native
    );
    assert_eq!(
        result.metadata()["chio"]["bridge"]["capabilityEnvelope"]["targetProtocol"].as_str(),
        Some("native")
    );
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        Some("native")
    );
    assert_eq!(result.trace.hops.len(), 2);
    assert_eq!(result.trace.hops[1].protocol, DiscoveryProtocol::Native);
}

#[test]
fn orchestrator_preserves_model_metadata_for_model_constrained_grant() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-model-1".to_string(),
                kernel_request_id: "a2a-model-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool_with_constraints(
                    &issuer,
                    &subject,
                    "test-srv",
                    "echo",
                    vec![Constraint::ModelConstraint {
                        allowed_model_ids: vec!["gpt-5".to_string()],
                        min_safety_tier: Some(ModelSafetyTier::High),
                    }],
                ),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: Some(ModelMetadata {
                    model_id: "gpt-5".to_string(),
                    safety_tier: Some(ModelSafetyTier::High),
                    provider: Some("openai".to_string()),
                    provenance_class:
                        chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
                }),
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap();

    assert!(matches!(result.response.verdict, KernelVerdict::Allow));
}

#[test]
fn orchestrator_denies_unregistered_non_native_target_with_signed_route_selection() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-mcp-missing".to_string(),
                kernel_request_id: "a2a-mcp-missing-1".to_string(),
                target_protocol: DiscoveryProtocol::Mcp,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap();

    assert!(matches!(result.response.verdict, KernelVerdict::Deny));
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["decision"].as_str(),
        Some("deny")
    );
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        None
    );
}

#[test]
fn orchestrator_dispatches_to_registered_openai_target_executor() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let executor = OpenAiTargetExecutor;
    let registry = test_manifest_registry();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry).with_executor(&executor);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-openai-1".to_string(),
                kernel_request_id: "a2a-openai-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::OpenAi,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                authenticated_session_id: None,
                security_context: None,
            },
        )
        .unwrap();

    assert_eq!(result.target_protocol, DiscoveryProtocol::OpenAi);
    assert_eq!(result.terminal_protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result
            .protocol_result
            .as_ref()
            .and_then(|value| value["type"].as_str()),
        Some("function_call_output")
    );
    assert_eq!(
        result
            .protocol_result
            .as_ref()
            .and_then(|value| value["receipt_ref"].as_str()),
        Some(result.response.receipt.id.as_str())
    );
    assert_eq!(result.trace.hops.len(), 3);
    assert_eq!(result.trace.hops[1].protocol, DiscoveryProtocol::OpenAi);
    assert_eq!(result.trace.hops[2].protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        Some("open_ai")
    );
}

fn governed_intent_with_control_plane(control_plane: Value) -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: "intent-1".to_string(),
        server_id: "test-srv".to_string(),
        tool_name: "echo".to_string(),
        purpose: "test route planning".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(json!({ "chioControlPlane": control_plane })),
        body: Default::default(),
    }
}

#[test]
fn plan_authoritative_route_prefers_registered_protocol_from_governed_intent() {
    let executor = MockMcpExecutor;
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
    let planning = plan_authoritative_route(
        "req-route-preferred",
        DiscoveryProtocol::A2a,
        DiscoveryProtocol::Native,
        Some(&governed_intent_with_control_plane(json!({
            "preferredTargetProtocol": "mcp",
            "allowNativeFallback": true
        }))),
        &registry,
        &BTreeMap::new(),
    )
    .unwrap();

    assert_eq!(
        planning.selected_target_protocol,
        Some(DiscoveryProtocol::Mcp)
    );
    assert_eq!(
        planning.evidence.decision,
        RouteSelectionDecision::Attenuate
    );
    assert_eq!(
        planning.evidence.selected_target_protocol,
        Some(DiscoveryProtocol::Mcp)
    );
}

#[test]
fn plan_authoritative_route_attentuates_to_native_fallback_when_requested_route_is_unavailable() {
    let mut availability = BTreeMap::new();
    availability.insert(
        DiscoveryProtocol::Mcp,
        RouteAvailabilityStatus::unavailable("mcp route unavailable"),
    );
    let executor = MockMcpExecutor;
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
    let planning = plan_authoritative_route(
        "req-route-fallback",
        DiscoveryProtocol::A2a,
        DiscoveryProtocol::Mcp,
        Some(&governed_intent_with_control_plane(json!({
            "allowNativeFallback": true
        }))),
        &registry,
        &availability,
    )
    .unwrap();

    assert_eq!(
        planning.selected_target_protocol,
        Some(DiscoveryProtocol::Native)
    );
    assert_eq!(
        planning.evidence.decision,
        RouteSelectionDecision::Attenuate
    );
    assert_eq!(
        planning.evidence.reason.as_deref(),
        Some("requested target protocol unavailable; attenuated to native fallback")
    );
}

#[test]
fn plan_authoritative_route_denies_when_projected_protocols_are_disallowed_without_native() {
    let executor = MockMcpExecutor;
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
    let mut availability = BTreeMap::new();
    availability.insert(
        DiscoveryProtocol::Native,
        RouteAvailabilityStatus::unavailable("native route unavailable"),
    );

    let planning = plan_authoritative_route(
        "req-route-deny",
        DiscoveryProtocol::A2a,
        DiscoveryProtocol::Mcp,
        Some(&governed_intent_with_control_plane(json!({
            "disallowProjectedProtocols": true
        }))),
        &registry,
        &availability,
    )
    .unwrap();

    assert_eq!(planning.selected_target_protocol, None);
    assert_eq!(planning.evidence.decision, RouteSelectionDecision::Deny);
    assert_eq!(
        planning.evidence.reason.as_deref(),
        Some("governed intent disallowed projected protocols and no native route was available")
    );
}

#[test]
fn plan_authoritative_route_denies_unregistered_target_even_when_marked_available() {
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native);
    let mut availability = BTreeMap::new();
    availability.insert(DiscoveryProtocol::Mcp, RouteAvailabilityStatus::available());

    let planning = plan_authoritative_route(
        "req-route-unregistered-available",
        DiscoveryProtocol::A2a,
        DiscoveryProtocol::Mcp,
        None,
        &registry,
        &availability,
    )
    .unwrap();

    assert_eq!(planning.selected_target_protocol, None);
    assert_eq!(planning.evidence.decision, RouteSelectionDecision::Deny);
    assert_eq!(planning.evidence.selected_target_protocol, None);
    assert_eq!(planning.evidence.candidates.len(), 1);
    assert!(!planning.evidence.candidates[0].available);
    assert_eq!(
        planning.evidence.candidates[0]
            .availability_reason
            .as_deref(),
        Some("target protocol `mcp` is not registered")
    );
}

#[test]
fn schema_extension_returns_named_extension_only_for_object_schema() {
    let schema = json!({
        "type": "object",
        "x-chio-publish": false
    });

    assert_eq!(
        schema_extension(&schema, "x-chio-publish"),
        Some(&Value::Bool(false))
    );
    assert_eq!(schema_extension(&schema, "x-chio-missing"), None);
    assert_eq!(
        schema_extension(&Value::String("not-object".to_string()), "x"),
        None
    );
}

#[test]
fn semantic_hints_respect_extensions_and_defaults() {
    let explicit = semantic_tool(
        "explicit",
        Some(LatencyHint::Fast),
        json!({
            "type": "object",
            "x-chio-publish": false,
            "x-chio-approval-required": true,
            "x-chio-cancellation": true
        }),
        Some(json!({
            "type": "object",
            "x-chio-streaming": true,
            "x-chio-partial-output": true
        })),
    );
    let explicit_hints = semantic_hints_for_tool(&explicit);
    assert!(!explicit_hints.publish);
    assert!(explicit_hints.approval_required);
    assert!(explicit_hints.streams_output);
    assert!(explicit_hints.supports_cancellation);
    assert!(explicit_hints.partial_output);

    let fallback = semantic_tool(
        "fallback",
        Some(LatencyHint::Slow),
        json!({"type": "object"}),
        None,
    );
    let fallback_hints = semantic_hints_for_tool(&fallback);
    assert!(fallback_hints.publish);
    assert!(!fallback_hints.approval_required);
    assert!(fallback_hints.streams_output);
    assert!(fallback_hints.supports_cancellation);
    assert!(fallback_hints.partial_output);
}

#[test]
fn runtime_lifecycle_contract_serializes_shared_surface_metadata() {
    let lifecycle = runtime_lifecycle_contract(RuntimeLifecycleSurface::A2aAuthoritative);
    let json = serde_json::to_value(lifecycle).unwrap();
    assert_eq!(json["surface"], "a2a_authoritative");
    assert_eq!(json["blockingEntrypoint"], "message/send");
    assert_eq!(json["streamEntrypoint"], "message/stream");
    assert_eq!(json["followUpEntrypoint"], "task/get");
    assert_eq!(json["cancelEntrypoint"], "task/cancel");
    assert_eq!(json["claimEligible"], true);
    assert_eq!(json["compatibilityOnly"], false);
}

#[test]
fn bridge_fidelity_helpers_report_publication_state() {
    let lossless = BridgeFidelity::Lossless;
    assert!(lossless.published_by_default());
    assert!(lossless.caveats().is_empty());
    assert_eq!(lossless.unsupported_reason(), None);

    let adapted = BridgeFidelity::Adapted {
        caveats: vec!["partial output collated".to_string()],
    };
    assert!(adapted.published_by_default());
    assert_eq!(adapted.caveats(), ["partial output collated"]);
    assert_eq!(adapted.unsupported_reason(), None);

    let unsupported = BridgeFidelity::Unsupported {
        reason: "interactive permission prompt required".to_string(),
    };
    assert!(!unsupported.published_by_default());
    assert!(unsupported.caveats().is_empty());
    assert_eq!(
        unsupported.unsupported_reason(),
        Some("interactive permission prompt required")
    );
}
