use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use chio_core::capability::{
    aggregate_invocation::{AggregateInvocationBudget, AggregateInvocationScope},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
};
use chio_manifest::{RuntimeToolTopology, VerifiedManifestRegistry};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};
use serde_json::{json, Value};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const SERVER: &str = "consumer-server";
pub const TOOL: &str = "read_file";

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Native,
    Mcp,
    A2a,
    Acp,
}

pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub signer: Keypair,
    pub agent: Keypair,
    pub calls: Arc<AtomicU64>,
    pub capability: CapabilityToken,
    pub approvers: [Keypair; 2],
    require_approvals: bool,
}

impl Fixture {
    pub fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let locks = directory.path().join("locks");
        std::fs::create_dir(&locks)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))?;
        }
        SqliteAuthorityStore::provision(directory.path().join("authority.db"), locks)?;
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "consumer-aggregate".to_string(),
                issuer: signer.public_key(),
                subject: agent.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: SERVER.to_string(),
                        tool_name: TOOL.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(2),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                issued_at: now,
                expires_at: now + 600,
                delegation_chain: vec![],
                aggregate_invocation_budget: Some(AggregateInvocationBudget {
                    scope: AggregateInvocationScope::Capability,
                    max_invocations: 1,
                    root_binding: None,
                }),
            },
            &signer,
        )?;
        Ok(Self {
            directory,
            signer,
            agent,
            capability,
            calls: Arc::new(AtomicU64::new(0)),
            approvers: [Keypair::generate(), Keypair::generate()],
            require_approvals: false,
        })
    }

    pub fn with_threshold_approval(mut self) -> TestResult<Self> {
        let mut body = self.capability.body();
        // Qualify the supported cumulative-approval profile independently.
        // Joint aggregate/cumulative roots remain explicitly unsupported.
        body.aggregate_invocation_budget = None;
        body.scope.grants[0].constraints.push(
            chio_core::capability::scope::Constraint::RequireCumulativeApprovalAbove {
                threshold: chio_core::capability::scope::MonetaryAmount {
                    units: 100,
                    currency: "USD".to_string(),
                },
                approval_budget_id: "consumer-approval-budget".to_string(),
                approval_budget_epoch: 1,
                cumulative_approval_root_binding: None,
            },
        );
        self.capability = CapabilityToken::sign(body, &self.signer)?;
        self.require_approvals = true;
        Ok(self)
    }

    pub fn request(&self, id: &str) -> TestResult<ToolCallRequest> {
        Ok(serde_json::from_value(json!({
            "request_id":id, "capability":self.capability, "agent_id":self.agent.public_key().to_hex(),
            "server_id":SERVER, "tool_name":TOOL, "arguments":{"record":"consumer-record"}
        }))?)
    }

    pub fn open(&self, protocol: Protocol) -> TestResult<Consumer> {
        let authority = SqliteAuthorityStore::open_serving(
            self.directory.path().join("authority.db"),
            self.directory.path().join("locks"),
        )?;
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: self.signer.clone(),
            ca_public_keys: vec![self.signer.public_key()],
            max_delegation_depth: 5,
            policy_hash: chio_core::sha256_hex(b"consumer-boundary-policy"),
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
        let receipts = SqliteReceiptStore::open(self.directory.path().join("receipts.db"))?;
        receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
        kernel.set_receipt_store_handle(Arc::new(receipts))?;
        kernel.set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
        if self.require_approvals {
            use chio_core::capability::threshold_approval::{
                ThresholdApprovalRequirement, ThresholdApproverIdentity,
            };
            let policy = chio_core::sha256_hex(b"consumer-boundary-policy");
            let requirement = ThresholdApprovalRequirement::new(
                policy.clone(),
                2,
                self.approvers
                    .iter()
                    .enumerate()
                    .map(|(index, key)| ThresholdApproverIdentity {
                        identifier: format!("reviewer-{index}"),
                        public_key: key.public_key(),
                    })
                    .collect(),
                "consumer-approver-directory-v1".to_string(),
                300,
            )?;
            kernel.set_threshold_approval_requirement_resolver(Arc::new(
                move |policy_hash: &str, server: &str, tool: &str| {
                    if policy_hash == policy && server == SERVER && tool == TOOL {
                        Ok(Some(requirement.clone()))
                    } else {
                        Err("unexpected approval authority request".to_string())
                    }
                },
            ));
        }
        kernel.register_tool_server(Box::new(CountedServer(self.calls.clone())));
        kernel.reconcile_durable_admission_startup()?;
        let manifest = chio_manifest::ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: SERVER.to_string(),
            name: "Consumer boundary fixture".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            public_key: self.signer.public_key().to_hex(),
            server_tools: vec![],
            required_permissions: None,
            tools: vec![chio_manifest::ToolDefinition {
                name: TOOL.to_string(),
                description: "Count one local invocation".to_string(),
                input_schema: json!({"type":"object"}),
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
        };
        let mut registry = VerifiedManifestRegistry::default();
        registry.register_public_only(
            chio_manifest::sign_manifest(&manifest, &self.signer)?,
            &self.signer.public_key(),
            RuntimeToolTopology::local(),
        )?;
        let peer = chio_mcp_edge::authorization::authorization_capabilities();
        let frontend = match protocol {
            Protocol::Native => Frontend::Native(Box::new(kernel)),
            Protocol::Mcp => {
                let mut edge = chio_mcp_edge::ChioMcpEdge::new_with_manifest_registry(
                    Default::default(),
                    kernel,
                    self.agent.public_key().to_hex(),
                    vec![self.capability.clone()],
                    &registry,
                )?;
                let initialized = edge
                    .handle_jsonrpc(
                        json!({"jsonrpc":"2.0", "id":"initialize", "method":"initialize",
                    "params":{"capabilities":{"experimental":{"chioAuthorization":peer}}}}),
                    )
                    .ok_or("initialize response")?;
                assert!(initialized.get("error").is_none(), "{initialized}");
                edge.handle_jsonrpc(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));
                Frontend::Mcp(Box::new(edge))
            }
            Protocol::A2a => Frontend::A2a(
                Box::new(kernel),
                chio_a2a_edge::ChioA2aEdge::new_with_registry(
                    chio_a2a_edge::A2aEdgeConfig {
                        peer_capabilities: peer,
                        ..Default::default()
                    },
                    &registry,
                )?,
            ),
            Protocol::Acp => Frontend::Acp(
                Box::new(kernel),
                chio_acp_edge::ChioAcpEdge::new_with_registry(
                    chio_acp_edge::AcpEdgeConfig {
                        peer_capabilities: peer,
                        ..Default::default()
                    },
                    &registry,
                )?,
            ),
        };
        Ok(Consumer {
            frontend,
            registry,
            authority,
        })
    }
}

struct CountedServer(Arc<AtomicU64>);
#[async_trait::async_trait]
impl ToolServerConnection for CountedServer {
    fn server_id(&self) -> &str {
        SERVER
    }
    fn tool_names(&self) -> Vec<String> {
        vec![TOOL.to_string()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

enum Frontend {
    Native(Box<ChioKernel>),
    Mcp(Box<chio_mcp_edge::ChioMcpEdge>),
    A2a(Box<ChioKernel>, chio_a2a_edge::ChioA2aEdge),
    Acp(Box<ChioKernel>, chio_acp_edge::ChioAcpEdge),
}

pub struct Consumer {
    frontend: Frontend,
    registry: VerifiedManifestRegistry,
    pub authority: SqliteAuthorityStore,
}

pub struct Observed {
    pub receipt: ChioReceipt,
    pub decision: String,
    pub output: Value,
}

impl Consumer {
    pub fn invoke(&mut self, request: &ToolCallRequest) -> TestResult<Observed> {
        let (metadata, output) = match &mut self.frontend {
            Frontend::Native(kernel) => {
                let response =
                    chio_cross_protocol::orchestrator::CrossProtocolOrchestrator::new(
                        kernel,
                        &self.registry,
                    )
                    .with_peer_capabilities(
                        &chio_mcp_edge::authorization::authorization_capabilities(),
                    )?
                    .execute(&NativeBridge, projected_request(request, &self.registry)?)?;
                let output = chio_cross_protocol::execution::pending_approval_result(
                    response.response.verdict,
                    response.response.output.as_ref(),
                )
                .unwrap_or_else(|| match response.response.output.as_ref() {
                    Some(chio_kernel::ToolCallOutput::Value(value)) => value.clone(),
                    _ => Value::Null,
                });
                (response.metadata(), output)
            }
            Frontend::Mcp(edge) => {
                let mut meta = json!({"chioRequestId":request.request_id});
                let value = serde_json::to_value(request)?;
                for (field, target) in [
                    ("approval_tokens", "chioApprovalTokens"),
                    (
                        "threshold_approval_proposal",
                        "chioThresholdApprovalProposal",
                    ),
                    ("governed_intent", "chioGovernedIntent"),
                ] {
                    if let Some(value) = value.get(field) {
                        meta[target] = value.clone();
                    }
                }
                let response = edge.handle_jsonrpc(json!({"jsonrpc":"2.0", "id":request.request_id,
                    "method":"tools/call", "params":{"name":TOOL,"arguments":request.arguments,"_meta":meta}}))
                    .ok_or("MCP tools/call response")?;
                assert!(response.get("error").is_none(), "{response}");
                (
                    response["result"]["_meta"].clone(),
                    response["result"]["structuredContent"].clone(),
                )
            }
            Frontend::A2a(kernel, edge) => {
                let context = chio_a2a_edge::A2aKernelExecutionContext {
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
                };
                let response = edge.handle_send_message_with_request_id(
                    &request.request_id,
                    TOOL,
                    &chio_a2a_edge::SendMessageRequest {
                        message: chio_a2a_edge::A2aMessage {
                            role: "user".to_string(),
                            parts: vec![chio_a2a_edge::A2aPart::Data {
                                data: request.arguments.clone(),
                            }],
                            metadata: None,
                        },
                        metadata: None,
                    },
                    kernel,
                    &context,
                )?;
                let output = response
                    .message
                    .and_then(|message| {
                        message.parts.into_iter().find_map(|part| match part {
                            chio_a2a_edge::A2aPart::Data { data } => Some(data),
                            _ => None,
                        })
                    })
                    .unwrap_or(Value::Null);
                (response.metadata.ok_or("A2A receipt metadata")?, output)
            }
            Frontend::Acp(kernel, edge) => {
                let context = chio_acp_edge::AcpKernelExecutionContext {
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
                };
                let response = edge.invoke_with_request_id(
                    &request.request_id,
                    TOOL,
                    request.arguments.clone(),
                    kernel,
                    &context,
                )?;
                (
                    response.metadata.ok_or("ACP receipt metadata")?,
                    response.data,
                )
            }
        };
        let receipt: ChioReceipt = serde_json::from_value(metadata["chio"]["receipt"].clone())?;
        assert!(receipt.verify_signature()?);
        Ok(Observed {
            receipt,
            decision: metadata["chio"]["decision"]
                .as_str()
                .ok_or("decision")?
                .to_string(),
            output,
        })
    }
}

fn projected_request(
    request: &ToolCallRequest,
    registry: &VerifiedManifestRegistry,
) -> TestResult<chio_cross_protocol::execution::CrossProtocolExecutionRequest> {
    Ok(
        chio_cross_protocol::execution::CrossProtocolExecutionRequest {
            origin_request_id: request.request_id.clone(),
            kernel_request_id: request.request_id.clone(),
            target_protocol: chio_cross_protocol::discovery::DiscoveryProtocol::Native,
            target_server_id: request.server_id.clone(),
            target_tool_name: request.tool_name.clone(),
            agent_id: request.agent_id.clone(),
            arguments: request.arguments.clone(),
            capability: request.capability.clone(),
            source_envelope: json!({}),
            dpop_proof: request.dpop_proof.clone(),
            execution_nonce: request.execution_nonce.clone(),
            governed_intent: request.governed_intent.clone(),
            approval_token: request.approval_token.clone(),
            approval_tokens: request.approval_tokens.clone(),
            threshold_approval_proposal: request.threshold_approval_proposal.clone(),
            supplemental_authorization: request.supplemental_authorization.clone(),
            model_metadata: request.model_metadata.clone(),
            authenticated_session_id: None,
            security_context: None,
            bridge_security: registry
                .bridge_security(SERVER, TOOL)
                .ok_or("manifest binding")?,
        },
    )
}

struct NativeBridge;
impl chio_cross_protocol::capability_bridge::CapabilityBridge for NativeBridge {
    fn source_protocol(&self) -> chio_cross_protocol::discovery::DiscoveryProtocol {
        chio_cross_protocol::discovery::DiscoveryProtocol::Native
    }
    fn extract_capability_ref(
        &self,
        _: &Value,
    ) -> Result<
        Option<chio_cross_protocol::capability_bridge::CrossProtocolCapabilityRef>,
        chio_cross_protocol::error::BridgeError,
    > {
        Ok(None)
    }
    fn inject_capability_ref(
        &self,
        envelope: &mut Value,
        reference: &chio_cross_protocol::capability_bridge::CrossProtocolCapabilityRef,
    ) -> Result<(), chio_cross_protocol::error::BridgeError> {
        envelope["capabilityRef"] = serde_json::to_value(reference).map_err(|error| {
            chio_cross_protocol::error::BridgeError::Canonical(error.to_string())
        })?;
        Ok(())
    }
    fn protocol_context(
        &self,
        _: &Value,
    ) -> Result<Option<Value>, chio_cross_protocol::error::BridgeError> {
        Ok(None)
    }
}
