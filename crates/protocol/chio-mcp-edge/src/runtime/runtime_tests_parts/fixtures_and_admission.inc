fn metrics_test_guard() -> std::sync::MutexGuard<'static, ()> {
    match METRICS_TEST_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn assert_kernel_error_not_counted_as_receipt_write(error: &KernelError) {
    assert_eq!(
        super::receipts::receipt_write_outcome_for_kernel_error(error),
        None
    );
}

fn adapter_authorization_artifacts(
    subject: &Keypair,
    request_id: &str,
) -> (
    Vec<GovernedApprovalToken>,
    ThresholdApprovalProposal,
    OpaqueSupplementalAuthorization,
) {
    let authority = Keypair::from_seed(&[95; 32]);
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody::new(
            "proposal-mcp-preservation",
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
            id: "approval-mcp-preservation".to_string(),
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
        "supplemental-mcp-preservation",
        vec![0x43, 0x48, 0x49, 0x4f],
    )
    .unwrap();
    (vec![token], proposal, supplemental)
}

fn active_response_intent(subject: &Keypair) -> GovernedTransactionIntent {
    let canonical_plan_body = json!({"action":"suspend_session"});
    let plan_body_hash =
        GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body).unwrap();
    GovernedTransactionIntent::active_response_plan(
        GovernedResponsePlanIntentBody::new(
            CHIO_RESPONSE_PLAN_SCHEMA,
            "plan-mcp-preservation",
            "operator-capability-mcp-preservation",
            "55".repeat(32),
            2_000,
            subject.public_key(),
            canonical_plan_body,
            plan_body_hash.clone(),
            json!({"sessionId":"session-mcp-preservation"}),
            vec![GovernedResponseEffect::SuspendSession],
            1_900,
            json!({"responsePlanHash":plan_body_hash}),
        )
        .unwrap(),
    )
}

fn legacy_approval_token(subject: &Keypair, request_id: &str) -> GovernedApprovalToken {
    let approver = Keypair::from_seed(&[96; 32]);
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("legacy-mcp-approval-{request_id}"),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "11".repeat(32),
            threshold_proposal_hash: None,
            request_id: request_id.to_string(),
            issued_at: 1_000,
            expires_at: 1_300,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .unwrap()
}

struct EchoServer;
struct CountingEchoServer {
    invocations: Arc<std::sync::atomic::AtomicUsize>,
}
struct StreamingEchoServer;
struct UrlRequiredServer;
struct CancelledServer;
struct RouteSelectionAdmissionHook;
struct AllowingSecurityPreDispatchHook;

impl SecurityPreDispatchHook for AllowingSecurityPreDispatchHook {
    fn name(&self) -> &str {
        "mcp-test-security-pre-dispatch"
    }

    fn commit(
        &self,
        _context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

struct TestSecurityInvocationContextAuthority {
    resolution_count: Arc<std::sync::atomic::AtomicUsize>,
    mismatched_session: bool,
}

impl SecurityInvocationContextAuthority for TestSecurityInvocationContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        self.resolution_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let session_id = if self.mismatched_session {
            "mcp-mismatched-session".to_string()
        } else {
            context.session_id.as_str().to_string()
        };
        Ok(SecurityInvocationContext::v1(
            SecurityInvocationContextV1::new(
                chio_security_types::ports::TenantId::new("tenant-mcp-test")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::SessionId::new(session_id)
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::PrincipalId::new(context.agent_id.clone())
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::IsolationEpochId::new("epoch-mcp-test")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                chio_security_types::ports::LineageId::new(
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
#[derive(Default)]
struct AsyncEventServer {
    events: Mutex<Vec<ToolServerEvent>>,
}
struct AsyncEventServerConnection(Arc<AsyncEventServer>);
struct DocsResourceProvider;
struct ExamplePromptProvider;

fn url_required_kernel_error() -> KernelError {
    KernelError::UrlElicitationsRequired {
        message: "URL elicitation is required for this operation".to_string(),
        elicitations: vec![CreateElicitationOperation::Url {
            meta: None,
            message: "Complete authorization in your browser".to_string(),
            url: "https://example.com/authorize".to_string(),
            elicitation_id: "elicit-auth".to_string(),
        }],
    }
}

fn cancelled_kernel_error() -> KernelError {
    KernelError::RequestCancelled {
        request_id: chio_core::session::RequestId::new("direct-bridge-cancelled"),
        reason: "cancelled by direct bridge test".to_string(),
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "echo_json".to_string(),
        ]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        match tool_name {
            "echo_json" => Ok(json!({
                "temperature": 22.5,
                "conditions": "Partly cloudy",
            })),
            _ => Ok(json!({
                "tool": tool_name,
                "arguments": arguments,
            })),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingEchoServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "echo_json".to_string(),
        ]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for StreamingEchoServer {
    fn server_id(&self) -> &str {
        "stream-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "stream_file".to_string(),
            "stream_file_incomplete".to_string(),
        ]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "tool": tool_name,
            "arguments": arguments,
            "fallback": true,
        }))
    }

    async fn invoke_stream(
        &self,
        tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let stream = ToolCallStream {
            chunks: vec![
                ToolCallChunk {
                    data: json!({"type": "text", "text": "chunk one"}),
                },
                ToolCallChunk {
                    data: json!({"type": "text", "text": "chunk two"}),
                },
            ],
        };

        let result = match tool_name {
            "stream_file" => ToolServerStreamResult::Complete(stream),
            "stream_file_incomplete" => ToolServerStreamResult::Incomplete {
                stream,
                reason: "upstream stream interrupted".to_string(),
            },
            _ => return Ok(None),
        };

        Ok(Some(result))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for UrlRequiredServer {
    fn server_id(&self) -> &str {
        "url-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["authorize".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(url_required_kernel_error())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CancelledServer {
    fn server_id(&self) -> &str {
        "cancel-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["cancel".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(cancelled_kernel_error())
    }
}

impl AsyncEventServer {
    fn push_event(&self, event: ToolServerEvent) {
        self.events.lock().unwrap().push(event);
    }
}

impl RuntimeAdmissionHook for RouteSelectionAdmissionHook {
    fn name(&self) -> &str {
        "test-route-selection-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let selected_route = context
            .extra_metadata
            .and_then(|metadata| metadata.get("route_selection"))
            .and_then(|route| route.get("selectedRouteId"))
            .and_then(Value::as_str);
        if selected_route == Some("mcp:task-child-a") {
            Ok(RuntimeAdmissionDecision::allow(None))
        } else {
            Ok(RuntimeAdmissionDecision::deny(
                "route selection metadata missing",
                None,
            ))
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for AsyncEventServerConnection {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "echo_json".to_string(),
        ]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "tool": tool_name,
            "arguments": arguments,
        }))
    }

    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        let mut events = self.0.events.lock().unwrap();
        Ok(std::mem::take(&mut *events))
    }
}

impl ResourceProvider for DocsResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "repo://docs/roadmap".to_string(),
                name: "Roadmap".to_string(),
                title: Some("Roadmap".to_string()),
                description: Some("Project roadmap".to_string()),
                mime_type: Some("text/markdown".to_string()),
                size: Some(128),
                annotations: Some(json!({"audience": "engineering"})),
                icons: None,
            },
            ResourceDefinition {
                uri: "repo://secret/ops".to_string(),
                name: "Ops Secret".to_string(),
                title: None,
                description: Some("Should be filtered".to_string()),
                mime_type: Some("text/plain".to_string()),
                size: None,
                annotations: None,
                icons: None,
            },
        ]
    }

    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        vec![ResourceTemplateDefinition {
            uri_template: "repo://docs/{slug}".to_string(),
            name: "Doc Template".to_string(),
            title: None,
            description: Some("Parameterized docs resource".to_string()),
            mime_type: Some("text/markdown".to_string()),
            annotations: None,
            icons: None,
        }]
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        match uri {
            "repo://docs/roadmap" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Roadmap".to_string()),
                blob: None,
                annotations: None,
            }])),
            _ => Ok(None),
        }
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        if uri == "repo://docs/{slug}" && argument_name == "slug" {
            let values = ["roadmap", "architecture", "api"]
                .into_iter()
                .filter(|candidate| candidate.starts_with(value))
                .map(str::to_string)
                .collect::<Vec<_>>();
            return Ok(Some(CompletionResult {
                total: Some(values.len() as u32),
                has_more: false,
                values,
            }));
        }

        Ok(None)
    }
}

struct FilesystemResourceProvider;

impl ResourceProvider for FilesystemResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "file:///workspace/project/docs/roadmap.md".to_string(),
                name: "Filesystem Roadmap".to_string(),
                title: Some("Filesystem Roadmap".to_string()),
                description: Some("In-root file-backed resource".to_string()),
                mime_type: Some("text/markdown".to_string()),
                size: Some(64),
                annotations: None,
                icons: None,
            },
            ResourceDefinition {
                uri: "file:///workspace/private/ops.md".to_string(),
                name: "Filesystem Ops".to_string(),
                title: None,
                description: Some("Out-of-root file-backed resource".to_string()),
                mime_type: Some("text/plain".to_string()),
                size: Some(32),
                annotations: None,
                icons: None,
            },
        ]
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        match uri {
            "file:///workspace/project/docs/roadmap.md" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Filesystem Roadmap".to_string()),
                blob: None,
                annotations: None,
            }])),
            "file:///workspace/private/ops.md" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("ops".to_string()),
                blob: None,
                annotations: None,
            }])),
            _ => Ok(None),
        }
    }
}

impl PromptProvider for ExamplePromptProvider {
    fn list_prompts(&self) -> Vec<PromptDefinition> {
        vec![
            PromptDefinition {
                name: "summarize_docs".to_string(),
                title: Some("Summarize Docs".to_string()),
                description: Some("Summarize a documentation resource".to_string()),
                arguments: vec![PromptArgument {
                    name: "topic".to_string(),
                    title: None,
                    description: Some("Topic to summarize".to_string()),
                    required: Some(true),
                }],
                icons: None,
            },
            PromptDefinition {
                name: "ops_secret".to_string(),
                title: None,
                description: Some("Should be filtered".to_string()),
                arguments: vec![],
                icons: None,
            },
        ]
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Option<PromptResult>, KernelError> {
        match name {
            "summarize_docs" => Ok(Some(PromptResult {
                description: Some("Summarize docs".to_string()),
                messages: vec![PromptMessage {
                    role: "user".to_string(),
                    content: json!({
                        "type": "text",
                        "text": format!(
                            "Summarize {}",
                            arguments["topic"].as_str().unwrap_or("the docs")
                        ),
                    }),
                }],
            })),
            _ => Ok(None),
        }
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        if name == "summarize_docs" && argument_name == "topic" {
            let values = ["roadmap", "architecture", "release-plan"]
                .into_iter()
                .filter(|candidate| candidate.starts_with(value))
                .map(str::to_string)
                .collect::<Vec<_>>();
            return Ok(Some(CompletionResult {
                total: Some(values.len() as u32),
                has_more: false,
                values,
            }));
        }

        Ok(None)
    }
}

fn make_kernel() -> (ChioKernel, Keypair) {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
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
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(EchoServer));
    kernel.register_resource_provider(Box::new(DocsResourceProvider));
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));
    (kernel, keypair)
}

fn make_web3_required_kernel() -> (ChioKernel, Keypair) {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: true,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(EchoServer));
    (kernel, keypair)
}

fn make_kernel_error_bridge_fixture(
    server: Box<dyn ToolServerConnection>,
    server_id: &str,
    tool_name: &str,
    request_id: &str,
) -> (ChioKernel, BridgeMcpToolCallRequest) {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: true,
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
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(server);
    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
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
            300,
        )
        .unwrap();
    let request = BridgeMcpToolCallRequest {
        request_id: request_id.to_string(),
        capability,
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        arguments: json!({}),
        agent_id: agent.public_key().to_hex(),
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        route_selection_metadata: None,
        peer_supports_chio_tool_streaming: false,
    };
    (kernel, request)
}

fn make_streaming_kernel() -> (ChioKernel, Keypair) {
    let (mut kernel, keypair) = make_kernel();
    kernel.register_tool_server(Box::new(StreamingEchoServer));
    (kernel, keypair)
}

fn issue_capabilities(kernel: &ChioKernel, agent: &Keypair) -> Vec<CapabilityToken> {
    issue_capabilities_with_resource_operations(kernel, agent, vec![Operation::Read])
}

fn issue_aggregate_family_capability(
    kernel: &ChioKernel,
    issuer: &Keypair,
    subject: &Keypair,
) -> CapabilityToken {
    let base = issue_capabilities(kernel, subject).remove(0);
    let mut scope = base.scope;
    scope
        .grants
        .iter_mut()
        .find(|grant| grant.server_id == "srv" && grant.tool_name == "read_file")
        .expect("read_file grant")
        .operations
        .push(Operation::Delegate);
    issue_aggregate_family_root(
        CapabilityTokenBody {
            id: "cap-aggregate-mcp-preservation".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope,
            issued_at: base.issued_at,
            expires_at: base.expires_at,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        3,
        issuer,
    )
    .expect("aggregate family capability should sign")
}

fn issue_streaming_capabilities(kernel: &ChioKernel, agent: &Keypair) -> Vec<CapabilityToken> {
    let mut capabilities = issue_capabilities(kernel, agent);
    capabilities.push(
        kernel
            .issue_capability(
                &agent.public_key(),
                ChioScope {
                    grants: vec![
                        ToolGrant {
                            server_id: "stream-srv".to_string(),
                            tool_name: "stream_file".to_string(),
                            operations: vec![Operation::Invoke],
                            constraints: vec![],
                            max_invocations: None,
                            max_cost_per_invocation: None,
                            max_total_cost: None,
                            dpop_required: None,
                        },
                        ToolGrant {
                            server_id: "stream-srv".to_string(),
                            tool_name: "stream_file_incomplete".to_string(),
                            operations: vec![Operation::Invoke],
                            constraints: vec![],
                            max_invocations: None,
                            max_cost_per_invocation: None,
                            max_total_cost: None,
                            dpop_required: None,
                        },
                    ],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap(),
    );
    capabilities
}

fn issue_capabilities_with_resource_operations(
    kernel: &ChioKernel,
    agent: &Keypair,
    resource_operations: Vec<Operation>,
) -> Vec<CapabilityToken> {
    issue_capabilities_with_resource_grants(
        kernel,
        agent,
        vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: resource_operations,
        }],
    )
}

fn issue_capabilities_with_resource_grants(
    kernel: &ChioKernel,
    agent: &Keypair,
    resource_grants: Vec<ResourceGrant>,
) -> Vec<CapabilityToken> {
    vec![kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![
                    ToolGrant {
                        server_id: "srv".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    },
                    ToolGrant {
                        server_id: "srv".to_string(),
                        tool_name: "echo_json".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    },
                ],
                resource_grants,
                prompt_grants: vec![PromptGrant {
                    prompt_name: "summarize_*".to_string(),
                    operations: vec![Operation::Get],
                }],
            },
            300,
        )
        .unwrap()]
}

fn issue_model_constrained_capability(kernel: &ChioKernel, agent: &Keypair) -> CapabilityToken {
    kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "read_file".to_string(),
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
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            300,
        )
        .unwrap()
}

fn sample_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.into(),
        server_id: "srv".into(),
        name: "Test Server".into(),
        description: Some("test".into()),
        version: "0.1.0".into(),
        tools: vec![
            ToolDefinition {
                name: "read_file".into(),
                description: "Read a file".into(),
                input_schema: json!({"type": "object"}),
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
            },
            ToolDefinition {
                name: "echo_json".into(),
                description: "Return a JSON object".into(),
                input_schema: json!({"type": "object"}),
                output_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "temperature": { "type": "number" },
                        "conditions": { "type": "string" }
                    }
                })),
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: Some(LatencyHint::Moderate),
                flow: None,
            },
            ToolDefinition {
                name: "write_file".into(),
                description: "Write a file".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: false,
                    destructive: true,
                    idempotent: false,
                    requires_approval: true,
                },
                latency_hint: Some(LatencyHint::Slow),
                flow: None,
            },
        ],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: Keypair::from_seed(&[7u8; 32]).public_key().to_hex(),
    }
}

fn edge_with_read_file_schema(
    input_schema: Value,
) -> Result<(ChioMcpEdge, Arc<std::sync::atomic::AtomicUsize>), AdapterError> {
    let (mut kernel, _) = make_kernel();
    let invocations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingEchoServer {
        invocations: Arc::clone(&invocations),
    }));
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    let mut manifest = sample_manifest();
    manifest.tools[0].input_schema = input_schema;
    ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![manifest],
    )
    .map(|edge| (edge, invocations))
}

fn verified_sample_registry(
    topology: chio_manifest::RuntimeToolTopology,
) -> chio_manifest::VerifiedManifestRegistry {
    let signer = Keypair::from_seed(&[7u8; 32]);
    let signed = chio_manifest::sign_manifest(&sample_manifest(), &signer)
        .unwrap_or_else(|error| panic!("sign MCP edge test manifest: {error}"));
    let mut registry = chio_manifest::VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), topology)
        .unwrap_or_else(|error| panic!("register MCP edge test manifest: {error}"));
    registry
}

fn enforced_context_edge(
    mismatched_session: bool,
) -> (ChioMcpEdge, Arc<std::sync::atomic::AtomicUsize>) {
    let (mut kernel, _) = make_kernel();
    kernel.set_security_pre_dispatch_hook(Arc::new(AllowingSecurityPreDispatchHook));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    let registry = verified_sample_registry(chio_manifest::RuntimeToolTopology::local());
    let resolution_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let authority = Arc::new(TestSecurityInvocationContextAuthority {
        resolution_count: Arc::clone(&resolution_count),
        mismatched_session,
    });
    let edge = ChioMcpEdge::new_with_security_context_authority(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        &registry,
        authority,
    )
    .unwrap_or_else(|error| panic!("construct enforced MCP edge: {error}"));
    (edge, resolution_count)
}

#[test]
fn production_edge_rejects_flow_required_registry_without_governed_runtime() {
    let (kernel, _) = make_kernel();
    let registry = verified_sample_registry(chio_manifest::RuntimeToolTopology::remote());
    let result = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        Keypair::generate().public_key().to_hex(),
        Vec::new(),
        &registry,
    );

    assert!(matches!(
        result,
        Err(AdapterError::FlowManifestRequiresRuntime)
    ));
}

#[test]
fn production_edge_accepts_local_registry_without_governed_runtime() {
    let (kernel, _) = make_kernel();
    let registry = verified_sample_registry(chio_manifest::RuntimeToolTopology::local());
    let result = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        Keypair::generate().public_key().to_hex(),
        Vec::new(),
        &registry,
    );

    assert!(result.is_ok());
}

#[test]
fn enforced_kernel_edge_rejects_missing_security_context_authority() {
    let (mut kernel, _) = make_kernel();
    kernel.set_security_pre_dispatch_hook(Arc::new(AllowingSecurityPreDispatchHook));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let registry = verified_sample_registry(chio_manifest::RuntimeToolTopology::local());
    let result = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        Keypair::generate().public_key().to_hex(),
        Vec::new(),
        &registry,
    );

    assert!(matches!(
        result,
        Err(AdapterError::SecurityInvocationContextAuthorityRequired)
    ));
}

#[test]
fn enforced_kernel_edge_resolves_authoritative_context_for_each_dispatch() {
    let (mut edge, resolution_count) = enforced_context_edge(false);
    initialize_edge(&mut edge);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/contextual.txt" }
            }
        }))
        .unwrap_or_else(|| panic!("MCP contextual dispatch returned no response"));

    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        resolution_count.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn enforced_kernel_edge_rejects_authoritative_context_for_another_session() {
    let (mut edge, resolution_count) = enforced_context_edge(true);
    initialize_edge(&mut edge);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/contextual.txt" }
            }
        }))
        .unwrap_or_else(|| panic!("MCP mismatched-context dispatch returned no response"));

    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"]["content"]
        .to_string()
        .contains("authoritative security context does not match the authenticated session"));
    assert_eq!(
        resolution_count.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

fn streaming_manifest() -> ToolManifest {
    ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.into(),
        server_id: "stream-srv".into(),
        name: "Streaming Test Server".into(),
        description: Some("streaming test".into()),
        version: "0.1.0".into(),
        tools: vec![
            ToolDefinition {
                name: "stream_file".into(),
                description: "Return streamed chunks".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: Some(LatencyHint::Moderate),
                flow: None,
            },
            ToolDefinition {
                name: "stream_file_incomplete".into(),
                description: "Return streamed chunks then terminate incomplete".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: Some(LatencyHint::Slow),
                flow: None,
            },
        ],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: Keypair::from_seed(&[8u8; 32]).public_key().to_hex(),
    }
}

#[test]
fn edge_rejects_manifest_with_unsupported_schema_version() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let mut manifest = sample_manifest();
    manifest.schema = "chio.manifest.v0".into();
    manifest.public_key = Keypair::from_seed(&[11u8; 32]).public_key().to_hex();

    let err = match ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        vec![],
        vec![manifest],
    ) {
        Ok(_) => panic!("MCP edge discovery must reject unsupported manifest schema versions"),
        Err(err) => err,
    };

    assert!(matches!(
        err,
        AdapterError::ManifestError(chio_manifest::ManifestError::UnsupportedSchema(schema))
            if schema == "chio.manifest.v0"
    ));
}

#[test]
fn edge_rejects_non_object_manifest_input_schema() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let mut manifest = sample_manifest();
    manifest.tools[0].input_schema = json!("not an object");

    let err = match ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        vec![],
        vec![manifest],
    ) {
        Ok(_) => panic!("MCP edge discovery must reject non-object inputSchema"),
        Err(err) => err,
    };

    assert!(matches!(
        err,
        AdapterError::ManifestError(chio_manifest::ManifestError::InvalidInputSchema(tool_name))
            if tool_name == "read_file"
    ));
}

#[test]
fn edge_rejects_non_object_manifest_output_schema() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let mut manifest = sample_manifest();
    manifest.tools[1].output_schema = Some(json!(["not", "an", "object"]));

    let err = match ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        vec![],
        vec![manifest],
    ) {
        Ok(_) => panic!("MCP edge discovery must reject non-object outputSchema"),
        Err(err) => err,
    };

    assert!(matches!(
        err,
        AdapterError::ManifestError(chio_manifest::ManifestError::InvalidOutputSchema(tool_name))
            if tool_name == "echo_json"
    ));
}

#[test]
fn edge_rejects_invalid_manifest_input_schema_at_startup() {
    let err = match edge_with_read_file_schema(json!({"type": 42})) {
        Ok(_) => panic!("MCP edge discovery must reject an invalid inputSchema"),
        Err(err) => err,
    };

    assert!(matches!(
        err,
        AdapterError::ParseError(message)
            if message.contains("read_file") && message.contains("inputSchema is invalid")
    ));
}

#[test]
fn edge_rejects_external_manifest_schema_references_before_startup() {
    for keyword in ["$ref", "$dynamicRef"] {
        let mut referenced_schema = json!({"type": "string"});
        referenced_schema.as_object_mut().unwrap().insert(
            keyword.to_string(),
            json!("https://schemas.example/remote.json"),
        );
        let input_schema = json!({
            "type": "object",
            "properties": {
                "message": referenced_schema
            }
        });

        let err = match edge_with_read_file_schema(input_schema) {
            Ok(_) => panic!("MCP edge discovery must reject external {keyword}"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            AdapterError::ParseError(message)
                if message.contains(keyword) && message.contains("local fragment reference")
        ));
    }
}

#[test]
fn edge_rejects_local_recursive_ref_under_draft_2020_12() {
    let input_schema = json!({
        "type": "object",
        "properties": {
            "child": {"$recursiveRef": "#"}
        }
    });

    let err = match edge_with_read_file_schema(input_schema) {
        Ok(_) => panic!("MCP edge discovery must reject local $recursiveRef"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        AdapterError::ParseError(message)
            if message.contains("$recursiveRef") && message.contains("Draft 2020-12")
    ));
}

#[test]
fn tools_call_enforces_compiled_input_schema_before_kernel_effects() {
    let (mut edge, invocations) = edge_with_read_file_schema(json!({
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
    }))
    .unwrap();
    initialize_edge(&mut edge);
    let receipt_count = edge.kernel.receipt_log().len();
    let invalid_arguments = [
        ("missing arguments", None),
        ("null arguments", Some(Value::Null)),
        ("array arguments", Some(json!([]))),
        ("string arguments", Some(json!("message"))),
        ("missing required property", Some(json!({}))),
        ("wrong property type", Some(json!({"message": true}))),
        ("empty string", Some(json!({"message": ""}))),
        ("ASCII over maximum", Some(json!({"message": "abcde"}))),
        (
            "Unicode over maximum",
            Some(json!({"message": "🧪🧪🧪🧪🧪"})),
        ),
        (
            "additional property",
            Some(json!({"message": "ok", "extra": true})),
        ),
    ];

    for (index, (case, arguments)) in invalid_arguments.into_iter().enumerate() {
        let mut params = json!({"name": "read_file"});
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        let response = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 100 + index,
                "method": "tools/call",
                "params": params
            }))
            .unwrap();
        assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS, "{case}");
        assert_eq!(
            edge.kernel.receipt_log().len(),
            receipt_count,
            "{case} must not reach receipt effects"
        );
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{case} must not invoke the tool server"
        );
    }

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 200,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"message": "🧪🧪🧪🧪"}
            }
        }))
        .unwrap();
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a valid call after rejections must still invoke the tool"
    );
}

fn make_edge(page_size: usize) -> ChioMcpEdge {
    make_edge_with_config(page_size, false)
}

fn make_model_constrained_edge(page_size: usize) -> ChioMcpEdge {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = vec![issue_model_constrained_capability(&kernel, &agent)];
    ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled: false,
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

fn run_stdio_session(edge: &mut ChioMcpEdge, messages: &[Value]) -> Vec<Value> {
    let mut input = String::new();
    for message in messages {
        input.push_str(&serde_json::to_string(message).unwrap());
        input.push('\n');
    }
    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.into_bytes()), &mut output)
        .unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

fn run_channel_session(edge: &mut ChioMcpEdge, messages: &[Value]) -> Vec<Value> {
    let (tx, rx) = std::sync::mpsc::channel();
    for message in messages {
        tx.send(message.clone()).unwrap();
    }
    drop(tx);

    let mut output = Vec::new();
    edge.serve_message_channels(rx, &mut output).unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

fn normalize_transport_output(messages: &mut [Value]) {
    for message in messages {
        normalize_dynamic_transport_fields(message);
    }
}

fn normalize_dynamic_transport_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(owner_session_id) = map.get_mut("ownerSessionId") {
                *owner_session_id = json!("$session");
            }
            // The two transports capture wall-clock timestamps independently;
            // a tick across a second boundary between the stdio and channel
            // runs causes assert_eq! to flake. The shape comparison is what
            // matters, so collapse the captured instants to a sentinel.
            for field in ["createdAt", "lastUpdatedAt"] {
                if let Some(ts) = map.get_mut(field) {
                    *ts = json!("$timestamp");
                }
            }
            for child in map.values_mut() {
                normalize_dynamic_transport_fields(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                normalize_dynamic_transport_fields(child);
            }
        }
        _ => {}
    }
}

fn make_edge_with_config(page_size: usize, logging_enabled: bool) -> ChioMcpEdge {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled,
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

fn make_edge_with_route_selection_admission(page_size: usize) -> ChioMcpEdge {
    let (mut kernel, _) = make_kernel();
    kernel.set_runtime_admission_hook(Arc::new(RouteSelectionAdmissionHook));
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled: false,
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

fn initialize_edge(edge: &mut ChioMcpEdge) {
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
}

fn threshold_and_broker_protocol_features() -> CapabilityNegotiation {
    let mut features = CapabilityNegotiation::t1_default();
    features
        .features
        .insert(AGGREGATE_INVOCATION_BUDGET.to_string(), true);
    features
        .features
        .insert(THRESHOLD_GOVERNED_APPROVALS.to_string(), true);
    features
        .features
        .insert(GOVERNED_ACTIVE_RESPONSE_PLAN.to_string(), true);
    features
        .features
        .insert(SUPPLEMENTAL_BROKER_EXECUTION_QUOTA.to_string(), true);
    features
}

fn initialize_edge_with_protocol_features(
    edge: &mut ChioMcpEdge,
    features: &CapabilityNegotiation,
) {
    edge.set_local_protocol_features(features.clone()).unwrap();
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "experimental": {
                    "chioProtocol": {
                        "capabilityNegotiation": features
                    }
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
}
