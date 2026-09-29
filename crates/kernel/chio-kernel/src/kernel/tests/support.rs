use super::*;


















static UNIQUE_RECEIPT_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) fn make_keypair() -> Keypair {
    Keypair::generate()
}

#[path = "support_kernel_config.rs"]
mod kernel_config;
pub(super) use kernel_config::{make_config, make_kernel};

pub(super) fn make_signed_receipt(kp: &Keypair, id: &str) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_100,
            capability_id: "cap-receipt".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"message": "hello"}))
                .expect("tool action"),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "0".repeat(64),
            policy_hash: "1".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        },
        kp,
    )
    .expect("sign receipt")
}

pub(super) fn unique_receipt_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let counter = UNIQUE_RECEIPT_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nonce}-{counter}.sqlite3",
        std::process::id()
    ))
}

pub(super) fn make_elicited_content() -> CreateElicitationResult {
    CreateElicitationResult {
        action: chio_core::session::ElicitationAction::Accept,
        content: Some(serde_json::json!({
            "environment": "staging",
        })),
    }
}

pub(super) fn make_grant(server: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

pub(super) fn make_scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

pub(super) fn make_capability(
    kernel: &ChioKernel,
    subject_kp: &Keypair,
    scope: ChioScope,
    ttl: u64,
) -> CapabilityToken {
    kernel
        .issue_capability(&subject_kp.public_key(), scope, ttl)
        .unwrap()
}

pub(super) fn make_direct_attenuated_capability(
    issuer: &Keypair,
    subject: &PublicKey,
    scope: ChioScope,
) -> CapabilityToken {
    let now = current_unix_timestamp();
    let parent_hash = scope_hash(&scope).expect("hash parent scope");
    let child_hash = scope_hash(&scope).expect("hash child scope");
    let witness = compute_attenuation_witness(&scope, &scope).expect("compute attenuation witness");
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "cap-direct-attenuated".to_string(),
                issuer: issuer.public_key(),
                subject: subject.clone(),
                scope,
                issued_at: now.saturating_sub(60),
                expires_at: now.saturating_add(300),
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash: parent_hash,
                child_scope_hash: child_hash,
                normalized_subset_proof: witness,
            },
            budget_share_bps: None,
        },
        issuer,
    )
    .expect("sign attenuated capability")
}

pub(super) fn make_request(
    request_id: &str,
    cap: &CapabilityToken,
    tool: &str,
    server: &str,
) -> ToolCallRequest {
    make_request_with_arguments(
        request_id,
        cap,
        tool,
        server,
        serde_json::json!({"path": "/app/src/main.rs"}),
    )
}

pub(super) fn make_request_with_arguments(
    request_id: &str,
    cap: &CapabilityToken,
    tool: &str,
    server: &str,
    arguments: serde_json::Value,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: cap.subject.to_hex(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

pub(super) fn make_operation_context(
    session_id: &SessionId,
    request_id: &str,
    agent_id: &str,
) -> OperationContext {
    OperationContext::new(
        session_id.clone(),
        RequestId::new(request_id),
        agent_id.to_string(),
    )
}

pub(super) fn session_tool_call(response: SessionOperationResponse) -> Option<ToolCallResponse> {
    if let SessionOperationResponse::ToolCall(response) = response {
        Some(response)
    } else {
        None
    }
}

pub(super) fn session_capability_list(response: SessionOperationResponse) -> Option<Vec<CapabilityToken>> {
    if let SessionOperationResponse::CapabilityList { capabilities } = response {
        Some(capabilities)
    } else {
        None
    }
}

pub(super) fn session_root_list(response: SessionOperationResponse) -> Option<Vec<RootDefinition>> {
    if let SessionOperationResponse::RootList { roots } = response {
        Some(roots)
    } else {
        None
    }
}

pub(super) fn session_resource_list(response: SessionOperationResponse) -> Option<Vec<ResourceDefinition>> {
    if let SessionOperationResponse::ResourceList { resources } = response {
        Some(resources)
    } else {
        None
    }
}

pub(super) fn session_resource_read(response: SessionOperationResponse) -> Option<Vec<ResourceContent>> {
    if let SessionOperationResponse::ResourceRead { contents } = response {
        Some(contents)
    } else {
        None
    }
}

pub(super) fn session_prompt_list(response: SessionOperationResponse) -> Option<Vec<PromptDefinition>> {
    if let SessionOperationResponse::PromptList { prompts } = response {
        Some(prompts)
    } else {
        None
    }
}

pub(super) fn session_prompt_get(response: SessionOperationResponse) -> Option<PromptResult> {
    if let SessionOperationResponse::PromptGet { prompt } = response {
        Some(prompt)
    } else {
        None
    }
}

pub(super) fn session_completion(response: SessionOperationResponse) -> Option<CompletionResult> {
    if let SessionOperationResponse::Completion { completion } = response {
        Some(completion)
    } else {
        None
    }
}

pub(super) fn tool_call_value_output(output: Option<ToolCallOutput>) -> Option<serde_json::Value> {
    if let Some(ToolCallOutput::Value(value)) = output {
        Some(value)
    } else {
        None
    }
}

pub(super) fn tool_call_stream_output(output: Option<ToolCallOutput>) -> Option<ToolCallStream> {
    if let Some(ToolCallOutput::Stream(stream)) = output {
        Some(stream)
    } else {
        None
    }
}

pub(super) fn assert_content_addressed_receipt_id(id: &str) {
    assert_eq!(id.len(), 64, "receipt id should be a SHA-256 hex digest");
    assert!(
        id.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "receipt id should be lowercase hex"
    );
}

pub(super) fn make_chain_bound_delegation_link(
    capability_id: &str,
    delegator_kp: &Keypair,
    delegatee: &PublicKey,
    authorized_scope: &ChioScope,
    timestamp: u64,
) -> DelegationLink {
    DelegationLink::sign(
        DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator_kp.public_key(),
            delegatee: delegatee.clone(),
            attenuations: vec![],
            timestamp,
            scope_hash: Some(scope_hash(authorized_scope).unwrap()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        delegator_kp,
    )
    .unwrap()
}

pub(super) fn make_chain_bound_capability(
    kernel: &ChioKernel,
    id: &str,
    subject: PublicKey,
    scope: ChioScope,
    delegation_chain: Vec<DelegationLink>,
    proof_parent_scope: &ChioScope,
    budget_share_bps: Option<u16>,
) -> CapabilityToken {
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(proof_parent_scope).unwrap(),
        child_scope_hash: scope_hash(&scope).unwrap(),
        normalized_subset_proof: compute_attenuation_witness(proof_parent_scope, &scope).unwrap(),
    };
    // Keep the delegated child strictly inside its parent's lifetime. The parent
    // helpers issue a 300s window; capture the clock once and use a shorter child
    // window so a sub-second tick between the parent's and child's timestamp reads
    // cannot make the child outlive the parent, which validate_delegation_admission
    // rejects before the scope checks these tests assert on.
    let issued_at = current_unix_timestamp();
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: id.to_string(),
                issuer: kernel.config.keypair.public_key(),
                subject,
                scope,
                issued_at,
                expires_at: issued_at.saturating_add(120),
                delegation_chain,
                aggregate_invocation_budget: None,
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps,
        },
        &kernel.config.keypair,
    )
    .unwrap()
}

pub(super) fn set_capability_trust_root_for_scope(kernel: &ChioKernel, scope: &ChioScope) {
    kernel.set_capability_trust_root(
        kernel.config.keypair.public_key(),
        scope_hash(scope).unwrap(),
    );
}

pub(super) struct V2DelegatedChildInput<'a> {
    pub(super) kernel: &'a ChioKernel,
    pub(super) parent: &'a CapabilityToken,
    pub(super) parent_kp: &'a Keypair,
    pub(super) child_kp: &'a Keypair,
    pub(super) parent_scope: &'a ChioScope,
    pub(super) child_scope: ChioScope,
    pub(super) id: &'a str,
    pub(super) share_bps: u16,
}

pub(super) fn make_v2_delegated_child(input: V2DelegatedChildInput<'_>) -> CapabilityToken {
    let parent_scope_hash = scope_hash(input.parent_scope).unwrap();
    let child_scope_hash = scope_hash(&input.child_scope).unwrap();
    let issued_at = current_unix_timestamp();
    let expires_at = issued_at.saturating_add(300).min(input.parent.expires_at);
    let proof = AttenuationProof {
        parent_scope_hash: parent_scope_hash.clone(),
        child_scope_hash,
        normalized_subset_proof: compute_attenuation_witness(
            input.parent_scope,
            &input.child_scope,
        )
        .unwrap(),
    };
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: input.parent.id.clone(),
            delegator: input.parent_kp.public_key(),
            delegatee: input.child_kp.public_key(),
            attenuations: vec![],
            timestamp: current_unix_timestamp(),
            scope_hash: Some(parent_scope_hash),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        input.parent_kp,
    )
    .unwrap();

    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: input.id.to_string(),
                issuer: input.kernel.config.keypair.public_key(),
                subject: input.child_kp.public_key(),
                scope: input.child_scope,
                issued_at,
                expires_at,
                delegation_chain: vec![link],
                aggregate_invocation_budget: None,
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: Some(input.share_bps),
        },
        &input.kernel.config.keypair,
    )
    .unwrap()
}

pub(super) struct EchoServer {
    pub(super) id: String,
    pub(super) tools: Vec<String>,
}

pub(super) struct SideEffectServer {
    pub(super) id: String,
    pub(super) tools: Vec<String>,
    pub(super) invocations: std::sync::Arc<AtomicU64>,
}

pub(super) struct IncompleteServer {
    pub(super) id: String,
}

pub(super) struct StreamingServer {
    pub(super) id: String,
    pub(super) chunks: Vec<serde_json::Value>,
}

pub(super) struct EventDrainServer {
    pub(super) id: String,
    events: Vec<ToolServerEvent>,
}

pub(super) struct FailingEventDrainServer {
    pub(super) id: String,
}

pub(super) struct NestedFlowServer {
    pub(super) id: String,
}

pub(super) struct MockNestedFlowClient {
    pub(super) roots: Vec<RootDefinition>,
    pub(super) sampled_message: CreateMessageResult,
    pub(super) elicited_content: CreateElicitationResult,
    pub(super) cancel_parent_on_create_message: bool,
    pub(super) cancel_child_on_create_message: bool,
    pub(super) completed_elicitation_ids: Vec<String>,
    pub(super) resource_updates: Vec<String>,
    pub(super) resources_list_changed_count: u32,
}

pub(super) struct DocsResourceProvider;
pub(super) struct StubPaymentAdapter;
pub(super) struct DecliningPaymentAdapter;
pub(super) struct PrepaidSettledPaymentAdapter;

impl EchoServer {
    pub(super) fn new(id: &str, tools: Vec<&str>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
        }
    }
}

impl SideEffectServer {
    pub(super) fn new(id: &str, tools: Vec<&str>, invocations: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            invocations,
        }
    }
}

impl EventDrainServer {
    pub(super) fn new(id: &str, events: Vec<ToolServerEvent>) -> Self {
        Self {
            id: id.to_string(),
            events,
        }
    }
}

impl FailingEventDrainServer {
    pub(super) fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PaymentAdapter for StubPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "auth_stub".to_string(),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({ "adapter": "stub" }),
        })
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: "txn_stub".to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "stub" }),
        })
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: "release_stub".to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "stub" }),
        })
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: "refund_stub".to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "stub" }),
        })
    }
}

impl PaymentAdapter for DecliningPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Err(PaymentError::InsufficientFunds)
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "capture should not run".to_string(),
        ))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "release should not run".to_string(),
        ))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("refund should not run".to_string()))
    }
}

impl PaymentAdapter for PrepaidSettledPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "x402_txn_paid".to_string(),
            state: PaymentAuthorizationState::PrepaidFinal,
            metadata: serde_json::json!({ "adapter": "x402" }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "x402" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "x402" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "x402" }),
        })
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        &self.id
    }
    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }
    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for SideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for EventDrainServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolNotRegistered(tool_name.to_string()))
    }

    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Ok(self.events.clone())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for FailingEventDrainServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolNotRegistered(tool_name.to_string()))
    }

    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Err(KernelError::Internal("drain failed".to_string()))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NestedFlowServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "sample_via_client".to_string(),
            "elicit_via_client".to_string(),
            "roots_via_client".to_string(),
            "notify_resources_via_client".to_string(),
        ]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let nested_flow_bridge = nested_flow_bridge
            .ok_or_else(|| KernelError::Internal("nested-flow bridge is required".to_string()))?;

        match tool_name {
            "sample_via_client" => {
                let message = nested_flow_bridge.create_message(CreateMessageOperation {
                    messages: vec![SamplingMessage {
                        role: "user".to_string(),
                        content: serde_json::json!({
                            "type": "text",
                            "text": "Summarize the roadmap",
                        }),
                        meta: None,
                    }],
                    model_preferences: None,
                    system_prompt: None,
                    include_context: None,
                    temperature: Some(0.2),
                    max_tokens: 128,
                    stop_sequences: vec![],
                    metadata: None,
                    tools: vec![],
                    tool_choice: None,
                })?;

                Ok(serde_json::json!({
                    "model": message.model,
                    "content": message.content,
                }))
            }
            "elicit_via_client" => {
                let elicitation =
                    nested_flow_bridge.create_elicitation(CreateElicitationOperation::Form {
                        meta: None,
                        message: "Which environment should this run against?".to_string(),
                        requested_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "environment": {
                                    "type": "string",
                                    "enum": ["staging", "production"]
                                }
                            },
                            "required": ["environment"]
                        }),
                    })?;

                Ok(serde_json::json!({
                    "action": elicitation.action,
                    "content": elicitation.content,
                }))
            }
            "roots_via_client" => {
                let roots = nested_flow_bridge.list_roots()?;
                Ok(serde_json::json!({
                    "roots": roots,
                }))
            }
            "notify_resources_via_client" => {
                nested_flow_bridge.notify_resource_updated("repo://docs/roadmap")?;
                nested_flow_bridge.notify_resource_updated("repo://secret/ops")?;
                nested_flow_bridge.notify_resources_list_changed()?;
                Ok(serde_json::json!({
                    "notified": true,
                }))
            }
            _ => Err(KernelError::ToolNotRegistered(tool_name.to_string())),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for IncompleteServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["drop_stream".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::RequestIncomplete(
            "upstream stream closed before tool response completed".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for StreamingServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["stream_file".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"unused": true}))
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: self
                .chunks
                .iter()
                .cloned()
                .map(|data| ToolCallChunk { data })
                .collect(),
        })))
    }
}

impl NestedFlowClient for MockNestedFlowClient {
    fn list_roots(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Ok(self.roots.clone())
    }

    fn create_message(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        _operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        if self.cancel_parent_on_create_message {
            return Err(KernelError::RequestCancelled {
                request_id: parent_context.request_id.clone(),
                reason: "client cancelled parent request".to_string(),
            });
        }

        if self.cancel_child_on_create_message {
            return Err(KernelError::RequestCancelled {
                request_id: child_context.request_id.clone(),
                reason: "client cancelled nested request".to_string(),
            });
        }

        Ok(self.sampled_message.clone())
    }

    fn create_elicitation(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Ok(self.elicited_content.clone())
    }

    fn notify_elicitation_completed(
        &mut self,
        _parent_context: &OperationContext,
        elicitation_id: &str,
    ) -> Result<(), KernelError> {
        self.completed_elicitation_ids
            .push(elicitation_id.to_string());
        Ok(())
    }

    fn notify_resource_updated(
        &mut self,
        _parent_context: &OperationContext,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.resource_updates.push(uri.to_string());
        Ok(())
    }

    fn notify_resources_list_changed(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        self.resources_list_changed_count += 1;
        Ok(())
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
                annotations: None,
                icons: None,
            },
            ResourceDefinition {
                uri: "repo://secret/ops".to_string(),
                name: "Ops".to_string(),
                title: None,
                description: Some("Hidden".to_string()),
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
            description: Some("Template".to_string()),
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

#[derive(Default)]
pub(super) struct AppendOnlyReceiptStore;

impl ReceiptStore for AppendOnlyReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}
#[path = "support_dead_writer.rs"]
mod dead_writer;
pub(super) use dead_writer::*;

/// A store that reports retention support but, like the real prefix-watermark
/// store, cannot honor a tenant-scoped policy (it inherits the default
/// `supports_tenant_scoped_retention` = false). Used to prove the attach path
/// rejects a tenant-scoped retention config before spawning the worker.
#[derive(Default)]
pub(super) struct RetentionCapableReceiptStore;

impl ReceiptStore for RetentionCapableReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn supports_retention(&self) -> bool {
        true
    }
}
/// A store-authoritative point-lookup store: appended chio receipts are retained
/// in-memory and `load_chio_receipt` resolves them by id. Models a durable store
/// that implements point loads, so an evicted parent receipt still resolves from
/// the store after the bounded mirror drops it.
#[derive(Default)]
pub(super) struct PointLookupReceiptStore {
    pub(super) chio: std::sync::Mutex<std::collections::HashMap<String, ChioReceipt>>,
}

impl ReceiptStore for PointLookupReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if let Ok(mut map) = self.chio.lock() {
            map.insert(receipt.id.clone(), receipt.clone());
        }
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .chio
            .lock()
            .ok()
            .and_then(|map| map.get(receipt_id).cloned()))
    }
}

/// A store that appends fine (so the local mirror is populated) but fails every
/// point load with a read-boundary error, exercising the fail-closed
/// error-propagation path.
#[derive(Default)]
pub(super) struct ErroringReceiptStore;

impl ReceiptStore for ErroringReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Err(ReceiptStoreError::ReadBoundary(
            "simulated receipt store read failure".to_string(),
        ))
    }

    fn load_child_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        Err(ReceiptStoreError::ReadBoundary(
            "simulated child receipt store read failure".to_string(),
        ))
    }
}

#[derive(Default)]
pub(super) struct FailingCheckpointHydrationReceiptStore;

impl ReceiptStore for FailingCheckpointHydrationReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_latest_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "checkpoint chain corrupted".to_string(),
        ))
    }
}

#[derive(Default)]
pub(super) struct FailingSessionAnchorReceiptStore;

impl ReceiptStore for FailingSessionAnchorReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn record_session_anchor(
        &self,
        _session_id: &str,
        _anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        _supersedes_anchor_id: Option<&str>,
        _anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "session anchor write failed".to_string(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordedSessionAnchor {
    pub(super) anchor_id: String,
    pub(super) supersedes_anchor_id: Option<String>,
}

#[derive(Default)]
pub(super) struct RecordingSessionAnchorReceiptStore {
    pub(super) anchors: std::sync::Arc<Mutex<Vec<RecordedSessionAnchor>>>,
}

impl ReceiptStore for RecordingSessionAnchorReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn record_session_anchor(
        &self,
        _session_id: &str,
        anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        _anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.anchors
            .lock()
            .map_err(|_| ReceiptStoreError::Conflict("anchor recorder lock poisoned".to_string()))?
            .push(RecordedSessionAnchor {
                anchor_id: anchor_id.to_string(),
                supersedes_anchor_id: supersedes_anchor_id.map(str::to_string),
            });
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct FailingRequestLineageReceiptStore;

impl ReceiptStore for FailingRequestLineageReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    #[allow(clippy::too_many_arguments, reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules.")]
    fn record_request_lineage(
        &self,
        _session_id: &str,
        _request_id: &str,
        _parent_request_id: Option<&str>,
        _session_anchor_id: Option<&str>,
        _recorded_at: u64,
        _request_fingerprint: Option<&str>,
        _lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "request lineage write failed".to_string(),
        ))
    }
}


#[path = "support_budget_store_impls.rs"]
pub(super) mod budget_store_impls;

#[path = "fixtures/receipt_store.rs"]
mod receipt_store;
pub(super) use receipt_store::SqliteReceiptStore;
#[path = "fixtures/revocation_store.rs"]
mod revocation_store;
pub(super) use revocation_store::SqliteRevocationStore;
