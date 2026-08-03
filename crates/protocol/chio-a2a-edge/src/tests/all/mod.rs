    use super::*;
    use chio_test_support::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        aggregate_budget::issue_aggregate_family_root,
        features::{
            CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET,
            GOVERNED_ACTIVE_RESPONSE_PLAN, SUPPLEMENTAL_BROKER_EXECUTION_QUOTA,
            THRESHOLD_GOVERNED_APPROVALS,
        },
        governance::{
            GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
            GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
            CHIO_RESPONSE_PLAN_SCHEMA,
        },
        scope::{ChioScope, Operation, ToolGrant},
        threshold_approval::{ThresholdApprovalProposal, ThresholdApprovalProposalBody},
        token::CapabilityTokenBody,
    };
    use chio_core::crypto::Keypair;
    use chio_core::message::OpaqueSupplementalAuthorization;
    use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ReceiptStore, ReceiptStoreError,
        RuntimeAdmissionContext, RuntimeAdmissionDecision, RuntimeAdmissionHook, ToolCallChunk,
        ToolCallStream, ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
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

    fn invocation_security_context(
        capability: &CapabilityToken,
        agent_id: &str,
        session_id: &str,
        generation: u64,
    ) -> SecurityInvocationContext {
        let lineage_root = capability
            .delegation_chain
            .first()
            .map_or(capability.id.as_str(), |link| link.capability_id.as_str());
        SecurityInvocationContext::v1(chio_kernel::SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("tenant-a2a-deferred").test_unwrap(),
            chio_security_types::ports::SessionId::new(session_id).test_unwrap(),
            chio_security_types::PrincipalId::new(agent_id).test_unwrap(),
            chio_security_types::ports::IsolationEpochId::new("epoch-a2a-deferred").test_unwrap(),
            chio_security_types::ports::LineageId::new(lineage_root).test_unwrap(),
            generation,
        ))
    }

    struct RecordingSecurityContextAuthority {
        generation: u64,
        resolved_generations: Arc<Mutex<Vec<u64>>>,
    }

    impl SecurityInvocationContextAuthority for RecordingSecurityContextAuthority {
        fn resolve_security_invocation_context(
            &self,
            context: &OperationContext,
            operation: &chio_core::session::ToolCallOperation,
        ) -> Result<SecurityInvocationContext, KernelError> {
            self.resolved_generations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(self.generation);
            Ok(invocation_security_context(
                &operation.capability,
                &context.agent_id,
                context.session_id.as_str(),
                self.generation,
            ))
        }
    }

    struct FixedSessionSecurityContextAuthority {
        session_id: &'static str,
    }

    impl SecurityInvocationContextAuthority for FixedSessionSecurityContextAuthority {
        fn resolve_security_invocation_context(
            &self,
            context: &OperationContext,
            operation: &chio_core::session::ToolCallOperation,
        ) -> Result<SecurityInvocationContext, KernelError> {
            Ok(invocation_security_context(
                &operation.capability,
                &context.agent_id,
                self.session_id,
                2,
            ))
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
        let authority = Keypair::from_seed(&[93; 32]);
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody::new(
                "proposal-a2a-preservation",
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
            .test_unwrap(),
            &authority,
        )
        .test_unwrap();
        let token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "approval-a2a-preservation".to_string(),
                approver: authority.public_key(),
                subject: subject.public_key(),
                governed_intent_hash: "11".repeat(32),
                threshold_proposal_hash: Some(proposal.proposal_hash().test_unwrap()),
                request_id: request_id.to_string(),
                issued_at: 1_000,
                expires_at: 1_300,
                decision: GovernedApprovalDecision::Approved,
            },
            &authority,
        )
        .test_unwrap();
        let supplemental = OpaqueSupplementalAuthorization::new(
            "supplemental-a2a-preservation",
            vec![0x43, 0x48, 0x49, 0x4f],
        )
        .test_unwrap();
        (vec![token], proposal, supplemental)
    }

    fn active_response_intent(subject: &Keypair) -> GovernedTransactionIntent {
        let canonical_plan_body = json!({"action":"suspend_session"});
        let plan_body_hash =
            GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body)
                .test_unwrap();
        GovernedTransactionIntent::active_response_plan(
            GovernedResponsePlanIntentBody::new(
                CHIO_RESPONSE_PLAN_SCHEMA,
                "plan-a2a-preservation",
                "operator-capability-a2a-preservation",
                "55".repeat(32),
                2_000,
                subject.public_key(),
                canonical_plan_body,
                plan_body_hash.clone(),
                json!({"sessionId":"session-a2a-preservation"}),
                vec![GovernedResponseEffect::SuspendSession],
                1_900,
                json!({"responsePlanHash":plan_body_hash}),
            )
            .test_unwrap(),
        )
    }

    fn tool_annotations(has_side_effects: bool) -> chio_manifest::ToolAnnotations {
        chio_manifest::ToolAnnotations {
            read_only: !has_side_effects,
            destructive: has_side_effects,
            idempotent: false,
            requires_approval: has_side_effects,
        }
    }

    struct MockToolServer {
        server_id: String,
        tools: Vec<String>,
        response: Value,
    }

    struct CountingNegotiationToolServer {
        invocations: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for CountingNegotiationToolServer {
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
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"result": "should-not-dispatch"}))
        }
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

    struct FailingAppendReceiptStore;

    impl ReceiptStore for FailingAppendReceiptStore {
        fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            Err(ReceiptStoreError::Conflict(
                "injected post-dispatch receipt failure".to_string(),
            ))
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
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

    fn test_manifest() -> ToolManifest {
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
                    annotations: tool_annotations(false),
                    latency_hint: None,
                    flow: None,
                },
                ToolDefinition {
                    name: "write".to_string(),
                    description: "Write data".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    annotations: tool_annotations(true),
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

    fn registry_with_nontrivial_flow() -> (
        chio_manifest::VerifiedManifestRegistry,
        chio_manifest::ToolFlowDeclaration,
    ) {
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
        let mut registry = chio_manifest::VerifiedManifestRegistry::default();
        registry
            .register(signed, &signer.public_key(), &policies, &topologies)
            .test_unwrap();
        (registry, flow)
    }

    fn test_server() -> MockToolServer {
        MockToolServer {
            server_id: "test-srv".to_string(),
            tools: vec!["echo".to_string(), "write".to_string()],
            response: json!({"result": "ok"}),
        }
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
                annotations: tool_annotations(false),
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
                annotations: tool_annotations(true),
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
                annotations: tool_annotations(false),
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
                    "properties": {
                        "message": {"type": "string", "minLength": 1, "maxLength": 32}
                    },
                    "required": ["message"],
                    "additionalProperties": false,
                    "x-chio-target-protocol": "mcp"
                }),
                output_schema: None,
                pricing: None,
                annotations: tool_annotations(false),
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
                annotations: tool_annotations(false),
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
                annotations: tool_annotations(false),
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
                annotations: tool_annotations(false),
                latency_hint: None,
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: manifest_public_key(8),
        }
    }

    fn text_message(text: &str) -> SendMessageRequest {
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

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("system time should be after unix epoch")
            .as_secs()
    }

    fn test_kernel_config() -> KernelConfig {
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
            dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
        }
    }

    fn capability_for_tool(
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

    fn aggregate_family_capability_for_tool(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        tool_name: &str,
    ) -> chio_core::capability::token::CapabilityToken {
        let now = unix_now();
        issue_aggregate_family_root(
            CapabilityTokenBody {
                id: format!("cap-aggregate-{server_id}-{tool_name}"),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke, Operation::Delegate],
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
            3,
            issuer,
        )
        .test_expect("aggregate family capability should sign")
    }

    fn assert_receipt_write_prometheus_sample_at_least(outcome: &str, minimum: u64) {
        let body =
            render_a2a_edge_metrics_prometheus(chio_kernel::ReceiptWriterLiveness::Healthy);
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

    // ---- Constructor and Agent Card tests ----

    fn assert_invalid_agent_card_config_rejected(config: A2aEdgeConfig, expected: &str) {
        let error = match ChioA2aEdge::new_from_unverified_internal(config, vec![test_manifest()]) {
            Ok(_) => panic!("A2A edge must reject invalid Agent Card config"),
            Err(error) => error,
        };

        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(message, expected);
    }

    #[test]
    fn edge_rejects_manifest_with_unsupported_schema_version() {
        let mut manifest = test_manifest();
        manifest.schema = "chio.manifest.v0".to_string();
        manifest.public_key = manifest_public_key(99);

        let error = match ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![manifest],
        ) {
            Ok(_) => panic!("A2A edge must reject unsupported manifest schema versions"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            A2aEdgeError::Manifest(chio_manifest::ManifestError::UnsupportedSchema(schema))
                if schema == "chio.manifest.v0"
        ));
    }

    #[test]
    fn edge_rejects_blank_agent_card_name_before_publication() {
        let config = A2aEdgeConfig {
            agent_name: "  ".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(config, "agent card name must not be empty");
    }

    #[test]
    fn edge_rejects_blank_agent_card_version_before_publication() {
        let config = A2aEdgeConfig {
            agent_version: String::new(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(config, "agent card version must not be empty");
    }

    #[test]
    fn edge_rejects_blank_agent_card_endpoint_before_publication() {
        let config = A2aEdgeConfig {
            endpoint_url: "\t".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card endpoint URL must not be empty",
        );
    }

    #[test]
    fn edge_rejects_padded_agent_card_endpoint_before_publication() {
        let config = A2aEdgeConfig {
            endpoint_url: " https://agent.example/a2a".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card endpoint URL must not include leading or trailing whitespace",
        );
    }

    #[test]
    fn edge_rejects_blank_agent_card_protocol_binding_before_publication() {
        let config = A2aEdgeConfig {
            protocol_binding: "\n".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card protocol binding must not be empty",
        );
    }

    #[test]
    fn edge_rejects_padded_agent_card_protocol_binding_before_publication() {
        let config = A2aEdgeConfig {
            protocol_binding: "JSONRPC ".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card protocol binding must not include leading or trailing whitespace",
        );
    }

    #[test]
    fn agent_card_default_config_fields_stay_stable() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let card = edge.agent_card();

        assert_eq!(card.name, "Chio A2A Edge");
        assert_eq!(
            card.description,
            "Chio-governed tools exposed as A2A skills"
        );
        assert_eq!(card.version, "0.1.0");
        assert_eq!(card.supported_interfaces.len(), 1);
        assert_eq!(card.supported_interfaces[0].url, "http://localhost:8080");
        assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
        assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
    }

    #[test]
    fn agent_card_has_correct_name() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.name, "Chio A2A Edge");
    }

    #[test]
    fn agent_card_has_correct_version() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.version, "0.1.0");
    }

    #[test]
    fn agent_card_includes_all_skills() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.skills.len(), 2);
        assert!(card.skills.iter().any(|s| s.id == "echo"));
        assert!(card.skills.iter().any(|s| s.id == "write"));
    }

    #[test]
    fn agent_card_has_interface() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.supported_interfaces.len(), 1);
        assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
        assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
    }

    #[test]
    fn agent_card_json_serializes() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let json_str = edge.agent_card_json().test_unwrap();
        let parsed: Value = serde_json::from_str(&json_str).test_unwrap();
        assert_eq!(parsed["name"], "Chio A2A Edge");
    }

    #[test]
    fn agent_card_custom_config() {
        let config = A2aEdgeConfig {
            agent_name: "My Agent".to_string(),
            agent_description: "Custom agent".to_string(),
            agent_version: "2.0.0".to_string(),
            endpoint_url: "https://myagent.com".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
        };
        let edge =
            ChioA2aEdge::new_from_unverified_internal(config, vec![test_manifest()]).test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.name, "My Agent");
        assert_eq!(card.description, "Custom agent");
        assert!(card.capabilities.streaming);
        assert_eq!(card.supported_interfaces[0].url, "https://myagent.com");
        assert_eq!(card.supported_interfaces[0].protocol_binding, "HTTP+JSON");
    }

    // ---- BridgeFidelity tests ----

    #[test]
    fn read_only_tool_has_lossless_fidelity() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let skill = edge.skill("echo").test_unwrap();
        assert_eq!(skill.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn side_effect_tool_has_adapted_fidelity_with_permission_caveat() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let skill = edge.skill("write").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("permission prompts") || c.contains("capability enforcement")));
    }

    #[test]
    fn approval_required_tool_is_not_auto_published() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![approval_manifest()],
        )
        .test_unwrap();
        assert!(edge.skill("approve").is_none());
        assert_eq!(
            edge.bridge_fidelity("approve"),
            Some(&BridgeFidelity::Unsupported {
                reason: "requires interactive approval semantics that the current A2A edge cannot truthfully project".to_string()
            })
        );
    }

    #[test]
    fn cancellation_tool_is_adapted_with_truthful_caveats() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![cancellation_manifest()],
        )
        .test_unwrap();
        let skill = edge.skill("cancel_me").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c
                .contains("cancellation is available only for deferred `message/stream` tasks")));
    }

    #[test]
    fn hidden_tool_is_not_auto_published() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![hidden_manifest()],
        )
        .test_unwrap();
        assert!(edge.skill("hidden").is_none());
        assert_eq!(
            edge.bridge_fidelity("hidden"),
            Some(&BridgeFidelity::Unsupported {
                reason: "publication disabled by x-chio-publish=false".to_string()
            })
        );
    }

    #[test]
    fn streaming_tool_is_adapted_with_truthful_caveats() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![stream_manifest()],
        )
        .test_unwrap();
        let skill = edge.skill("stream").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats.iter().any(|c| c.contains("deferred tasks")));
        assert!(caveats.iter().any(|c| c.contains("terminal task payload")));
    }

    // ---- Skill lookup tests ----

    #[test]
    fn skill_ids_returns_all() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let ids = edge.skill_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn skill_returns_none_for_unknown() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        assert!(edge.skill("nonexistent").is_none());
    }

    // ---- SendMessage tests ----

    #[test]
    fn send_message_completes_successfully() {
        let mut edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let server = test_server();
        let request = text_message("hello");
        let response = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Completed);
        assert!(response.message.is_some());
        assert_eq!(
            response
                .metadata
                .as_ref()
                .and_then(|metadata| { metadata["chio"]["authorityPath"].as_str() }),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn send_message_returns_task_id() {
        let mut edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let server = test_server();
        let request = text_message("test");
        let r1 = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .test_unwrap();
        let r2 = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .test_unwrap();
        assert_ne!(r1.id, r2.id);
        assert!(r1.id.starts_with("a2a-task-"));
    }

    #[test]
    fn send_message_unknown_skill_errors() {
        let mut edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let server = test_server();
        let request = text_message("test");
        let err = edge
            .compatibility()
            .handle_send_message_compatibility("nonexistent", &request, &server)
            .test_expect_err("unknown A2A skill must fail");
        assert!(matches!(err, A2aEdgeError::ToolNotFound(_)));
    }

    #[test]
    fn send_message_server_failure_returns_failed_task() {
        let server = FailingToolServer;
        // Need a manifest for the failing server
        let manifest = ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "fail-srv".to_string(),
            name: "Fail".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "fail_tool".to_string(),
                description: "Fails".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: tool_annotations(false),
                latency_hint: None,
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: manifest_public_key(9),
        };
        let mut edge =
            ChioA2aEdge::new_from_unverified_internal(A2aEdgeConfig::default(), vec![manifest])
                .test_unwrap();
        let request = text_message("test");
        let response = edge
            .compatibility()
            .handle_send_message_compatibility("fail_tool", &request, &server)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        assert!(response.status_message.is_some());
        assert_eq!(
            response
                .metadata
                .as_ref()
                .and_then(|metadata| { metadata["chio"]["authorityPath"].as_str() }),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn send_message_with_kernel_emits_signed_receipt_metadata() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            session_id: chio_core::session::SessionId::new("a2a-authenticated-session"),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            security_context: None,
        };

        let response = edge
            .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Completed);
        let metadata = response
            .metadata
            .test_expect("kernel path should attach metadata");
        assert!(metadata["chio"]["receiptId"].as_str().is_some());
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
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
            metadata["chio"]["lifecycle"]["messageSend"].as_str(),
            Some("blocking_terminal_task")
        );
        assert_eq!(
            metadata["chio"]["lifecycle"]["messageStream"].as_str(),
            Some("deferred_task_poll")
        );
        assert_eq!(
            metadata["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("a2a_authoritative")
        );
        assert_eq!(
            metadata["chio"]["receipt"]["capability_id"].as_str(),
            Some("cap-test-srv-echo")
        );
    }

    #[test]
    fn a2a_execution_request_preserves_complete_authorization_context() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let protocol_features = threshold_and_broker_protocol_features();
        edge.set_peer_protocol_negotiation(&protocol_features, &protocol_features)
            .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let kernel_request_id = "a2a-kernel-preservation";
        let (approval_tokens, proposal, supplemental) =
            adapter_authorization_artifacts(&subject, kernel_request_id);
        let capability =
            aggregate_family_capability_for_tool(&issuer, &subject, "test-srv", "echo");
        let aggregate_budget = capability
            .aggregate_invocation_budget
            .clone()
            .test_expect("aggregate family budget");
        assert!(aggregate_budget.root_binding.is_some());
        let governed_intent = active_response_intent(&subject);
        let execution = A2aKernelExecutionContext {
            capability: capability.clone(),
            agent_id: subject.public_key().to_hex(),
            session_id: chio_core::session::SessionId::new("a2a-authenticated-session"),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(governed_intent.clone()),
            approval_token: None,
            approval_tokens: approval_tokens.clone(),
            threshold_approval_proposal: Some(proposal.clone()),
            model_metadata: None,
            supplemental_authorization: Some(supplemental.clone()),
            security_context: None,
        };

        let request = edge
            .build_execution_request(
                "echo",
                &text_message("preserve authorization"),
                &execution,
                "a2a-origin-preservation".to_string(),
                kernel_request_id.to_string(),
            )
            .test_unwrap();

        assert_eq!(request.approval_tokens, approval_tokens);
        assert_eq!(
            serde_json::to_value(&request.capability).test_unwrap(),
            serde_json::to_value(&capability).test_unwrap()
        );
        assert_eq!(
            request.capability.aggregate_invocation_budget,
            Some(aggregate_budget)
        );
        assert_eq!(request.governed_intent, Some(governed_intent));
        assert_eq!(request.threshold_approval_proposal, Some(proposal));
        assert_eq!(request.supplemental_authorization, Some(supplemental));
        chio_cross_protocol::negotiation::validate_execution_feature_negotiation(
            &edge.trusted_peer_negotiation,
            &request.capability,
            request.governed_intent.as_ref(),
            request.approval_token.as_ref(),
            &request.approval_tokens,
            request.threshold_approval_proposal.as_ref(),
            request.supplemental_authorization.as_ref(),
        )
        .test_unwrap();
    }

    include!("security.rs");
