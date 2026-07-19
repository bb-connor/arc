    use super::*;
    use chio_test_support::prelude::*;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    };

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
        dpop, ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ReceiptStore,
        ReceiptStoreError, RuntimeAdmissionContext, RuntimeAdmissionDecision, RuntimeAdmissionHook,
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
            chio_security_types::ports::TenantId::new("tenant-acp-deferred").test_unwrap(),
            chio_security_types::ports::SessionId::new(session_id).test_unwrap(),
            chio_security_types::PrincipalId::new(agent_id).test_unwrap(),
            chio_security_types::ports::IsolationEpochId::new("epoch-acp-deferred").test_unwrap(),
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
        let authority = Keypair::from_seed(&[94; 32]);
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody::new(
                "proposal-acp-preservation",
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
                id: "approval-acp-preservation".to_string(),
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
            "supplemental-acp-preservation",
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
                "plan-acp-preservation",
                "operator-capability-acp-preservation",
                "55".repeat(32),
                2_000,
                subject.public_key(),
                canonical_plan_body,
                plan_body_hash.clone(),
                json!({"sessionId":"session-acp-preservation"}),
                vec![GovernedResponseEffect::SuspendSession],
                1_900,
                json!({"responsePlanHash":plan_body_hash}),
            )
            .test_unwrap(),
        )
    }

    struct MockToolServer {
        server_id: String,
        tools: Vec<String>,
        response: Value,
    }

    struct CountingNegotiationToolServer {
        calls: Arc<AtomicU64>,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for CountingNegotiationToolServer {
        fn server_id(&self) -> &str {
            "test-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["read_file".to_string()]
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
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

    fn test_manifest() -> ToolManifest {
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
        let mut registry = chio_manifest::VerifiedManifestRegistry::default();
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
                    "properties": {
                        "path": {"type": "string", "minLength": 1, "maxLength": 128}
                    },
                    "required": ["path"],
                    "additionalProperties": false,
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

    fn test_kernel_config() -> KernelConfig {
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
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        }
    }

    fn capability_for_tool(
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

    fn aggregate_family_capability_for_tool(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        tool_name: &str,
    ) -> chio_core::capability::token::CapabilityToken {
        let now = current_unix_timestamp();
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
        let body = render_acp_edge_metrics_prometheus();
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

        let error = match ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![manifest],
        ) {
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
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        assert_eq!(edge.capabilities().len(), 4);
    }

    #[test]
    fn edge_capability_ids_match_tool_names() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let ids = edge.capability_ids();
        assert!(ids.contains(&"read_file".to_string()));
        assert!(ids.contains(&"write_file".to_string()));
        assert!(ids.contains(&"exec_command".to_string()));
        assert!(ids.contains(&"search".to_string()));
    }

    #[test]
    fn edge_capability_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let cap = edge.capability("read_file").test_unwrap();
        assert_eq!(cap.description, "Read a file");
    }

    #[test]
    fn edge_unknown_capability_returns_none() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        assert!(edge.capability("nonexistent").is_none());
    }

    // ---- Category inference tests ----

    #[test]
    fn read_file_gets_filesystem_category() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let cap = edge.capability("read_file").test_unwrap();
        assert_eq!(cap.category, AcpCategory::Filesystem);
    }

    #[test]
    fn write_file_gets_filesystem_category() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let cap = edge.capability("write_file").test_unwrap();
        assert_eq!(cap.category, AcpCategory::Filesystem);
    }

    #[test]
    fn exec_command_gets_terminal_category() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let cap = edge.capability("exec_command").test_unwrap();
        assert_eq!(cap.category, AcpCategory::Terminal);
    }

    #[test]
    fn search_gets_default_tool_category() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let cap = edge.capability("search").test_unwrap();
        assert_eq!(cap.category, AcpCategory::Tool);
    }

    // ---- BridgeFidelity tests ----

    #[test]
    fn filesystem_tools_have_lossless_fidelity() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let cap = edge.capability("read_file").test_unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn terminal_tools_have_lossless_fidelity() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let cap = edge.capability("exec_command").test_unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn generic_readonly_tool_is_adapted_with_category_caveat() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
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
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![browser_manifest()],
        )
        .test_unwrap();
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
        let edge = ChioAcpEdge::new_from_unverified_internal(
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
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![approval_manifest()],
        )
        .test_unwrap();
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
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![streaming_manifest()],
        )
        .test_unwrap();
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
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![hidden_manifest()],
        )
        .test_unwrap();
        assert!(edge.capability("hidden_tool").is_none());
        assert_eq!(
            edge.bridge_fidelity("hidden_tool"),
            Some(&BridgeFidelity::Unsupported {
                reason: "publication disabled by x-chio-publish=false".to_string()
            })
        );
    }

    // ---- Permission tests ----

    #[test]
    fn side_effect_tools_require_permission() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let cap = edge.capability("write_file").test_unwrap();
        assert!(cap.requires_permission);
    }

    #[test]
    fn permission_denied_by_default_for_required_caps() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let request = PermissionRequest {
            capability_id: "write_file".to_string(),
            arguments: json!({}),
        };
        assert_eq!(
            edge.compatibility().preview_permission(&request),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn permission_denied_for_unknown_capability() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let request = PermissionRequest {
            capability_id: "nonexistent".to_string(),
            arguments: json!({}),
        };
        assert_eq!(
            edge.compatibility().preview_permission(&request),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn permission_not_required_when_config_disabled() {
        let config = AcpEdgeConfig {
            require_permission: false,
            default_category: AcpCategory::Tool,
        };
        let edge =
            ChioAcpEdge::new_from_unverified_internal(config, vec![test_manifest()]).test_unwrap();
        // read_file has no side effects and require_permission is false
        let cap = edge.capability("read_file").test_unwrap();
        assert!(!cap.requires_permission);
    }

    #[test]
    fn permission_with_capability_allows_matching_scope() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            session_id: chio_core::session::SessionId::new("acp-authenticated-session"),
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
        let request = PermissionRequest {
            capability_id: "read_file".to_string(),
            arguments: json!({"path": "/tmp"}),
        };

        assert_eq!(
            edge.evaluate_permission(&request, &execution),
            PermissionDecision::Allow
        );
    }

    #[test]
    fn acp_execution_request_preserves_complete_authorization_context() {
        let mut edge =
            verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let protocol_features = threshold_and_broker_protocol_features();
        edge.set_peer_protocol_negotiation(&protocol_features, &protocol_features)
            .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let kernel_request_id = "acp-kernel-preservation";
        let (approval_tokens, proposal, supplemental) =
            adapter_authorization_artifacts(&subject, kernel_request_id);
        let capability =
            aggregate_family_capability_for_tool(&issuer, &subject, "test-srv", "read_file");
        let aggregate_budget = capability
            .aggregate_invocation_budget
            .clone()
            .test_expect("aggregate family budget");
        assert!(aggregate_budget.root_binding.is_some());
        let governed_intent = active_response_intent(&subject);
        let execution = AcpKernelExecutionContext {
            capability: capability.clone(),
            agent_id: subject.public_key().to_hex(),
            session_id: chio_core::session::SessionId::new("acp-authenticated-session"),
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
        let binding = edge.capability_binding("read_file").test_unwrap();

        let request = edge
            .build_execution_request(
                "read_file",
                json!({"path":"/tmp/preserve"}),
                &execution,
                &binding,
                binding.target_protocol,
                AcpRequestIds {
                    origin_request_id: "acp-origin-preservation".to_string(),
                    kernel_request_id: kernel_request_id.to_string(),
                },
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

    #[test]
    fn acp_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation() {
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let calls = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(CountingNegotiationToolServer {
            calls: Arc::clone(&calls),
        }));
        let subject = Keypair::generate();
        let request_id = "acp-unnegotiated";
        let (approval_tokens, proposal, supplemental) =
            adapter_authorization_artifacts(&subject, request_id);
        let singular_approval = approval_tokens[0].clone();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            session_id: SessionId::new("acp-unnegotiated-session"),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens,
            threshold_approval_proposal: Some(proposal),
            model_metadata: None,
            supplemental_authorization: Some(supplemental),
            security_context: None,
        };
        let receipt_count_before = kernel.receipt_log().len();

        let error = edge
            .invoke(
                "read_file",
                json!({"path": "/tmp/unnegotiated"}),
                &kernel,
                &execution,
            )
            .test_expect_err("unnegotiated ACP extensions must fail closed");

        assert!(error.to_string().contains(THRESHOLD_GOVERNED_APPROVALS));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(kernel.receipt_log().len(), receipt_count_before);

        let singular_execution = AcpKernelExecutionContext {
            capability: execution.capability.clone(),
            agent_id: execution.agent_id.clone(),
            session_id: execution.session_id.clone(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: Some(singular_approval),
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            security_context: None,
        };
        let singular_error = edge
            .invoke(
                "read_file",
                json!({"path": "/tmp/unnegotiated-singular"}),
                &kernel,
                &singular_execution,
            )
            .test_expect_err("singular unnegotiated ACP approval must fail closed");
        assert!(singular_error
            .to_string()
            .contains(THRESHOLD_GOVERNED_APPROVALS));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(kernel.receipt_log().len(), receipt_count_before);
    }

    #[test]
    fn registry_admitted_flow_survives_acp_execution_projection_canonically() {
        let (registry, expected_flow) = registry_with_nontrivial_flow();
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), &registry).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            session_id: chio_core::session::SessionId::new("acp-authenticated-session"),
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
        let binding = edge.capability_binding("read_file").test_unwrap();

        let request = edge
            .build_execution_request(
                "read_file",
                json!({"path": "/tmp/preserve-flow"}),
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

    include!("security.rs");
