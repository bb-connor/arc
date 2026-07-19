    #[test]
    fn a2a_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let invocations = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingNegotiationToolServer {
            invocations: Arc::clone(&invocations),
        }));
        let subject = Keypair::generate();
        let request_id = "a2a-unnegotiated";
        let (approval_tokens, proposal, supplemental) =
            adapter_authorization_artifacts(&subject, request_id);
        let singular_approval = approval_tokens[0].clone();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            session_id: SessionId::new("a2a-unnegotiated-session"),
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
            .handle_send_message("echo", &text_message("deny"), &kernel, &execution)
            .test_expect_err("unnegotiated A2A extensions must fail closed");

        assert!(error.to_string().contains(THRESHOLD_GOVERNED_APPROVALS));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(kernel.receipt_log().len(), receipt_count_before);

        let singular_execution = A2aKernelExecutionContext {
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
            .handle_send_message(
                "echo",
                &text_message("deny singular"),
                &kernel,
                &singular_execution,
            )
            .test_expect_err("singular unnegotiated A2A approval must fail closed");
        assert!(singular_error
            .to_string()
            .contains(THRESHOLD_GOVERNED_APPROVALS));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(kernel.receipt_log().len(), receipt_count_before);
    }

    #[test]
    fn registry_admitted_flow_survives_a2a_execution_projection_canonically() {
        let (registry, expected_flow) = registry_with_nontrivial_flow();
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), &registry).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
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

        let request = edge
            .build_execution_request(
                "echo",
                &text_message("preserve admitted flow"),
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
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), &registry).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
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
        let request = edge
            .build_execution_request(
                "echo",
                &text_message("reject sidecar drift"),
                &execution,
                "a2a-flow-reject-origin".to_string(),
                "a2a-flow-reject-kernel".to_string(),
            )
            .test_unwrap();

        let runtime_error = execute_orchestrated_a2a_request(
            &kernel,
            &registry,
            request.clone(),
            &TrustedPeerNegotiation::default(),
        )
        .test_expect_err("flow-required A2A registry must reject an unprotected kernel");
        assert!(matches!(
            runtime_error,
            A2aEdgeError::Bridge(BridgeError::Kernel(KernelError::FlowRuntimeUnavailable))
        ));

        let mut removed = request.clone();
        removed.bridge_security = chio_manifest::BridgeSecurityMetadata::unconstrained();
        let removed_error = execute_orchestrated_a2a_request(
            &kernel,
            &registry,
            removed,
            &TrustedPeerNegotiation::default(),
        )
        .test_expect_err("removed A2A flow sidecar must fail before dispatch");
        assert_eq!(
            removed_error.to_string(),
            "bridge error: invalid request envelope: bridge security does not match live registry entry for test-srv/echo"
        );

        let mut mismatched = request;
        mismatched.target_tool_name = "different-tool".to_string();
        let mismatch_error = execute_orchestrated_a2a_request(
            &kernel,
            &registry,
            mismatched,
            &TrustedPeerNegotiation::default(),
        )
        .test_expect_err("mismatched A2A flow sidecar must fail before dispatch");
        assert_eq!(
            mismatch_error.to_string(),
            "bridge error: invalid request envelope: bridge security does not match live registry entry for test-srv/different-tool"
        );
    }

    #[test]
    fn send_message_rejects_blank_execution_agent_id_before_dispatch() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: "\t".to_string(),
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

        let error = edge
            .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
            .test_expect_err("blank A2A execution agent_id must fail");

        assert_eq!(
            error.to_string(),
            "invalid request: A2A execution agent_id must not be empty"
        );
    }

    #[test]
    fn execution_context_rejects_control_character_agent_id() {
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&Keypair::generate(), &subject, "test-srv", "echo"),
            agent_id: format!("{}{}suffix", subject.public_key().to_hex(), '\u{7}'),
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

        let error = validate_execution_context(&execution)
            .test_expect_err("control character A2A execution agent_id must fail");

        assert_eq!(
            error.to_string(),
            "invalid request: A2A execution agent_id must not include control characters"
        );
    }

    #[test]
    fn send_message_with_kernel_denial_still_returns_receipt_metadata() {
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
            .handle_send_message("write", &text_message("blocked"), &kernel, &execution)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        let metadata = response
            .metadata
            .test_expect("deny path should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
        assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
    }

    #[test]
    fn pending_approval_is_not_reported_as_completed() {
        let _metrics_guard = metrics_test_guard();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let request = text_message("blocked pending approval");
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let before_pending = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let response = edge
            .project_pending_approval_for_test(
                "echo",
                &request,
                &kernel,
                &A2aKernelExecutionContext {
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
                },
                "approval required",
            )
            .test_unwrap();
        let metadata = response
            .metadata
            .test_expect("pending approval should attach metadata");

        assert_eq!(response.status, TaskStatus::Failed);
        assert_eq!(
            response.status_message.as_deref(),
            Some("approval required")
        );
        assert!(response.message.is_none());
        assert_eq!(
            metadata["chio"]["decision"].as_str(),
            Some("pending_approval")
        );
        let pending_total = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
        assert!(pending_total > before_pending);
        assert_receipt_write_prometheus_sample_at_least(
            RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
            pending_total,
        );
        assert_eq!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
            before_error
        );
    }

    #[test]
    fn send_message_kernel_error_records_receipt_write_error_outcome() {
        let _metrics_guard = metrics_test_guard();
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let mut config = test_kernel_config();
        config.require_web3_evidence = true;
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
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let error = edge
            .handle_send_message("echo", &text_message("boom"), &kernel, &execution)
            .test_expect_err("A2A web3 evidence prerequisite failure must reject");

        assert!(error
            .to_string()
            .contains("web3 evidence prerequisites unavailable"));
        assert!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR) > before_error,
            "a2a orchestrator error path must advance receipt write error"
        );
    }

    #[test]
    fn pre_kernel_bridge_error_does_not_record_receipt_write_error_outcome() {
        let _metrics_guard = metrics_test_guard();
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
        let capability_ref = CrossProtocolCapabilityRef {
            chio_capability_id: "wrong-capability".to_string(),
            origin_protocol: DiscoveryProtocol::A2a,
            protocol_context: Some(json!({ "targetSkillId": "echo" })),
            parent_capability_hash: "wrong-parent-hash".to_string(),
        };
        let mut request = text_message("boom");
        request.metadata = Some(json!({
            "chio": {
                "capabilityRef": serde_json::to_value(capability_ref).test_unwrap()
            }
        }));
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let error = edge
            .handle_send_message("echo", &request, &kernel, &execution)
            .test_expect_err("A2A capability reference mismatch must reject");

        assert!(error.to_string().contains("capability reference mismatch"));
        assert_eq!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
            before_error,
            "pre-kernel A2A bridge errors must not advance receipt write error"
        );
    }

    #[test]
    fn send_message_kernel_failure_still_returns_receipt_metadata() {
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
            public_key: manifest_public_key(10),
        };
        let mut edge = verified_test_edge(A2aEdgeConfig::default(), manifest, 10).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(FailingToolServer));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "fail-srv", "fail_tool"),
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
            .handle_send_message("fail_tool", &text_message("boom"), &kernel, &execution)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        let metadata = response
            .metadata
            .test_expect("kernel failure should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
        assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
    }

    // ---- Message extraction tests ----

    #[test]
    fn extract_text_from_parts() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Text {
                text: "hello world".to_string(),
            }],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg).test_unwrap();
        assert_eq!(args["message"], "hello world");
    }

    #[test]
    fn extract_data_from_parts() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: json!({"key": "value"}),
            }],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg).test_unwrap();
        assert_eq!(args["key"], "value");
    }

    #[test]
    fn extract_rejects_scalar_data_part_arguments() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: json!("not-an-argument-object"),
            }],
            metadata: None,
        };

        let error = extract_arguments_from_message(&msg)
            .test_expect_err("scalar data parts must fail before dispatch");
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert!(message.contains("data part must be a JSON object"));
    }

    #[test]
    fn extract_rejects_array_data_part_arguments() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: json!(["not", "an", "argument", "object"]),
            }],
            metadata: None,
        };

        let error = extract_arguments_from_message(&msg)
            .test_expect_err("array data parts must fail before dispatch");
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert!(message.contains("data part must be a JSON object"));
    }

    #[test]
    fn extract_prefers_data_over_text() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![
                A2aPart::Text {
                    text: "hello".to_string(),
                },
                A2aPart::Data {
                    data: json!({"priority": "high"}),
                },
            ],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg).test_unwrap();
        assert_eq!(args["priority"], "high");
    }

    #[test]
    fn compatibility_send_rejects_multiple_data_parts() {
        let mut edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1);
                m
            }],
        )
        .test_unwrap();
        let server = test_server();
        let request = SendMessageRequest {
            message: A2aMessage {
                role: "user".to_string(),
                parts: vec![
                    A2aPart::Data {
                        data: json!({"first": true}),
                    },
                    A2aPart::Data {
                        data: json!({"second": true}),
                    },
                ],
                metadata: None,
            },
            metadata: None,
        };

        let error = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .test_expect_err("multiple A2A data parts must fail");
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert!(message.contains("at most one data part"));
    }

    // ---- Result conversion tests ----

    #[test]
    fn result_text_to_parts() {
        let parts = result_to_parts(&json!("hello"));
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            A2aPart::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("expected text part"),
        }
    }

    #[test]
    fn result_object_to_data_parts() {
        let parts = result_to_parts(&json!({"key": "value"}));
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            A2aPart::Data { data } => assert_eq!(data["key"], "value"),
            _ => panic!("expected data part"),
        }
    }

    #[test]
    fn result_content_array_to_text_parts() {
        let parts = result_to_parts(&json!({
            "content": [
                {"type": "text", "text": "part1"},
                {"type": "text", "text": "part2"},
            ]
        }));
        assert_eq!(parts.len(), 2);
    }

    // ---- JSON-RPC handler tests ----

    #[test]
    fn jsonrpc_send_message_param_parser_infers_single_skill_and_labels_stream_errors() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![{
                let mut manifest = test_manifest();
                manifest.tools.truncate(1);
                manifest
            }],
        )
        .test_unwrap();

        let (skill_id, request) = edge
            .parse_jsonrpc_send_message_params(
                serde_json::to_value(text_message("hi")).test_unwrap(),
                "SendMessage",
            )
            .test_unwrap();
        assert_eq!(skill_id, "echo");
        assert_eq!(request.message.role, "user");

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": "bad"
                }
            }),
            "SendStreamingMessage",
        ) {
            Ok(_) => panic!("expected invalid request error"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert!(message.contains("invalid SendStreamingMessage request:"));
    }

    #[test]
    fn jsonrpc_send_message_param_parser_requires_skill_id_for_multiple_skills() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected missing target skill error"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(
            message,
            "metadata.chio.targetSkillId is required when multiple skills are exposed"
        );
    }

    #[test]
    fn jsonrpc_single_skill_rejects_malformed_chio_metadata() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![{
                let mut manifest = test_manifest();
                manifest.tools.truncate(1);
                manifest
            }],
        )
        .test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": "not-an-object"
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected malformed metadata.chio to fail"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(message, "metadata.chio must be a JSON object");
    }

    #[test]
    fn jsonrpc_single_skill_rejects_non_string_target_skill_id() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![{
                let mut manifest = test_manifest();
                manifest.tools.truncate(1);
                manifest
            }],
        )
        .test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": {"targetSkillId": 123}
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected non-string targetSkillId to fail"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(message, "metadata.chio.targetSkillId must be a string");
    }

    #[test]
    fn jsonrpc_single_skill_rejects_empty_target_skill_id_before_lookup() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![{
                let mut manifest = test_manifest();
                manifest.tools.truncate(1);
                manifest
            }],
        )
        .test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": {"targetSkillId": "   "}
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected empty targetSkillId to fail before lookup"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(message, "metadata.chio.targetSkillId must not be empty");
    }

    #[test]
    fn jsonrpc_rejects_padded_target_skill_id_before_lookup() {
        let edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": {"targetSkillId": " echo "}
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected padded targetSkillId to fail before lookup"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(
            message,
            "metadata.chio.targetSkillId must not include leading or trailing whitespace"
        );
    }

    #[test]
    fn jsonrpc_send_message_single_skill() {
        let mut manifest = test_manifest();
        manifest.tools.truncate(1); // Only "echo"
        let mut edge = verified_test_edge(A2aEdgeConfig::default(), manifest, 1).test_unwrap();
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
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_send_message_rejects_empty_parts() {
        let mut manifest = test_manifest();
        manifest.tools.truncate(1);
        let mut edge = verified_test_edge(A2aEdgeConfig::default(), manifest, 1).test_unwrap();
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": []
                    }
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "message.parts must contain at least one part"
        );
    }

    #[test]
    fn jsonrpc_send_message_with_skill_id() {
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
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    },
                    "metadata": {
                        "chio": {"targetSkillId": "echo"}
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_missing_skill_id_with_multiple_skills_errors() {
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
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("error").is_some());
    }

    #[test]
    fn jsonrpc_unknown_method_returns_error() {
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
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "unknown/method",
                "params": {}
            }),
            &kernel,
            &execution,
        );
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn jsonrpc_send_rejects_non_object_params_before_skill_resolution() {
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 41,
                "method": "message/send",
                "params": []
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "message/send params must be an object"
        );
    }

    #[test]
    fn jsonrpc_task_get_rejects_non_object_params_before_lookup() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), stream_manifest(), 2).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "task/get",
                "params": []
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "task/get params must be an object"
        );
    }

    #[test]
    fn jsonrpc_rejects_non_scalar_request_ids_before_method_dispatch() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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

        for invalid_id in [json!(true), json!({"nested": 1}), json!([1])] {
            let response = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": invalid_id,
                    "method": "unknown/method",
                    "params": {}
                }),
                &kernel,
                &execution,
            );

            assert_eq!(response["id"], Value::Null);
            assert_eq!(response["error"]["code"], -32600);
            assert_eq!(
                response["error"]["message"],
                "request id must be string, number, or null"
            );
        }
    }

    #[test]
    fn jsonrpc_invalid_version_preserves_scalar_request_id() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "1.0",
                "id": "request-7",
                "method": "message/send",
                "params": {}
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["id"], "request-7");
        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(response["error"]["message"], "invalid jsonrpc envelope");
    }

    #[test]
    fn jsonrpc_compatibility_send_rejects_non_object_params_before_passthrough() {
        let mut edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1);
                m
            }],
        )
        .test_unwrap();
        let server = test_server();

        let response = edge.compatibility().handle_jsonrpc_compatibility(
            json!({
                "jsonrpc": "2.0",
                "id": 43,
                "method": "message/send",
                "params": []
            }),
            &server,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "message/send params must be an object"
        );
    }

    #[test]
    fn jsonrpc_passthrough_marks_compatibility_path() {
        let mut edge = ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1);
                m
            }],
        )
        .test_unwrap();
        let server = test_server();
        let response = edge.compatibility().handle_jsonrpc_compatibility(
            // This explicit compatibility wrapper remains available for bounded
            // migrations, but it is not the receipt-bearing trust path.
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &server,
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["authoritative"].as_bool(),
            Some(false)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["lifecycle"]["messageStream"].as_str(),
            Some("unsupported")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("a2a_compatibility")
        );
    }

    #[test]
    fn jsonrpc_send_with_streaming_tool_collates_output_into_final_message() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), stream_manifest(), 2).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(StreamingToolServer));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(
            response["result"]["metadata"]["chio"]["streamProjection"].as_str(),
            Some("collated_final_message")
        );
        let parts = response["result"]["message"]["parts"]
            .as_array()
            .test_expect("stream response should contain parts");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["text"], "chunk-1");
        assert_eq!(parts[1]["text"], "chunk-2");
    }

    include!("lifecycle.rs");
