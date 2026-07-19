    #[test]
    fn acp_execution_boundary_rejects_removed_or_mismatched_flow_sidecar() {
        let (registry, _) = registry_with_nontrivial_flow();
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), &registry).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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
                json!({"path": "/tmp/reject-flow-drift"}),
                &execution,
                &binding,
                binding.target_protocol,
                AcpRequestIds {
                    origin_request_id: "acp-flow-reject-origin".to_string(),
                    kernel_request_id: "acp-flow-reject-kernel".to_string(),
                },
            )
            .test_unwrap();

        let runtime_error = execute_orchestrated_acp_request(
            &kernel,
            &registry,
            request.clone(),
            &TrustedPeerNegotiation::default(),
        )
        .test_expect_err("flow-required ACP registry must reject an unprotected kernel");
        assert!(matches!(
            runtime_error,
            AcpEdgeError::Bridge(BridgeError::Kernel(KernelError::FlowRuntimeUnavailable))
        ));

        let mut removed = request.clone();
        removed.bridge_security = chio_manifest::BridgeSecurityMetadata::unconstrained();
        let removed_error = execute_orchestrated_acp_request(
            &kernel,
            &registry,
            removed,
            &TrustedPeerNegotiation::default(),
        )
        .test_expect_err("removed ACP flow sidecar must fail before dispatch");
        assert_eq!(
            removed_error.to_string(),
            "bridge error: invalid request envelope: bridge security does not match live registry entry for test-srv/read_file"
        );

        let mut mismatched = request;
        mismatched.target_tool_name = "different-tool".to_string();
        let mismatch_error = execute_orchestrated_acp_request(
            &kernel,
            &registry,
            mismatched,
            &TrustedPeerNegotiation::default(),
        )
        .test_expect_err("mismatched ACP flow sidecar must fail before dispatch");
        assert_eq!(
            mismatch_error.to_string(),
            "bridge error: invalid request envelope: bridge security does not match live registry entry for test-srv/different-tool"
        );
    }

    #[test]
    fn permission_with_capability_denies_sender_bound_scope_without_dpop() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool_with_dpop_requirement(
                &issuer,
                &subject,
                "test-srv",
                "read_file",
                Some(true),
            ),
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
            PermissionDecision::Deny
        );
    }

    #[test]
    fn permission_with_capability_denies_sender_bound_scope_with_mismatched_dpop() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let capability = capability_for_tool_with_dpop_requirement(
            &issuer,
            &subject,
            "test-srv",
            "read_file",
            Some(true),
        );
        let request_arguments = json!({"path": "/tmp"});
        let mismatched_proof = dpop_proof_for_request(
            &subject,
            &capability,
            "test-srv",
            "write_file",
            &request_arguments,
            "acp-preview-nonce-wrong-tool",
        );
        let execution = AcpKernelExecutionContext {
            capability,
            agent_id: subject.public_key().to_hex(),
            session_id: chio_core::session::SessionId::new("acp-authenticated-session"),
            dpop_proof: Some(mismatched_proof),
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
            arguments: request_arguments,
        };

        assert_eq!(
            edge.evaluate_permission(&request, &execution),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn permission_preview_accepts_valid_dpop_without_consuming_invocation_nonce() {
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        kernel.set_dpop_store(
            dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300)),
            dpop::DpopConfig::default(),
        );
        let subject = Keypair::generate();
        let capability = capability_for_tool_with_dpop_requirement(
            &issuer,
            &subject,
            "test-srv",
            "read_file",
            Some(true),
        );
        let request_arguments = json!({"path": "/tmp"});
        let proof = dpop_proof_for_request(
            &subject,
            &capability,
            "test-srv",
            "read_file",
            &request_arguments,
            "acp-preview-valid-invoke-nonce",
        );
        let execution = AcpKernelExecutionContext {
            capability,
            agent_id: subject.public_key().to_hex(),
            session_id: chio_core::session::SessionId::new("acp-authenticated-session"),
            dpop_proof: Some(proof),
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
            arguments: request_arguments.clone(),
        };

        assert_eq!(
            edge.evaluate_permission_with_kernel(&request, &kernel, &execution),
            PermissionDecision::Allow
        );
        let result = edge
            .invoke("read_file", request_arguments, &kernel, &execution)
            .test_expect("valid DPoP proof should remain usable for invoke");
        assert!(result.success);
    }

    #[test]
    fn jsonrpc_permission_preview_uses_kernel_dpop_config() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.set_dpop_store(
            dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300)),
            dpop::DpopConfig {
                proof_ttl_secs: 5,
                max_clock_skew_secs: 0,
                nonce_store_capacity: 1024,
            },
        );
        let subject = Keypair::generate();
        let capability = capability_for_tool_with_dpop_requirement(
            &issuer,
            &subject,
            "test-srv",
            "read_file",
            Some(true),
        );
        let request_arguments = json!({"path": "/tmp"});
        let stale_under_kernel_config = dpop_proof_for_request_issued_at(
            &subject,
            &capability,
            "test-srv",
            "read_file",
            &request_arguments,
            "acp-preview-kernel-dpop-config",
            current_unix_timestamp().saturating_sub(60),
        );
        let execution = AcpKernelExecutionContext {
            capability,
            agent_id: subject.public_key().to_hex(),
            session_id: chio_core::session::SessionId::new("acp-authenticated-session"),
            dpop_proof: Some(stale_under_kernel_config),
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
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": request_arguments
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(
            response["result"]["decision"],
            serde_json::to_value(PermissionDecision::Deny).test_unwrap()
        );
    }

    #[test]
    fn permission_with_capability_denies_out_of_scope_request() {
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
            capability_id: "write_file".to_string(),
            arguments: json!({"path": "/tmp"}),
        };

        assert_eq!(
            edge.evaluate_permission(&request, &execution),
            PermissionDecision::Deny
        );
    }

    // ---- Invocation tests ----

    #[test]
    fn invoke_succeeds() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let server = test_server();
        let result = edge
            .compatibility()
            .invoke("read_file", json!({"path": "/tmp"}), &server)
            .test_unwrap();
        assert!(result.success);
        assert_eq!(result.data["result"], "ok");
        assert_eq!(
            result
                .metadata
                .as_ref()
                .and_then(|metadata| metadata["chio"]["authorityPath"].as_str()),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn invoke_unknown_tool_errors() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let server = test_server();
        let err = edge
            .compatibility()
            .invoke("nonexistent", json!({}), &server)
            .test_expect_err("unknown ACP tool must fail");
        assert!(matches!(err, AcpEdgeError::ToolNotFound(_)));
    }

    #[test]
    fn invoke_server_failure_returns_unsuccessful() {
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
            public_key: manifest_public_key(11),
        };
        let edge =
            ChioAcpEdge::new_from_unverified_internal(AcpEdgeConfig::default(), vec![manifest])
                .test_unwrap();
        let server = FailingToolServer;
        let result = edge
            .compatibility()
            .invoke("fail_tool", json!({}), &server)
            .test_unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(
            result
                .metadata
                .as_ref()
                .and_then(|metadata| metadata["chio"]["authorityPath"].as_str()),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn invoke_with_kernel_emits_signed_receipt_metadata() {
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

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

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();
        assert!(result.success);
        let metadata = result
            .metadata
            .test_expect("kernel path should attach metadata");
        assert!(metadata["chio"]["receiptId"].as_str().is_some());
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("acp")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("native")
        );
        assert_eq!(
            metadata["chio"]["receipt"]["capability_id"].as_str(),
            Some("cap-test-srv-read_file")
        );
    }

    #[test]
    fn invoke_rejects_blank_execution_agent_id_before_dispatch() {
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: "\n".to_string(),
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

        let error = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_expect_err("blank ACP execution agent_id must fail");

        assert_eq!(
            error.to_string(),
            "invalid request: ACP execution agent_id must not be empty"
        );
    }

    #[test]
    fn invoke_rejects_control_character_execution_agent_id_before_dispatch() {
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: format!("{}{}suffix", subject.public_key().to_hex(), '\u{7}'),
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

        let error = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_expect_err("control character ACP execution agent_id must fail");

        assert_eq!(
            error.to_string(),
            "invalid request: ACP execution agent_id must not include control characters"
        );
    }

    #[test]
    fn invoke_with_kernel_denial_still_emits_receipt_metadata() {
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

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

        let result = edge
            .invoke("write_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();
        assert!(!result.success);
        let metadata = result
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
    fn pending_approval_is_not_reported_as_success() {
        let _metrics_guard = metrics_test_guard();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let before_pending = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let result = edge
            .project_pending_approval_for_test(
                "read_file",
                json!({"path": "/tmp"}),
                &kernel,
                &AcpKernelExecutionContext {
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
                },
                "approval required",
            )
            .test_unwrap();
        let metadata = result
            .metadata
            .test_expect("pending approval should attach metadata");

        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("approval required"));
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
    fn invoke_kernel_error_records_receipt_write_error_outcome() {
        let _metrics_guard = metrics_test_guard();
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let mut config = test_kernel_config();
        config.require_web3_evidence = true;
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

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
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let error = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_expect_err("ACP web3 evidence prerequisite failure must reject");

        assert!(error
            .to_string()
            .contains("web3 evidence prerequisites unavailable"));
        assert!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR) > before_error,
            "acp orchestrator error path must advance receipt write error"
        );
    }

    #[test]
    fn pre_kernel_bridge_error_does_not_record_receipt_write_error_outcome() {
        let _metrics_guard = metrics_test_guard();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let capability = capability_for_tool(&issuer, &subject, "test-srv", "read_file");
        let capability_ref = CrossProtocolCapabilityRef {
            chio_capability_id: "wrong-capability".to_string(),
            origin_protocol: DiscoveryProtocol::Acp,
            protocol_context: Some(json!({ "capabilityId": "read_file" })),
            parent_capability_hash: "wrong-parent-hash".to_string(),
        };
        let arguments = json!({ "path": "/tmp" });
        let request = CrossProtocolExecutionRequest {
            origin_request_id: "acp-pre-kernel-mismatch".to_string(),
            kernel_request_id: "acp-pre-kernel-mismatch-kernel".to_string(),
            target_protocol: DiscoveryProtocol::Native,
            target_server_id: "test-srv".to_string(),
            target_tool_name: "read_file".to_string(),
            agent_id: subject.public_key().to_hex(),
            arguments: arguments.clone(),
            capability,
            source_envelope: json!({
                "capabilityId": "read_file",
                "arguments": arguments,
                "metadata": {
                    "chio": {
                        "capabilityRef": serde_json::to_value(capability_ref).test_unwrap()
                    }
                }
            }),
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
            bridge_security: {
                let (registry, _) = registry_with_nontrivial_flow();
                registry
                    .bridge_security("test-srv", "read_file")
                    .test_expect("registry sidecar")
            },
        };
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);
        let (registry, _) = registry_with_nontrivial_flow();

        let error = execute_orchestrated_acp_request(
            &kernel,
            &registry,
            request,
            &TrustedPeerNegotiation::default(),
        )
        .test_expect_err("ACP capability reference mismatch must reject");

        assert!(error.to_string().contains("capability reference mismatch"));
        assert_eq!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
            before_error,
            "pre-kernel ACP bridge errors must not advance receipt write error"
        );
    }

    #[test]
    fn invoke_with_mcp_target_emits_receipt_metadata_and_mcp_projection() {
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

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

        let result = edge
            .invoke_with_mcp_target("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();

        assert!(result.success);
        assert_eq!(result.data["isError"], Value::Bool(false));
        assert_eq!(
            result.data["structuredContent"]["result"].as_str(),
            Some("ok")
        );
        let metadata = result
            .metadata
            .test_expect("MCP target should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("acp")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["multiHop"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["selectedProtocols"],
            json!(["acp", "mcp", "native"])
        );
    }

    #[test]
    fn default_invoke_honors_protocol_aware_target_binding() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), mcp_target_manifest(), 6).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

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

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();

        let metadata = result
            .metadata
            .test_expect("protocol-aware invoke should attach metadata");
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
    }

    #[test]
    fn default_mcp_target_rejects_schema_mismatch_before_receipt_and_recovers() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), mcp_target_manifest(), 6).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

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
        let receipt_count = kernel.receipt_log().len();

        let error = edge
            .invoke("read_file", json!({"path": 7}), &kernel, &execution)
            .test_expect_err("ACP MCP target must reject arguments outside the signed schema");
        assert!(error
            .to_string()
            .contains("signed manifest input schema"));
        assert_eq!(kernel.receipt_log().len(), receipt_count);

        let result = edge
            .invoke(
                "read_file",
                json!({"path": "/tmp/recovered"}),
                &kernel,
                &execution,
            )
            .test_unwrap();
        assert!(result.success);
        assert_eq!(kernel.receipt_log().len(), receipt_count + 1);
    }

    #[test]
    fn default_invoke_supports_openai_target_binding() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), openai_target_manifest(), 7).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

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

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();

        let metadata = result
            .metadata
            .test_expect("protocol-aware invoke should attach metadata");
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("open_ai")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
        assert_eq!(result.data["type"].as_str(), Some("function_call_output"));
    }

    #[test]
    fn invalid_target_protocol_metadata_is_rejected() {
        let error = match ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![invalid_target_manifest()],
        ) {
            Ok(_) => panic!("expected invalid target protocol metadata to fail"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported x-chio-target-protocol value"));
    }

    // ---- JSON-RPC handler tests ----

    #[test]
    fn jsonrpc_param_helpers_validate_capability_and_default_arguments() {
        let missing = match ChioAcpEdge::jsonrpc_permission_request(&json!({})) {
            Ok(_) => panic!("expected missing capabilityId to fail"),
            Err(error) => error,
        };
        assert_eq!(
            missing.to_string(),
            "invalid request: session/request_permission requires params.capabilityId"
        );

        let permission = ChioAcpEdge::jsonrpc_permission_request(&json!({
            "capabilityId": "read_file",
            "arguments": { "path": "/workspace/README.md" }
        }))
        .test_unwrap();
        assert_eq!(permission.capability_id, "read_file");
        assert_eq!(
            permission.arguments,
            json!({ "path": "/workspace/README.md" })
        );

        let non_string = match ChioAcpEdge::jsonrpc_invocation_params(
            &json!({
                "capabilityId": 7,
                "arguments": ["kept"]
            }),
            "tool/invoke",
        ) {
            Ok(_) => panic!("expected non-string capabilityId to fail"),
            Err(error) => error,
        };
        assert_eq!(
            non_string.to_string(),
            "invalid request: tool/invoke params.capabilityId must be a string"
        );

        let (capability_id, default_arguments) = ChioAcpEdge::jsonrpc_invocation_params(
            &json!({
                "capabilityId": "search"
            }),
            "tool/invoke",
        )
        .test_unwrap();
        assert_eq!(capability_id, "search");
        assert_eq!(default_arguments, json!({}));
    }

    #[test]
    fn jsonrpc_list_capabilities() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "session/list_capabilities",
                "params": {}
            }),
            &kernel,
            &execution,
        );
        let caps = response["result"]["capabilities"].as_array().test_unwrap();
        assert_eq!(caps.len(), 4);
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["invokeMode"].as_str(),
            Some("blocking_or_deferred_task")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["lifecycle"]["toolStream"].as_str(),
            Some("deferred_task_resume")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("acp_authoritative")
        );
    }

    #[test]
    fn jsonrpc_request_permission() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("capability_preview")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(false)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["invokeAuthorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_permission_rejects_padded_execution_agent_id_before_preview() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: format!(" {} ", subject.public_key().to_hex()),
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 49,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"].as_str(),
            Some("ACP execution agent_id must not include leading or trailing whitespace")
        );
    }

    #[test]
    fn jsonrpc_request_permission_rejects_empty_capability_id_before_preview() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 41,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "  ",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "session/request_permission params.capabilityId must not be empty"
        );
    }

    #[test]
    fn jsonrpc_request_permission_rejects_padded_capability_id_before_preview() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 44,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": " read_file ",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "session/request_permission params.capabilityId must not include leading or trailing whitespace"
        );
    }

    #[test]
    fn jsonrpc_request_permission_rejects_control_character_capability_id_before_preview() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 47,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file\nwrite_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "session/request_permission params.capabilityId must not include control characters"
        );
    }

    #[test]
    fn jsonrpc_tool_invoke() {
        let edge = verified_test_edge(AcpEdgeConfig::default(), test_manifest(), 1).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tool/invoke",
                "params": {
                    "capabilityId": "search",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response["result"]["success"].as_bool().unwrap_or(false));
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_tool_invoke_rejects_non_string_capability_id_before_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tool/invoke",
                "params": {
                    "capabilityId": 7,
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "tool/invoke params.capabilityId must be a string"
        );
    }

    #[test]
    fn jsonrpc_tool_invoke_rejects_padded_capability_id_before_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 45,
                "method": "tool/invoke",
                "params": {
                    "capabilityId": " search ",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "tool/invoke params.capabilityId must not include leading or trailing whitespace"
        );
    }

    #[test]
    fn jsonrpc_tool_invoke_rejects_control_character_capability_id_before_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 48,
                "method": "tool/invoke",
                "params": {
                    "capabilityId": "search\nread_file",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "tool/invoke params.capabilityId must not include control characters"
        );
    }

    #[test]
    fn jsonrpc_list_capabilities_rejects_non_object_params_before_listing() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 44,
                "method": "session/list_capabilities",
                "params": []
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "session/list_capabilities params must be an object"
        );
    }

    #[test]
    fn jsonrpc_tool_invoke_rejects_non_object_params_before_capability_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 45,
                "method": "tool/invoke",
                "params": []
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "tool/invoke params must be an object"
        );
    }

    include!("lifecycle.rs");
