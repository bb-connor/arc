    #[test]
    fn jsonrpc_resume_rejects_non_object_params_before_task_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![streaming_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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
                "id": 46,
                "method": "tool/resume",
                "params": []
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "tool/resume params must be an object"
        );
    }

    #[test]
    fn jsonrpc_unknown_method() {
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
                "method": "unknown/method",
                "params": {}
            }),
            &kernel,
            &execution,
        );
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn jsonrpc_rejects_non_scalar_request_ids_before_method_dispatch() {
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

        for invalid_id in [json!(false), json!({"nested": 1}), json!([1])] {
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
                "jsonrpc": "1.0",
                "id": "request-7",
                "method": "session/list_capabilities",
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
    fn jsonrpc_compatibility_permission_rejects_non_object_params_before_preview() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let server = test_server();

        let response = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 47,
                "method": "session/request_permission",
                "params": []
            }),
            &server,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "session/request_permission params must be an object"
        );
    }

    #[test]
    fn jsonrpc_passthrough_marks_non_authoritative_paths() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest()],
        )
        .test_unwrap();
        let server = test_server();

        let listed = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "session/list_capabilities",
                "params": {}
            }),
            &server,
        );
        assert_eq!(
            listed["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            listed["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );

        let permission = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &server,
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("config_preview")
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["previewOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["invokeAuthorityPath"].as_str(),
            Some("passthrough_compatibility")
        );

        let invoke = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tool/invoke",
                "params": {
                    "capabilityId": "search",
                    "arguments": {"query": "test"}
                }
            }),
            &server,
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["authoritative"].as_bool(),
            Some(false)
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn jsonrpc_stream_creates_deferred_task_and_resume_resolves_result() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(MockToolServer {
            server_id: "streaming-srv".to_string(),
            tools: vec!["search_stream".to_string()],
            response: json!({"content": [{"text": "chunk-1"}, {"text": "chunk-2"}]}),
        }));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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
                "id": 9,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            response["result"]["task"]["status"].as_str(),
            Some("working")
        );
        let task_id = response["result"]["task"]["id"]
            .as_str()
            .test_expect("tool/stream should create task")
            .to_string();
        assert_eq!(
            response["result"]["task"]["metadata"]["chio"]["receiptPending"].as_bool(),
            Some(true)
        );
        assert_eq!(
            response["result"]["task"]["metadata"]["chio"]["runtimeLifecycle"]["streamEntrypoint"]
                .as_str(),
            Some("tool/stream")
        );

        let resumed = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tool/resume",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            resumed["result"]["task"]["status"].as_str(),
            Some("completed")
        );
        assert_eq!(
            resumed["result"]["result"]["metadata"]["chio"]["receiptId"]
                .as_str()
                .map(|value| !value.is_empty()),
            Some(true)
        );
        assert!(resumed["result"]["result"]["data"]["content"].is_array());
    }

    #[test]
    fn deferred_acp_task_discards_snapshot_and_rebinds_fresh_generation() {
        let mut edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(MockToolServer {
            server_id: "streaming-srv".to_string(),
            tools: vec!["search_stream".to_string()],
            response: json!({"content": [{"text": "chunk-1"}]}),
        }));
        let subject = Keypair::generate();
        let capability = capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream");
        let agent_id = subject.public_key().to_hex();
        let mut execution = AcpKernelExecutionContext {
            capability,
            agent_id,
            session_id: SessionId::new("session-acp-deferred"),
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
        execution.security_context = Some(invocation_security_context(
            &execution.capability,
            &execution.agent_id,
            "session-acp-deferred",
            1,
        ));
        let resolved_generations = Arc::new(Mutex::new(Vec::new()));
        edge.set_deferred_security_context_authority(
            SessionId::new("session-acp-deferred"),
            Arc::new(RecordingSecurityContextAuthority {
                generation: 2,
                resolved_generations: Arc::clone(&resolved_generations),
            }),
        )
        .test_unwrap();

        let accepted = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = accepted["result"]["task"]["id"]
            .as_str()
            .test_expect("tool/stream should return task id")
            .to_string();
        let retained_request = edge
            .tasks
            .borrow()
            .get(&task_id)
            .test_expect("deferred ACP task is retained")
            .request
            .clone();
        assert!(retained_request.security_context.is_none());

        let mut fresh_execution = execution.clone();
        fresh_execution.security_context = Some(invocation_security_context(
            &fresh_execution.capability,
            &fresh_execution.agent_id,
            "session-acp-deferred",
            99,
        ));
        let mut mismatched_execution = fresh_execution.clone();
        mismatched_execution.capability.id.push_str("-different");
        let mut rejected_request = retained_request.clone();
        assert!(refresh_deferred_acp_security_context(
            &mut rejected_request,
            &mismatched_execution,
            &execution.session_id,
        )
        .is_err());
        let mut rebound_request = retained_request;
        refresh_deferred_acp_security_context(
            &mut rebound_request,
            &fresh_execution,
            &execution.session_id,
        )
        .test_unwrap();
        assert!(rebound_request.security_context.is_none());

        let resumed = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tool/resume",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &fresh_execution,
        );
        assert_eq!(
            resumed["result"]["task"]["status"].as_str(),
            Some("completed")
        );
        assert_eq!(
            *resolved_generations
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            vec![2]
        );
    }

    #[test]
    fn deferred_acp_task_rejects_foreign_session_resume_and_cancel() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let calls = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(CountingToolServer {
            calls: Arc::clone(&calls),
        }));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
            agent_id: subject.public_key().to_hex(),
            session_id: SessionId::new("session-acp-owner"),
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
        let accepted = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = accepted["result"]["task"]["id"]
            .as_str()
            .test_expect("tool/stream should return task id")
            .to_string();
        let mut foreign_execution = execution.clone();
        foreign_execution.session_id = SessionId::new("session-acp-foreign");

        for method in ["tool/resume", "tool/cancel"] {
            let rejected = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": 31,
                    "method": method,
                    "params": { "taskId": task_id }
                }),
                &kernel,
                &foreign_execution,
            );
            assert!(rejected["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("session")));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            edge.tasks
                .borrow()
                .get(&task_id)
                .test_expect("owner task remains retained")
                .task
                .status,
            AcpTaskStatus::Working
        );
    }

    #[test]
    fn deferred_acp_task_rejects_authority_context_for_wrong_session() {
        let mut edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let calls = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(CountingToolServer {
            calls: Arc::clone(&calls),
        }));
        let subject = Keypair::generate();
        let capability = capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream");
        let agent_id = subject.public_key().to_hex();
        let execution = AcpKernelExecutionContext {
            security_context: Some(invocation_security_context(
                &capability,
                &agent_id,
                "session-acp-authority-owner",
                1,
            )),
            capability,
            agent_id,
            session_id: SessionId::new("session-acp-authority-owner"),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
        };
        edge.set_deferred_security_context_authority(
            execution.session_id.clone(),
            Arc::new(FixedSessionSecurityContextAuthority {
                session_id: "session-acp-authority-foreign",
            }),
        )
        .test_unwrap();
        let accepted = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 32,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = accepted["result"]["task"]["id"]
            .as_str()
            .test_expect("tool/stream should return task id")
            .to_string();

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 33,
                "method": "tool/resume",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &execution,
        );
        assert!(rejected["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("authenticated session")));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn deferred_acp_post_dispatch_error_terminalizes_without_replay() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel
            .set_receipt_store(Box::new(FailingAppendReceiptStore))
            .test_unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(CountingToolServer {
            calls: Arc::clone(&calls),
        }));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
            agent_id: subject.public_key().to_hex(),
            session_id: SessionId::new("session-acp-post-dispatch"),
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
        let accepted = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 34,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = accepted["result"]["task"]["id"]
            .as_str()
            .test_expect("tool/stream should return task id")
            .to_string();

        let first = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 35,
                "method": "tool/resume",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &execution,
        );
        assert!(first["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("receipt failure")));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let second = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 36,
                "method": "tool/resume",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(second["result"]["task"]["status"].as_str(), Some("failed"));
        assert_eq!(
            second["result"]["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("outcome_unknown")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn jsonrpc_resume_runtime_admission_denies_before_stream_tool_dispatch() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let tool_calls = Arc::new(AtomicU64::new(0));
        let admission_calls = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(CountingToolServer {
            calls: Arc::clone(&tool_calls),
        }));
        kernel.set_runtime_admission_hook(Arc::new(DenyingAcpRuntimeAdmissionHook {
            calls: Arc::clone(&admission_calls),
        }));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 70,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = created["result"]["task"]["id"]
            .as_str()
            .test_expect("tool/stream should create task")
            .to_string();

        let resumed = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 71,
                "method": "tool/resume",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);
        assert_eq!(resumed["result"]["task"]["status"].as_str(), Some("failed"));
        assert_eq!(
            resumed["result"]["result"]["error"].as_str(),
            Some("acp runtime admission denied")
        );
        assert_eq!(
            resumed["result"]["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("deny")
        );
        assert_eq!(
            resumed["result"]["result"]["metadata"]["chio"]["reason"].as_str(),
            Some("acp runtime admission denied")
        );
    }

    #[test]
    fn jsonrpc_stream_notification_creates_task_without_response() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );

        assert!(response.is_notification());
        assert_eq!(edge.tasks.borrow().len(), 1);
    }

    #[test]
    fn jsonrpc_resume_retains_completed_deferred_task_result() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(MockToolServer {
            server_id: "streaming-srv".to_string(),
            tools: vec!["search_stream".to_string()],
            response: json!({"content": [{"text": "chunk-1"}]}),
        }));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = created["result"]["task"]["id"]
            .as_str()
            .test_unwrap()
            .to_string();

        let resumed = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tool/resume",
                "params": { "taskId": task_id.clone() }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(
            resumed["result"]["task"]["status"].as_str(),
            Some("completed")
        );
        assert!(edge.tasks.borrow().contains_key(&task_id));

        let repeated = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 32,
                "method": "tool/resume",
                "params": { "taskId": task_id.clone() }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            repeated["result"]["task"]["status"].as_str(),
            Some("completed")
        );
        assert_eq!(
            repeated["result"]["result"]["metadata"]["chio"]["receiptId"],
            resumed["result"]["result"]["metadata"]["chio"]["receiptId"]
        );
    }

    #[test]
    fn jsonrpc_lifecycle_rejects_empty_task_id_before_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![streaming_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        for method in ["tool/cancel", "tool/resume"] {
            let response = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": 43,
                    "method": method,
                    "params": {
                        "taskId": ""
                    }
                }),
                &kernel,
                &execution,
            );

            assert_eq!(response["error"]["code"], -32602);
            assert_eq!(
                response["error"]["message"],
                format!("{method} params.taskId must not be empty")
            );
        }
    }

    #[test]
    fn jsonrpc_lifecycle_rejects_padded_task_id_before_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![streaming_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        for method in ["tool/cancel", "tool/resume"] {
            let response = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": 46,
                    "method": method,
                    "params": {
                        "taskId": " acp-task-1 "
                    }
                }),
                &kernel,
                &execution,
            );

            assert_eq!(response["error"]["code"], -32602);
            assert_eq!(
                response["error"]["message"],
                format!("{method} params.taskId must not include leading or trailing whitespace")
            );
        }
    }

    #[test]
    fn jsonrpc_lifecycle_rejects_control_character_task_id_before_lookup() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![streaming_manifest()],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        for method in ["tool/cancel", "tool/resume"] {
            let response = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": 49,
                    "method": method,
                    "params": {
                        "taskId": "acp-task-1\nacp-task-2"
                    }
                }),
                &kernel,
                &execution,
            );

            assert_eq!(response["error"]["code"], -32602);
            assert_eq!(
                response["error"]["message"],
                format!("{method} params.taskId must not include control characters")
            );
        }
    }

    #[test]
    fn jsonrpc_stream_rejects_deferred_task_map_over_cap() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        for index in 0..1_024 {
            let response = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tool/stream",
                    "params": {
                        "capabilityId": "search_stream",
                        "arguments": {"query": "test"}
                    }
                }),
                &kernel,
                &execution,
            );
            assert_eq!(
                response["result"]["task"]["status"].as_str(),
                Some("working")
            );
        }

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 2_000,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );

        assert!(rejected["error"]["message"]
            .as_str()
            .test_unwrap()
            .contains("too many deferred tasks"));
    }

    #[test]
    fn jsonrpc_stream_rejects_padded_execution_agent_id_before_task_retention() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 2_500,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(rejected["error"]["code"], -32602);
        assert_eq!(
            rejected["error"]["message"].as_str(),
            Some("ACP execution agent_id must not include leading or trailing whitespace")
        );
        assert!(edge.tasks.borrow().is_empty());
    }

    #[test]
    fn jsonrpc_stream_capacity_ignores_retained_cancelled_deferred_tasks() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        for index in 0..MAX_DEFERRED_ACP_TASKS {
            let created = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tool/stream",
                    "params": {
                        "capabilityId": "search_stream",
                        "arguments": {"query": "test"}
                    }
                }),
                &kernel,
                &execution,
            );
            assert_eq!(
                created["result"]["task"]["status"].as_str(),
                Some("working")
            );
            let task_id = created["result"]["task"]["id"]
                .as_str()
                .test_expect("tool/stream should return task id")
                .to_string();

            let cancelled = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": index + MAX_DEFERRED_ACP_TASKS,
                    "method": "tool/cancel",
                    "params": {
                        "taskId": task_id
                    }
                }),
                &kernel,
                &execution,
            );
            assert_eq!(
                cancelled["result"]["task"]["status"].as_str(),
                Some("cancelled")
            );
        }

        assert_eq!(edge.tasks.borrow().len(), MAX_DEFERRED_ACP_TASKS);

        let accepted = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 3_000,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(
            accepted["result"]["task"]["status"].as_str(),
            Some("working")
        );
    }

    #[test]
    fn jsonrpc_cancel_marks_deferred_stream_task_cancelled() {
        let edge =
            verified_test_edge(AcpEdgeConfig::default(), streaming_manifest(), 5).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = created["result"]["task"]["id"]
            .as_str()
            .test_unwrap()
            .to_string();

        let cancelled = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tool/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            cancelled["result"]["task"]["status"].as_str(),
            Some("cancelled")
        );
        assert_eq!(
            cancelled["result"]["task"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );

        let cancelled_again = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tool/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            cancelled_again["result"]["task"]["status"].as_str(),
            Some("cancelled")
        );
        assert_eq!(
            cancelled_again["result"]["task"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );
    }

    #[test]
    fn compatibility_jsonrpc_explicitly_rejects_unimplemented_lifecycle_methods() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![streaming_manifest()],
        )
        .test_unwrap();
        let server = test_server();

        let response = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tool/cancel",
                "params": {
                    "capabilityId": "search_stream"
                }
            }),
            &server,
        );
        assert_eq!(response["error"]["code"], -32601);
        assert_eq!(
            response["error"]["data"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            response["error"]["data"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
    }

    // ---- Deduplication tests ----

    #[test]
    fn duplicate_tools_across_manifests_deduplicated() {
        let m1 = test_manifest();
        let m2 = test_manifest();
        let edge =
            ChioAcpEdge::new_from_unverified_internal(AcpEdgeConfig::default(), vec![m1, m2])
                .test_unwrap();
        assert_eq!(edge.capabilities().len(), 4);
    }

    #[test]
    fn colliding_capability_ids_are_withheld_deterministically() {
        let edge = ChioAcpEdge::new_from_unverified_internal(
            AcpEdgeConfig::default(),
            vec![test_manifest(), colliding_search_manifest()],
        )
        .test_unwrap();

        assert!(edge.capability("search").is_none());
        assert_eq!(edge.capabilities().len(), 3);

        let fidelity = edge
            .bridge_fidelity("search")
            .test_expect("collision should still have fidelity classification");
        let BridgeFidelity::Unsupported { reason } = fidelity else {
            panic!("colliding capability should be unsupported");
        };
        assert!(reason.contains("withheld from discovery"));
        assert!(reason.contains("other-srv/search"));
        assert!(reason.contains("test-srv/search"));
    }

    // ---- Error display tests ----

    #[test]
    fn error_display_tool_not_found() {
        let err = AcpEdgeError::ToolNotFound("x".into());
        assert!(format!("{err}").contains("x"));
    }

    #[test]
    fn error_display_access_denied() {
        let err = AcpEdgeError::AccessDenied("no cap".into());
        assert!(format!("{err}").contains("no cap"));
    }

    #[test]
    fn error_display_kernel() {
        let err = AcpEdgeError::Kernel("internal".into());
        assert!(format!("{err}").contains("internal"));
    }

    // ---- Serde tests ----

    #[test]
    fn bridge_fidelity_serializes() {
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Lossless).test_unwrap(),
            json!({"kind": "lossless"})
        );
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Adapted {
                caveats: vec!["preview only".to_string()]
            })
            .test_unwrap(),
            json!({"kind": "adapted", "caveats": ["preview only"]})
        );
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Unsupported {
                reason: "not publishable".to_string()
            })
            .test_unwrap(),
            json!({"kind": "unsupported", "reason": "not publishable"})
        );
    }

    #[test]
    fn acp_category_serializes() {
        assert_eq!(
            serde_json::to_value(AcpCategory::Tool).test_unwrap(),
            "tool"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Filesystem).test_unwrap(),
            "filesystem"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Terminal).test_unwrap(),
            "terminal"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Browser).test_unwrap(),
            "browser"
        );
    }

    #[test]
    fn permission_decision_serializes() {
        assert_eq!(
            serde_json::to_value(PermissionDecision::Allow).test_unwrap(),
            "allow"
        );
        assert_eq!(
            serde_json::to_value(PermissionDecision::Deny).test_unwrap(),
            "deny"
        );
    }

    // ---- Default config tests ----

    #[test]
    fn default_config_requires_permission() {
        let config = AcpEdgeConfig::default();
        assert!(config.require_permission);
        assert_eq!(config.default_category, AcpCategory::Tool);
    }
