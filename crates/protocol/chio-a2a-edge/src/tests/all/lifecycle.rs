    #[test]
    fn jsonrpc_stream_creates_deferred_task_and_task_get_resolves_result() {
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
                "method": "message/stream",
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
        assert_eq!(response["result"]["status"].as_str(), Some("working"));
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["streamEntrypoint"].as_str(),
            Some("message/stream")
        );
        let task_id = response["result"]["id"]
            .as_str()
            .test_expect("message/stream should return task id")
            .to_string();
        assert_eq!(
            response["result"]["metadata"]["chio"]["receiptPending"].as_bool(),
            Some(true)
        );

        let resolved = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "task/get",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(resolved["result"]["status"].as_str(), Some("completed"));
        assert_eq!(
            resolved["result"]["metadata"]["chio"]["receiptId"]
                .as_str()
                .map(|value| !value.is_empty()),
            Some(true)
        );
        let parts = resolved["result"]["message"]["parts"]
            .as_array()
            .test_expect("resolved task should contain parts");
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn deferred_a2a_task_discards_snapshot_and_rebinds_fresh_generation() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), stream_manifest(), 2).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(StreamingToolServer));
        let subject = Keypair::generate();
        let capability = capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream");
        let agent_id = subject.public_key().to_hex();
        let session_id = SessionId::new("session-a2a-deferred");
        kernel
            .open_session_with_id(
                session_id.clone(),
                agent_id.clone(),
                vec![capability.clone()],
            )
            .test_unwrap();
        kernel.activate_session(&session_id).test_unwrap();
        let mut execution = A2aKernelExecutionContext {
            capability,
            agent_id,
            session_id: session_id.clone(),
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
            "session-a2a-deferred",
            1,
        ));
        let resolved_generations = Arc::new(Mutex::new(Vec::new()));
        edge.set_deferred_security_context_authority(
            session_id,
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
                "method": "message/stream",
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
        let task_id = accepted["result"]["id"]
            .as_str()
            .test_expect("message/stream should return task id")
            .to_string();
        let retained_request = edge
            .tasks
            .get(&task_id)
            .test_expect("deferred A2A task is retained")
            .request
            .clone();
        assert!(retained_request.security_context.is_none());

        let mut fresh_execution = execution.clone();
        fresh_execution.security_context = Some(invocation_security_context(
            &fresh_execution.capability,
            &fresh_execution.agent_id,
            "session-a2a-deferred",
            99,
        ));
        let mut mismatched_execution = fresh_execution.clone();
        mismatched_execution.capability.id.push_str("-different");
        let mut rejected_request = retained_request.clone();
        assert!(refresh_deferred_a2a_security_context(
            &mut rejected_request,
            &mismatched_execution,
            &execution.session_id,
        )
        .is_err());
        let mut rebound_request = retained_request;
        refresh_deferred_a2a_security_context(
            &mut rebound_request,
            &fresh_execution,
            &execution.session_id,
        )
        .test_unwrap();
        assert!(rebound_request.security_context.is_none());

        let resolved = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 21,
                "method": "task/get",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &fresh_execution,
        );
        assert_eq!(
            resolved["result"]["status"].as_str(),
            Some("completed"),
            "{resolved:?}"
        );
        assert_eq!(
            *resolved_generations
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            vec![2]
        );
    }

    #[test]
    fn deferred_a2a_task_rejects_foreign_session_get_and_cancel() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), stream_manifest(), 2).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let invocations = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingStreamingToolServer {
            invocations: Arc::clone(&invocations),
        }));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            session_id: SessionId::new("session-a2a-owner"),
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
                "method": "message/stream",
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
        let task_id = accepted["result"]["id"]
            .as_str()
            .test_expect("message/stream should return task id")
            .to_string();
        let mut foreign_execution = execution.clone();
        foreign_execution.session_id = SessionId::new("session-a2a-foreign");

        for method in ["task/get", "task/cancel"] {
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
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(
            edge.tasks
                .get(&task_id)
                .test_expect("owner task remains retained")
                .response
                .status,
            TaskStatus::Working
        );
    }

    #[test]
    fn deferred_a2a_task_rejects_authority_context_for_wrong_session() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), stream_manifest(), 2).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let invocations = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingStreamingToolServer {
            invocations: Arc::clone(&invocations),
        }));
        let subject = Keypair::generate();
        let capability = capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream");
        let agent_id = subject.public_key().to_hex();
        let execution = A2aKernelExecutionContext {
            security_context: Some(invocation_security_context(
                &capability,
                &agent_id,
                "session-a2a-authority-owner",
                1,
            )),
            capability,
            agent_id,
            session_id: SessionId::new("session-a2a-authority-owner"),
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
                session_id: "session-a2a-authority-foreign",
            }),
        )
        .test_unwrap();
        let accepted = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 32,
                "method": "message/stream",
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
        let task_id = accepted["result"]["id"]
            .as_str()
            .test_expect("message/stream should return task id")
            .to_string();

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 33,
                "method": "task/get",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &execution,
        );
        assert!(rejected["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("authenticated session")));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn deferred_a2a_post_dispatch_error_terminalizes_without_replay() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), stream_manifest(), 2).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel
            .set_receipt_store(Box::new(FailingAppendReceiptStore))
            .test_unwrap();
        let invocations = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingStreamingToolServer {
            invocations: Arc::clone(&invocations),
        }));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            session_id: SessionId::new("session-a2a-post-dispatch"),
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
                "method": "message/stream",
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
        let task_id = accepted["result"]["id"]
            .as_str()
            .test_expect("message/stream should return task id")
            .to_string();

        let first = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 35,
                "method": "task/get",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &execution,
        );
        assert!(first["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("receipt failure")));
        assert_eq!(invocations.load(Ordering::SeqCst), 1);

        let second = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 36,
                "method": "task/get",
                "params": { "taskId": task_id }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(second["result"]["status"].as_str(), Some("failed"));
        assert_eq!(
            second["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("outcome_unknown")
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn jsonrpc_task_get_runtime_admission_denies_before_deferred_dispatch() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), stream_manifest(), 2).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let invocations = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingStreamingToolServer {
            invocations: Arc::clone(&invocations),
        }));
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

        let accepted = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "message/stream",
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
        assert_eq!(accepted["result"]["status"].as_str(), Some("working"));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        let task_id = accepted["result"]["id"]
            .as_str()
            .test_expect("message/stream should return task id")
            .to_string();

        kernel.set_runtime_admission_hook(Arc::new(DenyingRuntimeAdmissionHook));
        let denied = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "task/get",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(denied["result"]["status"].as_str(), Some("failed"));
        assert_eq!(
            denied["result"]["statusMessage"].as_str(),
            Some("a2a edge runtime admission denied")
        );
        assert_eq!(
            denied["result"]["metadata"]
                .pointer("/chio/receipt/metadata/chio_runtime/failure_code")
                .and_then(Value::as_str),
            Some("a2a_edge_runtime_admission_denied")
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn jsonrpc_stream_notification_creates_task_without_response() {
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
                "method": "message/stream",
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

        assert!(response.is_notification());
        assert_eq!(edge.tasks.len(), 1);
    }

    #[test]
    fn jsonrpc_task_get_retains_completed_deferred_task_result() {
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

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "message/stream",
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
        let task_id = created["result"]["id"].as_str().test_unwrap().to_string();

        let resolved = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 31,
                "method": "task/get",
                "params": { "taskId": task_id.clone() }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(resolved["result"]["status"].as_str(), Some("completed"));
        assert!(edge.tasks.contains_key(&task_id));

        let repeated = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 32,
                "method": "task/get",
                "params": { "taskId": task_id.clone() }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(repeated["result"]["status"].as_str(), Some("completed"));
        assert_eq!(
            repeated["result"]["metadata"]["chio"]["receiptId"],
            resolved["result"]["metadata"]["chio"]["receiptId"]
        );
    }

    #[test]
    fn jsonrpc_task_get_rejects_empty_task_id_before_lookup() {
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
                "id": 32,
                "method": "task/get",
                "params": { "taskId": "" }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "task/get params.taskId must not be empty"
        );
    }

    #[test]
    fn jsonrpc_task_id_params_reject_surrounding_whitespace_before_lookup() {
        let error = match ChioA2aEdge::parse_jsonrpc_task_id_params(
            &json!({ "taskId": " task-1 " }),
            "task/cancel",
        ) {
            Ok(_) => panic!("expected padded taskId to fail before lookup"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(
            message,
            "task/cancel params.taskId must not include leading or trailing whitespace"
        );
    }

    #[test]
    fn jsonrpc_task_id_params_reject_control_characters_before_lookup() {
        let error = match ChioA2aEdge::parse_jsonrpc_task_id_params(
            &json!({ "taskId": "a2a-task-1\na2a-task-2" }),
            "task/get",
        ) {
            Ok(_) => panic!("expected control-character taskId to fail before lookup"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(
            message,
            "task/get params.taskId must not include control characters"
        );
    }

    #[test]
    fn jsonrpc_stream_rejects_deferred_task_map_over_cap() {
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

        for index in 0..1_024 {
            let response = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "message/stream",
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
            assert_eq!(response["result"]["status"].as_str(), Some("working"));
        }

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 2_000,
                "method": "message/stream",
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

        assert!(rejected["error"]["message"]
            .as_str()
            .test_unwrap()
            .contains("too many deferred tasks"));
    }

    #[test]
    fn jsonrpc_stream_rejects_padded_execution_agent_id_before_task_retention() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), stream_manifest(), 2).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: format!(" {} ", subject.public_key().to_hex()),
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

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 2_500,
                "method": "message/stream",
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

        assert_eq!(rejected["error"]["code"], -32602);
        assert_eq!(
            rejected["error"]["message"].as_str(),
            Some("A2A execution agent_id must not include leading or trailing whitespace")
        );
        assert!(edge.tasks.is_empty());
    }

    #[test]
    fn jsonrpc_stream_capacity_ignores_retained_terminal_deferred_tasks() {
        for terminal_status in [TaskStatus::Cancelled, TaskStatus::Completed] {
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

            for index in 0..MAX_DEFERRED_A2A_TASKS {
                let created = edge.handle_jsonrpc(
                    json!({
                        "jsonrpc": "2.0",
                        "id": index,
                        "method": "message/stream",
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
                assert_eq!(created["result"]["status"].as_str(), Some("working"));
                let task_id = created["result"]["id"]
                    .as_str()
                    .test_expect("message/stream should return task id")
                    .to_string();
                let task = edge
                    .tasks
                    .get_mut(&task_id)
                    .test_expect("stream task should be retained");
                task.response.status = terminal_status;
            }

            assert_eq!(edge.tasks.len(), MAX_DEFERRED_A2A_TASKS);

            let accepted = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": 3_000,
                    "method": "message/stream",
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

            assert_eq!(accepted["result"]["status"].as_str(), Some("working"));
        }
    }

    #[test]
    fn jsonrpc_task_cancel_marks_stream_task_cancelled() {
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
                "id": 12,
                "method": "message/stream",
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
        let task_id = response["result"]["id"].as_str().test_unwrap().to_string();

        let cancelled = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 13,
                "method": "task/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(cancelled["result"]["status"].as_str(), Some("cancelled"));
        assert_eq!(
            cancelled["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );

        let cancelled_again = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 14,
                "method": "task/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            cancelled_again["result"]["status"].as_str(),
            Some("cancelled")
        );
        assert_eq!(
            cancelled_again["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );
    }

    #[test]
    fn complete_task_preserves_cancelled_deferred_task() {
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

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 15,
                "method": "message/stream",
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
        let task_id = created["result"]["id"].as_str().test_unwrap().to_string();

        let cancelled = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 16,
                "method": "task/cancel",
                "params": {
                    "taskId": task_id.clone()
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(cancelled["result"]["status"].as_str(), Some("cancelled"));

        let completed_after_cancel = edge.complete_task(&task_id, &kernel, &execution, json!(17));
        assert_eq!(
            completed_after_cancel["result"]["status"].as_str(),
            Some("cancelled")
        );
        assert_eq!(
            completed_after_cancel["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );

        let repeated = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 18,
                "method": "task/get",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(repeated["result"]["status"].as_str(), Some("cancelled"));
    }

    #[test]
    fn authoritative_send_uses_protocol_aware_target_binding() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), mcp_target_manifest(), 5).test_unwrap();
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
            .handle_send_message(
                "echo",
                &SendMessageRequest {
                    message: A2aMessage {
                        role: "user".to_string(),
                        parts: vec![A2aPart::Data {
                            data: json!({"message": "hello"}),
                        }],
                        metadata: None,
                    },
                    metadata: None,
                },
                &kernel,
                &execution,
            )
            .test_unwrap();

        let metadata = response.metadata.test_unwrap();
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["multiHop"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["selectedProtocols"],
            json!(["a2a", "mcp", "native"])
        );
    }

    #[test]
    fn authoritative_mcp_target_rejects_schema_mismatch_before_receipt_and_recovers() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), mcp_target_manifest(), 5).test_unwrap();
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
        let receipt_count = kernel.receipt_log().len();

        let error = edge
            .handle_send_message(
                "echo",
                &SendMessageRequest {
                    message: A2aMessage {
                        role: "user".to_string(),
                        parts: vec![A2aPart::Data {
                            data: json!({"message": true}),
                        }],
                        metadata: None,
                    },
                    metadata: None,
                },
                &kernel,
                &execution,
            )
            .test_expect_err("A2A MCP target must reject arguments outside the signed schema");
        assert!(error
            .to_string()
            .contains("signed manifest input schema"));
        assert_eq!(kernel.receipt_log().len(), receipt_count);

        let response = edge
            .handle_send_message(
                "echo",
                &SendMessageRequest {
                    message: A2aMessage {
                        role: "user".to_string(),
                        parts: vec![A2aPart::Data {
                            data: json!({"message": "recovered"}),
                        }],
                        metadata: None,
                    },
                    metadata: None,
                },
                &kernel,
                &execution,
            )
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Completed);
        assert_eq!(kernel.receipt_log().len(), receipt_count + 1);
    }

    #[test]
    fn authoritative_send_supports_openai_target_binding() {
        let mut edge =
            verified_test_edge(A2aEdgeConfig::default(), openai_target_manifest(), 6).test_unwrap();
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
            .handle_send_message(
                "echo",
                &SendMessageRequest {
                    message: A2aMessage {
                        role: "user".to_string(),
                        parts: vec![A2aPart::Data {
                            data: json!({"message": "hello"}),
                        }],
                        metadata: None,
                    },
                    metadata: None,
                },
                &kernel,
                &execution,
            )
            .test_unwrap();

        let metadata = response.metadata.test_unwrap();
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("open_ai")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn invalid_target_protocol_metadata_fails_closed() {
        let error = match ChioA2aEdge::new_from_unverified_internal(
            A2aEdgeConfig::default(),
            vec![invalid_target_manifest()],
        ) {
            Ok(_) => panic!("expected invalid target protocol metadata to fail"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("unsupported x-chio-target-protocol value"));
    }

    // ---- Error type tests ----

    #[test]
    fn error_display_tool_not_found() {
        let err = A2aEdgeError::ToolNotFound("missing".into());
        assert!(format!("{err}").contains("missing"));
    }

    #[test]
    fn error_display_invalid_request() {
        let err = A2aEdgeError::InvalidRequest("bad".into());
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn error_display_kernel() {
        let err = A2aEdgeError::Kernel("denied".into());
        assert!(format!("{err}").contains("denied"));
    }

    // ---- Duplicate skill handling ----

    #[test]
    fn duplicate_skills_across_manifests_receive_qualified_ids() {
        let m1 = test_manifest();
        let m2 = test_manifest(); // Same tool names
        let edge =
            ChioA2aEdge::new_from_unverified_internal(A2aEdgeConfig::default(), vec![m1, m2])
                .test_unwrap();
        assert_eq!(edge.skill_ids().len(), 4);
        assert!(edge.skill("test-srv::echo").is_some());
        assert!(edge.skill("test-srv::echo#2").is_some());
        assert!(edge.skill("test-srv::write").is_some());
        assert!(edge.skill("test-srv::write#2").is_some());
        assert_eq!(
            edge.bridge_fidelity("echo"),
            Some(&BridgeFidelity::Unsupported {
                reason: "skill id collides across manifests; use one of the qualified ids: test-srv::echo, test-srv::echo#2".to_string()
            })
        );
    }

    #[test]
    fn ambiguous_unqualified_skill_id_returns_guidance() {
        let m1 = test_manifest();
        let m2 = test_manifest(); // Same tool names
        let mut edge =
            ChioA2aEdge::new_from_unverified_internal(A2aEdgeConfig::default(), vec![m1, m2])
                .test_unwrap();
        let server = test_server();
        let error = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &text_message("hello"), &server)
            .test_expect_err("ambiguous unqualified A2A skill id must fail");

        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request");
        };
        assert!(message.contains("ambiguous"));
        assert!(message.contains("test-srv::echo"));
        assert!(message.contains("test-srv::echo#2"));
    }

    // ---- Default config tests ----

    #[test]
    fn default_config_has_reasonable_values() {
        let config = A2aEdgeConfig::default();
        assert!(!config.agent_name.is_empty());
        assert_eq!(config.protocol_binding, "JSONRPC");
    }

    // ---- TaskStatus serde ----

    #[test]
    fn task_status_serializes_correctly() {
        let json = serde_json::to_value(TaskStatus::Completed).test_unwrap();
        assert_eq!(json, "completed");
        let json = serde_json::to_value(TaskStatus::Failed).test_unwrap();
        assert_eq!(json, "failed");
    }

    #[test]
    fn bridge_fidelity_serializes_correctly() {
        let json = serde_json::to_value(BridgeFidelity::Lossless).test_unwrap();
        assert_eq!(json, json!({"kind": "lossless"}));
        let json = serde_json::to_value(BridgeFidelity::Adapted {
            caveats: vec!["stream collated".to_string()],
        })
        .test_unwrap();
        assert_eq!(
            json,
            json!({"kind": "adapted", "caveats": ["stream collated"]})
        );
        let json = serde_json::to_value(BridgeFidelity::Unsupported {
            reason: "needs cancellation".to_string(),
        })
        .test_unwrap();
        assert_eq!(
            json,
            json!({"kind": "unsupported", "reason": "needs cancellation"})
        );
    }
