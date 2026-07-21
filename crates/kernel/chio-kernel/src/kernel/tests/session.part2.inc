#[test]
fn tool_call_nested_flow_rejects_malformed_execution_nonce_without_inflight_leak() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id =
        match kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]) {
            Ok(session_id) => session_id,
            Err(error) => panic!("session should open: {error}"),
        };
    if let Err(error) = kernel.activate_session(&session_id) {
        panic!("session should activate: {error}");
    }

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-malformed-nonce",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        supplemental_authorization: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        execution_nonce: Some(serde_json::json!("not-a-signed-execution-nonce")),
        model_metadata: None,
        extra_metadata: None,
        declassification_grant: None,
    };

    let error = match kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    ) {
        Ok(_) => panic!("malformed execution_nonce should fail closed"),
        Err(error) => error,
    };
    assert!(
        format!("{error}").contains("session tool call execution_nonce is malformed"),
        "unexpected error: {error}"
    );
    let no_inflight_request = kernel
        .session(&session_id)
        .map(|session| session.inflight().is_empty())
        .unwrap_or(false);
    assert!(
        no_inflight_request,
        "malformed nonce must not leak inflight state"
    );

    let retry_error = match kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    ) {
        Ok(_) => panic!("retry with malformed execution_nonce should still fail closed"),
        Err(error) => error,
    };
    assert!(
        format!("{retry_error}").contains("session tool call execution_nonce is malformed"),
        "unexpected retry error: {retry_error}"
    );
}

#[test]
fn tool_call_nested_flow_bridge_filters_resource_notifications_to_session_subscriptions() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let tool_capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "notify_resources_via_client")]),
        300,
    );
    let resource_capability = make_capability(
        &kernel,
        &agent_kp,
        ChioScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read, Operation::Subscribe],
            }],
            ..ChioScope::default()
        },
        300,
    );
    let session_id = kernel
        .open_session(
            agent_kp.public_key().to_hex(),
            vec![tool_capability.clone(), resource_capability.clone()],
        )
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .subscribe_session_resource(
            &session_id,
            &resource_capability,
            &agent_kp.public_key().to_hex(),
            "repo://docs/architecture",
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-resource-notify",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: tool_capability,
        server_id: "nested".to_string(),
        tool_name: "notify_resources_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        supplemental_authorization: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
        declassification_grant: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        client.resource_updates,
        vec!["repo://docs/architecture".to_string()]
    );
    assert_eq!(client.resources_list_changed_count, 1);
}

#[test]
fn session_operation_list_resources_filters_to_session_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![cap])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let context =
        make_operation_context(&session_id, "resources-1", &agent_kp.public_key().to_hex());

    let response = kernel
        .evaluate_session_operation(&context, &SessionOperation::ListResources)
        .unwrap();

    let resources = session_resource_list(response).expect("expected resource list response");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].uri, "repo://docs/architecture");
}

#[test]
fn session_operation_read_resource_enforces_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let allowed_context = make_operation_context(
        &session_id,
        "resource-read-1",
        &agent_kp.public_key().to_hex(),
    );
    let allowed = kernel
        .evaluate_session_operation(
            &allowed_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap.clone(),
                uri: "repo://docs/architecture".to_string(),
            }),
        )
        .unwrap();
    let contents = session_resource_read(allowed).expect("expected resource read response");
    assert_eq!(contents[0].text.as_deref(), Some("# Architecture"));

    let denied_context = make_operation_context(
        &session_id,
        "resource-read-2",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "repo://secret/ops".to_string(),
        }),
    );
    assert!(matches!(
        denied,
        Err(KernelError::OutOfScopeResource { .. })
    ));
}

#[test]
fn session_operation_read_resource_enforces_session_roots_for_filesystem_resources() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let allowed_context = make_operation_context(
        &session_id,
        "resource-read-file-1",
        &agent_kp.public_key().to_hex(),
    );
    let allowed = kernel
        .evaluate_session_operation(
            &allowed_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap.clone(),
                uri: "file:///workspace/project/docs/architecture.md".to_string(),
            }),
        )
        .unwrap();
    let contents = session_resource_read(allowed).expect("expected resource read response");
    assert_eq!(contents[0].text.as_deref(), Some("# Filesystem Architecture"));

    let denied_context = make_operation_context(
        &session_id,
        "resource-read-file-2",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "file:///workspace/private/ops.md".to_string(),
        }),
    );
    let receipt = match denied {
        Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => Some(receipt),
        _ => None,
    }
    .expect("expected signed resource read denial");
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_denied());
    assert_eq!(receipt.tool_name, "resources/read");
    assert_eq!(receipt.tool_server, "session");
    assert_eq!(
            receipt.decision,
            Some(Decision::Deny {
                reason:
                    "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
                        .to_string(),
                guard: "session_roots".to_string(),
            })
        );
}

#[test]
fn session_operation_read_resource_fails_closed_when_filesystem_roots_are_missing() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "resource-read-file-3",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "file:///workspace/project/docs/architecture.md".to_string(),
        }),
    );
    let receipt = match denied {
        Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => Some(receipt),
        _ => None,
    }
    .expect("expected signed resource read denial");
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_denied());
    assert_eq!(
        receipt.decision,
        Some(Decision::Deny {
            reason: "no enforceable filesystem roots are available for this session".to_string(),
            guard: "session_roots".to_string(),
        })
    );
}

#[test]
fn subscribe_session_resource_requires_subscribe_operation() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let read_only_scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let read_only_cap = make_capability(&kernel, &agent_kp, read_only_scope, 300);

    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![read_only_cap.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let denied = kernel.subscribe_session_resource(
        &session_id,
        &read_only_cap,
        &agent_kp.public_key().to_hex(),
        "repo://docs/architecture",
    );
    assert!(matches!(
        denied,
        Err(KernelError::OutOfScopeResource { .. })
    ));

    let subscribe_scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read, Operation::Subscribe],
        }],
        ..ChioScope::default()
    };
    let subscribe_cap = make_capability(&kernel, &agent_kp, subscribe_scope, 300);
    kernel
        .subscribe_session_resource(
            &session_id,
            &subscribe_cap,
            &agent_kp.public_key().to_hex(),
            "repo://docs/architecture",
        )
        .unwrap();

    assert!(kernel
        .session_has_resource_subscription(&session_id, "repo://docs/architecture")
        .unwrap());
}

#[test]
fn unsubscribe_session_resource_is_idempotent() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read, Operation::Subscribe],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .subscribe_session_resource(
            &session_id,
            &cap,
            &agent_kp.public_key().to_hex(),
            "repo://docs/architecture",
        )
        .unwrap();

    kernel
        .unsubscribe_session_resource(&session_id, "repo://docs/architecture")
        .unwrap();
    kernel
        .unsubscribe_session_resource(&session_id, "repo://docs/architecture")
        .unwrap();

    assert!(!kernel
        .session_has_resource_subscription(&session_id, "repo://docs/architecture")
        .unwrap());
}

#[test]
fn session_operation_get_prompt_enforces_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        prompt_grants: vec![PromptGrant {
            prompt_name: "summarize_*".to_string(),
            operations: vec![Operation::Get],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let list_context =
        make_operation_context(&session_id, "prompts-1", &agent_kp.public_key().to_hex());
    let list_response = kernel
        .evaluate_session_operation(&list_context, &SessionOperation::ListPrompts)
        .unwrap();
    let prompts = session_prompt_list(list_response).expect("expected prompt list response");
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].name, "summarize_docs");

    let get_context =
        make_operation_context(&session_id, "prompts-2", &agent_kp.public_key().to_hex());
    let get_response = kernel
        .evaluate_session_operation(
            &get_context,
            &SessionOperation::GetPrompt(GetPromptOperation {
                capability: cap.clone(),
                prompt_name: "summarize_docs".to_string(),
                arguments: serde_json::json!({"topic": "architecture"}),
            }),
        )
        .unwrap();
    let prompt = session_prompt_get(get_response).expect("expected prompt get response");
    assert_eq!(prompt.messages[0].content["text"], "Summarize architecture");

    let denied_context =
        make_operation_context(&session_id, "prompts-3", &agent_kp.public_key().to_hex());
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::GetPrompt(GetPromptOperation {
            capability: cap,
            prompt_name: "ops_secret".to_string(),
            arguments: serde_json::json!({}),
        }),
    );
    assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
}

#[test]
fn session_operation_completion_returns_candidates_and_enforces_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        prompt_grants: vec![PromptGrant {
            prompt_name: "summarize_*".to_string(),
            operations: vec![Operation::Get],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let prompt_context =
        make_operation_context(&session_id, "complete-1", &agent_kp.public_key().to_hex());
    let prompt_completion = kernel
        .evaluate_session_operation(
            &prompt_context,
            &SessionOperation::Complete(CompleteOperation {
                capability: cap.clone(),
                reference: CompletionReference::Prompt {
                    name: "summarize_docs".to_string(),
                },
                argument: CompletionArgument {
                    name: "topic".to_string(),
                    value: "r".to_string(),
                },
                context_arguments: serde_json::json!({}),
            }),
        )
        .unwrap();
    let completion = session_completion(prompt_completion).expect("expected completion response");
    assert_eq!(completion.total, Some(2));
    assert_eq!(completion.values, vec!["architecture", "release-notes"]);

    let resource_context =
        make_operation_context(&session_id, "complete-2", &agent_kp.public_key().to_hex());
    let resource_completion = kernel
        .evaluate_session_operation(
            &resource_context,
            &SessionOperation::Complete(CompleteOperation {
                capability: cap.clone(),
                reference: CompletionReference::Resource {
                    uri: "repo://docs/{slug}".to_string(),
                },
                argument: CompletionArgument {
                    name: "slug".to_string(),
                    value: "a".to_string(),
                },
                context_arguments: serde_json::json!({}),
            }),
        )
        .unwrap();
    let completion = session_completion(resource_completion).expect("expected completion response");
    assert_eq!(completion.total, Some(2));
    assert_eq!(completion.values, vec!["architecture", "api"]);

    let denied_context =
        make_operation_context(&session_id, "complete-3", &agent_kp.public_key().to_hex());
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::Complete(CompleteOperation {
            capability: cap,
            reference: CompletionReference::Prompt {
                name: "ops_secret".to_string(),
            },
            argument: CompletionArgument {
                name: "topic".to_string(),
                value: "o".to_string(),
            },
            context_arguments: serde_json::json!({}),
        }),
    );
    assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
}
