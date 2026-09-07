#[test]
fn sampling_validation_requires_policy_and_negotiation() {
    let mut kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let parent_context =
        make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let child_context = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("child-1"),
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap();
    let operation = CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "Summarize the diff"
            }),
            meta: None,
        }],
        model_preferences: None,
        system_prompt: None,
        include_context: None,
        temperature: None,
        max_tokens: 256,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![],
        tool_choice: None,
    };

    let denied = kernel.validate_sampling_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingNotAllowedByPolicy)
    ));

    kernel.config.allow_sampling = true;
    let denied = kernel.validate_sampling_request(&child_context, &operation);
    assert!(matches!(denied, Err(KernelError::SamplingNotNegotiated)));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: true,
                sampling_context: true,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();
    kernel
        .validate_sampling_request(&child_context, &operation)
        .unwrap();

    let tool_operation = CreateMessageOperation {
        tools: vec![SamplingTool {
            name: "search_docs".to_string(),
            description: Some("Search docs".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        }],
        tool_choice: Some(SamplingToolChoice {
            mode: "auto".to_string(),
        }),
        ..operation
    };
    let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingToolUseNotAllowedByPolicy)
    ));

    kernel.config.allow_sampling_tool_use = true;
    let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingToolUseNotNegotiated)
    ));
}

#[test]
fn elicitation_validation_requires_policy_and_form_negotiation() {
    let mut kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let parent_context = make_operation_context(
        &session_id,
        "parent-elicit-1",
        &agent_kp.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let child_context = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("child-elicit-1"),
            OperationKind::CreateElicitation,
            None,
            true,
        )
        .unwrap();
    let operation = CreateElicitationOperation::Form {
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
    };

    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationNotAllowedByPolicy)
    ));

    kernel.config.allow_elicitation = true;
    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(denied, Err(KernelError::ElicitationNotNegotiated)));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();
    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationFormNotSupported)
    ));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: true,
                elicitation_url: false,
            },
        )
        .unwrap();
    kernel
        .validate_elicitation_request(&child_context, &operation)
        .unwrap();

    let url_operation = CreateElicitationOperation::Url {
        meta: None,
        message: "Open the secure enrollment flow".to_string(),
        url: "https://example.test/consent".to_string(),
        elicitation_id: "elicitation-123".to_string(),
    };
    let denied = kernel.validate_elicitation_request(&child_context, &url_operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationUrlNotSupported)
    ));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: true,
                elicitation_url: true,
            },
        )
        .unwrap();
    kernel
        .validate_elicitation_request(&child_context, &url_operation)
        .unwrap();
}
