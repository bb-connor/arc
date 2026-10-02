// Included inside the existing test module to reuse its kernel fixtures.

fn v1_execution(issuer: &Keypair) -> A2aKernelExecutionContext {
    let subject = Keypair::generate();
    A2aKernelExecutionContext {
        capability: capability_for_tool(issuer, &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    }
}

fn v1_request() -> Value {
    json!({
        "jsonrpc": "2.0", "id": "request-1", "method": "SendMessage",
        "params": {
            "message": {
                "messageId": "review-1", "role": "ROLE_USER",
                "parts": [{"data": {"target": "payments-api"}}]
            },
            "metadata": {"chio": {"targetSkillId": "echo"}},
            "configuration": {"returnImmediately": true}
        }
    })
}

#[test]
fn v1_rejects_unsupported_or_ambiguous_semantics_before_task_retention() {
    let config = test_kernel_config();
    let execution = v1_execution(&config.keypair);
    let kernel = ChioKernel::new(config);
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut cases = Vec::new();
    for (pointer, value) in [
        ("/params/message/role", json!("ROLE_AGENT")),
        ("/params/message/messageId", json!(" ")),
        ("/params/message/messageId", json!("padded ")),
        ("/params/message/parts", json!([])),
        ("/params/message/parts", json!([{"text": "a", "data": {}}])),
        ("/params/message/parts", json!([{"data": {}}, {"data": {}}])),
        (
            "/params/message/parts",
            json!([{"data": {}, "mediaType": "image/png"}]),
        ),
        (
            "/params/message/parts",
            json!([{"text": "x", "raw": "eA=="}]),
        ),
        ("/params/configuration", json!({"historyLength": 1})),
        (
            "/params/configuration",
            json!({"acceptedOutputModes": ["image/png"]}),
        ),
    ] {
        let mut request = v1_request();
        *request.pointer_mut(pointer).test_unwrap() = value;
        cases.push(request);
    }
    for field in ["taskId", "contextId", "referenceTaskIds", "extensions"] {
        let mut request = v1_request();
        request["params"]["message"][field] = json!("unsupported");
        cases.push(request);
    }
    let mut tenant = v1_request();
    tenant["params"]["tenant"] = json!("unconfigured-tenant");
    cases.push(tenant);
    for request in cases {
        let response = edge
            .handle_jsonrpc(request.clone(), &kernel, &execution)
            .into_value()
            .test_unwrap();
        assert_eq!(response["error"]["code"], -32602, "{request}: {response}");
        assert!(edge.tasks.is_empty());
    }
}

#[test]
fn v1_task_get_and_cancel_keep_the_original_owner_boundary() {
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let other = v1_execution(&config.keypair);
    let kernel = ChioKernel::new(config);
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let started = edge
        .handle_jsonrpc(v1_request(), &kernel, &owner)
        .into_value()
        .test_unwrap();
    let task_id = started["result"]["task"]["id"].as_str().test_unwrap();
    for method in ["GetTask", "CancelTask"] {
        let request =
            json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": {"id": task_id}});
        let denied = edge
            .handle_jsonrpc(request, &kernel, &other)
            .into_value()
            .test_unwrap();
        assert!(denied.get("error").is_some());
        assert_eq!(edge.tasks[task_id].response.status, TaskStatus::Working);
    }
    let cancel =
        json!({"jsonrpc": "2.0", "id": 3, "method": "CancelTask", "params": {"id": task_id}});
    let response = edge
        .handle_jsonrpc(cancel.clone(), &kernel, &owner)
        .into_value()
        .test_unwrap();
    assert_eq!(response["result"]["status"]["state"], "TASK_STATE_CANCELED");
    assert_eq!(
        edge.handle_jsonrpc(cancel, &kernel, &owner)
            .into_value()
            .test_unwrap(),
        response
    );
    let get = json!({"jsonrpc": "2.0", "id": 4, "method": "GetTask", "params": {"id": task_id}});
    assert_eq!(
        edge.handle_jsonrpc(get, &kernel, &owner)
            .into_value()
            .test_unwrap()["result"],
        response["result"]
    );
}

#[test]
fn v1_card_does_not_advertise_sse_for_a_polling_lifecycle() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let card = edge.agent_card();
    assert!(!card.capabilities.streaming);
    for skill in card.skills {
        assert!(skill.input_modes.contains(&"application/json".to_string()));
        assert!(skill.output_modes.contains(&"text/plain".to_string()));
    }
}

#[test]
fn v1_restart_never_rebinds_an_old_task_identifier() {
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let kernel = ChioKernel::new(config);
    let start = || ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut first = start();
    let previous = first
        .handle_jsonrpc(v1_request(), &kernel, &owner)
        .into_value()
        .test_unwrap();
    let old_id = previous["result"]["task"]["id"].as_str().test_unwrap();
    drop(first);
    let mut restarted = start();
    let next = restarted
        .handle_jsonrpc(v1_request(), &kernel, &owner)
        .into_value()
        .test_unwrap();
    assert_ne!(next["result"]["task"]["id"], old_id);
    let get = json!({"jsonrpc": "2.0", "id": 2, "method": "GetTask", "params": {"id": old_id}});
    let response = restarted
        .handle_jsonrpc(get, &kernel, &owner)
        .into_value()
        .test_unwrap();
    assert!(response.get("error").is_some());
    assert!(restarted
        .tasks
        .values()
        .all(|task| task.response.status == TaskStatus::Working));
}

#[test]
fn v1_output_negotiation_is_retained_when_polling() {
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut request = v1_request();
    request["params"]["configuration"] = json!({"acceptedOutputModes": ["text/plain"]});
    let result = edge
        .handle_jsonrpc(request, &kernel, &owner)
        .into_value()
        .test_unwrap();
    let task = &result["result"]["task"];
    assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");
    assert!(task["artifacts"][0]["parts"][0]["text"].is_string());
    assert!(task["artifacts"][0]["parts"][0].get("data").is_none());
    let get = json!({"jsonrpc": "2.0", "id": 2, "method": "GetTask", "params": {"id": task["id"]}});
    assert_eq!(
        edge.handle_jsonrpc(get, &kernel, &owner)
            .into_value()
            .test_unwrap()["result"],
        *task
    );
}
