//! V1 wire projection and retained task custody, using shared kernel fixtures.

use super::*;
use crate::tests::{capability_for_tool, test_kernel_config, test_manifest, test_server};
use chio_core::crypto::Keypair;
use chio_test_support::prelude::*;

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
            "configuration": {"returnImmediately": false}
        }
    })
}

#[test]
fn v1_async_rejection_accepts_no_work_and_allows_a_blocking_retry() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let config = test_kernel_config();
    let execution = v1_execution(&config.keypair);
    let mut kernel = ChioKernel::new(config);
    let calls = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(
        crate::tests::authorization_projection::CountedToolServer {
            server: "test-srv".to_string(),
            tool: "echo".to_string(),
            calls: calls.clone(),
        },
    ));
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut request = v1_request();
    request["params"]["configuration"] = json!({"returnImmediately": true});
    let rejected = edge
        .handle_jsonrpc(
            &serde_json::to_vec(&request).test_unwrap(),
            &kernel,
            &execution,
        )
        .test_unwrap();
    assert_eq!(rejected["id"], request["id"]);
    assert_eq!(rejected["error"]["code"], -32004, "{rejected:?}");
    assert!(matches!(
        rejected.local_error(),
        Some(A2aEdgeError::UnsupportedOperation(_))
    ));
    assert!(edge.tasks.is_empty());
    assert_eq!(edge.task_counter, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(kernel.receipt_log().receipts().is_empty());
    request["params"]["configuration"] = json!({"returnImmediately": false});
    let completed = edge
        .handle_jsonrpc(
            &serde_json::to_vec(&request).test_unwrap(),
            &kernel,
            &execution,
        )
        .test_unwrap();
    assert_eq!(
        completed["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
    assert!(edge.tasks.is_empty());
}

#[test]
fn v1_get_observes_retained_tasks_without_dispatching_them() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let mut kernel = ChioKernel::new(config);
    let calls = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(
        crate::tests::authorization_projection::CountedToolServer {
            server: "test-srv".to_string(),
            tool: "echo".to_string(),
            calls: calls.clone(),
        },
    ));
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let pending = retained_task(&mut edge, &kernel, &owner, "retained-pending");
    let get = json!({"jsonrpc": "2.0", "id": "observation", "method": "GetTask", "params": {"id": pending.id}});
    for _ in 0..2 {
        let observed = edge
            .handle_jsonrpc(&serde_json::to_vec(&get).test_unwrap(), &kernel, &owner)
            .test_unwrap();
        assert_eq!(observed["result"]["status"]["state"], "TASK_STATE_WORKING");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(kernel.receipt_log().receipts().is_empty());
    }
    assert_eq!(edge.tasks[&pending.id].response.status, TaskStatus::Working);
}

#[test]
fn v1_blocking_completion_releases_task_custody_on_success_and_failure() {
    for registered in [true, false] {
        let config = test_kernel_config();
        let execution = v1_execution(&config.keypair);
        let mut kernel = ChioKernel::new(config);
        if registered {
            kernel.register_tool_server(Box::new(test_server()));
        }
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        for index in 0..4 {
            let mut request = v1_request();
            request["params"]["message"]["messageId"] = json!(format!("blocking-{index}"));
            request["params"]["configuration"] = json!({"returnImmediately": false});
            if index % 2 == 0 {
                request["params"]
                    .as_object_mut()
                    .test_unwrap()
                    .remove("configuration");
            }
            let response = edge
                .handle_jsonrpc(
                    &serde_json::to_vec(&request).test_unwrap(),
                    &kernel,
                    &execution,
                )
                .test_unwrap();
            if registered {
                assert_eq!(
                    response["result"]["task"]["status"]["state"],
                    "TASK_STATE_COMPLETED"
                );
            } else {
                assert_eq!(
                    response["result"]["task"]["status"]["state"],
                    "TASK_STATE_FAILED"
                );
            }
            assert!(
                edge.tasks.is_empty(),
                "blocking completion retained task custody"
            );
        }
    }
}

#[test]
fn retained_task_capacity_is_bounded_per_subject() {
    let config = test_kernel_config();
    let mut owner = v1_execution(&config.keypair);
    let other = v1_execution(&config.keypair);
    let kernel = ChioKernel::new(config);
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    for index in 0..128 {
        let response = retained_task(&mut edge, &kernel, &owner, &format!("deferred-{index}"));
        assert_eq!(response.status, TaskStatus::Working);
    }
    // Display-name changes cannot bypass the authenticated subject's quota.
    owner.agent_id = "renamed-owner".into();
    let request = empty_request();
    let denied = edge
        .retain_task(
            "quota",
            "echo",
            &request,
            &kernel,
            &owner,
            V1OutputMode::Json,
        )
        .test_unwrap_err();
    assert!(matches!(denied, A2aEdgeError::TaskCapacity));
    let allowed = retained_task(&mut edge, &kernel, &other, "independent-owner");
    assert_eq!(allowed.status, TaskStatus::Working);
    assert_eq!(edge.tasks.len(), 129);
}

fn empty_request() -> SendMessageRequest {
    SendMessageRequest {
        message: A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data { data: json!({}) }],
            metadata: None,
        },
        metadata: None,
    }
}

fn retained_task(
    edge: &mut ChioA2aEdge,
    kernel: &ChioKernel,
    owner: &A2aKernelExecutionContext,
    id: &str,
) -> TaskResponse {
    edge.retain_task(
        id,
        "echo",
        &empty_request(),
        kernel,
        owner,
        V1OutputMode::Json,
    )
    .test_unwrap()
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
    for field in ["contextId", "referenceTaskIds", "extensions"] {
        let mut request = v1_request();
        request["params"]["message"][field] = json!("unsupported");
        cases.push(request);
    }
    let mut tenant = v1_request();
    tenant["params"]["tenant"] = json!("unconfigured-tenant");
    cases.push(tenant);
    for request in cases {
        let response = edge
            .handle_jsonrpc(
                &serde_json::to_vec(&request.clone()).test_unwrap(),
                &kernel,
                &execution,
            )
            .test_unwrap()
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
    let started = retained_task(&mut edge, &kernel, &owner, "owner-boundary");
    let task_id = started.id.as_str();
    for method in ["GetTask", "CancelTask"] {
        let request =
            json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": {"id": task_id}});
        let denied = edge
            .handle_jsonrpc(&serde_json::to_vec(&request).test_unwrap(), &kernel, &other)
            .test_unwrap();
        assert!(matches!(
            denied.local_error(),
            Some(A2aEdgeError::TaskNotFound(id)) if id == task_id
        ));
        let denied = denied.into_value().test_unwrap();
        assert_eq!(denied["id"], 2);
        assert_eq!(denied["error"]["code"], -32001);
        let absent =
            json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": {"id": "absent-task"}});
        let absent = edge
            .handle_jsonrpc(&serde_json::to_vec(&absent).test_unwrap(), &kernel, &other)
            .test_unwrap()
            .into_value()
            .test_unwrap();
        assert_eq!(
            denied, absent,
            "task lookup disclosed another caller's task"
        );
        assert_eq!(edge.tasks[task_id].response.status, TaskStatus::Working);
    }
    let cancel =
        json!({"jsonrpc": "2.0", "id": 3, "method": "CancelTask", "params": {"id": task_id}});
    let response = edge
        .handle_jsonrpc(
            &serde_json::to_vec(&cancel.clone()).test_unwrap(),
            &kernel,
            &owner,
        )
        .test_unwrap()
        .into_value()
        .test_unwrap();
    assert_eq!(response["result"]["status"]["state"], "TASK_STATE_CANCELED");
    assert_eq!(
        edge.handle_jsonrpc(&serde_json::to_vec(&cancel).test_unwrap(), &kernel, &owner)
            .test_unwrap()
            .into_value()
            .test_unwrap(),
        response
    );
    let get = json!({"jsonrpc": "2.0", "id": 4, "method": "GetTask", "params": {"id": task_id}});
    assert_eq!(
        edge.handle_jsonrpc(&serde_json::to_vec(&get).test_unwrap(), &kernel, &owner)
            .test_unwrap()
            .into_value()
            .test_unwrap()["result"],
        response["result"]
    );
}

#[test]
fn v1_unknown_task_errors_use_standard_codes_and_preserve_typed_causes() {
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let kernel = ChioKernel::new(config);
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    for method in ["GetTask", "CancelTask"] {
        let request = json!({"jsonrpc": "2.0", "id": "missing-task", "method": method,
            "params": {"id": "unknown-task"}});
        let response = edge
            .handle_jsonrpc(&serde_json::to_vec(&request).test_unwrap(), &kernel, &owner)
            .test_unwrap();
        assert_eq!(response["error"]["code"], -32001);
        assert!(matches!(
            response.local_error(),
            Some(A2aEdgeError::TaskNotFound(task_id)) if task_id == "unknown-task"
        ));
        assert_eq!(
            response.into_value().test_unwrap(),
            json!({"jsonrpc": "2.0", "id": "missing-task",
                "error": {"code": -32001, "message": "task not found"}})
        );
    }
}

#[test]
fn v1_completed_task_cancellation_reports_the_standard_error() {
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let pending = retained_task(&mut edge, &kernel, &owner, "completed-cancel");
    let completed = edge.complete_task(&pending.id, &kernel, &owner, json!(1));
    assert_eq!(completed["result"]["status"], "completed");
    let cancel =
        json!({"jsonrpc": "2.0", "id": 2, "method": "CancelTask", "params": {"id": pending.id}});
    let rejected = edge
        .handle_jsonrpc(&serde_json::to_vec(&cancel).test_unwrap(), &kernel, &owner)
        .test_unwrap();
    assert_eq!(rejected["error"]["code"], -32002);
    assert!(
        matches!(rejected.local_error(), Some(A2aEdgeError::TaskNotCancelable(id)) if id == &pending.id)
    );
    assert_eq!(
        edge.tasks[&pending.id].response.status,
        TaskStatus::Completed
    );
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
}

#[test]
fn task_ownership_keeps_the_subject_boundary_when_agent_labels_overlap() {
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let mut other = v1_execution(&config.keypair);
    other.agent_id = owner.agent_id.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let pending = retained_task(&mut edge, &kernel, &owner, "overlapping-labels");
    for (method, params, expected_code) in [
        ("GetTask", json!({"id": pending.id}), -32001),
        ("CancelTask", json!({"id": pending.id}), -32001),
    ] {
        let request =
            json!({"jsonrpc": "2.0", "id": "other-subject", "method": method, "params": params});
        let denied = edge
            .handle_jsonrpc(&serde_json::to_vec(&request).test_unwrap(), &kernel, &other)
            .test_unwrap();
        assert_eq!(
            denied["error"]["code"], expected_code,
            "{method}: {denied:?}"
        );
        assert_eq!(edge.tasks[&pending.id].response.status, TaskStatus::Working);
        assert!(kernel.receipt_log().receipts().is_empty());
    }
    let own =
        json!({"jsonrpc": "2.0", "id": "owner", "method": "GetTask", "params": {"id": pending.id}});
    let observed = edge
        .handle_jsonrpc(&serde_json::to_vec(&own).test_unwrap(), &kernel, &owner)
        .test_unwrap();
    assert_eq!(observed["result"]["status"]["state"], "TASK_STATE_WORKING");
    assert!(kernel.receipt_log().receipts().is_empty());
    let completed = edge.complete_task(&pending.id, &kernel, &owner, json!("owner"));
    assert_eq!(completed["result"]["status"], "completed");
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
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
        .handle_jsonrpc(
            &serde_json::to_vec(&v1_request()).test_unwrap(),
            &kernel,
            &owner,
        )
        .test_unwrap()
        .into_value()
        .test_unwrap();
    let old_id = previous["result"]["task"]["id"].as_str().test_unwrap();
    drop(first);
    let mut restarted = start();
    let next = restarted
        .handle_jsonrpc(
            &serde_json::to_vec(&v1_request()).test_unwrap(),
            &kernel,
            &owner,
        )
        .test_unwrap()
        .into_value()
        .test_unwrap();
    assert_ne!(next["result"]["task"]["id"], old_id);
    let get = json!({"jsonrpc": "2.0", "id": 2, "method": "GetTask", "params": {"id": old_id}});
    let response = restarted
        .handle_jsonrpc(&serde_json::to_vec(&get).test_unwrap(), &kernel, &owner)
        .test_unwrap()
        .into_value()
        .test_unwrap();
    assert!(response.get("error").is_some());
    assert!(restarted.tasks.is_empty());
}

#[test]
fn v1_blocking_output_negotiation_supports_omitted_and_false_execution_modes() {
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    for (index, configuration) in [
        json!({"acceptedOutputModes": ["text/plain"]}),
        json!({"acceptedOutputModes": ["text/plain"], "returnImmediately": false}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = v1_request();
        request["params"]["message"]["messageId"] = json!(format!("output-{index}"));
        request["params"]["configuration"] = configuration;
        let result = edge
            .handle_jsonrpc(&serde_json::to_vec(&request).test_unwrap(), &kernel, &owner)
            .test_unwrap();
        let task = &result["result"]["task"];
        assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");
        assert!(task["artifacts"][0]["parts"][0]["text"].is_string());
        assert!(task["artifacts"][0]["parts"][0].get("data").is_none());
        assert!(edge.tasks.is_empty());
    }
}

#[test]
fn v1_continuation_rejects_expired_tasks() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let config = test_kernel_config();
    let owner = v1_execution(&config.keypair);
    let mut kernel = ChioKernel::new(config);
    let calls = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(
        crate::tests::authorization_projection::CountedToolServer {
            server: "test-srv".into(),
            tool: "echo".into(),
            calls: calls.clone(),
        },
    ));
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let accepted = retained_task(&mut edge, &kernel, &owner, "unavailable-continuation");
    {
        use chio_security_types::clock::{ClockReading, MonotonicInstant, UnixMillis};
        // Stamp the retained fixture with an already elapsed deadline. The
        // real clock and request handler run without sleeps.
        let retained = edge.tasks.get_mut(&accepted.id).test_unwrap();
        retained.deadline = AuthorityDeadline::for_timeout_ms(
            ClockReading::new(UnixMillis::new(1), MonotonicInstant::from_nanos(0)),
            1,
        )
        .test_unwrap();
    }
    let request = json!({
        "jsonrpc": "2.0", "id": "resume", "method": "SendMessage",
        "params": {"message": {"messageId": "unavailable-continuation",
            "taskId": accepted.id, "role": "ROLE_USER", "parts": [{"data": {}}]},
            "metadata": {"chio": {"targetSkillId": "echo"}}}
    });
    let refused = edge
        .handle_jsonrpc(&serde_json::to_vec(&request).test_unwrap(), &kernel, &owner)
        .test_unwrap();
    assert_eq!(refused["error"]["code"], -32001, "{refused:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(kernel.receipt_log().receipts().is_empty());
    assert_eq!(edge.task_counter, 1);
    assert!(edge.tasks.is_empty());
}
