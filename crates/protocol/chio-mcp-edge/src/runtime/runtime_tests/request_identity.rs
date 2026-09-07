use super::*;

#[test]
fn external_request_identity_is_unique_without_a_caller_stable_id() {
    let first = build_operation_context(
        &json!(41),
        SessionId::new("stable-session-a"),
        "agent",
        "tools/call",
        &json!({}),
    )
    .unwrap();
    let replay = build_operation_context(
        &json!(41),
        SessionId::new("stable-session-a"),
        "agent",
        "tools/call",
        &json!({}),
    )
    .unwrap();
    let other_session = build_operation_context(
        &json!(41),
        SessionId::new("stable-session-b"),
        "agent",
        "tools/call",
        &json!({}),
    )
    .unwrap();
    let other_request = build_operation_context(
        &json!(42),
        SessionId::new("stable-session-a"),
        "agent",
        "tools/call",
        &json!({}),
    )
    .unwrap();

    assert_ne!(first.request_id, replay.request_id);
    assert_ne!(first.request_id, other_session.request_id);
    assert_ne!(first.request_id, other_request.request_id);
    assert!(first.request_id.as_str().starts_with("mcp-edge-req-"));
}

#[test]
fn caller_supplied_request_identity_is_stable_across_sessions() {
    let first = build_operation_context(
        &json!(41),
        SessionId::new("caller-session-a"),
        "agent",
        "tools/call",
        &json!({
            "_meta": {
                "chioRequestId": "caller-stable-request"
            }
        }),
    )
    .expect("caller request ID should build");
    let replay = build_operation_context(
        &json!(99),
        SessionId::new("caller-session-b"),
        "agent",
        "tools/call",
        &json!({
            "_meta": {
                "chioRequestId": "caller-stable-request",
                "progressToken": "retry"
            }
        }),
    )
    .expect("caller request ID replay should build");

    assert_eq!(first.request_id.as_str(), "caller-stable-request");
    assert_eq!(first.request_id, replay.request_id);
}

#[test]
fn caller_supplied_request_identity_rejects_invalid_values() {
    for invalid in [
        Value::Null,
        json!(""),
        json!(" padded"),
        json!("control\ncharacter"),
        json!("x".repeat(2_049)),
    ] {
        let error = build_operation_context(
            &json!(41),
            SessionId::new("caller-session"),
            "agent",
            "tools/call",
            &json!({
                "_meta": {
                    "chioRequestId": invalid
                }
            }),
        )
        .expect_err("invalid caller request ID must be rejected");
        assert_eq!(error["error"]["code"], JSONRPC_INVALID_PARAMS);
    }
}

#[test]
fn request_bound_artifacts_require_a_caller_supplied_request_identity() {
    let mut edge = make_edge(10);
    initialize_edge(&mut edge);
    let params = json!({
        "name": "read_file",
        "arguments": { "path": "/tmp/demo.txt" },
        "_meta": {
            "supplementalAuthorization": {
                "signed_extension": "opaque"
            }
        }
    });
    let error = edge
        .prepare_tool_call_request(&json!(2), &params)
        .expect_err("request-bound artifacts must require a stable request ID");
    assert_eq!(error["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert!(error["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("_meta.chioRequestId")));

    let mut stable_params = params;
    stable_params["_meta"]["chioRequestId"] = json!("mcp-stable-authorization-request");
    let (_session_id, context, operation) = edge
        .prepare_tool_call_request(&json!(2), &stable_params)
        .expect("stable request ID path should accept request-bound artifacts");
    assert_eq!(
        context.request_id.as_str(),
        "mcp-stable-authorization-request"
    );
    assert!(operation.supplemental_authorization.is_some());
}

#[test]
fn external_request_identity_separates_reused_jsonrpc_ids() {
    let session_id = SessionId::new("reuse-session");
    let tool_call = build_operation_context(
        &json!(1),
        session_id.clone(),
        "agent",
        "tools/call",
        &json!({ "name": "read_file" }),
    )
    .unwrap();
    let other_method = build_operation_context(
        &json!(1),
        session_id.clone(),
        "agent",
        "resources/read",
        &json!({ "name": "read_file" }),
    )
    .unwrap();
    let other_params = build_operation_context(
        &json!(1),
        session_id.clone(),
        "agent",
        "tools/call",
        &json!({ "name": "write_file" }),
    )
    .unwrap();

    assert_ne!(tool_call.request_id, other_method.request_id);
    assert_ne!(tool_call.request_id, other_params.request_id);
    assert_ne!(other_method.request_id, other_params.request_id);
}

#[test]
fn execution_nonce_retry_uses_the_nonce_bound_request_identity() {
    let session_id = SessionId::new("nonce-retry-session");
    let preflight = build_operation_context(
        &json!(7),
        session_id.clone(),
        "agent",
        "tools/call",
        &json!({ "name": "read_file", "arguments": { "path": "/tmp/demo.txt" } }),
    )
    .unwrap();
    let retry = build_operation_context_for_retry(
        &json!(7),
        session_id.clone(),
        "agent",
        "tools/call",
        &json!({
            "name": "read_file",
            "arguments": { "path": "/tmp/demo.txt" },
            "_meta": { "chioExecutionNonce": { "nonce": "opaque" } }
        }),
        Some(preflight.request_id.as_str()),
    )
    .unwrap();

    assert_eq!(preflight.request_id, retry.request_id);
}
