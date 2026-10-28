use super::*;

/// The edge's control credential holds only the `kernel-host` preset. A tool
/// call through it is admitted, receipted and readable, and the same
/// credential is refused on an operator route.
#[test]
fn mcp_serve_http_kernel_host_preset_serves_a_tool_call_without_operator_scopes() {
    skip_when_loopback_denied!(
        mcp_serve_http_kernel_host_preset_serves_a_tool_call_without_operator_scopes
    );
    let dir = unique_test_dir();
    let node_dir = dir.join("node");
    fs::create_dir_all(&node_dir).expect("create node dir");
    let receipt_db_path = dir.join("control-receipts.sqlite3");
    let authority_db_path = dir.join("control-authority.sqlite3");
    let joint_authority_db_path = dir.join("control-joint-authority.sqlite3");
    let auth_token = "edge-token";
    let admin_token = "edge-admin-token";
    let control_token = "control-token";
    let authority_workload_token = "authority-workload-token";
    let kernel_host_token = trust_access::kernel_host_token(control_token);
    let client = Client::builder()
        .timeout(HTTP_CLIENT_TIMEOUT)
        .build()
        .expect("build reqwest client");

    let (control_listen, _control) = spawn_with_bind_retry(
        &client,
        "trust control service",
        |listen| {
            spawn_trust_control_service(
                listen,
                control_token,
                authority_workload_token,
                &receipt_db_path,
                &authority_db_path,
                &joint_authority_db_path,
            )
        },
        wait_for_control_service_result,
    );
    let control_base_url = format!("http://{control_listen}");
    let authority = get_control_authority(&client, &control_base_url, &kernel_host_token);
    assert_eq!(authority.status(), reqwest::StatusCode::OK);
    let authority: Value = authority.json().expect("control authority json");
    let public_key = authority["publicKey"]
        .as_str()
        .expect("authority public key")
        .to_string();

    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "kernel-host MCP server",
        |listen| {
            spawn_http_server_with_control_plane(
                &node_dir,
                listen,
                auth_token,
                admin_token,
                &control_base_url,
                control_token,
                &public_key,
                &[],
                authority_workload_token,
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");
    let (session, protocol) = initialize_session(&client, &base_url, auth_token);
    let tool_call = post_json(
        &client,
        &base_url,
        auth_token,
        Some(&session),
        Some(&protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "kernel host preset"}
            }
        }),
    );
    assert_eq!(tool_call.status(), reqwest::StatusCode::OK);
    let (tool_call, notifications) = read_sse_until_response(tool_call, json!(51), |_| {});
    assert!(notifications.is_empty());
    assert_eq!(
        tool_call["result"]["structuredContent"]["echo"], "kernel host preset",
        "kernel-host tool response: {tool_call:#}"
    );

    let receipts = get_control_tool_receipts(
        &client,
        &control_base_url,
        &kernel_host_token,
        &[("toolName", "echo_json"), ("limit", "10")],
    );
    assert_eq!(receipts.status(), reqwest::StatusCode::OK);
    let receipts: Value = receipts.json().expect("control receipts json");
    assert_eq!(receipts["count"], 1);

    let refused = client
        .get(format!("{control_base_url}/v1/admin/emergency-status"))
        .header(AUTHORIZATION, format!("Bearer {kernel_host_token}"))
        .send()
        .expect("send emergency status request");
    assert_eq!(refused.status(), reqwest::StatusCode::FORBIDDEN);
    let refused: Value = refused.json().expect("refusal json");
    assert_eq!(
        refused,
        json!({"error": "trust-control credential lacks scope admin:emergency"})
    );
}
