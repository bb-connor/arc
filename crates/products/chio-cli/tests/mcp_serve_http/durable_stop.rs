use super::*;

fn emergency_admin(client: &Client, base_url: &str, path: &str, body: Option<&Value>) -> Response {
    let request = match body {
        Some(body) => client.post(format!("{base_url}{path}")).json(body),
        None => client.get(format!("{base_url}{path}")),
    };
    request
        .header(AUTHORIZATION, format!("Bearer {EDGE_ADMIN_TOKEN}"))
        .send()
        .expect("send emergency admin request")
}

fn echo_is_error(client: &Client, base_url: &str, token: &str, id: u64) -> bool {
    let (session_id, protocol_version) = initialize_session(client, base_url, token);
    let response = post_json(
        client,
        base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": "echo_json", "arguments": {"message": "stop drill"}}
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let (result, _) = read_sse_until_response(response, json!(id), |_| {});
    result["result"]["isError"] == json!(true)
}

#[test]
fn mcp_serve_http_durable_stop_survives_restart_and_resumes() {
    skip_when_loopback_denied!(mcp_serve_http_durable_stop_survives_restart_and_resumes);
    let dir = unique_test_dir();
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");
    let policy_path = dir.join("durable-stop-policy.yaml");
    fs::write(
        &policy_path,
        "kernel:\n  max_capability_ttl: 3600\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: wrapped-http-mock\n        tool: echo_json\n        operations: [invoke]\n        ttl: 300\n",
    )
    .expect("write durable stop policy");
    let client = Client::builder()
        .timeout(HTTP_CLIENT_TIMEOUT)
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    let spawn = || {
        spawn_http_server_with_policy_path_and_session_lifecycle(
            &dir,
            &policy_path,
            listen,
            token,
            Some(&session_db_path),
            None,
            None,
            None,
        )
    };

    {
        let mut server = spawn();
        wait_for_server_result(&client, &base_url, &mut server).expect("start durable edge");
        assert!(!echo_is_error(&client, &base_url, token, 1));

        let unauthenticated = client
            .post(format!("{base_url}/admin/emergency-stop"))
            .json(&json!({"reason": "no credential"}))
            .send()
            .expect("send unauthenticated stop");
        assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);

        let stopped = emergency_admin(
            &client,
            &base_url,
            "/admin/emergency-stop",
            Some(&json!({"reason": "incident drill"})),
        );
        assert_eq!(stopped.status(), reqwest::StatusCode::OK);
        let stopped: Value = stopped.json().expect("stop status");
        assert_eq!(stopped["durability"], "durable", "{stopped}");
        assert_eq!(stopped["head"]["epoch"], 1, "{stopped}");
        assert!(echo_is_error(&client, &base_url, token, 2));
    }

    let mut server = spawn();
    wait_for_server_result(&client, &base_url, &mut server).expect("restart durable edge");
    let status: Value = emergency_admin(&client, &base_url, "/admin/emergency-status", None)
        .json()
        .expect("status after restart");
    assert_eq!(status["readiness"]["state"], "ready_stopped", "{status}");
    assert!(echo_is_error(&client, &base_url, token, 3));

    let moved = emergency_admin(
        &client,
        &base_url,
        "/admin/emergency-resume",
        Some(&json!({"expected_epoch": {"chain_generation": 1, "epoch": 9}})),
    );
    assert_eq!(moved.status(), reqwest::StatusCode::CONFLICT);
    let resumed = emergency_admin(
        &client,
        &base_url,
        "/admin/emergency-resume",
        Some(&json!({"expected_epoch": {"chain_generation": 1, "epoch": 1}})),
    );
    assert_eq!(resumed.status(), reqwest::StatusCode::OK);
    assert!(!echo_is_error(&client, &base_url, token, 4));
}
