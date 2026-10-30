use super::*;

/// Exit class of `chio` when trust-control refuses the admin credential.
const EXIT_UNAUTHORIZED: i32 = 77;

/// Run `chio trust emergency ...` against `control_url` with the admin token
/// in `CHIO_CONTROL_TOKEN`, never on the command line.
fn emergency(control_url: &str, token: Option<&str>, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .args(["--json", "--control-url", control_url, "trust", "emergency"])
        .args(args)
        .env_remove("CHIO_CONTROL_TOKEN")
        .stdin(Stdio::null());
    if let Some(token) = token {
        command.env("CHIO_CONTROL_TOKEN", token);
    }
    command.output().expect("run chio trust emergency")
}

fn stdout_json(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "chio trust emergency failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("chio trust emergency json")
}

fn echo_denied(client: &Client, base_url: &str, token: &str, id: u64) -> bool {
    let (session, protocol) = initialize_session(client, base_url, token);
    let response = post_json(
        client,
        base_url,
        token,
        Some(&session),
        Some(&protocol),
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

/// `chio trust emergency` drives the trust-control stop routes: a wrong token
/// exits with the unauthorized class and leaves admissions running, a stop
/// denies the next tool call at an edge admitting through this trust-control,
/// status reports the stopped head, and resume at that head admits again.
#[test]
fn chio_trust_emergency_stops_and_resumes_edge_admissions() {
    skip_when_loopback_denied!(chio_trust_emergency_stops_and_resumes_edge_admissions);
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
    let control_url = format!("http://{control_listen}");
    let authority = get_control_authority(&client, &control_url, &kernel_host_token);
    assert_eq!(authority.status(), reqwest::StatusCode::OK);
    let authority: Value = authority.json().expect("control authority json");
    let public_key = authority["publicKey"]
        .as_str()
        .expect("authority public key")
        .to_string();
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "control-backed MCP server",
        |listen| {
            spawn_http_server_with_control_plane(
                &node_dir,
                listen,
                auth_token,
                admin_token,
                &control_url,
                control_token,
                &public_key,
                &[],
                authority_workload_token,
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");
    assert!(!echo_denied(&client, &base_url, auth_token, 61));

    let refused = emergency(
        &control_url,
        Some("wrong-token"),
        &["stop", "--reason", "drill"],
    );
    assert_eq!(refused.status.code(), Some(EXIT_UNAUTHORIZED));
    assert!(!echo_denied(&client, &base_url, auth_token, 62));

    let stopped = stdout_json(&emergency(
        &control_url,
        Some(control_token),
        &["stop", "--reason", "drill"],
    ));
    assert_eq!(stopped["stopped"], json!(true));
    assert!(echo_denied(&client, &base_url, auth_token, 63));

    let status = stdout_json(&emergency(&control_url, Some(control_token), &["status"]));
    assert_eq!(status["stopped"], json!(true));
    assert_eq!(status["readiness"]["state"], json!("ready_stopped"));
    let generation = status["head"]["chain_generation"].to_string();
    let epoch = status["head"]["epoch"].to_string();

    let resumed = stdout_json(&emergency(
        &control_url,
        Some(control_token),
        &[
            "resume",
            "--expected-generation",
            &generation,
            "--expected-epoch",
            &epoch,
        ],
    ));
    assert_eq!(resumed["stopped"], json!(false));
    assert!(!echo_denied(&client, &base_url, auth_token, 64));
}
