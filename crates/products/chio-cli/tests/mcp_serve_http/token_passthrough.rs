use super::*;

/// The wrapped MCP server records its environment, argv and every message it
/// receives. Neither the inbound bearer token nor its fingerprint may appear.
#[test]
fn mcp_serve_http_wrapped_server_never_observes_inbound_bearer() {
    skip_when_loopback_denied!(mcp_serve_http_wrapped_server_never_observes_inbound_bearer);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let jwt_signing_key = Keypair::generate();
    let observation_log = dir.join("wrapped-observations.jsonl");
    let policy_path = write_policy(&dir);
    let script_path = write_mock_server_script(&dir);
    let session_db_path = default_session_db_path(&dir, listen);

    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .env(
            "CHIO_MCP_OBSERVATION_LOG_PATH",
            observation_log.to_str().expect("observation log path"),
        )
        .args([
            "--receipt-db",
            dir.join("remote-receipts.sqlite3")
                .to_str()
                .expect("receipt db path"),
            "--authority-seed-file",
            dir.join("remote-authority.seed")
                .to_str()
                .expect("authority seed path"),
            "mcp",
            "serve-http",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-http-mock",
            "--server-name",
            "Wrapped HTTP Mock",
            "--listen",
            &listen.to_string(),
            "--auth-jwt-public-key",
            &jwt_signing_key.public_key().to_hex(),
            "--auth-jwt-issuer",
            issuer,
            "--auth-jwt-audience",
            audience,
            "--auth-scope",
            "mcp:invoke",
            "--admin-token",
            EDGE_ADMIN_TOKEN,
        ]);
    add_remote_session_state(&mut command, &dir, &session_db_path);
    let _server =
        spawn_secured_http_command(command, &dir, &script_path, "spawn observed serve-http");
    let client = Client::builder()
        .timeout(HTTP_CLIENT_TIMEOUT)
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke",
            "client_id": "client-abc",
            "jti": "passthrough-check",
            "exp": 4_102_444_800_u64,
        }),
    );
    let (session_id, protocol_version) = initialize_session(&client, &base_url, &token);
    let call = post_json(
        &client,
        &base_url,
        &token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": { "message": "passthrough-check" }
            }
        }),
    );
    assert_eq!(call.status(), reqwest::StatusCode::OK);
    let _ = call.text();

    let observations = fs::read_to_string(&observation_log).expect("read observations");
    let records = observations
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("observation record"))
        .collect::<Vec<_>>();
    assert!(records.iter().any(|record| record.get("environ").is_some()));
    assert!(records.iter().any(|record| record["received"]
        .as_str()
        .is_some_and(|line| line.contains("passthrough-check"))));
    let fingerprint = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(token.as_bytes()))
    };
    let signature = token.rsplit('.').next().expect("token signature");
    for needle in [token.as_str(), fingerprint.as_str(), signature] {
        assert!(
            !observations.contains(needle),
            "wrapped server observed inbound credential material"
        );
    }
}
