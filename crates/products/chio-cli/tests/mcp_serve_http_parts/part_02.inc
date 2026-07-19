fn post_notification(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
    protocol_version: Option<&str>,
    body: &Value,
) -> Response {
    post_json(
        client,
        base_url,
        token,
        Some(session_id),
        protocol_version,
        body,
    )
}

fn get_session_stream(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
    protocol_version: Option<&str>,
    last_event_id: Option<&str>,
) -> Response {
    let mut request = client
        .get(format!("{base_url}/mcp"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, "text/event-stream")
        .header("MCP-Session-Id", session_id);

    if let Some(protocol_version) = protocol_version {
        request = request.header("MCP-Protocol-Version", protocol_version);
    }
    if let Some(last_event_id) = last_event_id {
        request = request.header("Last-Event-ID", last_event_id);
    }

    request.send().expect("send GET session stream request")
}

fn delete_session(client: &Client, base_url: &str, token: &str, session_id: &str) -> Response {
    client
        .delete(format!("{base_url}/mcp"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header("MCP-Session-Id", session_id)
        .send()
        .expect("send session delete request")
}

fn get_admin_authority(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .get(format!("{base_url}/admin/authority"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin authority get request")
}

fn get_control_authority(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .get(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send control authority get request")
}

fn get_protected_resource_metadata(client: &Client, base_url: &str) -> Response {
    client
        .get(format!(
            "{base_url}/.well-known/oauth-protected-resource/mcp"
        ))
        .send()
        .expect("send protected resource metadata request")
}

fn get_oauth_authorization_server_metadata(
    client: &Client,
    base_url: &str,
    issuer_path: &str,
) -> Response {
    client
        .get(format!(
            "{base_url}/.well-known/oauth-authorization-server/{}",
            issuer_path.trim_start_matches('/')
        ))
        .send()
        .expect("send oauth authorization server metadata request")
}

fn post_admin_rotate_authority(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .post(format!("{base_url}/admin/authority"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin authority rotate request")
}

fn post_control_rotate_authority(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .post(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({}))
        .send()
        .expect("send control authority rotate request")
}

fn get_admin_session_trust(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
) -> Response {
    client
        .get(format!("{base_url}/admin/sessions/{session_id}/trust"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin trust get request")
}

fn get_admin_sessions(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .get(format!("{base_url}/admin/sessions"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin sessions get request")
}

fn get_admin_health(client: &Client, base_url: &str, token: &str) -> Response {
    client
        .get(format!("{base_url}/admin/health"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin health request")
}

fn post_admin_session_revoke(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
) -> Response {
    client
        .post(format!("{base_url}/admin/sessions/{session_id}/trust"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin trust revoke request")
}

fn post_admin_session_drain(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
) -> Response {
    client
        .post(format!("{base_url}/admin/sessions/{session_id}/drain"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin session drain request")
}

fn post_admin_session_shutdown(
    client: &Client,
    base_url: &str,
    token: &str,
    session_id: &str,
) -> Response {
    client
        .post(format!("{base_url}/admin/sessions/{session_id}/shutdown"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin session shutdown request")
}

fn get_admin_tool_receipts(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/admin/receipts/tools"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin tool receipts request")
}

fn get_control_tool_receipts(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/v1/receipts/tools"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send control tool receipts request")
}

fn get_admin_child_receipts(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/admin/receipts/children"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin child receipts request")
}

fn get_admin_revocations(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/admin/revocations"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send admin revocations request")
}

fn get_control_revocations(
    client: &Client,
    base_url: &str,
    token: &str,
    query: &[(&str, &str)],
) -> Response {
    client
        .get(format!("{base_url}/v1/revocations"))
        .query(query)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .expect("send control revocations request")
}

fn post_admin_capability_revoke(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
) -> Response {
    client
        .post(format!("{base_url}/admin/revocations"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({ "capability_id": capability_id }))
        .send()
        .expect("send admin capability revoke request")
}

fn read_sse_until_response<F>(
    response: Response,
    expected_id: Value,
    mut on_message: F,
) -> (Value, Vec<Value>)
where
    F: FnMut(&Value),
{
    let mut reader = BufReader::new(response);
    let mut messages = Vec::new();

    loop {
        let Some(message) = read_next_sse_message(&mut reader) else {
            panic!("expected terminal JSON-RPC response on SSE stream");
        };
        if message.get("id") == Some(&expected_id) && message.get("method").is_none() {
            return (message, messages);
        }
        on_message(&message);
        messages.push(message);
    }
}

fn read_sse_events_until_response(
    response: Response,
    expected_id: Value,
) -> (Value, Vec<SseEvent>) {
    let mut reader = BufReader::new(response);
    let mut events = Vec::new();

    loop {
        let Some(event) = read_next_sse_event(&mut reader) else {
            panic!("expected terminal JSON-RPC response on SSE stream");
        };
        let Some(message) = event.message.as_ref() else {
            continue;
        };
        if message.get("id") == Some(&expected_id) && message.get("method").is_none() {
            return (message.clone(), events);
        }
        events.push(event);
    }
}

#[derive(Debug)]
struct SseEvent {
    id: Option<String>,
    message: Option<Value>,
}

fn read_next_sse_event(reader: &mut impl BufRead) -> Option<SseEvent> {
    let mut id = None;
    let mut data = Vec::new();

    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).expect("read SSE line");
        if bytes == 0 {
            return None;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            if id.is_none() && data.is_empty() {
                continue;
            }

            let message = if data.is_empty() {
                None
            } else {
                let payload = data.join("\n");
                Some(serde_json::from_str(&payload).expect("parse SSE JSON-RPC payload"))
            };
            return Some(SseEvent { id, message });
        }

        if let Some(rest) = trimmed.strip_prefix("id:") {
            id = Some(rest.trim_start().to_string());
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("data:") {
            data.push(rest.trim_start().to_string());
        }
    }
}

fn read_next_sse_message(reader: &mut impl BufRead) -> Option<Value> {
    loop {
        let event = read_next_sse_event(reader)?;
        if let Some(message) = event.message {
            return Some(message);
        }
    }
}

fn sign_jwt(keypair: &Keypair, claims: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "JWT"
        }))
        .expect("serialize JWT header"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize JWT claims"));
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(keypair.sign(signing_input.as_bytes()).to_bytes());
    format!("{signing_input}.{signature}")
}

fn sign_jwt_with_header(header: Value, claims: &Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize JWT header"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize JWT claims"));
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes()));
    format!("{signing_input}.{signature}")
}

fn sign_jwt_rs256(private_key: &rsa::RsaPrivateKey, claims: &Value, kid: &str) -> String {
    use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
    use rsa::signature::{SignatureEncoding as _, Signer as _};

    let signing_key = RsaPkcs1v15SigningKey::<sha2::Sha256>::new(private_key.clone());
    sign_jwt_with_header(
        json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| signing_key.sign(message).to_vec(),
    )
}

fn sign_jwt_es256(signing_key: &p256::ecdsa::SigningKey, claims: &Value, kid: &str) -> String {
    use p256::ecdsa::signature::Signer as _;

    sign_jwt_with_header(
        json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| {
            let signature: p256::ecdsa::Signature = signing_key.sign(message);
            signature.to_bytes().to_vec()
        },
    )
}

fn initialize_session(client: &Client, base_url: &str, token: &str) -> (String, String) {
    initialize_session_with_capabilities(
        client,
        base_url,
        token,
        json!({
            "sampling": {
                "context": {},
                "tools": {}
            }
        }),
    )
}

fn initialize_session_with_capabilities(
    client: &Client,
    base_url: &str,
    token: &str,
    capabilities: Value,
) -> (String, String) {
    let response = post_json(
        client,
        base_url,
        token,
        None,
        Some("2025-11-25"),
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": capabilities,
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    if response.status() != reqwest::StatusCode::OK {
        let status = response.status();
        let body = response
            .text()
            .unwrap_or_else(|error| format!("failed to read initialize error body: {error}"));
        panic!("initialize returned {status}: {body}");
    }
    let session_id = response
        .headers()
        .get("MCP-Session-Id")
        .expect("session id header")
        .to_str()
        .expect("session id string")
        .to_string();
    let (initialize, init_messages) = read_sse_until_response(response, json!(1), |_| {});
    assert!(init_messages.is_empty());
    let protocol_version = initialize["result"]["protocolVersion"]
        .as_str()
        .expect("protocol version")
        .to_string();

    let initialized = post_notification(
        client,
        base_url,
        token,
        &session_id,
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    assert_eq!(initialized.status(), reqwest::StatusCode::ACCEPTED);

    (session_id, protocol_version)
}

#[test]
fn mcp_serve_http_streams_roots_request_after_initialized_when_client_supports_roots() {
    skip_when_loopback_denied!(
        mcp_serve_http_streams_roots_request_after_initialized_when_client_supports_roots
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_json(
        &client,
        &base_url,
        token,
        None,
        Some("2025-11-25"),
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "roots": {
                        "listChanged": true
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let session_id = response
        .headers()
        .get("MCP-Session-Id")
        .expect("session id header")
        .to_str()
        .expect("session id string")
        .to_string();
    let (initialize, init_messages) = read_sse_until_response(response, json!(1), |_| {});
    assert!(init_messages.is_empty());
    let protocol_version = initialize["result"]["protocolVersion"]
        .as_str()
        .expect("protocol version")
        .to_string();

    let initialized = post_notification(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    assert_eq!(initialized.status(), reqwest::StatusCode::OK);

    let mut reader = BufReader::new(initialized);
    let roots_request = read_next_sse_message(&mut reader).expect("roots/list request");
    assert_eq!(roots_request["method"], "roots/list");
    let roots_request_id = roots_request["id"]
        .as_str()
        .expect("roots request id")
        .to_string();

    let roots_response = post_notification(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": roots_request_id,
            "result": {
                "roots": [{
                    "uri": "file:///workspace/project",
                    "name": "Project"
                }]
            }
        }),
    );
    assert!(matches!(
        roots_response.status(),
        reqwest::StatusCode::OK | reqwest::StatusCode::ACCEPTED
    ));
}

#[test]
fn mcp_serve_http_requires_auth_reuses_sessions_and_supports_delete() {
    skip_when_loopback_denied!(mcp_serve_http_requires_auth_reuses_sessions_and_supports_delete);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let unauthenticated = post_json_no_auth(
        &client,
        &base_url,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let (tools_list, notifications) = read_sse_until_response(response, json!(2), |_| {});
    assert!(notifications.is_empty());
    let tool_names = tools_list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert!(tool_names.contains(&"echo_json"));
    assert!(tool_names.contains(&"sampled_echo"));
    assert!(tool_names.contains(&"slow_echo"));

    let deleted = delete_session(&client, &base_url, token, &session_id);
    assert_eq!(deleted.status(), reqwest::StatusCode::NO_CONTENT);

    let deleted_trust = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(deleted_trust.status(), reqwest::StatusCode::OK);
    let deleted_trust: Value = deleted_trust.json().expect("deleted trust json");
    assert_eq!(
        deleted_trust["lifecycle"]["state"].as_str(),
        Some("deleted")
    );
    assert_eq!(
        deleted_trust["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(false)
    );

    let missing_session = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(missing_session.status(), reqwest::StatusCode::GONE);

    let missing_stream = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(missing_stream.status(), reqwest::StatusCode::GONE);
}

#[test]
fn mcp_serve_http_session_trust_reports_lifecycle_and_reconnect_contract() {
    skip_when_loopback_denied!(
        mcp_serve_http_session_trust_reports_lifecycle_and_reconnect_contract
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let token = "test-token";
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server",
        |listen| spawn_http_server(&dir, listen, token),
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("session trust json");
    assert_eq!(
        trust_status["sessionId"].as_str(),
        Some(session_id.as_str())
    );
    assert_eq!(trust_status["lifecycle"]["state"].as_str(), Some("ready"));
    assert_eq!(
        trust_status["lifecycle"]["protocolVersion"].as_str(),
        Some(protocol_version.as_str())
    );
    assert!(trust_status["lifecycle"]["createdAt"].as_u64().is_some());
    assert!(trust_status["lifecycle"]["lastSeenAt"].as_u64().is_some());
    assert_eq!(
        trust_status["ownership"]["requestStreamOwner"].as_str(),
        Some("exclusive_request_stream")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["workOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["resultStreamOwner"].as_str(),
        Some("request_stream")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["terminalStateOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["notificationStreamOwner"].as_str(),
        Some("session_notification_stream")
    );
    assert_eq!(
        trust_status["ownership"]["notificationDelivery"].as_str(),
        Some("post_response_fallback")
    );
    assert_eq!(
        trust_status["ownership"]["hostedIsolation"].as_str(),
        Some("dedicated_per_session")
    );
    assert_eq!(
        trust_status["ownership"]["hostedIdentityProfile"].as_str(),
        Some("strong_dedicated_session")
    );
    assert_eq!(
        trust_status["ownership"]["requestStreamActive"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_status["ownership"]["notificationStreamAttached"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_status["lifecycle"]["reconnect"]["mode"].as_str(),
        Some("post-session-reuse-only")
    );
    assert_eq!(
        trust_status["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(true)
    );
    assert_eq!(
        trust_status["lifecycle"]["reconnect"]["requiresAuthContinuity"].as_bool(),
        Some(true)
    );
    let terminal_states = trust_status["lifecycle"]["reconnect"]["terminalStates"]
        .as_array()
        .expect("terminal states");
    assert!(terminal_states
        .iter()
        .any(|value| value.as_str() == Some("deleted")));
    assert!(terminal_states
        .iter()
        .any(|value| value.as_str() == Some("expired")));
    assert!(terminal_states
        .iter()
        .any(|value| value.as_str() == Some("draining")));
    assert!(terminal_states
        .iter()
        .any(|value| value.as_str() == Some("closed")));
}

#[test]
fn mcp_serve_http_session_trust_reports_request_stream_lease_while_post_stream_is_open() {
    skip_when_loopback_denied!(
        mcp_serve_http_session_trust_reports_request_stream_lease_while_post_stream_is_open
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let call = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "lease-check" }
            }
        }),
    );

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("session trust json");
    assert_eq!(
        trust_status["ownership"]["requestStreamActive"].as_bool(),
        Some(true)
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["workOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["terminalStateOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["notificationStreamAttached"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_status["ownership"]["notificationDelivery"].as_str(),
        Some("post_response_fallback")
    );

    let (response, events) = read_sse_until_response(call, json!(22), |_| {});
    assert!(events.is_empty());
    assert_eq!(response["result"]["content"][0]["text"], "slow response");

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("session trust json");
    assert_eq!(
        trust_status["ownership"]["requestStreamActive"].as_bool(),
        Some(false)
    );
}

#[test]
fn mcp_serve_http_idle_expiry_reaps_sessions_and_blocks_reuse() {
    skip_when_loopback_denied!(mcp_serve_http_idle_expiry_reaps_sessions_and_blocks_reuse);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server_with_session_lifecycle_tuning(
        &dir,
        listen,
        token,
        None,
        Some(250),
        Some(250),
        Some(50),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);

    let mut expired = None;
    for _ in 0..40 {
        let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
        assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
        let trust_status: Value = trust_status.json().expect("session trust json");
        if trust_status["lifecycle"]["state"].as_str() == Some("expired") {
            expired = Some(trust_status);
            break;
        }
        thread::sleep(Duration::from_millis(75));
    }
    let expired = expired.expect("session to expire");
    assert_eq!(
        expired["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(false)
    );
    assert!(expired["lifecycle"]["reconnect"]["terminalStates"]
        .as_array()
        .expect("terminal states")
        .iter()
        .any(|value| value.as_str() == Some("expired")));

    let resumed_post = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(resumed_post.status(), reqwest::StatusCode::GONE);

    let resumed_get = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(resumed_get.status(), reqwest::StatusCode::GONE);
}

#[test]
fn mcp_serve_http_admin_drain_shutdown_and_delete_have_distinct_terminal_states() {
    skip_when_loopback_denied!(
        mcp_serve_http_admin_drain_shutdown_and_delete_have_distinct_terminal_states
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server_with_session_lifecycle_tuning(
        &dir,
        listen,
        token,
        None,
        Some(5_000),
        Some(250),
        Some(50),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (draining_session, draining_protocol) = initialize_session(&client, &base_url, token);
    let drain = post_admin_session_drain(&client, &base_url, token, &draining_session);
    assert_eq!(drain.status(), reqwest::StatusCode::OK);
    let drain: Value = drain.json().expect("drain json");
    assert_eq!(drain["lifecycle"]["state"].as_str(), Some("draining"));

    let draining_post = post_json(
        &client,
        &base_url,
        token,
        Some(&draining_session),
        Some(&draining_protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(draining_post.status(), reqwest::StatusCode::CONFLICT);

    let mut deleted = None;
    for _ in 0..40 {
        let trust_status = get_admin_session_trust(&client, &base_url, token, &draining_session);
        assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
        let trust_status: Value = trust_status.json().expect("draining trust json");
        if trust_status["lifecycle"]["state"].as_str() == Some("deleted") {
            deleted = Some(trust_status);
            break;
        }
        thread::sleep(Duration::from_millis(75));
    }
    let deleted = deleted.expect("draining session to settle as deleted");
    assert_eq!(
        deleted["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(false)
    );

    let deleted_post = post_json(
        &client,
        &base_url,
        token,
        Some(&draining_session),
        Some(&draining_protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(deleted_post.status(), reqwest::StatusCode::GONE);

    let (deleted_session, deleted_protocol) = initialize_session(&client, &base_url, token);
    let deleted_direct = delete_session(&client, &base_url, token, &deleted_session);
    assert_eq!(deleted_direct.status(), reqwest::StatusCode::NO_CONTENT);
    let deleted_trust = get_admin_session_trust(&client, &base_url, token, &deleted_session);
    assert_eq!(deleted_trust.status(), reqwest::StatusCode::OK);
    let deleted_trust: Value = deleted_trust.json().expect("deleted trust json");
    assert_eq!(
        deleted_trust["lifecycle"]["state"].as_str(),
        Some("deleted")
    );

    let deleted_post = post_json(
        &client,
        &base_url,
        token,
        Some(&deleted_session),
        Some(&deleted_protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(deleted_post.status(), reqwest::StatusCode::GONE);

    let (shutdown_session, shutdown_protocol) = initialize_session(&client, &base_url, token);
    let shutdown = post_admin_session_shutdown(&client, &base_url, token, &shutdown_session);
    assert_eq!(shutdown.status(), reqwest::StatusCode::OK);
    let shutdown: Value = shutdown.json().expect("shutdown json");
    assert_eq!(shutdown["lifecycle"]["state"].as_str(), Some("closed"));

    let shutdown_post = post_json(
        &client,
        &base_url,
        token,
        Some(&shutdown_session),
        Some(&shutdown_protocol),
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(shutdown_post.status(), reqwest::StatusCode::GONE);

    let sessions = get_admin_sessions(&client, &base_url, token);
    assert_eq!(sessions.status(), reqwest::StatusCode::OK);
    let sessions: Value = sessions.json().expect("admin sessions json");
    assert!(sessions["terminalCount"].as_u64().unwrap_or(0) >= 3);
}

#[test]
fn mcp_serve_http_terminal_tombstones_survive_restart_and_block_reuse() {
    skip_when_loopback_denied!(mcp_serve_http_terminal_tombstones_survive_restart_and_block_reuse);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-tombstones.sqlite3");

    // Phase 1a: create the deleted-session tombstone with a long idle expiry so the
    // session cannot race the reaper between `initialize` and `notifications/initialized`.
    let (deleted_session, deleted_protocol) = {
        let _server = spawn_http_server_with_session_lifecycle_tuning(
            &dir,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);

        let (deleted_session, deleted_protocol) = initialize_session(&client, &base_url, token);
        let deleted = delete_session(&client, &base_url, token, &deleted_session);
        assert_eq!(deleted.status(), reqwest::StatusCode::NO_CONTENT);
        let deleted_trust = get_admin_session_trust(&client, &base_url, token, &deleted_session);
        assert_eq!(deleted_trust.status(), reqwest::StatusCode::OK);
        let deleted_trust: Value = deleted_trust.json().expect("deleted trust json");
        assert_eq!(
            deleted_trust["lifecycle"]["state"].as_str(),
            Some("deleted")
        );

        (deleted_session, deleted_protocol)
    };

    // Phase 1b: create the expired-session tombstone using a tight idle expiry so the
    // reaper can transition the session to Expired within the wait loop budget. The
    // session is only `initialize`d once, so the brief race between `initialize` and
    // `notifications/initialized` is the only timing constraint here.
    let (expired_session, expired_protocol) = {
        let idle_expiry_millis: u64 = 1_500;
        let _server = spawn_http_server_with_session_lifecycle_tuning(
            &dir,
            listen,
            token,
            Some(&session_db_path),
            Some(idle_expiry_millis),
            Some(idle_expiry_millis),
            Some(50),
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);

        let (expired_session, expired_protocol) = initialize_session(&client, &base_url, token);
        let poll_interval = Duration::from_millis(75);
        // Allow at least 4x the idle expiry to absorb reaper jitter and CI scheduling slack.
        let max_wait = Duration::from_millis(idle_expiry_millis * 4);
        let deadline = std::time::Instant::now() + max_wait;
        let mut expired = None;
        while std::time::Instant::now() < deadline {
            let trust_status = get_admin_session_trust(&client, &base_url, token, &expired_session);
            assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
            let trust_status: Value = trust_status.json().expect("expired trust json");
            if trust_status["lifecycle"]["state"].as_str() == Some("expired") {
                expired = Some(trust_status);
                break;
            }
            thread::sleep(poll_interval);
        }
        let expired = expired.expect("session to expire before restart");
        assert_eq!(expired["sessionId"], expired_session);

        (expired_session, expired_protocol)
    };

    // Phase 1c: create the shutdown-session tombstone with a long idle expiry so the
    // session cannot race the reaper before the admin shutdown call lands.
    let (shutdown_session, shutdown_protocol) = {
        let _server = spawn_http_server_with_session_lifecycle_tuning(
            &dir,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);

        let (shutdown_session, shutdown_protocol) = initialize_session(&client, &base_url, token);
        let shutdown = post_admin_session_shutdown(&client, &base_url, token, &shutdown_session);
        assert_eq!(shutdown.status(), reqwest::StatusCode::OK);
        let shutdown: Value = shutdown.json().expect("shutdown json");
        assert_eq!(shutdown["lifecycle"]["state"].as_str(), Some("closed"));

        (shutdown_session, shutdown_protocol)
    };

    let _server = spawn_http_server_with_session_lifecycle_tuning(
        &dir,
        listen,
        token,
        Some(&session_db_path),
        Some(250),
        Some(250),
        Some(50),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let sessions = get_admin_sessions(&client, &base_url, token);
    assert_eq!(sessions.status(), reqwest::StatusCode::OK);
    let sessions: Value = sessions.json().expect("admin sessions json");
    assert!(sessions["terminalCount"].as_u64().unwrap_or(0) >= 3);

    for (session_id, protocol_version, expected_state) in [
        (&deleted_session, &deleted_protocol, "deleted"),
        (&expired_session, &expired_protocol, "expired"),
        (&shutdown_session, &shutdown_protocol, "closed"),
    ] {
        let trust_status = get_admin_session_trust(&client, &base_url, token, session_id);
        assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
        let trust_status: Value = trust_status.json().expect("terminal trust json");
        assert_eq!(
            trust_status["lifecycle"]["state"].as_str(),
            Some(expected_state)
        );

        let reuse_post = post_json(
            &client,
            &base_url,
            token,
            Some(session_id),
            Some(protocol_version),
            &json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/list",
                "params": {}
            }),
        );
        assert_eq!(reuse_post.status(), reqwest::StatusCode::GONE);
    }
}

#[test]
fn mcp_serve_http_ready_sessions_survive_restart_and_resume_authenticated_calls() {
    skip_when_loopback_denied!(
        mcp_serve_http_ready_sessions_survive_restart_and_resume_authenticated_calls
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");

    let (session_id, protocol_version) = {
        let _server = spawn_http_server_with_session_lifecycle_tuning(
            &dir,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);

        let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
        let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
        assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
        let trust_status: Value = trust_status.json().expect("ready trust json");
        assert_eq!(trust_status["lifecycle"]["state"].as_str(), Some("ready"));
        (session_id, protocol_version)
    };

    let _server = spawn_http_server_with_session_lifecycle_tuning(
        &dir,
        listen,
        token,
        Some(&session_db_path),
        Some(5_000),
        Some(5_000),
        Some(50),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("restored trust json");
    assert_eq!(trust_status["lifecycle"]["state"].as_str(), Some("ready"));

    let resumed_post = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(resumed_post.status(), reqwest::StatusCode::OK);
    let (resumed_tools, notifications) = read_sse_until_response(resumed_post, json!(12), |_| {});
    assert!(notifications.is_empty());
    assert!(resumed_tools["result"]["tools"]
        .as_array()
        .is_some_and(|tools| !tools.is_empty()));

    let resumed_get = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(resumed_get.status(), reqwest::StatusCode::OK);
}

#[test]
fn mcp_serve_http_ready_sessions_reissue_capabilities_after_policy_tightening() {
    skip_when_loopback_denied!(
        mcp_serve_http_ready_sessions_reissue_capabilities_after_policy_tightening
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");
    let policy_path = write_policy_with_tools(&dir, &["echo_json", "sampled_echo"]);

    let (session_id, protocol_version) = {
        let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
            &dir,
            &policy_path,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
            "Chio",
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);
        initialize_session(&client, &base_url, token)
    };

    let policy_path = write_policy_with_tools(&dir, &["sampled_echo"]);
    let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
        &dir,
        &policy_path,
        listen,
        token,
        Some(&session_db_path),
        Some(5_000),
        Some(5_000),
        Some(50),
        "Chio",
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);

    let denied_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 77,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "should now be denied"}
            }
        }),
    );
    assert_eq!(denied_response.status(), reqwest::StatusCode::OK);
    let (denied_tool_call, denied_notifications) =
        read_sse_until_response(denied_response, json!(77), |_| {});
    assert_eq!(denied_notifications.len(), 1);
    assert_eq!(
        denied_notifications[0]["method"].as_str(),
        Some("notifications/message")
    );
    assert_eq!(
        denied_notifications[0]["params"]["data"]["event"].as_str(),
        Some("tool_denied")
    );
    assert_eq!(
        denied_notifications[0]["params"]["data"]["tool"].as_str(),
        Some("echo_json")
    );
    assert_eq!(denied_tool_call["result"]["isError"], true);
}

#[test]
fn mcp_serve_http_restores_sessions_with_fresh_capabilities_after_ttl_expiry() {
    skip_when_loopback_denied!(
        mcp_serve_http_restores_sessions_with_fresh_capabilities_after_ttl_expiry
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");
    let policy_path = write_policy_with_tools_and_ttl(&dir, &["echo_json"], 1);

    let (session_id, protocol_version) = {
        let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
            &dir,
            &policy_path,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
            "Chio",
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);
        initialize_session(&client, &base_url, token)
    };

    thread::sleep(Duration::from_secs(2));

    let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
        &dir,
        &policy_path,
        listen,
        token,
        Some(&session_db_path),
        Some(5_000),
        Some(5_000),
        Some(50),
        "Chio",
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let restored_response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 88,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "restored session should refresh capabilities"}
            }
        }),
    );
    assert_eq!(restored_response.status(), reqwest::StatusCode::OK);
    let (tool_call, notifications) = read_sse_until_response(restored_response, json!(88), |_| {});
    assert!(notifications.is_empty());
    assert_ne!(tool_call["result"]["isError"], true);
}

#[test]
fn mcp_serve_http_drops_restored_sessions_when_auth_mode_changes() {
    skip_when_loopback_denied!(mcp_serve_http_drops_restored_sessions_when_auth_mode_changes);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let session_db_path = dir.join("remote-session-state.sqlite3");
    let policy_path = write_policy(&dir);

    let session_id = {
        let _server = spawn_http_server_with_policy_path_and_session_lifecycle_env_prefix(
            &dir,
            &policy_path,
            listen,
            token,
            Some(&session_db_path),
            Some(5_000),
            Some(5_000),
            Some(50),
            "Chio",
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        let base_url = format!("http://{listen}");
        wait_for_server(&client, &base_url);
        let (session_id, _) = initialize_session(&client, &base_url, token);
        session_id
    };

    let auth_kp = Keypair::generate();
    let issuer = "https://issuer.example/restore-auth-mode";
    let audience = "chio-restore-auth-mode";
    let admin_token = "admin-token";
    let _server = spawn_http_server_with_policy_path_and_jwt_auth(
        &dir,
        &policy_path,
        listen,
        &auth_kp.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
        Some(&session_db_path),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let trust_status = get_admin_session_trust(&client, &base_url, admin_token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::NOT_FOUND);
}

#[test]
fn mcp_serve_http_isolates_multiple_sessions() {
    skip_when_loopback_denied!(mcp_serve_http_isolates_multiple_sessions);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let shared_owner_capabilities = json!({
        "sampling": {
            "context": {},
            "tools": {}
        },
        "resources": {
            "subscribe": true,
            "listChanged": true
        }
    });
    let (session_a, protocol_a) = initialize_session_with_capabilities(
        &client,
        &base_url,
        token,
        shared_owner_capabilities.clone(),
    );
    let (session_b, protocol_b) =
        initialize_session_with_capabilities(&client, &base_url, token, shared_owner_capabilities);
    assert_ne!(session_a, session_b);

    let session_a_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_a),
        Some(&protocol_a),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": {},
                "task": {}
            }
        }),
    );
    let (task_created, task_messages) = read_sse_until_response(session_a_task, json!(2), |_| {});
    assert!(task_messages.is_empty());
    let task_id = task_created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let session_b_task_get = post_json(
        &client,
        &base_url,
        token,
        Some(&session_b),
        Some(&protocol_b),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/get",
            "params": { "taskId": task_id }
        }),
    );
    let (task_get, task_get_messages) =
        read_sse_until_response(session_b_task_get, json!(3), |_| {});
    assert!(task_get_messages.is_empty());
    assert_eq!(task_get["error"]["code"], -32602);
    assert!(task_get["error"]["message"]
        .as_str()
        .expect("task get error")
        .contains("task not found"));
}

#[test]
fn mcp_serve_http_get_stream_owns_session_notifications_when_attached() {
    skip_when_loopback_denied!(mcp_serve_http_get_stream_owns_session_notifications_when_attached);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let get_stream = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(get_stream.status(), reqwest::StatusCode::OK);
    let mut get_reader = BufReader::new(get_stream);
    let trust_status = get_admin_session_trust(&client, &base_url, token, &session_id);
    assert_eq!(trust_status.status(), reqwest::StatusCode::OK);
    let trust_status: Value = trust_status.json().expect("session trust json");
    assert_eq!(
        trust_status["ownership"]["notificationDelivery"].as_str(),
        Some("get_sse")
    );
    assert_eq!(
        trust_status["ownership"]["requestOwnership"]["workOwner"].as_str(),
        Some("request")
    );
    assert_eq!(
        trust_status["ownership"]["requestStreamActive"].as_bool(),
        Some(false)
    );
    assert_eq!(
        trust_status["ownership"]["notificationStreamAttached"].as_bool(),
        Some(true)
    );

    let create_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": { "message": "stream to GET" },
                "task": {}
            }
        }),
    );
    let (created, create_messages) = read_sse_until_response(create_task, json!(30), |_| {});
    assert!(create_messages.is_empty());
    assert_eq!(created["result"]["task"]["ownership"]["workOwner"], "task");
    assert_eq!(
        created["result"]["task"]["ownership"]["resultStreamOwner"],
        "request_stream"
    );
    assert_eq!(
        created["result"]["task"]["ownership"]["statusNotificationOwner"],
        "session_notification_stream"
    );
    assert_eq!(
        created["result"]["task"]["ownership"]["terminalStateOwner"],
        "task"
    );
    assert!(created["result"]["task"]["ownerSessionId"]
        .as_str()
        .expect("owner session id")
        .starts_with("sess-"));
    assert!(created["result"]["task"]["ownerRequestId"]
        .as_str()
        .expect("owner request id")
        .starts_with("mcp-edge-req-"));
    assert!(created["result"]["task"]["parentRequestId"].is_null());
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let cancel_task = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tasks/cancel",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (cancelled, cancel_messages) = read_sse_until_response(cancel_task, json!(31), |_| {});
    assert_eq!(cancelled["result"]["status"], "cancelled");
    assert!(
        cancel_messages.is_empty(),
        "POST stream should not duplicate session notifications while GET is attached"
    );

    let first = read_next_sse_event(&mut get_reader).expect("GET task notification event");
    assert!(first.id.is_some());
    assert_eq!(
        first.message.as_ref().expect("GET notification message")["method"],
        "notifications/tasks/status"
    );
    assert_eq!(
        first
            .message
            .as_ref()
            .expect("GET task notification message")["params"]["taskId"],
        task_id
    );
}
