#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::support::{self, TestServer};

use reqwest::blocking::Response;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::{json, Value};

const STATELESS: &str = "2026-07-28";

fn stateless_body(id: u64, method: &str, mut params: Value, version: &str) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": { "name": "stateless-client", "version": "1" },
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

fn post(server: &TestServer, headers: &[(&str, &str)], body: &Value) -> Response {
    let mut request = server
        .client
        .post(format!("{}/mcp", server.base_url))
        .header(AUTHORIZATION, format!("Bearer {}", server.token))
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(body).unwrap());
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.send().unwrap()
}

/// POST with the headers a conforming 2026-07-28 client mirrors from the body.
fn post_stateless(server: &TestServer, body: &Value) -> Response {
    let method = body["method"].as_str().unwrap();
    let version = body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"]
        .as_str()
        .unwrap();
    let name = body["params"]["name"]
        .as_str()
        .or_else(|| body["params"]["uri"].as_str());
    let mut headers = vec![("MCP-Protocol-Version", version), ("Mcp-Method", method)];
    if let Some(name) = name {
        headers.push(("Mcp-Name", name));
    }
    post(server, &headers, body)
}

fn json_body(response: Response) -> Value {
    assert_eq!(
        response.headers()[CONTENT_TYPE].to_str().unwrap(),
        "application/json"
    );
    assert!(response.headers().get("mcp-session-id").is_none());
    response.json().unwrap()
}

#[test]
fn stateless_client_discovers_lists_and_calls_without_a_session() {
    let server = support::start_http_server("test-token");

    let discover = post_stateless(
        &server,
        &stateless_body(1, "server/discover", json!({}), STATELESS),
    );
    assert_eq!(discover.status(), StatusCode::OK);
    let discover = json_body(discover);
    assert_eq!(
        discover["result"]["supportedVersions"],
        json!([STATELESS, "2025-11-25"])
    );
    assert_eq!(discover["result"]["resultType"], "complete");

    let tools = post_stateless(
        &server,
        &stateless_body(2, "tools/list", json!({}), STATELESS),
    );
    assert_eq!(tools.status(), StatusCode::OK);
    let tools = json_body(tools);
    assert_eq!(tools["result"]["tools"][0]["name"], "echo_json");
    assert_eq!(tools["result"]["cacheScope"], "private");

    let call = post_stateless(
        &server,
        &stateless_body(
            3,
            "tools/call",
            json!({ "name": "echo_json", "arguments": { "message": "stateless" } }),
            STATELESS,
        ),
    );
    assert_eq!(call.status(), StatusCode::OK);
    let call = json_body(call);
    assert_eq!(call["id"], 3);
    assert_eq!(call["result"]["structuredContent"]["echo"], "stateless");
    assert_eq!(call["result"]["resultType"], "complete");
    assert_eq!(
        call["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "Chio MCP Edge"
    );
}

#[test]
fn mirrored_headers_must_match_the_body() {
    let server = support::start_http_server("test-token");
    let call = stateless_body(
        1,
        "tools/call",
        json!({ "name": "echo_json", "arguments": {} }),
        STATELESS,
    );
    let cases: [&[(&str, &str)]; 5] = [
        &[("Mcp-Method", "tools/call"), ("Mcp-Name", "echo_json")],
        &[
            ("MCP-Protocol-Version", "2025-11-25"),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "echo_json"),
        ],
        &[
            ("MCP-Protocol-Version", STATELESS),
            ("Mcp-Name", "echo_json"),
        ],
        &[
            ("MCP-Protocol-Version", STATELESS),
            ("Mcp-Method", "tools/list"),
            ("Mcp-Name", "echo_json"),
        ],
        &[
            ("MCP-Protocol-Version", STATELESS),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "other_tool"),
        ],
    ];
    for headers in cases {
        let response = post(&server, headers, &call);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{headers:?}");
        let body: Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], -32020, "{headers:?}");
    }

    let encoded = post(
        &server,
        &[
            ("MCP-Protocol-Version", STATELESS),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "=?base64?ZWNob19qc29u?="),
        ],
        &call,
    );
    assert_eq!(encoded.status(), StatusCode::OK);

    let with_session = post(
        &server,
        &[
            ("MCP-Protocol-Version", STATELESS),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "echo_json"),
            ("Mcp-Session-Id", "not-a-session"),
        ],
        &call,
    );
    assert_ne!(with_session.status(), StatusCode::OK);
}

#[test]
fn unsupported_versions_and_removed_methods_are_refused() {
    let server = support::start_http_server("test-token");

    let unsupported = post_stateless(
        &server,
        &stateless_body(1, "tools/list", json!({}), "1900-01-01"),
    );
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
    let unsupported: Value = unsupported.json().unwrap();
    assert_eq!(unsupported["error"]["code"], -32022);
    assert_eq!(unsupported["error"]["data"]["requested"], "1900-01-01");
    assert_eq!(
        unsupported["error"]["data"]["supported"],
        json!([STATELESS, "2025-11-25"])
    );

    let removed = post_stateless(&server, &stateless_body(2, "ping", json!({}), STATELESS));
    assert_eq!(removed.status(), StatusCode::NOT_FOUND);
    let removed: Value = removed.json().unwrap();
    assert_eq!(removed["error"]["code"], -32601);

    let initialize = post_stateless(
        &server,
        &stateless_body(
            3,
            "initialize",
            json!({ "protocolVersion": STATELESS, "capabilities": {} }),
            STATELESS,
        ),
    );
    assert_eq!(initialize.status(), StatusCode::BAD_REQUEST);
    let initialize: Value = initialize.json().unwrap();
    assert_eq!(initialize["error"]["code"], -32600);
}

#[test]
fn handshake_sessions_keep_working_beside_stateless_requests() {
    let server = support::start_http_server("test-token");
    let session = server.initialize_session();
    assert_eq!(session.protocol_version, "2025-11-25");

    let stateless = post_stateless(
        &server,
        &stateless_body(9, "tools/list", json!({}), STATELESS),
    );
    assert_eq!(stateless.status(), StatusCode::OK);

    let tools = server.list_tools(&session);
    assert_eq!(tools["result"]["tools"][0]["name"], "echo_json");
    assert!(tools["result"].get("resultType").is_none());
}

#[cfg(target_os = "linux")]
const TEARDOWN_CHILD: &str = "CHIO_TEST_SESSION_TEARDOWN_CHILD";

#[cfg(target_os = "linux")]
fn store_pool_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter(|task| {
            std::fs::read_to_string(task.as_ref().unwrap().path().join("comm"))
                .is_ok_and(|name| name.starts_with("r2d2-worker"))
        })
        .count()
}

/// Thread counts are process-wide, so the measurement runs alone in a child
/// test process.
#[cfg(target_os = "linux")]
#[test]
fn ended_sessions_release_their_store_pool_threads() {
    if std::env::var_os(TEARDOWN_CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "hosted_tests::stateless_http::ended_sessions_release_their_store_pool_threads",
                "--test-threads",
                "1",
            ])
            .env(TEARDOWN_CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }

    let server = support::start_http_server("test-token");
    let baseline = store_pool_threads();
    let settled = |phase: &str| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while store_pool_threads() > baseline {
            assert!(
                std::time::Instant::now() < deadline,
                "{phase}: {} store pool threads outlived their sessions (baseline {baseline})",
                store_pool_threads()
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    };

    for id in 0..10 {
        let response = post_stateless(
            &server,
            &stateless_body(
                id,
                "tools/call",
                json!({ "name": "echo_json", "arguments": { "message": "teardown" } }),
                STATELESS,
            ),
        );
        assert_eq!(response.status(), StatusCode::OK);
    }
    settled("stateless requests");

    let session = server.initialize_session();
    assert!(store_pool_threads() > baseline);
    assert!(server.delete_session(&session.id).status().is_success());
    settled("DELETE");
}
