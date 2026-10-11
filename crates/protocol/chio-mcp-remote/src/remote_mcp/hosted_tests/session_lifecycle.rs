#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::support;

use serde_json::json;

use support::{start_http_server, start_http_server_with_lifecycle_tuning, LifecycleTuning};

#[test]
fn hosted_roots_wait_refuses_notification_accumulation_without_tool_calls() {
    let server = start_http_server("test-token");
    let initialize = server.post_json(
        None,
        None,
        &json!({"jsonrpc":"2.0","id":1,
        "method":"initialize","params":{"protocolVersion":"2025-11-25",
            "capabilities":{"roots":{"listChanged":true}},
            "clientInfo":{"name":"bounded-client","version":"1"}}}),
    );
    assert_eq!(initialize.status(), reqwest::StatusCode::OK);
    let session_id = initialize.headers()["MCP-Session-Id"]
        .to_str()
        .unwrap()
        .to_owned();
    drop(initialize);
    struct SessionRescue<'a>(&'a support::TestServer, &'a str);
    impl Drop for SessionRescue<'_> {
        fn drop(&mut self) {
            let _response = self.0.post_admin_session_shutdown(self.1);
        }
    }
    let _rescue = SessionRescue(&server, &session_id);
    let roots_stream = server.get_session_stream(&session_id, Some("2025-11-25"), None);
    assert_eq!(roots_stream.status(), reqwest::StatusCode::OK);
    let initialized = server.post_json(
        Some(&session_id),
        Some("2025-11-25"),
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(initialized.status(), reqwest::StatusCode::ACCEPTED);
    assert!(initialized.bytes().unwrap().is_empty());
    let mut line = String::new();
    // The refresh rides the next client request's stream even with a GET
    // attached, and the reply is withheld.
    let ping = server.post_json(
        Some(&session_id),
        Some("2025-11-25"),
        &json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
    );
    assert_eq!(ping.status(), reqwest::StatusCode::OK);
    let mut ping_reader = std::io::BufReader::new(ping);
    let roots_request_id = loop {
        use std::io::BufRead;
        line.clear();
        assert!(ping_reader.read_line(&mut line).unwrap() > 0);
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data.is_empty() {
                continue;
            }
            let message: serde_json::Value = serde_json::from_str(data).unwrap();
            assert_eq!(
                message["method"], "roots/list",
                "ping was answered before its roots refresh: {message}"
            );
            break message["id"].clone();
        }
    };
    let mut reader = std::io::BufReader::new(roots_stream);
    let mut rejected = false;
    for _ in 0..20 {
        let response = server.post_json(
            Some(&session_id),
            Some("2025-11-25"),
            &json!({"jsonrpc":"2.0","method":"notifications/message",
                "params":{"data":"x".repeat(512 * 1024)}}),
        );
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            rejected = true;
            break;
        }
        assert_eq!(response.status(), reqwest::StatusCode::ACCEPTED);
    }
    let receipts: serde_json::Value = server.get_admin_tool_receipts(&[]).json().unwrap();
    assert_eq!(receipts["receipts"].as_array().unwrap().len(), 0);
    assert!(
        rejected,
        "withheld roots reply retained unlimited notification bodies"
    );
    let wrong_reply = server.post_json(
        Some(&session_id),
        Some("2025-11-25"),
        &json!({"jsonrpc":"2.0","id":"wrong-reply",
            "result":{"roots":[],"padding":"x".repeat(512 * 1024)}}),
    );
    assert_eq!(wrong_reply.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let matching_reply = server.post_json(
        Some(&session_id),
        Some("2025-11-25"),
        &json!({"jsonrpc":"2.0","id":roots_request_id,
            "result":{"roots":[],"padding":"x".repeat(512 * 1024)}}),
    );
    assert_eq!(matching_reply.status(), reqwest::StatusCode::ACCEPTED);
    assert!(matching_reply.bytes().unwrap().is_empty());
    loop {
        use std::io::BufRead;
        line.clear();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data.is_empty() {
                continue;
            }
            let message: serde_json::Value = serde_json::from_str(data).unwrap();
            assert_ne!(message["method"], "roots/list");
            assert_ne!(message["params"]["data"]["event"], "roots_refresh_failed");
            if message["method"] == "notifications/message"
                && message["params"]["logger"] == "chio.mcp.roots"
                && message["params"]["data"]["event"] == "roots_refreshed"
            {
                assert_eq!(message["params"]["data"]["rootCount"], 0);
                break;
            }
        }
    }
    drop(reader);
    loop {
        use std::io::BufRead;
        line.clear();
        assert!(ping_reader.read_line(&mut line).unwrap() > 0);
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data.is_empty() {
                continue;
            }
            let message: serde_json::Value = serde_json::from_str(data).unwrap();
            if message["id"] == 2 {
                assert_eq!(message["result"], json!({}));
                break;
            }
        }
    }
    drop(ping_reader);
    let recovery_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let healthy = loop {
        let response = server.post_json(
            Some(&session_id),
            Some("2025-11-25"),
            &json!({"jsonrpc":"2.0","id":99,"method":"ping","params":{}}),
        );
        if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
            break response;
        }
        assert!(std::time::Instant::now() < recovery_deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert_eq!(healthy.status(), reqwest::StatusCode::OK);
    let mut reader = std::io::BufReader::new(healthy);
    loop {
        use std::io::BufRead;
        line.clear();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if let Some(data) = line.strip_prefix("data:") {
            let message: serde_json::Value = serde_json::from_str(data.trim()).unwrap();
            if message["id"] == 99 {
                assert_eq!(message["result"], json!({}));
                break;
            }
        }
    }
    let receipts: serde_json::Value = server.get_admin_tool_receipts(&[]).json().unwrap();
    assert_eq!(receipts["receipts"].as_array().unwrap().len(), 0);
}

#[test]
fn hosted_mcp_sessions_initialize_resume_and_report_ready_state() {
    let server = start_http_server("test-token");
    let session = server.initialize_session();

    let trust = server.get_admin_session_trust(&session.id);
    assert_eq!(trust.status(), reqwest::StatusCode::OK);
    let trust: serde_json::Value = trust.json().expect("session trust json");
    assert_eq!(trust["sessionId"].as_str(), Some(session.id.as_str()));
    assert_eq!(trust["lifecycle"]["state"].as_str(), Some("ready"));
    assert_eq!(
        trust["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(true)
    );
    assert_eq!(
        trust["ownership"]["hostedIsolation"].as_str(),
        Some("dedicated_per_session")
    );
    assert_eq!(
        trust["ownership"]["hostedIdentityProfile"].as_str(),
        Some("strong_dedicated_session")
    );

    let list = server.list_tools(&session);
    let tools = list["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"].as_str(), Some("echo_json"));

    let repeat_trust = server.get_admin_session_trust(&session.id);
    assert_eq!(repeat_trust.status(), reqwest::StatusCode::OK);
    let repeat_trust: serde_json::Value = repeat_trust.json().expect("repeat trust json");
    assert_eq!(repeat_trust["lifecycle"]["state"].as_str(), Some("ready"));
}

#[test]
fn hosted_mcp_sessions_expire_under_ttl_and_cannot_be_reused() {
    let server = start_http_server_with_lifecycle_tuning(
        "test-token",
        LifecycleTuning {
            idle_expiry_millis: Some(250),
            drain_grace_millis: Some(250),
            reaper_interval_millis: Some(50),
            ..LifecycleTuning::default()
        },
    );
    let session = server.initialize_session();

    let expired = server.wait_for_session_state(&session.id, "expired");
    assert_eq!(
        expired["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(false)
    );
    assert!(expired["lifecycle"]["reconnect"]["terminalStates"]
        .as_array()
        .expect("terminal states")
        .iter()
        .any(|value| value.as_str() == Some("expired")));

    let resumed_post = server.post_json(
        Some(&session.id),
        Some(&session.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(resumed_post.status(), reqwest::StatusCode::GONE);

    let resumed_get = server.get_session_stream(&session.id, Some(&session.protocol_version), None);
    assert_eq!(resumed_get.status(), reqwest::StatusCode::GONE);

    let fresh_session = server.initialize_session();
    assert_ne!(fresh_session.id, session.id);
    assert_eq!(fresh_session.protocol_version, session.protocol_version);
}
