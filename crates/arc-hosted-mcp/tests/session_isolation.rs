#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::BTreeMap;

use arc_core::crypto::Keypair;
use serde_json::{json, Value};

use support::{sign_jwt, start_jwt_http_server, unix_now};

fn jwt_for(
    signing_key: &Keypair,
    issuer: &str,
    audience: &str,
    subject: &str,
    client_id: &str,
    tenant_id: &str,
    exp_offset_secs: u64,
) -> String {
    sign_jwt(
        signing_key,
        &json!({
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": client_id,
            "tid": tenant_id,
            "exp": unix_now() + exp_offset_secs,
        }),
    )
}

#[test]
fn hosted_mcp_rejects_cross_tenant_session_reuse() {
    let issuer = "https://issuer.example";
    let audience = "arc-mcp";
    let admin_token = "admin-secret";
    let signing_key = Keypair::generate();
    let server = start_jwt_http_server(
        &signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );

    let token_a = jwt_for(
        &signing_key,
        issuer,
        audience,
        "user-123",
        "client-a",
        "tenant-a",
        300,
    );
    let token_b = jwt_for(
        &signing_key,
        issuer,
        audience,
        "user-456",
        "client-b",
        "tenant-b",
        600,
    );

    let session_a = server.initialize_session_with_token(&token_a);
    let session_b = server.initialize_session_with_token(&token_b);

    let cross_a = server.post_json_with_token(
        &token_b,
        Some(&session_a.id),
        Some(&session_a.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(cross_a.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(cross_a
        .text()
        .expect("cross-session body")
        .contains("authenticated principal does not match session"));

    let cross_b = server.post_json_with_token(
        &token_a,
        Some(&session_b.id),
        Some(&session_b.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(cross_b.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(cross_b
        .text()
        .expect("cross-session body")
        .contains("authenticated principal does not match session"));

    let tools_a = server.list_tools_with_token(&token_a, &session_a);
    assert_eq!(
        tools_a["result"]["tools"][0]["name"].as_str(),
        Some("echo_json")
    );
    let tools_b = server.list_tools_with_token(&token_b, &session_b);
    assert_eq!(
        tools_b["result"]["tools"][0]["name"].as_str(),
        Some("echo_json")
    );
}

#[test]
fn hosted_mcp_isolates_receipt_and_trust_attribution_by_session() {
    let issuer = "https://issuer.example";
    let audience = "arc-mcp";
    let admin_token = "admin-secret";
    let signing_key = Keypair::generate();
    let server = start_jwt_http_server(
        &signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );

    let token_a = jwt_for(
        &signing_key,
        issuer,
        audience,
        "user-123",
        "client-a",
        "tenant-a",
        300,
    );
    let token_b = jwt_for(
        &signing_key,
        issuer,
        audience,
        "user-456",
        "client-b",
        "tenant-b",
        600,
    );

    let session_a = server.initialize_session_with_token(&token_a);
    let session_b = server.initialize_session_with_token(&token_b);

    let trust_a: Value = server
        .get_admin_session_trust(&session_a.id)
        .json()
        .expect("session A trust json");
    let trust_b: Value = server
        .get_admin_session_trust(&session_b.id)
        .json()
        .expect("session B trust json");

    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-a")
    );
    assert_eq!(
        trust_b["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-b")
    );

    let subject_a = trust_a["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session A subject key")
        .to_string();
    let subject_b = trust_b["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session B subject key")
        .to_string();
    assert_ne!(subject_a, subject_b);

    let echo_a = server.call_echo_json_with_token(&token_a, &session_a, 41, "tenant-a");
    assert_eq!(echo_a["result"]["structuredContent"]["echo"], "tenant-a");
    let echo_b = server.call_echo_json_with_token(&token_b, &session_b, 42, "tenant-b");
    assert_eq!(echo_b["result"]["structuredContent"]["echo"], "tenant-b");

    let receipts = server.get_admin_tool_receipts(&[("toolName", "echo_json"), ("limit", "10")]);
    assert_eq!(receipts.status(), reqwest::StatusCode::OK);
    let receipts: Value = receipts.json().expect("tool receipts json");
    let receipts = receipts["receipts"]
        .as_array()
        .expect("tool receipts array");
    assert_eq!(receipts.len(), 2);

    let mut subject_counts = BTreeMap::new();
    for receipt in receipts {
        assert_eq!(receipt["tool_name"].as_str(), Some("echo_json"));
        assert_eq!(receipt["decision"]["verdict"].as_str(), Some("allow"));
        let subject_key = receipt["metadata"]["attribution"]["subject_key"]
            .as_str()
            .expect("receipt subject key");
        *subject_counts
            .entry(subject_key.to_string())
            .or_insert(0usize) += 1;
    }

    assert_eq!(subject_counts.get(&subject_a), Some(&1));
    assert_eq!(subject_counts.get(&subject_b), Some(&1));
}
