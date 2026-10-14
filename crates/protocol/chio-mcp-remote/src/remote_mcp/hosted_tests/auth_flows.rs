#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core::crypto::Keypair;
use reqwest::header::LOCATION;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use support::{
    sign_jwt, start_http_server, start_jwt_http_server, start_local_oauth_http_server, unix_now,
    TestServer,
};

fn initialize_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "integration-test",
                "version": "0.1.0"
            }
        }
    })
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn consent_page(
    server: &TestServer,
    redirect_uri: &str,
    resource: &str,
    challenge: &str,
) -> String {
    let page = server
        .client
        .get(format!("{}/oauth/authorize", server.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", "https://client.example/app"),
            ("redirect_uri", redirect_uri),
            ("state", "state-123"),
            ("resource", resource),
            ("scope", "mcp:invoke"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .expect("send authorize request")
        .error_for_status()
        .expect("authorize page ok")
        .text()
        .expect("authorize page text");
    assert!(page.contains("Approve"));
    page
}

/// The hidden fields a browser submits from the rendered consent form.
fn hidden_inputs(page: &str) -> Vec<(String, String)> {
    let unescape = |value: &str| {
        value
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    };
    page.split("<input type=\"hidden\" ")
        .skip(1)
        .map(|input| {
            let name = input
                .strip_prefix("name=\"")
                .and_then(|rest| rest.split_once('"'))
                .expect("hidden input name")
                .0;
            let value = input
                .split_once("value=\"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .expect("hidden input value")
                .0;
            (name.to_string(), unescape(value))
        })
        .collect()
}

fn submit_consent(
    server: &TestServer,
    fields: &[(String, String)],
    decision: &str,
) -> reqwest::blocking::Response {
    let mut form = fields.to_vec();
    form.push(("decision".to_string(), decision.to_string()));
    server
        .client
        .post(format!("{}/oauth/authorize", server.base_url))
        .form(&form)
        .send()
        .expect("submit consent")
}

fn redirect_query(response: &reqwest::blocking::Response) -> Vec<(String, String)> {
    let location = response
        .headers()
        .get(LOCATION)
        .expect("consent redirect")
        .to_str()
        .expect("location string");
    Url::parse(location)
        .expect("parse redirect URL")
        .query_pairs()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn authorize_code(
    server: &TestServer,
    redirect_uri: &str,
    resource: &str,
    code_verifier: &str,
) -> String {
    let page = consent_page(
        server,
        redirect_uri,
        resource,
        &pkce_challenge(code_verifier),
    );
    let approval = submit_consent(server, &hidden_inputs(&page), "approve");
    assert!(approval.status().is_redirection());
    redirect_query(&approval)
        .into_iter()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value)
        .expect("authorization code")
}

fn exchange_code(
    server: &TestServer,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    resource: &str,
) -> reqwest::blocking::Response {
    server
        .client
        .post(format!("{}/oauth/token", server.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", "https://client.example/app"),
            ("code_verifier", code_verifier),
            ("resource", resource),
        ])
        .send()
        .expect("exchange authorization code")
}

fn decode_jwt_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload segment");
    let decoded = URL_SAFE_NO_PAD.decode(payload).expect("decode JWT payload");
    serde_json::from_slice(&decoded).expect("parse JWT payload")
}

#[test]
fn hosted_mcp_accepts_static_bearer_and_rejects_invalid_token() {
    let server = start_http_server("test-token");

    let session = server.initialize_session();
    assert!(!session.id.is_empty());

    assert_ne!(server.token, server.admin_token);
    assert_eq!(
        server.get_admin_session_trust(&session.id).status(),
        reqwest::StatusCode::OK,
    );
    assert_eq!(
        server
            .get_admin_session_trust_with_token(&server.token, &session.id)
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
    );
    let admin_as_session = server.post_raw(
        Some(&server.admin_token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &initialize_request(8),
    );
    assert_eq!(admin_as_session.status(), reqwest::StatusCode::UNAUTHORIZED);

    let invalid = server.post_raw(
        Some("wrong-token"),
        None,
        "application/json, text/event-stream",
        "application/json",
        &initialize_request(9),
    );
    assert_eq!(invalid.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        invalid
            .headers()
            .get("WWW-Authenticate")
            .expect("www-authenticate header")
            .to_str()
            .expect("challenge string"),
        "Bearer"
    );
}

#[test]
fn hosted_mcp_accepts_jwt_and_rejects_wrong_audience() {
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let signing_key = Keypair::generate();
    let server = start_jwt_http_server(
        &signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );

    let valid_token = sign_jwt(
        &signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": unix_now() + 300,
        }),
    );
    let session = server.initialize_session_with_token(&valid_token);
    let trust: Value = server
        .get_admin_session_trust(&session.id)
        .json()
        .expect("session trust json");
    assert_eq!(
        trust["authContext"]["method"]["principal"].as_str(),
        Some("oidc:https://issuer.example#sub:user-123")
    );

    let wrong_audience_token = sign_jwt(
        &signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": "wrong-audience",
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": unix_now() + 300,
        }),
    );
    let response = server.post_raw(
        Some(&wrong_audience_token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &initialize_request(10),
    );
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(response
        .headers()
        .get("WWW-Authenticate")
        .expect("www-authenticate header")
        .to_str()
        .expect("challenge string")
        .contains("Bearer"));
}

#[test]
fn hosted_mcp_accepts_local_oauth_pkce_and_rejects_invalid_verifier() {
    let server = start_local_oauth_http_server("admin-token");
    let metadata: Value = server
        .get_protected_resource_metadata()
        .json()
        .expect("protected resource metadata");
    let resource = metadata["resource"].as_str().expect("resource").to_string();
    let redirect_uri = "http://localhost:7777/callback";

    let invalid_code = authorize_code(&server, redirect_uri, &resource, "chio-auth-verifier");
    let invalid_exchange = exchange_code(
        &server,
        &invalid_code,
        redirect_uri,
        "wrong-verifier",
        &resource,
    );
    assert_eq!(invalid_exchange.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_exchange: Value = invalid_exchange.json().expect("invalid exchange json");
    assert_eq!(invalid_exchange["error"].as_str(), Some("invalid_grant"));
    assert_eq!(
        invalid_exchange["error_description"].as_str(),
        Some("urn:chio:error:policy:decision-denied")
    );

    let code = authorize_code(&server, redirect_uri, &resource, "chio-auth-verifier");
    let token_response = exchange_code(
        &server,
        &code,
        redirect_uri,
        "chio-auth-verifier",
        &resource,
    );
    assert_eq!(token_response.status(), reqwest::StatusCode::OK);
    let token_response: Value = token_response.json().expect("token response json");
    let access_token = token_response["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let access_payload = decode_jwt_payload(&access_token);
    assert_eq!(access_payload["aud"].as_str(), Some(resource.as_str()));
    assert_eq!(access_payload["resource"].as_str(), Some(resource.as_str()));

    let session = server.initialize_session_with_token(&access_token);
    assert!(!session.id.is_empty());
}

#[test]
fn local_authorization_server_rejects_approval_without_consent_nonce() {
    let server = start_local_oauth_http_server("admin-token");
    let metadata: Value = server
        .get_protected_resource_metadata()
        .json()
        .expect("protected resource metadata");
    let resource = metadata["resource"].as_str().expect("resource").to_string();
    let redirect_uri = "http://localhost:7777/callback";
    let challenge = pkce_challenge("chio-auth-verifier");
    let forged = [
        ("response_type", "code"),
        ("client_id", "https://client.example/app"),
        ("redirect_uri", redirect_uri),
        ("state", "state-123"),
        ("resource", resource.as_str()),
        ("scope", "mcp:invoke"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]
    .map(|(name, value)| (name.to_string(), value.to_string()));
    let mut unknown_nonce = forged.to_vec();
    unknown_nonce.push(("consent_nonce".to_string(), "consent-forged".to_string()));

    let page = consent_page(&server, redirect_uri, &resource, &challenge);
    let rendered = hidden_inputs(&page);
    let approved = submit_consent(&server, &rendered, "approve");
    assert!(approved.status().is_redirection());

    for fields in [forged.to_vec(), unknown_nonce, rendered] {
        let refused = submit_consent(&server, &fields, "approve");
        assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
        assert!(refused.headers().get(LOCATION).is_none());
        let body: Value = refused.json().expect("refusal json");
        assert_eq!(
            body,
            json!({
                "error": "invalid_request",
                "error_description": "urn:chio:error:transport:invalid-request-shape",
            })
        );
    }
}
