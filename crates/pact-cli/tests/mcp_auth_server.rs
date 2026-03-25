#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, LOCATION};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pact-cli-auth-server-{nonce}"))
}

fn reserve_listen_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_mock_server_script(dir: &Path) -> PathBuf {
    let script = r##"
import json
import sys

def respond(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

TOOLS = [{
    "name": "echo_json",
    "description": "Echo JSON",
    "inputSchema": {"type": "object"},
    "annotations": {"readOnlyHint": True}
}]

for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-http-upstream", "version": "0.1.0"}
            }
        })
        continue
    if method == "notifications/initialized":
        continue
    if method == "tools/list":
        respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
        continue
    respond({
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {"code": -32601, "message": f"unknown method: {method}"}
    })
"##;

    let path = dir.join("mock_http_auth_server.py");
    fs::write(&path, script).expect("write mock server script");
    path
}

fn write_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
capabilities:
  default:
    tools:
      - server: wrapped-http-mock
        tool: echo_json
        operations: [invoke]
        ttl: 300
"#;

    let path = dir.join("http-policy.yaml");
    fs::write(&path, policy).expect("write policy");
    path
}

fn spawn_http_server_with_local_auth(
    dir: &Path,
    listen: SocketAddr,
    admin_token: &str,
) -> ServerGuard {
    let policy_path = write_policy(dir);
    let script_path = write_mock_server_script(dir);
    let receipt_db_path = dir.join("remote-receipts.sqlite3");
    let revocation_db_path = dir.join("remote-revocations.sqlite3");
    let authority_seed_path = dir.join("remote-authority.seed");
    let auth_server_seed_path = dir.join("auth-server.seed");
    let public_base_url = format!("http://{listen}");
    let audience = format!("{public_base_url}/mcp");

    let child = Command::new(env!("CARGO_BIN_EXE_pact"))
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-seed-file",
            authority_seed_path.to_str().expect("authority seed path"),
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
            "--public-base-url",
            &public_base_url,
            "--auth-server-seed-file",
            auth_server_seed_path
                .to_str()
                .expect("auth server seed path"),
            "--auth-jwt-audience",
            &audience,
            "--auth-scope",
            "mcp:invoke",
            "--admin-token",
            admin_token,
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pact mcp serve-http");

    ServerGuard { child }
}

fn wait_for_http_server(client: &Client, base_url: &str) {
    for _ in 0..100 {
        match client
            .get(format!(
                "{base_url}/.well-known/oauth-protected-resource/mcp"
            ))
            .send()
        {
            Ok(response) if response.status().is_success() => return,
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    panic!("remote MCP auth server did not become ready");
}

fn post_mcp_json(client: &Client, base_url: &str, token: &str, body: &Value) -> Response {
    client
        .post(format!("{base_url}/mcp"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(body).expect("serialize request body"))
        .send()
        .expect("send HTTP MCP request")
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[test]
fn mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create test dir");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let admin_token = "admin-token";
    let _server = spawn_http_server_with_local_auth(&dir, listen, admin_token);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");
    wait_for_http_server(&client, &base_url);

    let protected_resource: Value = client
        .get(format!(
            "{base_url}/.well-known/oauth-protected-resource/mcp"
        ))
        .send()
        .expect("send protected resource request")
        .error_for_status()
        .expect("protected resource ok")
        .json()
        .expect("decode protected resource");
    let issuer = protected_resource["authorization_servers"][0]
        .as_str()
        .expect("issuer")
        .to_string();
    let auth_metadata_path = format!(
        "{base_url}/.well-known/oauth-authorization-server/{}",
        Url::parse(&issuer)
            .expect("parse issuer")
            .path()
            .trim_matches('/')
    );
    let auth_metadata: Value = client
        .get(&auth_metadata_path)
        .send()
        .expect("send auth metadata request")
        .error_for_status()
        .expect("auth metadata ok")
        .json()
        .expect("decode auth metadata");
    assert_eq!(
        auth_metadata["grant_types_supported"],
        json!([
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ])
    );

    let code_verifier = "pact-auth-verifier";
    let redirect_uri = "http://localhost:7777/callback";
    let resource = format!("{base_url}/mcp");
    let state = "state-123";

    let authorize_response = client
        .get(format!(
            "{base_url}/oauth/authorize?response_type=code&client_id=https%3A%2F%2Fclient.example%2Fapp&redirect_uri={redirect_uri}&state={state}&resource={resource}&scope=mcp%3Ainvoke&code_challenge={challenge}&code_challenge_method=S256",
            challenge = pkce_challenge(code_verifier),
        ))
        .send()
        .expect("send authorize request")
        .error_for_status()
        .expect("authorize page ok")
        .text()
        .expect("read authorize page");
    assert!(authorize_response.contains("Approve"));

    let approval_response = client
        .post(format!("{base_url}/oauth/authorize"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "response_type=code&client_id=https%3A%2F%2Fclient.example%2Fapp&redirect_uri={redirect_uri}&state={state}&resource={resource}&scope=mcp%3Ainvoke&code_challenge={challenge}&code_challenge_method=S256&decision=approve",
            challenge = pkce_challenge(code_verifier),
        ))
        .send()
        .expect("submit approval");
    assert!(approval_response.status().is_redirection());
    let location = approval_response
        .headers()
        .get(LOCATION)
        .expect("approval location")
        .to_str()
        .expect("location str");
    let redirect = Url::parse(location).expect("parse approval redirect");
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("authorization code");

    let token_response: Value = client
        .post(format!("{base_url}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={code}&redirect_uri={redirect_uri}&client_id=https%3A%2F%2Fclient.example%2Fapp&code_verifier={code_verifier}&resource={resource}",
        ))
        .send()
        .expect("exchange authorization code")
        .error_for_status()
        .expect("token exchange ok")
        .json()
        .expect("decode token response");
    let access_token = token_response["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    assert_eq!(token_response["scope"].as_str(), Some("mcp:invoke"));

    let initialize_response = post_mcp_json(
        &client,
        &base_url,
        &access_token,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "auth-test", "version": "0.1.0"}
            }
        }),
    );
    let initialize_status = initialize_response.status();
    let initialize_headers = initialize_response.headers().clone();
    let initialize_body = initialize_response.text().expect("initialize body");
    assert!(
        initialize_status.is_success(),
        "initialize failed: status={initialize_status} body={initialize_body}"
    );
    assert!(initialize_headers.get("MCP-Session-Id").is_some());

    let exchanged_response: Value = client
        .post(format!("{base_url}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={access_token}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&resource={resource}&scope=mcp%3Ainvoke",
        ))
        .send()
        .expect("exchange subject token")
        .error_for_status()
        .expect("token exchange ok")
        .json()
        .expect("decode exchanged token response");
    let exchanged_token = exchanged_response["access_token"]
        .as_str()
        .expect("exchanged access token");
    assert_ne!(exchanged_token, access_token);

    let exchanged_initialize = post_mcp_json(
        &client,
        &base_url,
        exchanged_token,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "auth-test-2", "version": "0.1.0"}
            }
        }),
    );
    let exchanged_status = exchanged_initialize.status();
    let exchanged_body = exchanged_initialize
        .text()
        .expect("exchanged initialize body");
    assert!(
        exchanged_status.is_success(),
        "exchanged initialize failed: status={exchanged_status} body={exchanged_body}"
    );
}
