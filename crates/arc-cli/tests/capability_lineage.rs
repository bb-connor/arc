//! Integration test: capability lineage is recorded at issuance.
//!
//! Verifies that GET /v1/lineage/{capability_id} returns a snapshot
//! immediately after POST /v1/capabilities/issue creates the token.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn reserve_listen_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
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

fn spawn_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    receipt_db_path: &PathBuf,
    revocation_db_path: &PathBuf,
    authority_db_path: &PathBuf,
    budget_db_path: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn wait_for_trust_service(client: &Client, base_url: &str) {
    for _ in 0..50 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
}

#[test]
fn issue_capability_records_lineage_snapshot() {
    let dir = unique_dir("arc-cli-lineage-test");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "lineage-test-token";
    let base_url = format!("http://{listen}");

    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    // Generate a fresh Ed25519 keypair for the subject (agent).
    // We encode the public key as hex for the request body.
    let subject_kp = arc_core::crypto::Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();

    // Issue a capability via the trust-control HTTP endpoint.
    let issue_body = serde_json::json!({
        "subjectPublicKey": subject_hex,
        "scope": {
            "grants": [{
                "server_id": "test-server",
                "tool_name": "test_tool",
                "operations": ["invoke"],
                "constraints": []
            }],
            "resourceGrants": [],
            "promptGrants": []
        },
        "ttlSeconds": 3600
    });

    let issue_resp = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&issue_body)
        .send()
        .expect("send issue capability request");

    assert_eq!(
        issue_resp.status(),
        reqwest::StatusCode::OK,
        "issue capability should succeed; body: {}",
        issue_resp.text().unwrap_or_default()
    );

    let issue_json: serde_json::Value = issue_resp.json().expect("parse issue capability response");
    let capability_id = issue_json["capability"]["id"]
        .as_str()
        .expect("capability.id should be a string")
        .to_string();
    assert!(
        !capability_id.is_empty(),
        "capability id should not be empty"
    );

    // Query the lineage endpoint to verify the snapshot was recorded.
    let lineage_resp = client
        .get(format!("{base_url}/v1/lineage/{capability_id}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .send()
        .expect("send lineage query request");

    assert_eq!(
        lineage_resp.status(),
        reqwest::StatusCode::OK,
        "lineage query should return 200; body: {}",
        lineage_resp.text().unwrap_or_default()
    );

    let lineage_json: serde_json::Value = lineage_resp.json().expect("parse lineage response");

    // Verify the snapshot fields match the issued capability.
    assert_eq!(
        lineage_json["capability_id"].as_str().unwrap_or(""),
        capability_id,
        "lineage capability_id should match issued id"
    );
    assert_eq!(
        lineage_json["subject_key"].as_str().unwrap_or(""),
        subject_hex,
        "lineage subject_key should match the agent's public key"
    );
    assert_eq!(
        lineage_json["delegation_depth"].as_u64().unwrap_or(999),
        0,
        "root capability should have delegation_depth = 0"
    );
    assert!(
        lineage_json["parent_capability_id"].is_null(),
        "root capability should have no parent"
    );

    let _ = std::fs::remove_dir_all(dir);
}
