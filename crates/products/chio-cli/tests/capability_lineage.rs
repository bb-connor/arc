//! Integration tests for capability-authority HTTP role separation.
//!
//! Signed issuance and its durable lineage snapshot are covered by the
//! control-plane handler tests, where the test-only signing backend can be
//! injected without weakening the production keyring requirement.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn unique_dir(prefix: &str) -> PathBuf {
    chio_test_support::private_fs::private_tempdir(prefix)
        .expect("create private test directory")
        .keep()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
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
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
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
            "--authority-admin-token",
            "capability-lineage-authority-admin-token",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn wait_for_trust_service(client: &Client, base_url: &str, service: &mut ServerGuard) {
    for _ in 0..150 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
        if let Some(status) = service.child.try_wait().expect("poll trust service") {
            let mut stderr = String::new();
            if let Some(child_stderr) = service.child.stderr.as_mut() {
                let _ = child_stderr.read_to_string(&mut stderr);
            }
            panic!("trust service exited before becoming ready (status {status}): {stderr}");
        }
    }
    panic!("trust service did not become ready");
}

#[test]
fn authority_endpoints_require_auth_and_rotate_generation() {
    if skip_when_loopback_bind_denied("authority_endpoints_require_auth_and_rotate_generation") {
        return;
    }

    let dir = unique_dir("chio-cli-authority-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "authority-http-token";
    let base_url = format!("http://{listen}");

    let mut service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url, &mut service);

    let unauthorized = client
        .get(format!("{base_url}/v1/authority"))
        .send()
        .expect("send unauthorized authority request");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

    let before = client
        .get(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("send authority status request");
    assert_eq!(before.status(), reqwest::StatusCode::OK);
    let before: serde_json::Value = before.json().expect("parse authority status");
    let before_generation = before["generation"].as_u64().expect("authority generation");

    let unauthorized_rotate = client
        .post(format!("{base_url}/v1/authority"))
        .send()
        .expect("send unauthorized rotate request");
    assert_eq!(
        unauthorized_rotate.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    let rotated = client
        .post(format!("{base_url}/v1/authority"))
        .header(
            AUTHORIZATION,
            bearer("capability-lineage-authority-admin-token"),
        )
        .send()
        .expect("send rotate request");
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    let rotated: serde_json::Value = rotated.json().expect("parse rotated authority");
    let rotated_generation = rotated["generation"]
        .as_u64()
        .expect("rotated authority generation");
    assert!(
        rotated_generation > before_generation,
        "rotation should advance authority generation"
    );

    let after = client
        .get(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("send authority status request after rotation");
    assert_eq!(after.status(), reqwest::StatusCode::OK);
    let after: serde_json::Value = after.json().expect("parse post-rotation authority status");
    assert_eq!(after["generation"].as_u64(), Some(rotated_generation));

    let _ = std::fs::remove_dir_all(dir);
}
