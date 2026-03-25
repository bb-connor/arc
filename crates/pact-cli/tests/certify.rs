#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::{canonical_json_bytes, PublicKey, Signature};
use reqwest::blocking::Client;

fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
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
    certification_registry_file: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--certification-registry-file",
            certification_registry_file
                .to_str()
                .expect("certification registry path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn wait_for_trust_service(client: &Client, base_url: &str) {
    for _ in 0..100 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
}

fn write_scenario(dir: &PathBuf, id: &str) {
    fs::create_dir_all(dir).expect("create scenarios dir");
    fs::write(
        dir.join(format!("{id}.json")),
        format!(
            r#"{{
  "id": "{id}",
  "title": "Scenario {id}",
  "area": "core",
  "category": "mcp-core",
  "specVersions": ["2025-11-25"],
  "transport": ["stdio"],
  "peerRoles": ["client_to_pact_server"],
  "deploymentModes": ["wrapped_stdio"],
  "requiredCapabilities": {{"server": [], "client": []}},
  "tags": ["wave1"],
  "expected": "pass"
}}"#
        ),
    )
    .expect("write scenario");
}

fn write_results(dir: &PathBuf, scenario_id: &str, status: &str) {
    fs::create_dir_all(dir).expect("create results dir");
    fs::write(
        dir.join("results.json"),
        format!(
            r#"[{{
  "scenarioId": "{scenario_id}",
  "peer": "js",
  "peerRole": "client_to_pact_server",
  "deploymentMode": "wrapped_stdio",
  "transport": "stdio",
  "specVersion": "2025-11-25",
  "category": "mcp-core",
  "status": "{status}",
  "durationMs": 12,
  "assertions": [{{"name": "ok", "status": "pass"}}]
}}]"#
        ),
    )
    .expect("write results");
}

fn run_certify_check(
    scenarios_dir: &PathBuf,
    results_dir: &PathBuf,
    output_path: &PathBuf,
    seed_path: &PathBuf,
    tool_server_id: &str,
    tool_server_name: Option<&str>,
) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pact"));
    command.current_dir(workspace_root()).args([
        "certify",
        "check",
        "--scenarios-dir",
        scenarios_dir.to_str().expect("scenarios dir"),
        "--results-dir",
        results_dir.to_str().expect("results dir"),
        "--output",
        output_path.to_str().expect("output path"),
        "--tool-server-id",
        tool_server_id,
        "--signing-seed-file",
        seed_path.to_str().expect("seed path"),
    ]);
    if let Some(tool_server_name) = tool_server_name {
        command.args(["--tool-server-name", tool_server_name]);
    }
    let output = command.output().expect("run pact certify check");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn certify_check_emits_signed_pass_artifact_and_report() {
    let scenarios_dir = unique_path("pact-certify-scenarios", "");
    let results_dir = unique_path("pact-certify-results", "");
    let output_path = unique_path("pact-certify-artifact", ".json");
    let report_path = unique_path("pact-certify-report", ".md");
    let seed_path = unique_path("pact-certify-seed", ".txt");

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");

    let output = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "certify",
            "check",
            "--scenarios-dir",
            scenarios_dir.to_str().expect("scenarios dir"),
            "--results-dir",
            results_dir.to_str().expect("results dir"),
            "--output",
            output_path.to_str().expect("output path"),
            "--tool-server-id",
            "demo-server",
            "--tool-server-name",
            "Demo Server",
            "--report-output",
            report_path.to_str().expect("report path"),
            "--signing-seed-file",
            seed_path.to_str().expect("seed path"),
        ])
        .output()
        .expect("run pact certify check");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_path.exists(), "artifact should exist");
    assert!(report_path.exists(), "report should exist");
    assert!(seed_path.exists(), "seed file should exist");

    let artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(&output_path).expect("read artifact"))
            .expect("parse artifact");
    assert_eq!(artifact["body"]["verdict"], "pass");
    assert_eq!(
        artifact["body"]["criteriaProfile"],
        "conformance-all-pass-v1"
    );
    assert_eq!(artifact["body"]["summary"]["passCount"], 1);

    let public_key: PublicKey =
        serde_json::from_value(artifact["signerPublicKey"].clone()).expect("public key");
    let signature: Signature =
        serde_json::from_value(artifact["signature"].clone()).expect("signature");
    let body = artifact["body"].clone();
    let body_bytes = canonical_json_bytes(&body).expect("canonical body");
    assert!(public_key.verify(&body_bytes, &signature));

    let _ = fs::remove_dir_all(scenarios_dir);
    let _ = fs::remove_dir_all(results_dir);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(report_path);
    let _ = fs::remove_file(seed_path);
}

#[test]
fn certify_check_emits_signed_fail_artifact_with_findings() {
    let scenarios_dir = unique_path("pact-certify-scenarios-fail", "");
    let results_dir = unique_path("pact-certify-results-fail", "");
    let output_path = unique_path("pact-certify-artifact-fail", ".json");
    let seed_path = unique_path("pact-certify-seed-fail", ".txt");

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "unsupported");

    let output = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "certify",
            "check",
            "--scenarios-dir",
            scenarios_dir.to_str().expect("scenarios dir"),
            "--results-dir",
            results_dir.to_str().expect("results dir"),
            "--output",
            output_path.to_str().expect("output path"),
            "--tool-server-id",
            "demo-server",
            "--signing-seed-file",
            seed_path.to_str().expect("seed path"),
        ])
        .output()
        .expect("run pact certify check");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(&output_path).expect("read artifact"))
            .expect("parse artifact");
    assert_eq!(artifact["body"]["verdict"], "fail");
    assert_eq!(artifact["body"]["summary"]["unsupportedCount"], 1);
    assert!(artifact["body"]["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .any(|finding| finding["kind"] == "non-pass-result"));

    let public_key: PublicKey =
        serde_json::from_value(artifact["signerPublicKey"].clone()).expect("public key");
    let signature: Signature =
        serde_json::from_value(artifact["signature"].clone()).expect("signature");
    let body = artifact["body"].clone();
    let body_bytes = canonical_json_bytes(&body).expect("canonical body");
    assert!(public_key.verify(&body_bytes, &signature));

    let _ = fs::remove_dir_all(scenarios_dir);
    let _ = fs::remove_dir_all(results_dir);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(seed_path);
}

#[test]
fn certify_verify_accepts_signed_artifact() {
    let scenarios_dir = unique_path("pact-certify-verify-scenarios", "");
    let results_dir = unique_path("pact-certify-verify-results", "");
    let output_path = unique_path("pact-certify-verify-artifact", ".json");
    let seed_path = unique_path("pact-certify-verify-seed", ".txt");

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        "demo-server",
        Some("Demo Server"),
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "verify",
            "--input",
            output_path.to_str().expect("artifact path"),
        ])
        .output()
        .expect("run pact certify verify");
    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_body: serde_json::Value =
        serde_json::from_slice(&verify.stdout).expect("parse verify output");
    assert_eq!(verify_body["toolServerId"], "demo-server");
    assert_eq!(verify_body["verdict"], "pass");
    assert_eq!(verify_body["verified"], true);

    let _ = fs::remove_dir_all(scenarios_dir);
    let _ = fs::remove_dir_all(results_dir);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(seed_path);
}

#[test]
fn certify_registry_local_publish_resolve_and_revoke_work() {
    let scenarios_dir = unique_path("pact-certify-registry-local-scenarios", "");
    let results_dir = unique_path("pact-certify-registry-local-results", "");
    let output_path = unique_path("pact-certify-registry-local-artifact", ".json");
    let replacement_output_path =
        unique_path("pact-certify-registry-local-artifact-replacement", ".json");
    let seed_path = unique_path("pact-certify-registry-local-seed", ".txt");
    let registry_path = unique_path("pact-certify-registry-local", ".json");

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        "demo-server",
        Some("Demo Server"),
    );
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &replacement_output_path,
        &seed_path,
        "demo-server",
        Some("Demo Server Replacement"),
    );

    let publish = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "publish",
            "--input",
            output_path.to_str().expect("artifact path"),
            "--certification-registry-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local certification publish");
    assert!(
        publish.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish.stdout),
        String::from_utf8_lossy(&publish.stderr)
    );
    let publish_body: serde_json::Value =
        serde_json::from_slice(&publish.stdout).expect("parse publish output");
    let first_artifact_id = publish_body["artifactId"]
        .as_str()
        .expect("first artifact id")
        .to_string();
    assert_eq!(publish_body["toolServerId"], "demo-server");
    assert_eq!(publish_body["status"], "active");

    let publish_replacement = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "publish",
            "--input",
            replacement_output_path
                .to_str()
                .expect("replacement artifact path"),
            "--certification-registry-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run replacement certification publish");
    assert!(
        publish_replacement.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish_replacement.stdout),
        String::from_utf8_lossy(&publish_replacement.stderr)
    );
    let publish_replacement_body: serde_json::Value =
        serde_json::from_slice(&publish_replacement.stdout)
            .expect("parse replacement publish output");
    let replacement_artifact_id = publish_replacement_body["artifactId"]
        .as_str()
        .expect("replacement artifact id")
        .to_string();
    assert_ne!(replacement_artifact_id, first_artifact_id);
    assert_eq!(publish_replacement_body["status"], "active");

    let list = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "list",
            "--certification-registry-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local certification list");
    assert!(
        list.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_body: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("parse list output");
    assert_eq!(list_body["count"], 2);
    assert!(list_body["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .any(|entry| entry["artifactId"] == first_artifact_id && entry["status"] == "superseded"));
    assert!(
        list_body["artifacts"]
            .as_array()
            .expect("artifacts array")
            .iter()
            .any(|entry| entry["artifactId"] == replacement_artifact_id
                && entry["status"] == "active")
    );

    let get = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "get",
            "--artifact-id",
            &replacement_artifact_id,
            "--certification-registry-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local certification get");
    assert!(
        get.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&get.stdout),
        String::from_utf8_lossy(&get.stderr)
    );
    let get_body: serde_json::Value =
        serde_json::from_slice(&get.stdout).expect("parse get output");
    assert_eq!(get_body["artifactId"], replacement_artifact_id);
    assert_eq!(get_body["status"], "active");

    let resolve = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "resolve",
            "--tool-server-id",
            "demo-server",
            "--certification-registry-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local certification resolve");
    assert!(
        resolve.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&resolve.stdout),
        String::from_utf8_lossy(&resolve.stderr)
    );
    let resolve_body: serde_json::Value =
        serde_json::from_slice(&resolve.stdout).expect("parse resolve output");
    assert_eq!(resolve_body["state"], "active");
    assert_eq!(
        resolve_body["current"]["artifactId"],
        replacement_artifact_id
    );

    let revoke = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "revoke",
            "--artifact-id",
            &replacement_artifact_id,
            "--reason",
            "operator-revoked",
            "--certification-registry-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local certification revoke");
    assert!(
        revoke.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );
    let revoke_body: serde_json::Value =
        serde_json::from_slice(&revoke.stdout).expect("parse revoke output");
    assert_eq!(revoke_body["artifactId"], replacement_artifact_id);
    assert_eq!(revoke_body["status"], "revoked");
    assert_eq!(revoke_body["revokedReason"], "operator-revoked");

    let resolve_after_revoke = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "resolve",
            "--tool-server-id",
            "demo-server",
            "--certification-registry-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local certification resolve after revoke");
    assert!(
        resolve_after_revoke.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&resolve_after_revoke.stdout),
        String::from_utf8_lossy(&resolve_after_revoke.stderr)
    );
    let resolve_after_revoke_body: serde_json::Value =
        serde_json::from_slice(&resolve_after_revoke.stdout)
            .expect("parse resolve after revoke output");
    assert_eq!(resolve_after_revoke_body["state"], "revoked");
    assert_eq!(
        resolve_after_revoke_body["current"]["artifactId"],
        replacement_artifact_id
    );

    let _ = fs::remove_dir_all(scenarios_dir);
    let _ = fs::remove_dir_all(results_dir);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(replacement_output_path);
    let _ = fs::remove_file(seed_path);
    let _ = fs::remove_file(registry_path);
}

#[test]
fn certify_registry_remote_publish_list_get_resolve_and_revoke_work() {
    let scenarios_dir = unique_path("pact-certify-registry-remote-scenarios", "");
    let results_dir = unique_path("pact-certify-registry-remote-results", "");
    let output_path = unique_path("pact-certify-registry-remote-artifact", ".json");
    let seed_path = unique_path("pact-certify-registry-remote-seed", ".txt");
    let registry_path = unique_path("pact-certify-registry-remote", ".json");

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        "demo-server-remote",
        Some("Demo Server Remote"),
    );

    let listen = reserve_listen_addr();
    let service_token = "certify-registry-remote-token";
    let _service = spawn_trust_service(listen, service_token, &registry_path);
    let client = Client::builder().build().expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let publish = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "certify",
            "registry",
            "publish",
            "--input",
            output_path.to_str().expect("artifact path"),
        ])
        .output()
        .expect("run remote certification publish");
    assert!(
        publish.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish.stdout),
        String::from_utf8_lossy(&publish.stderr)
    );
    let publish_body: serde_json::Value =
        serde_json::from_slice(&publish.stdout).expect("parse publish output");
    let artifact_id = publish_body["artifactId"]
        .as_str()
        .expect("artifact id")
        .to_string();
    assert_eq!(publish_body["toolServerId"], "demo-server-remote");
    assert_eq!(publish_body["status"], "active");

    let health_after_publish = client
        .get(format!("{base_url}/health"))
        .send()
        .expect("send health request after publish");
    assert_eq!(health_after_publish.status(), reqwest::StatusCode::OK);
    let health_after_publish: serde_json::Value = health_after_publish
        .json()
        .expect("health json after publish");
    assert_eq!(
        health_after_publish["federation"]["certifications"]["configured"],
        true
    );
    assert_eq!(
        health_after_publish["federation"]["certifications"]["count"],
        1
    );
    assert_eq!(
        health_after_publish["federation"]["certifications"]["activeCount"],
        1
    );

    let list = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "certify",
            "registry",
            "list",
        ])
        .output()
        .expect("run remote certification list");
    assert!(
        list.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_body: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("parse list output");
    assert_eq!(list_body["count"], 1);
    assert_eq!(list_body["artifacts"][0]["artifactId"], artifact_id);

    let get = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "certify",
            "registry",
            "get",
            "--artifact-id",
            &artifact_id,
        ])
        .output()
        .expect("run remote certification get");
    assert!(
        get.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&get.stdout),
        String::from_utf8_lossy(&get.stderr)
    );
    let get_body: serde_json::Value =
        serde_json::from_slice(&get.stdout).expect("parse get output");
    assert_eq!(get_body["artifactId"], artifact_id);

    let resolve = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "certify",
            "registry",
            "resolve",
            "--tool-server-id",
            "demo-server-remote",
        ])
        .output()
        .expect("run remote certification resolve");
    assert!(
        resolve.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&resolve.stdout),
        String::from_utf8_lossy(&resolve.stderr)
    );
    let resolve_body: serde_json::Value =
        serde_json::from_slice(&resolve.stdout).expect("parse resolve output");
    assert_eq!(resolve_body["state"], "active");
    assert_eq!(resolve_body["current"]["artifactId"], artifact_id);

    let revoke = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "certify",
            "registry",
            "revoke",
            "--artifact-id",
            &artifact_id,
            "--reason",
            "remote-revocation",
        ])
        .output()
        .expect("run remote certification revoke");
    assert!(
        revoke.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );
    let revoke_body: serde_json::Value =
        serde_json::from_slice(&revoke.stdout).expect("parse revoke output");
    assert_eq!(revoke_body["artifactId"], artifact_id);
    assert_eq!(revoke_body["status"], "revoked");
    assert_eq!(revoke_body["revokedReason"], "remote-revocation");

    let health_after_revoke = client
        .get(format!("{base_url}/health"))
        .send()
        .expect("send health request after revoke");
    assert_eq!(health_after_revoke.status(), reqwest::StatusCode::OK);
    let health_after_revoke: serde_json::Value = health_after_revoke
        .json()
        .expect("health json after revoke");
    assert_eq!(
        health_after_revoke["federation"]["certifications"]["count"],
        1
    );
    assert_eq!(
        health_after_revoke["federation"]["certifications"]["activeCount"],
        0
    );
    assert_eq!(
        health_after_revoke["federation"]["certifications"]["revokedCount"],
        1
    );

    let _ = fs::remove_dir_all(scenarios_dir);
    let _ = fs::remove_dir_all(results_dir);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(seed_path);
    let _ = fs::remove_file(registry_path);
}
