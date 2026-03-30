#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_core::{canonical_json_bytes, PublicKey, Signature};
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
    certification_registry_file: Option<&PathBuf>,
    certification_discovery_file: Option<&PathBuf>,
    advertise_url: Option<&str>,
    certification_public_metadata_ttl_seconds: Option<u64>,
) -> ServerGuard {
    let mut command = Command::new(env!("CARGO_BIN_EXE_arc"));
    command.current_dir(workspace_root()).args([
        "trust",
        "serve",
        "--listen",
        &listen.to_string(),
        "--service-token",
        service_token,
    ]);
    if let Some(certification_registry_file) = certification_registry_file {
        command.args([
            "--certification-registry-file",
            certification_registry_file
                .to_str()
                .expect("certification registry path"),
        ]);
    }
    if let Some(certification_discovery_file) = certification_discovery_file {
        command.args([
            "--certification-discovery-file",
            certification_discovery_file
                .to_str()
                .expect("certification discovery path"),
        ]);
    }
    let advertise_url = advertise_url
        .map(str::to_string)
        .unwrap_or_else(|| format!("http://{listen}"));
    command.args(["--advertise-url", &advertise_url]);
    if let Some(ttl_seconds) = certification_public_metadata_ttl_seconds {
        command.args([
            "--certification-public-metadata-ttl-seconds",
            &ttl_seconds.to_string(),
        ]);
    }
    let child = command
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
  "peerRoles": ["client_to_arc_server"],
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
  "peerRole": "client_to_arc_server",
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

fn write_discovery_network(path: &PathBuf, operators: &[(&str, &str, &str, bool)]) {
    let operators_json = operators
        .iter()
        .map(
            |(operator_id, registry_url, control_token, allow_publish)| {
                (
                    operator_id.to_string(),
                    serde_json::json!({
                        "operatorId": operator_id,
                        "operatorName": format!("Operator {operator_id}"),
                        "registryUrl": registry_url,
                        "controlToken": control_token,
                        "allowPublish": allow_publish,
                        "trustLabels": ["public"]
                    }),
                )
            },
        )
        .collect::<serde_json::Map<String, serde_json::Value>>();
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": "arc.certify.discovery-network.v1",
            "operators": operators_json
        }))
        .expect("serialize discovery network"),
    )
    .expect("write discovery network");
}

fn run_certify_check(
    scenarios_dir: &PathBuf,
    results_dir: &PathBuf,
    output_path: &PathBuf,
    seed_path: &PathBuf,
    tool_server_id: &str,
    tool_server_name: Option<&str>,
) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_arc"));
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
    let output = command.output().expect("run arc certify check");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn publish_remote_certification(
    base_url: &str,
    service_token: &str,
    artifact_path: &PathBuf,
) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            base_url,
            "--control-token",
            service_token,
            "certify",
            "registry",
            "publish",
            "--input",
            artifact_path.to_str().expect("artifact path"),
        ])
        .output()
        .expect("run remote certification publish");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse remote publish output")
}

fn revoke_remote_certification(
    base_url: &str,
    service_token: &str,
    artifact_id: &str,
    reason: &str,
) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            base_url,
            "--control-token",
            service_token,
            "certify",
            "registry",
            "revoke",
            "--artifact-id",
            artifact_id,
            "--reason",
            reason,
        ])
        .output()
        .expect("run remote certification revoke");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse remote revoke output")
}

#[test]
fn certify_check_emits_signed_pass_artifact_and_report() {
    let scenarios_dir = unique_path("arc-certify-scenarios", "");
    let results_dir = unique_path("arc-certify-results", "");
    let output_path = unique_path("arc-certify-artifact", ".json");
    let report_path = unique_path("arc-certify-report", ".md");
    let seed_path = unique_path("arc-certify-seed", ".txt");

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");

    let output = Command::new(env!("CARGO_BIN_EXE_arc"))
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
        .expect("run arc certify check");

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
    assert_eq!(artifact["body"]["schema"], "arc.certify.check.v1");
    assert_eq!(artifact["body"]["verdict"], "pass");
    assert_eq!(
        artifact["body"]["criteriaProfile"],
        "conformance-all-pass-v1"
    );
    assert_eq!(
        artifact["body"]["evidence"]["evidenceProfile"],
        "conformance-report-bundle-v1"
    );
    assert_eq!(
        artifact["body"]["evidence"]["generatedReportMediaType"],
        "text/markdown"
    );
    assert_eq!(
        artifact["body"]["evidence"]["provenanceMode"],
        "artifact-signer-key"
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
    let scenarios_dir = unique_path("arc-certify-scenarios-fail", "");
    let results_dir = unique_path("arc-certify-results-fail", "");
    let output_path = unique_path("arc-certify-artifact-fail", ".json");
    let seed_path = unique_path("arc-certify-seed-fail", ".txt");

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "unsupported");

    let output = Command::new(env!("CARGO_BIN_EXE_arc"))
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
        .expect("run arc certify check");

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
    let scenarios_dir = unique_path("arc-certify-verify-scenarios", "");
    let results_dir = unique_path("arc-certify-verify-results", "");
    let output_path = unique_path("arc-certify-verify-artifact", ".json");
    let seed_path = unique_path("arc-certify-verify-seed", ".txt");

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

    let verify = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "verify",
            "--input",
            output_path.to_str().expect("artifact path"),
        ])
        .output()
        .expect("run arc certify verify");
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
    let scenarios_dir = unique_path("arc-certify-registry-local-scenarios", "");
    let results_dir = unique_path("arc-certify-registry-local-results", "");
    let output_path = unique_path("arc-certify-registry-local-artifact", ".json");
    let replacement_output_path =
        unique_path("arc-certify-registry-local-artifact-replacement", ".json");
    let seed_path = unique_path("arc-certify-registry-local-seed", ".txt");
    let registry_path = unique_path("arc-certify-registry-local", ".json");

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

    let publish = Command::new(env!("CARGO_BIN_EXE_arc"))
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

    let publish_replacement = Command::new(env!("CARGO_BIN_EXE_arc"))
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

    let list = Command::new(env!("CARGO_BIN_EXE_arc"))
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

    let get = Command::new(env!("CARGO_BIN_EXE_arc"))
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

    let resolve = Command::new(env!("CARGO_BIN_EXE_arc"))
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

    let revoke = Command::new(env!("CARGO_BIN_EXE_arc"))
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

    let resolve_after_revoke = Command::new(env!("CARGO_BIN_EXE_arc"))
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
    let scenarios_dir = unique_path("arc-certify-registry-remote-scenarios", "");
    let results_dir = unique_path("arc-certify-registry-remote-results", "");
    let output_path = unique_path("arc-certify-registry-remote-artifact", ".json");
    let seed_path = unique_path("arc-certify-registry-remote-seed", ".txt");
    let registry_path = unique_path("arc-certify-registry-remote", ".json");
    let tool_server_id = "demo/server?mode=remote#1";

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Demo Server Remote"),
    );

    let listen = reserve_listen_addr();
    let service_token = "certify-registry-remote-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        Some(&registry_path),
        None,
        None,
        None,
    );
    let client = Client::builder().build().expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let publish = Command::new(env!("CARGO_BIN_EXE_arc"))
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
    assert_eq!(publish_body["toolServerId"], tool_server_id);
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

    let list = Command::new(env!("CARGO_BIN_EXE_arc"))
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

    let get = Command::new(env!("CARGO_BIN_EXE_arc"))
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

    let resolve = Command::new(env!("CARGO_BIN_EXE_arc"))
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
            tool_server_id,
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

    let revoke = Command::new(env!("CARGO_BIN_EXE_arc"))
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

#[test]
fn certify_registry_discover_reports_per_operator_public_state() {
    let scenarios_dir = unique_path("arc-certify-discover-scenarios", "");
    let results_dir = unique_path("arc-certify-discover-results", "");
    let output_path = unique_path("arc-certify-discover-artifact", ".json");
    let seed_path = unique_path("arc-certify-discover-seed", ".txt");
    let registry_a_path = unique_path("arc-certify-discover-registry-a", ".json");
    let registry_b_path = unique_path("arc-certify-discover-registry-b", ".json");
    let network_path = unique_path("arc-certify-discovery-network", ".json");

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        "demo-server-discovery",
        Some("Demo Server Discovery"),
    );

    let listen_a = reserve_listen_addr();
    let listen_b = reserve_listen_addr();
    let token_a = "certify-discover-token-a";
    let token_b = "certify-discover-token-b";
    let _service_a =
        spawn_trust_service(listen_a, token_a, Some(&registry_a_path), None, None, None);
    let _service_b =
        spawn_trust_service(listen_b, token_b, Some(&registry_b_path), None, None, None);
    let client = Client::builder().build().expect("build reqwest client");
    let base_url_a = format!("http://{listen_a}");
    let base_url_b = format!("http://{listen_b}");
    wait_for_trust_service(&client, &base_url_a);
    wait_for_trust_service(&client, &base_url_b);

    let publish_a = publish_remote_certification(&base_url_a, token_a, &output_path);
    let publish_b = publish_remote_certification(&base_url_b, token_b, &output_path);
    assert_eq!(publish_a["status"], "active");
    let artifact_id = publish_b["artifactId"]
        .as_str()
        .expect("artifact id")
        .to_string();
    revoke_remote_certification(&base_url_b, token_b, &artifact_id, "discovery-revoked");

    write_discovery_network(
        &network_path,
        &[
            ("alpha", &base_url_a, token_a, true),
            ("beta", &base_url_b, token_b, true),
        ],
    );

    let discover = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "discover",
            "--tool-server-id",
            "demo-server-discovery",
            "--certification-discovery-file",
            network_path.to_str().expect("network path"),
        ])
        .output()
        .expect("run certification discovery");
    assert!(
        discover.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&discover.stdout),
        String::from_utf8_lossy(&discover.stderr)
    );
    let discover_body: serde_json::Value =
        serde_json::from_slice(&discover.stdout).expect("parse discovery output");
    assert_eq!(discover_body["peerCount"], 2);
    assert_eq!(discover_body["reachableCount"], 2);
    assert_eq!(discover_body["activeCount"], 1);
    assert_eq!(discover_body["revokedCount"], 1);
    assert!(discover_body["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .any(|peer| peer["operatorId"] == "alpha" && peer["resolution"]["state"] == "active"));
    assert!(discover_body["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .any(|peer| peer["operatorId"] == "beta" && peer["resolution"]["state"] == "revoked"));

    let _ = fs::remove_dir_all(scenarios_dir);
    let _ = fs::remove_dir_all(results_dir);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(seed_path);
    let _ = fs::remove_file(registry_a_path);
    let _ = fs::remove_file(registry_b_path);
    let _ = fs::remove_file(network_path);
}

#[test]
fn certify_registry_publish_network_and_remote_discover_work() {
    let scenarios_dir = unique_path("arc-certify-network-publish-scenarios", "");
    let results_dir = unique_path("arc-certify-network-publish-results", "");
    let output_path = unique_path("arc-certify-network-publish-artifact", ".json");
    let seed_path = unique_path("arc-certify-network-publish-seed", ".txt");
    let registry_a_path = unique_path("arc-certify-network-publish-registry-a", ".json");
    let registry_b_path = unique_path("arc-certify-network-publish-registry-b", ".json");
    let aggregator_registry_path =
        unique_path("arc-certify-network-publish-aggregator-registry", ".json");
    let network_path = unique_path("arc-certify-network-publish-network", ".json");
    let tool_server_id = "demo/server?mode=network#1";

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Demo Server Network Publish"),
    );

    let listen_a = reserve_listen_addr();
    let listen_b = reserve_listen_addr();
    let listen_aggregator = reserve_listen_addr();
    let token_a = "certify-network-token-a";
    let token_b = "certify-network-token-b";
    let aggregator_token = "certify-network-aggregator-token";
    let _service_a =
        spawn_trust_service(listen_a, token_a, Some(&registry_a_path), None, None, None);
    let _service_b =
        spawn_trust_service(listen_b, token_b, Some(&registry_b_path), None, None, None);
    let client = Client::builder().build().expect("build reqwest client");
    let base_url_a = format!("http://{listen_a}");
    let base_url_b = format!("http://{listen_b}");
    wait_for_trust_service(&client, &base_url_a);
    wait_for_trust_service(&client, &base_url_b);

    write_discovery_network(
        &network_path,
        &[
            ("alpha", &base_url_a, token_a, true),
            ("beta", &base_url_b, token_b, true),
        ],
    );

    let base_url_aggregator = format!("http://{listen_aggregator}");
    let _aggregator = spawn_trust_service(
        listen_aggregator,
        aggregator_token,
        Some(&aggregator_registry_path),
        Some(&network_path),
        None,
        None,
    );
    wait_for_trust_service(&client, &base_url_aggregator);

    let publish_network = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_aggregator,
            "--control-token",
            aggregator_token,
            "certify",
            "registry",
            "publish-network",
            "--input",
            output_path.to_str().expect("artifact path"),
        ])
        .output()
        .expect("run certification network publish");
    assert!(
        publish_network.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish_network.stdout),
        String::from_utf8_lossy(&publish_network.stderr)
    );
    let publish_network_body: serde_json::Value =
        serde_json::from_slice(&publish_network.stdout).expect("parse publish network output");
    assert_eq!(publish_network_body["peerCount"], 2);
    assert_eq!(publish_network_body["successCount"], 2);

    let discover_network = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_aggregator,
            "--control-token",
            aggregator_token,
            "certify",
            "registry",
            "discover",
            "--tool-server-id",
            tool_server_id,
        ])
        .output()
        .expect("run remote certification discovery");
    assert!(
        discover_network.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&discover_network.stdout),
        String::from_utf8_lossy(&discover_network.stderr)
    );
    let discover_network_body: serde_json::Value =
        serde_json::from_slice(&discover_network.stdout).expect("parse discovery network output");
    assert_eq!(discover_network_body["peerCount"], 2);
    assert_eq!(discover_network_body["activeCount"], 2);
    assert!(discover_network_body["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .all(|peer| peer["resolution"]["state"] == "active"));

    let resolve_a = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_a,
            "--control-token",
            token_a,
            "certify",
            "registry",
            "resolve",
            "--tool-server-id",
            tool_server_id,
        ])
        .output()
        .expect("run remote certification resolve alpha");
    assert!(resolve_a.status.success());
    let resolve_a_body: serde_json::Value =
        serde_json::from_slice(&resolve_a.stdout).expect("parse resolve alpha");
    assert_eq!(resolve_a_body["state"], "active");

    let resolve_b = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_b,
            "--control-token",
            token_b,
            "certify",
            "registry",
            "resolve",
            "--tool-server-id",
            tool_server_id,
        ])
        .output()
        .expect("run remote certification resolve beta");
    assert!(resolve_b.status.success());
    let resolve_b_body: serde_json::Value =
        serde_json::from_slice(&resolve_b.stdout).expect("parse resolve beta");
    assert_eq!(resolve_b_body["state"], "active");

    let _ = fs::remove_dir_all(scenarios_dir);
    let _ = fs::remove_dir_all(results_dir);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(seed_path);
    let _ = fs::remove_file(registry_a_path);
    let _ = fs::remove_file(registry_b_path);
    let _ = fs::remove_file(aggregator_registry_path);
    let _ = fs::remove_file(network_path);
}

#[test]
fn certify_registry_discover_fails_closed_on_stale_and_mismatched_public_metadata() {
    let scenarios_dir = unique_path("arc-certify-public-metadata-scenarios", "");
    let results_dir = unique_path("arc-certify-public-metadata-results", "");
    let output_path = unique_path("arc-certify-public-metadata-artifact", ".json");
    let seed_path = unique_path("arc-certify-public-metadata-seed", ".txt");
    let registry_good = unique_path("arc-certify-public-metadata-registry-good", ".json");
    let registry_stale = unique_path("arc-certify-public-metadata-registry-stale", ".json");
    let registry_mismatch = unique_path("arc-certify-public-metadata-registry-mismatch", ".json");
    let network_path = unique_path("arc-certify-public-metadata-network", ".json");
    let tool_server_id = "demo-server-public-metadata";

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Demo Server Public Metadata"),
    );

    let listen_good = reserve_listen_addr();
    let listen_stale = reserve_listen_addr();
    let listen_mismatch = reserve_listen_addr();
    let token_good = "certify-public-metadata-good";
    let token_stale = "certify-public-metadata-stale";
    let token_mismatch = "certify-public-metadata-mismatch";
    let base_url_good = format!("http://{listen_good}");
    let base_url_stale = format!("http://{listen_stale}");
    let base_url_mismatch = format!("http://{listen_mismatch}");
    let _service_good = spawn_trust_service(
        listen_good,
        token_good,
        Some(&registry_good),
        None,
        Some(&base_url_good),
        None,
    );
    let _service_stale = spawn_trust_service(
        listen_stale,
        token_stale,
        Some(&registry_stale),
        None,
        Some(&base_url_stale),
        Some(0),
    );
    let _service_mismatch = spawn_trust_service(
        listen_mismatch,
        token_mismatch,
        Some(&registry_mismatch),
        None,
        Some("https://mismatch.example"),
        None,
    );
    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url_good);
    wait_for_trust_service(&client, &base_url_stale);
    wait_for_trust_service(&client, &base_url_mismatch);

    let publish_good = publish_remote_certification(&base_url_good, token_good, &output_path);
    let publish_stale = publish_remote_certification(&base_url_stale, token_stale, &output_path);
    let publish_mismatch =
        publish_remote_certification(&base_url_mismatch, token_mismatch, &output_path);
    assert_eq!(publish_good["status"], "active");
    assert_eq!(publish_stale["status"], "active");
    assert_eq!(publish_mismatch["status"], "active");

    write_discovery_network(
        &network_path,
        &[
            ("good", &base_url_good, token_good, true),
            ("stale", &base_url_stale, token_stale, true),
            ("mismatch", &base_url_mismatch, token_mismatch, true),
        ],
    );

    let discover = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "certify",
            "registry",
            "discover",
            "--tool-server-id",
            tool_server_id,
            "--certification-discovery-file",
            network_path.to_str().expect("network path"),
        ])
        .output()
        .expect("run marketplace discovery");
    assert!(
        discover.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&discover.stdout),
        String::from_utf8_lossy(&discover.stderr)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&discover.stdout).expect("parse discovery output");
    assert_eq!(body["peerCount"], 3);
    assert_eq!(body["activeCount"], 1);
    assert!(body["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .any(|peer| peer["operatorId"] == "good"
            && peer["metadataValid"] == true
            && peer["resolution"]["state"] == "active"));
    assert!(body["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .any(|peer| peer["operatorId"] == "stale"
            && peer["metadataValid"] == false
            && peer["error"]
                .as_str()
                .expect("stale error")
                .contains("expired")));
    assert!(body["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .any(|peer| peer["operatorId"] == "mismatch"
            && peer["metadataValid"] == false
            && peer["error"]
                .as_str()
                .expect("mismatch error")
                .contains("does not match expected")));
}

#[test]
fn certify_marketplace_search_transparency_consume_and_dispute_work() {
    let scenarios_dir = unique_path("arc-certify-marketplace-scenarios", "");
    let results_dir = unique_path("arc-certify-marketplace-results", "");
    let output_path = unique_path("arc-certify-marketplace-artifact", ".json");
    let seed_path = unique_path("arc-certify-marketplace-seed", ".txt");
    let registry_alpha = unique_path("arc-certify-marketplace-registry-alpha", ".json");
    let registry_beta = unique_path("arc-certify-marketplace-registry-beta", ".json");
    let aggregator_registry = unique_path("arc-certify-marketplace-registry-aggregator", ".json");
    let network_path = unique_path("arc-certify-marketplace-network", ".json");
    let tool_server_id = "demo-server-marketplace";

    write_scenario(&scenarios_dir, "initialize");
    write_results(&results_dir, "initialize", "pass");
    run_certify_check(
        &scenarios_dir,
        &results_dir,
        &output_path,
        &seed_path,
        tool_server_id,
        Some("Demo Server Marketplace"),
    );

    let listen_alpha = reserve_listen_addr();
    let listen_beta = reserve_listen_addr();
    let listen_aggregator = reserve_listen_addr();
    let token_alpha = "certify-marketplace-alpha";
    let token_beta = "certify-marketplace-beta";
    let token_aggregator = "certify-marketplace-aggregator";
    let base_url_alpha = format!("http://{listen_alpha}");
    let base_url_beta = format!("http://{listen_beta}");
    let base_url_aggregator = format!("http://{listen_aggregator}");
    let _service_alpha = spawn_trust_service(
        listen_alpha,
        token_alpha,
        Some(&registry_alpha),
        None,
        Some(&base_url_alpha),
        None,
    );
    let _service_beta = spawn_trust_service(
        listen_beta,
        token_beta,
        Some(&registry_beta),
        None,
        Some(&base_url_beta),
        None,
    );
    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url_alpha);
    wait_for_trust_service(&client, &base_url_beta);

    write_discovery_network(
        &network_path,
        &[
            ("alpha", &base_url_alpha, token_alpha, true),
            ("beta", &base_url_beta, token_beta, true),
        ],
    );
    let _aggregator = spawn_trust_service(
        listen_aggregator,
        token_aggregator,
        Some(&aggregator_registry),
        Some(&network_path),
        Some(&base_url_aggregator),
        None,
    );
    wait_for_trust_service(&client, &base_url_aggregator);

    let publish_network = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_aggregator,
            "--control-token",
            token_aggregator,
            "certify",
            "registry",
            "publish-network",
            "--input",
            output_path.to_str().expect("artifact path"),
        ])
        .output()
        .expect("run network publish");
    assert!(publish_network.status.success());

    let beta_listing = publish_remote_certification(&base_url_beta, token_beta, &output_path);
    let beta_artifact_id = beta_listing["artifactId"]
        .as_str()
        .expect("beta artifact id")
        .to_string();
    revoke_remote_certification(
        &base_url_beta,
        token_beta,
        &beta_artifact_id,
        "beta-revoked",
    );

    let search = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_aggregator,
            "--control-token",
            token_aggregator,
            "certify",
            "registry",
            "search",
            "--tool-server-id",
            tool_server_id,
        ])
        .output()
        .expect("run marketplace search");
    assert!(search.status.success());
    let search_body: serde_json::Value =
        serde_json::from_slice(&search.stdout).expect("parse search");
    assert_eq!(search_body["count"], 2);
    assert!(search_body["results"]
        .as_array()
        .expect("results array")
        .iter()
        .any(
            |result| result["publisher"]["publisherId"] == base_url_alpha
                && result["entry"]["status"] == "active"
        ));
    assert!(search_body["results"]
        .as_array()
        .expect("results array")
        .iter()
        .any(|result| result["publisher"]["publisherId"] == base_url_beta
            && result["entry"]["status"] == "revoked"));

    let transparency = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_aggregator,
            "--control-token",
            token_aggregator,
            "certify",
            "registry",
            "transparency",
            "--tool-server-id",
            tool_server_id,
        ])
        .output()
        .expect("run marketplace transparency");
    assert!(transparency.status.success());
    let transparency_body: serde_json::Value =
        serde_json::from_slice(&transparency.stdout).expect("parse transparency");
    assert!(transparency_body["events"]
        .as_array()
        .expect("events array")
        .iter()
        .any(|event| event["kind"] == "published"
            && event["publisher"]["publisherId"] == base_url_alpha));
    assert!(transparency_body["events"]
        .as_array()
        .expect("events array")
        .iter()
        .any(|event| event["kind"] == "revoked"
            && event["publisher"]["publisherId"] == base_url_beta));

    let consume = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_aggregator,
            "--control-token",
            token_aggregator,
            "certify",
            "registry",
            "consume",
            "--tool-server-id",
            tool_server_id,
        ])
        .output()
        .expect("run marketplace consume");
    assert!(consume.status.success());
    let consume_body: serde_json::Value =
        serde_json::from_slice(&consume.stdout).expect("parse consume");
    assert_eq!(consume_body["admittedCount"], 1);
    assert_eq!(consume_body["rejectedCount"], 1);
    assert!(consume_body["decisions"]
        .as_array()
        .expect("decisions array")
        .iter()
        .any(|decision| decision["operatorId"] == "alpha" && decision["accepted"] == true));
    assert!(consume_body["decisions"]
        .as_array()
        .expect("decisions array")
        .iter()
        .any(|decision| decision["operatorId"] == "beta"
            && decision["accepted"] == false
            && decision["reasons"]
                .as_array()
                .expect("reasons array")
                .iter()
                .any(|reason| reason.as_str().expect("reason").contains("revoked"))));

    let alpha_listing = publish_remote_certification(&base_url_alpha, token_alpha, &output_path);
    let alpha_artifact_id = alpha_listing["artifactId"]
        .as_str()
        .expect("alpha artifact id")
        .to_string();
    let dispute = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_alpha,
            "--control-token",
            token_alpha,
            "certify",
            "registry",
            "dispute",
            "--artifact-id",
            &alpha_artifact_id,
            "--state",
            "resolved-revoked",
            "--note",
            "operator dispute resolved as revoked",
        ])
        .output()
        .expect("run certification dispute");
    assert!(dispute.status.success());
    let dispute_body: serde_json::Value =
        serde_json::from_slice(&dispute.stdout).expect("parse dispute");
    assert_eq!(dispute_body["status"], "revoked");
    assert_eq!(dispute_body["dispute"]["state"], "resolved-revoked");

    let consume_after_dispute = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_aggregator,
            "--control-token",
            token_aggregator,
            "certify",
            "registry",
            "consume",
            "--tool-server-id",
            tool_server_id,
            "--operator-id",
            "alpha",
        ])
        .output()
        .expect("run marketplace consume after dispute");
    assert!(consume_after_dispute.status.success());
    let consume_after_dispute_body: serde_json::Value =
        serde_json::from_slice(&consume_after_dispute.stdout).expect("parse consume after dispute");
    assert_eq!(consume_after_dispute_body["admittedCount"], 0);
    assert!(consume_after_dispute_body["decisions"]
        .as_array()
        .expect("decisions array")
        .iter()
        .any(|decision| decision["operatorId"] == "alpha"
            && decision["accepted"] == false
            && decision["reasons"]
                .as_array()
                .expect("reasons array")
                .iter()
                .any(|reason| reason.as_str().expect("reason").contains("revoked"))));

    let transparency_after_dispute = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_aggregator,
            "--control-token",
            token_aggregator,
            "certify",
            "registry",
            "transparency",
            "--tool-server-id",
            tool_server_id,
            "--operator-id",
            "alpha",
        ])
        .output()
        .expect("run transparency after dispute");
    assert!(
        transparency_after_dispute.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&transparency_after_dispute.stdout),
        String::from_utf8_lossy(&transparency_after_dispute.stderr)
    );
    let transparency_after_dispute_body: serde_json::Value =
        serde_json::from_slice(&transparency_after_dispute.stdout)
            .expect("parse transparency after dispute");
    assert!(transparency_after_dispute_body["events"]
        .as_array()
        .expect("events array")
        .iter()
        .any(|event| event["kind"] == "dispute-resolved-revoked"));
}
