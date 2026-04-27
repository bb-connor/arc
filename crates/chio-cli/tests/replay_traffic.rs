#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("replay_traffic")
        .join("fixtures")
        .join(name)
}

fn run_traffic(fixture: &Path, extra: &[String]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .arg("replay")
        .arg("traffic")
        .arg("--from")
        .arg(fixture)
        .arg("--json");
    for arg in extra {
        command.arg(arg);
    }
    command.output().expect("spawn chio replay traffic")
}

fn assert_exit(output: &Output, expected: i32) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code().unwrap_or(i32::MIN),
        expected,
        "stdout=<<<{stdout}>>>\nstderr=<<<{stderr}>>>",
    );
}

fn write_allow_all_policy(dir: &Path) -> PathBuf {
    let path = dir.join("allow-all-policy.yaml");
    fs::write(
        &path,
        r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 4
  allow_sampling: false
  allow_sampling_tool_use: false
  allow_elicitation: false
  require_web3_evidence: false
  checkpoint_batch_size: 100
guards: {}
capabilities: {}
"#,
    )
    .expect("write allow policy");
    path
}

#[test]
fn clean_match_exits_zero() {
    let output = run_traffic(&fixture_path("clean_match.ndjson"), &[]);

    assert_exit(&output, 0);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["ok"], true);
    assert_eq!(report["first_error"], serde_json::Value::Null);
}

#[test]
fn verdict_drift_exits_ten() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = write_allow_all_policy(dir.path());
    let extra = vec![
        "--against".to_string(),
        policy.display().to_string(),
        "--run-id".to_string(),
        "m10p2t4".to_string(),
    ];

    let output = run_traffic(&fixture_path("verdict_drift.ndjson"), &extra);

    assert_exit(&output, 10);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json diff report");
    assert_eq!(report["drifts"], 1);
    assert_eq!(report["groups"][0]["class"], "allow_deny_flip");
}

#[test]
fn sig_mismatch_exits_twenty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pubkey_path = dir.path().join("tenant.pub");
    fs::write(&pubkey_path, [7u8; 32]).expect("write tenant pubkey");
    let extra = vec![
        "--tenant-pubkey".to_string(),
        pubkey_path.display().to_string(),
    ];

    let output = run_traffic(&fixture_path("sig_mismatch.ndjson"), &extra);

    assert_exit(&output, 20);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["first_error"]["exit_code"], 20);
}

#[test]
fn parse_error_exits_thirty() {
    let output = run_traffic(&fixture_path("parse_error.ndjson"), &[]);

    assert_exit(&output, 30);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["first_error"]["exit_code"], 30);
}

#[test]
fn schema_mismatch_exits_forty() {
    let output = run_traffic(&fixture_path("schema_mismatch.ndjson"), &[]);

    assert_exit(&output, 40);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["first_error"]["exit_code"], 40);
}

#[test]
fn redaction_mismatch_exits_fifty() {
    let output = run_traffic(&fixture_path("redaction_mismatch.ndjson"), &[]);

    assert_exit(&output, 50);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["first_error"]["exit_code"], 50);
}
