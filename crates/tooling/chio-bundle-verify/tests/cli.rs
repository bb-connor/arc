//! The `chio-verify` binary exits with the class of its result.

mod support;

use std::path::Path;
use std::process::{Command, Output};

use chio_core_types::crypto::Keypair;
use chio_test_support::prelude::*;
use support::*;

fn trust_file(dir: &Path, kernel_key: String, required: &[&str]) -> std::path::PathBuf {
    let path = dir.join("verifier-trust.json");
    let trust = serde_json::json!({
        "schema": "chio.verifier-trust.v1",
        "kernel_keys": [kernel_key],
        "exchange_keys": [],
        "root_policy_keys": [],
        "required_columns": required,
    });
    std::fs::write(&path, serde_json::to_vec(&trust).test_unwrap()).test_unwrap();
    path
}

fn chio_verify(bundle: &Path, trust: &Path, json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio-verify"));
    command.arg(bundle).arg("--trust").arg(trust);
    if json {
        command.arg("--json");
    }
    command.output().test_unwrap()
}

fn package() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().test_unwrap();
    let bundle = directory.path().join("bundle");
    std::fs::create_dir(&bundle).test_unwrap();
    write(&bundle, &sample_bundle(), &package_keypair());
    (directory, bundle)
}

#[test]
fn verified_bundle_exits_zero_with_the_report() {
    let (directory, bundle) = package();
    let trust = trust_file(
        directory.path(),
        package_keypair().public_key().to_hex(),
        &["decision"],
    );
    let output = chio_verify(&bundle, &trust, true);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).test_unwrap();
    assert_eq!(report["schema"], "chio.bundle-verify-report.v1");
    assert_eq!(
        report["receipts"][0]["columns"]["decision"]["class"],
        "verified"
    );
}

#[test]
fn unverified_required_column_exits_ten() {
    let (directory, bundle) = package();
    let trust = trust_file(
        directory.path(),
        package_keypair().public_key().to_hex(),
        &["decision", "content"],
    );
    assert_eq!(chio_verify(&bundle, &trust, false).status.code(), Some(10));
}

#[test]
fn tampered_file_exits_twenty() {
    let (directory, bundle) = package();
    std::fs::write(bundle.join("query.json"), b"{\"tampered\":true}\n").test_unwrap();
    let trust = trust_file(
        directory.path(),
        package_keypair().public_key().to_hex(),
        &[],
    );
    let output = chio_verify(&bundle, &trust, true);
    assert_eq!(output.status.code(), Some(20));
    let rejection: serde_json::Value = serde_json::from_slice(&output.stderr).test_unwrap();
    assert_eq!(
        rejection["code"],
        "urn:chio:error:attest:bundle-file-hash-mismatch"
    );
}

#[test]
fn unpinned_signer_exits_fifty() {
    let (directory, bundle) = package();
    let trust = trust_file(
        directory.path(),
        Keypair::generate().public_key().to_hex(),
        &[],
    );
    assert_eq!(chio_verify(&bundle, &trust, false).status.code(), Some(50));
}

#[test]
fn invalid_trust_file_exits_fifty_and_missing_trust_flag_exits_two() {
    let (directory, bundle) = package();
    let trust = directory.path().join("empty-trust.json");
    std::fs::write(
        &trust,
        br#"{"schema":"chio.verifier-trust.v1","kernel_keys":[],"exchange_keys":[],"root_policy_keys":[]}"#,
    )
    .test_unwrap();
    assert_eq!(chio_verify(&bundle, &trust, false).status.code(), Some(50));
    let output = Command::new(env!("CARGO_BIN_EXE_chio-verify"))
        .arg(&bundle)
        .output()
        .test_unwrap();
    assert_eq!(output.status.code(), Some(2));
}
