#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn chio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temporary = tempfile::tempdir().expect("create test directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let tools = root.join("reviewed-tools.json");
    fs::write(
        &tools,
        serde_json::to_vec_pretty(&serde_json::json!({
            "tools": [{
                "name": "echo",
                "description": "Echo a reviewed value",
                "inputSchema": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"]
                },
                "annotations": {"readOnlyHint": true}
            }]
        }))
        .expect("encode tools fixture"),
    )
    .expect("write tools fixture");
    let target_a = root.join("target-a");
    let target_b = root.join("target-b");
    write_executable(&target_a, b"#!/bin/sh\nexit 0\n");
    write_executable(&target_b, b"#!/bin/sh\nexit 1\n");
    (temporary, tools, target_a, target_b)
}

fn write_executable(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write target executable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("set target executable mode");
    }
}

fn provision(output: &Path, tools: &Path, target: &Path) -> Output {
    provision_with_runtime_directory(output, None, tools, target)
}

fn provision_with_runtime_directory(
    output: &Path,
    runtime_security_directory: Option<&Path>,
    tools: &Path,
    target: &Path,
) -> Output {
    let mut command = Command::new(chio());
    command
        .args(["security", "provision-native-mcp-demo", "--output-dir"])
        .arg(output);
    if let Some(directory) = runtime_security_directory {
        command.arg("--runtime-security-dir").arg(directory);
    }
    command
        .arg("--tools-fixture")
        .arg(tools)
        .arg("--target")
        .arg(target)
        .args([
            "--target-arg",
            "demo-argument",
            "--execution-uid",
            "10001",
            "--execution-gid",
            "10001",
            "--execution-supplementary-gid",
            "10002",
            "--server-id",
            "provision-test",
            "--server-name",
            "Provision test MCP",
            "--server-version",
            "1.0.0",
        ]);
    command.output().expect("run native MCP demo provisioner")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "provisioner failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn exact_rerun_is_idempotent_and_emits_no_secret() {
    let (temporary, tools, target, _) = setup();
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let output_directory = root.join("security-material");

    let first = provision(&output_directory, &tools, &target);
    assert_success(&first);
    let first_report: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("decode first report");
    assert_eq!(
        first_report["securityMode"],
        "disabled_legacy_authorized_demo"
    );
    assert_eq!(first_report["containmentEnforced"], false);
    assert_eq!(
        first_report["executionIdentity"],
        serde_json::json!({
            "uid": 10001,
            "gid": 10001,
            "supplementary_gids": [10002]
        })
    );
    assert_eq!(
        first_report["warning"],
        "Disabled is legacy-authorized demo mode, not cage containment."
    );
    assert_eq!(
        first_report["runtimeSecurityDirectory"],
        output_directory.to_str().expect("UTF-8 output directory")
    );
    let target_command: serde_json::Value = serde_json::from_slice(
        &fs::read(output_directory.join("target-command")).expect("read target command"),
    )
    .expect("decode target command");
    assert_eq!(
        target_command,
        serde_json::json!([target.to_str().expect("UTF-8 target path"), "demo-argument"])
    );
    let private_seed = fs::read_to_string(output_directory.join("control-authority.seed"))
        .expect("read private seed");
    assert!(
        !String::from_utf8_lossy(&first.stdout).contains(private_seed.trim()),
        "provision report leaked a private seed"
    );

    let report_before =
        fs::read(output_directory.join("provision-report.json")).expect("read provision report");
    let second = provision(&output_directory, &tools, &target);
    assert_success(&second);
    let report_after = fs::read(output_directory.join("provision-report.json"))
        .expect("read rerun provision report");
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(report_before, report_after);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(
            fs::symlink_metadata(&output_directory)
                .expect("output metadata")
                .mode()
                & 0o777,
            0o700
        );
        for entry in fs::read_dir(&output_directory).expect("list output artifacts") {
            let entry = entry.expect("output entry");
            assert_eq!(
                entry.metadata().expect("artifact metadata").mode() & 0o777,
                0o600,
                "artifact mode drift: {}",
                entry.path().display()
            );
        }
    }
}

#[test]
fn distinct_logical_runtime_directory_is_signed_while_artifacts_remain_in_output() {
    let (temporary, tools, target, _) = setup();
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let output_directory = root.join("security-material");
    let runtime_security_directory = root.join("runtime-security-material");

    let provisioned = provision_with_runtime_directory(
        &output_directory,
        Some(&runtime_security_directory),
        &tools,
        &target,
    );
    assert_success(&provisioned);
    assert!(output_directory
        .join("enterprise-migration.sqlite3")
        .is_file());
    assert!(output_directory.join("cage-receipt-signer.seed").is_file());
    assert!(!runtime_security_directory.exists());

    let report: serde_json::Value =
        serde_json::from_slice(&provisioned.stdout).expect("decode provision report");
    assert_eq!(
        report["outputDirectory"],
        output_directory.to_str().expect("UTF-8 output directory")
    );
    assert_eq!(
        report["runtimeSecurityDirectory"],
        runtime_security_directory
            .to_str()
            .expect("UTF-8 runtime directory")
    );
    assert_eq!(
        report["artifacts"]["migrationDatabase"],
        output_directory
            .join("enterprise-migration.sqlite3")
            .to_str()
            .expect("UTF-8 migration database")
    );

    let policy: serde_json::Value = serde_json::from_slice(
        &fs::read(output_directory.join("cage-launch-policy.json")).expect("read cage policy"),
    )
    .expect("decode cage policy");
    assert_eq!(
        policy["body"]["enterprise_migration"]["state_database_path"],
        runtime_security_directory
            .join("enterprise-migration.sqlite3")
            .to_str()
            .expect("UTF-8 logical migration database")
    );
    assert_eq!(
        policy["body"]["receipt"]["database_path"],
        runtime_security_directory
            .join("cage-receipts.sqlite3")
            .to_str()
            .expect("UTF-8 logical receipt database")
    );
    assert_eq!(
        policy["body"]["receipt"]["signer_seed_path"],
        runtime_security_directory
            .join("cage-receipt-signer.seed")
            .to_str()
            .expect("UTF-8 logical receipt signer seed")
    );

    let rerun = provision_with_runtime_directory(
        &output_directory,
        Some(&runtime_security_directory),
        &tools,
        &target,
    );
    assert_success(&rerun);
    assert_eq!(provisioned.stdout, rerun.stdout);
}

#[test]
fn relative_runtime_directory_is_rejected() {
    let (temporary, tools, target, _) = setup();
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let output_directory = root.join("security-material");

    let rejected = provision_with_runtime_directory(
        &output_directory,
        Some(Path::new("relative-security-material")),
        &tools,
        &target,
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("exact absolute non-root path"),
        "unexpected relative path error: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(!output_directory.exists());
}

#[test]
fn runtime_directory_drift_is_rejected_without_overwrite() {
    let (temporary, tools, target, _) = setup();
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let output_directory = root.join("security-material");
    let original_runtime_directory = root.join("runtime-security-a");
    let drifted_runtime_directory = root.join("runtime-security-b");
    let first = provision_with_runtime_directory(
        &output_directory,
        Some(&original_runtime_directory),
        &tools,
        &target,
    );
    assert_success(&first);
    let report_before =
        fs::read(output_directory.join("provision-report.json")).expect("read provision report");

    let rerun = provision_with_runtime_directory(
        &output_directory,
        Some(&drifted_runtime_directory),
        &tools,
        &target,
    );
    assert!(
        !rerun.status.success(),
        "runtime path drift unexpectedly passed"
    );
    assert!(
        String::from_utf8_lossy(&rerun.stderr).contains("partial, tampered, or input-mismatched"),
        "unexpected runtime path drift error: {}",
        String::from_utf8_lossy(&rerun.stderr)
    );
    assert_eq!(
        fs::read(output_directory.join("provision-report.json"))
            .expect("read report after rejected rerun"),
        report_before
    );
}

#[cfg(unix)]
#[test]
fn symlinked_runtime_directory_is_rejected() {
    use std::os::unix::fs::symlink;

    let (temporary, tools, target, _) = setup();
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let output_directory = root.join("security-material");
    let real_runtime_directory = root.join("runtime-security-real");
    fs::create_dir(&real_runtime_directory).expect("create real runtime directory");
    let symlinked_runtime_directory = root.join("runtime-security-link");
    symlink(&real_runtime_directory, &symlinked_runtime_directory)
        .expect("create runtime directory symlink");

    let rejected = provision_with_runtime_directory(
        &output_directory,
        Some(&symlinked_runtime_directory),
        &tools,
        &target,
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("must not contain symlink components"),
        "unexpected symlink path error: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(!output_directory.exists());
}

#[test]
fn tampered_artifact_is_rejected_without_overwrite() {
    let (temporary, tools, target, _) = setup();
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let output_directory = root.join("security-material");
    let first = provision(&output_directory, &tools, &target);
    assert_success(&first);

    let manifest_path = output_directory.join("signed-manifest.json");
    let mut manifest = fs::OpenOptions::new()
        .append(true)
        .open(&manifest_path)
        .expect("open signed manifest");
    manifest.write_all(b"\n").expect("tamper signed manifest");
    let tampered = fs::read(&manifest_path).expect("read tampered manifest");

    let rerun = provision(&output_directory, &tools, &target);
    assert!(
        !rerun.status.success(),
        "tampered provision unexpectedly passed"
    );
    assert!(
        String::from_utf8_lossy(&rerun.stderr).contains("partial, tampered, or input-mismatched"),
        "unexpected tamper error: {}",
        String::from_utf8_lossy(&rerun.stderr)
    );
    assert_eq!(
        fs::read(&manifest_path).expect("read manifest after rejection"),
        tampered,
        "tampered artifact was silently overwritten"
    );
}

#[test]
fn exact_target_mismatch_is_rejected() {
    let (temporary, tools, target_a, target_b) = setup();
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let output_directory = root.join("security-material");
    let first = provision(&output_directory, &tools, &target_a);
    assert_success(&first);

    let rerun = provision(&output_directory, &tools, &target_b);
    assert!(
        !rerun.status.success(),
        "target mismatch unexpectedly passed"
    );
    assert!(
        String::from_utf8_lossy(&rerun.stderr).contains("partial, tampered, or input-mismatched"),
        "unexpected target mismatch error: {}",
        String::from_utf8_lossy(&rerun.stderr)
    );
}
