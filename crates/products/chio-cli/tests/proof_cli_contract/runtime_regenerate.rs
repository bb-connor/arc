use super::support::*;
use chio_test_support::prelude::*;
use std::path::Path;

const RELATIVE: &str = "public-stages/recursive-runtime-swarm";

fn runtime_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().test_expect("runtime fixture root");
    copy_dir_all(
        &workspace_root().join("fixtures/proof-room").join(RELATIVE),
        &root.path().join(RELATIVE),
    ).test_expect("copy runtime fixture");
    let catalog = serde_json::json!({
        "schema": "chio.proof-room.fixture-root-catalog.v1",
        "fixtures": [{
            "id": "recursive-runtime-swarm", "kind": "proof-room",
            "path": "fixtures/proof-room/public-stages/recursive-runtime-swarm",
            "description": "Runtime fixture"
        }]
    });
    std::fs::write(root.path().join("catalog.json"), serde_json::to_vec(&catalog).test_expect("catalog JSON"))
        .test_expect("write catalog");
    root
}

fn check(root: &Path) -> std::process::Output {
    chio(&["proof", "fixture", "regenerate", "--root", &utf8_path(root), "--check", "--json"])
}

#[test]
fn runtime_regenerate_check_verifies_committed_source_without_creating_a_store() {
    let root = runtime_root();
    let output = check(root.path());
    assert_success(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).test_expect("report JSON");
    assert_eq!(report["passes"], 1);
    assert_eq!(report["changed"], serde_json::json!([]));
}

#[test]
fn runtime_regenerate_check_refuses_missing_proof_package() {
    let root = runtime_root();
    std::fs::remove_file(root.path().join(RELATIVE).join("proof-room-bundle/proof-package.json"))
        .test_expect("remove package");
    assert_failure(&check(root.path()), "runtime fixture missing required file: proof-package.json");
}

#[test]
fn runtime_regenerate_check_refuses_report_mismatch() {
    let root = runtime_root();
    let path = root.path().join(RELATIVE).join("proof-room-bundle/verifier-report.json");
    let mut report: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).test_expect("read report")).test_expect("report JSON");
    report["accepted"] = serde_json::json!(false);
    std::fs::write(&path, serde_json::to_vec(&report).test_expect("encode report")).test_expect("write report");
    assert_failure(&check(root.path()), "runtime fixture verifier report mismatch");
}

#[test]
fn runtime_regenerate_check_refuses_report_schema_drift() {
    let root = runtime_root();
    let path = root.path().join(RELATIVE).join("proof-room-bundle/verifier-report.json");
    let mut report: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).test_expect("read report")).test_expect("report JSON");
    report["schema"] = serde_json::json!("chio.attest.verifier-report.v2");
    std::fs::write(&path, serde_json::to_vec(&report).test_expect("encode report")).test_expect("write report");
    assert_failure(&check(root.path()), "runtime fixture schema mismatch: verifier-report.json");
}

#[test]
fn runtime_regenerate_check_refuses_package_byte_tamper() {
    let root = runtime_root();
    let path = root.path().join(RELATIVE).join("proof-room-bundle/proof-package.json");
    let mut bytes = std::fs::read(&path).test_expect("read package");
    bytes.push(b' ');
    std::fs::write(&path, bytes).test_expect("write package");
    assert_failure(&check(root.path()), "runtime fixture bundle integrity:");
}
