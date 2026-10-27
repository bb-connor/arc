use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::fixture_paths::{unique_path, workspace_root};

pub(crate) fn write_kernel_trust_file(kernel_key: &str) -> PathBuf {
    let path = unique_path("federated-import-trust", ".json");
    let trust = serde_json::json!({
        "schema": "chio.verifier-trust.v1",
        "kernel_keys": [kernel_key],
        "exchange_keys": [],
        "root_policy_keys": [],
    });
    fs::write(
        &path,
        serde_json::to_vec(&trust).expect("encode trust file"),
    )
    .expect("write trust file");
    path
}

pub(crate) fn create_evidence_federation_policy(
    output_path: &Path,
    signing_seed_path: &Path,
    issuer: &str,
    partner: &str,
    capability_id: &str,
) {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "evidence",
            "federation-policy",
            "create",
            "--output",
            output_path.to_str().expect("federation policy path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("signing seed path"),
            "--issuer",
            issuer,
            "--partner",
            partner,
            "--capability",
            capability_id,
            "--admin-all",
            "--expires-at",
            "1900000000",
        ])
        .output()
        .expect("run evidence federation policy create");
    assert!(
        output.status.success(),
        "chio evidence federation-policy create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
