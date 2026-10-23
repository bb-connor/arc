//! `--trust` pinning on `mercury verify`, `inquiry export` and the pipeline exports.

use std::process::Output;

use super::signed_reader::{export_signed_proof_package, first_signed_receipt};
use super::*;

const TRUSTED_KERNEL_AUTHORITY: &str =
    "every tool receipt, child receipt, and checkpoint signer is present in the trusted Mercury kernel-key set";

fn mercury(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .args(args)
        .output()
        .expect("run mercury")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn trusted_signer() -> PathBuf {
    kernel_trust_file(&Keypair::from_seed(&[58; 32]).public_key())
}

fn untrusted_signer() -> PathBuf {
    kernel_trust_file(&Keypair::from_seed(&[59; 32]).public_key())
}

fn cleanup(paths: impl IntoIterator<Item = PathBuf>) {
    for path in paths {
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&path);
    }
}

fn kernel_authority_step(report: &serde_json::Value) -> &str {
    report["steps"]
        .as_array()
        .and_then(|steps| steps.iter().find(|step| step["name"] == "kernel_authority"))
        .and_then(|step| step["detail"].as_str())
        .expect("report carries a kernel_authority step")
}

fn assert_clap_refuses_missing_trust(output: &Output) {
    assert_eq!(output.status.code(), Some(2), "stderr={}", stderr(output));
    let stderr = stderr(output);
    assert!(
        stderr.contains("error: the following required arguments were not provided:"),
        "stderr={stderr}"
    );
    assert!(stderr.contains("--trust <TRUST>"), "stderr={stderr}");
}

fn assert_untrusted_receipt_refusal(output: &Output, proof_package_path: &Path) {
    let package: serde_json::Value =
        serde_json::from_slice(&fs::read(proof_package_path).expect("read proof package"))
            .expect("proof package json");
    let receipt_id = first_signed_receipt(&package).expect("package embeds a signed receipt")["id"]
        .as_str()
        .expect("receipt id")
        .to_string();
    let expected = format!(
        "validation error: tool receipt {receipt_id} was signed by an untrusted Mercury kernel key"
    );
    assert_eq!(output.status.code(), Some(1), "stderr={}", stderr(output));
    assert!(
        stderr(output).lines().any(|line| line == expected),
        "stderr={}",
        stderr(output)
    );
}

/// A trust file pinning the kernel key recorded in a pipeline summary's `export` paths.
pub(super) fn run_kernel_trust_file(summary_path: &Path) -> PathBuf {
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(summary_path).expect("read run summary"))
            .expect("run summary json");
    let key = summary["export"]["kernelPublicKey"]
        .as_str()
        .expect("run summary carries the run kernel key");
    kernel_trust_file(&chio_core::crypto::PublicKey::from_hex(key).expect("run kernel key hex"))
}

#[test]
fn mercury_proof_and_inquiry_packages_export_and_verify() {
    let (proof_package_path, mut paths) = export_signed_proof_package("chio-mercury-proof");
    let inquiry_package_path = unique_path("chio-mercury-inquiry-package", ".json");
    let trust = trusted_signer();

    let proof_verify = mercury(&[
        "--json".as_ref(),
        "verify".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
        "--trust".as_ref(),
        trust.as_os_str(),
    ]);
    assert!(
        proof_verify.status.success(),
        "stderr={}",
        stderr(&proof_verify)
    );
    let proof_report: serde_json::Value =
        serde_json::from_slice(&proof_verify.stdout).expect("proof report json");
    assert_eq!(proof_report["packageKind"], "proof");
    assert_eq!(proof_report["workflowId"], "workflow-release-control");
    assert_eq!(proof_report["verifierEquivalent"], false);
    assert_eq!(
        kernel_authority_step(&proof_report),
        TRUSTED_KERNEL_AUTHORITY
    );

    let inquiry_export = mercury(&[
        "inquiry".as_ref(),
        "export".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
        "--trust".as_ref(),
        trust.as_os_str(),
        "--output".as_ref(),
        inquiry_package_path.as_os_str(),
        "--audience".as_ref(),
        "compliance".as_ref(),
        "--redaction-profile".as_ref(),
        "internal-default".as_ref(),
        "--verifier-equivalent".as_ref(),
    ]);
    assert!(
        inquiry_export.status.success(),
        "stderr={}",
        stderr(&inquiry_export)
    );
    let stdout = String::from_utf8_lossy(&inquiry_export.stdout);
    assert!(
        stdout.contains("verifier_equivalent: false"),
        "stdout={stdout}"
    );

    let inquiry_verify = mercury(&[
        "--json".as_ref(),
        "verify".as_ref(),
        "--input".as_ref(),
        inquiry_package_path.as_os_str(),
        "--trust".as_ref(),
        trust.as_os_str(),
    ]);
    assert!(
        inquiry_verify.status.success(),
        "stderr={}",
        stderr(&inquiry_verify)
    );
    let inquiry_report: serde_json::Value =
        serde_json::from_slice(&inquiry_verify.stdout).expect("inquiry report json");
    assert_eq!(inquiry_report["packageKind"], "inquiry");
    assert_eq!(inquiry_report["verifierEquivalent"], false);

    paths.extend([inquiry_package_path, trust]);
    cleanup(paths);
}

#[test]
fn mercury_verify_refuses_without_trust_file() {
    let (proof_package_path, paths) = export_signed_proof_package("chio-mercury-no-trust");
    let output = mercury(&[
        "verify".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
    ]);
    assert_clap_refuses_missing_trust(&output);
    cleanup(paths);
}

#[test]
fn mercury_inquiry_export_refuses_without_trust_file() {
    let (proof_package_path, mut paths) =
        export_signed_proof_package("chio-mercury-inquiry-no-trust");
    let inquiry_package_path = unique_path("chio-mercury-inquiry-no-trust-out", ".json");
    let output = mercury(&[
        "inquiry".as_ref(),
        "export".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
        "--output".as_ref(),
        inquiry_package_path.as_os_str(),
        "--audience".as_ref(),
        "a".as_ref(),
    ]);
    assert_clap_refuses_missing_trust(&output);
    assert!(!inquiry_package_path.exists());
    paths.push(inquiry_package_path);
    cleanup(paths);
}

#[test]
fn mercury_verify_refuses_untrusted_kernel_key() {
    let (proof_package_path, mut paths) = export_signed_proof_package("chio-mercury-untrusted");
    let trust = untrusted_signer();
    let output = mercury(&[
        "verify".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
        "--trust".as_ref(),
        trust.as_os_str(),
    ]);
    assert_untrusted_receipt_refusal(&output, &proof_package_path);
    assert!(output.stdout.is_empty());
    paths.push(trust);
    cleanup(paths);
}

#[test]
fn mercury_inquiry_export_refuses_untrusted_kernel_key() {
    let (proof_package_path, mut paths) =
        export_signed_proof_package("chio-mercury-inquiry-untrusted");
    let inquiry_package_path = unique_path("chio-mercury-inquiry-untrusted-out", ".json");
    let trust = untrusted_signer();
    let output = mercury(&[
        "inquiry".as_ref(),
        "export".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
        "--trust".as_ref(),
        trust.as_os_str(),
        "--output".as_ref(),
        inquiry_package_path.as_os_str(),
        "--audience".as_ref(),
        "a".as_ref(),
    ]);
    assert_untrusted_receipt_refusal(&output, &proof_package_path);
    assert!(!inquiry_package_path.exists());
    paths.extend([inquiry_package_path, trust]);
    cleanup(paths);
}

#[test]
fn mercury_verify_accepts_trusted_kernel_key() {
    let (proof_package_path, mut paths) = export_signed_proof_package("chio-mercury-trusted");
    let trust = trusted_signer();
    let json = mercury(&[
        "--json".as_ref(),
        "verify".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
        "--trust".as_ref(),
        trust.as_os_str(),
    ]);
    assert_eq!(json.status.code(), Some(0), "stderr={}", stderr(&json));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).expect("report json");
    assert_eq!(kernel_authority_step(&report), TRUSTED_KERNEL_AUTHORITY);

    let human = mercury(&[
        "verify".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
        "--trust".as_ref(),
        trust.as_os_str(),
    ]);
    assert_eq!(human.status.code(), Some(0), "stderr={}", stderr(&human));
    assert_eq!(
        String::from_utf8_lossy(&human.stdout).lines().next(),
        Some("mercury proof package verified")
    );
    paths.push(trust);
    cleanup(paths);
}

#[test]
fn mercury_verify_refuses_missing_trust_file_path() {
    let (proof_package_path, paths) = export_signed_proof_package("chio-mercury-missing-trust");
    let missing = unique_path("chio-mercury-missing-trust-file", ".json");
    let output = mercury(&[
        "verify".as_ref(),
        "--input".as_ref(),
        proof_package_path.as_os_str(),
        "--trust".as_ref(),
        missing.as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(1), "stderr={}", stderr(&output));
    let prefix = format!(
        "urn:chio:error:cli:io [cli:error]: cannot open trust file {}: ",
        missing.display()
    );
    let hint = " (Check the path, permissions, and filesystem state before retrying.)";
    assert!(
        stderr(&output)
            .lines()
            .any(|line| line.starts_with(&prefix) && line.ends_with(hint)),
        "stderr={}",
        stderr(&output)
    );
    cleanup(paths);
}

fn kernel_keys(value: &serde_json::Value, keys: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(key)) = map.get("kernel_key") {
                keys.push(key.clone());
            }
            map.values().for_each(|child| kernel_keys(child, keys));
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| kernel_keys(item, keys)),
        _ => {}
    }
}

#[test]
fn mercury_pilot_export_pins_run_kernel_key() {
    let output_dir = unique_path("chio-mercury-pilot-pin", "");
    let output = mercury(&[
        "pilot".as_ref(),
        "export".as_ref(),
        "--output".as_ref(),
        output_dir.as_os_str(),
    ]);
    assert!(output.status.success(), "stderr={}", stderr(&output));
    let summary: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("pilot-summary.json")).expect("read pilot summary"),
    )
    .expect("pilot summary json");

    for run in ["primary", "rollback"] {
        let run_key = summary[run]["kernelPublicKey"]
            .as_str()
            .expect("run paths carry the run kernel key");
        let report: serde_json::Value = serde_json::from_slice(
            &fs::read(output_dir.join(run).join("proof-verification.json"))
                .expect("read proof verification"),
        )
        .expect("proof verification json");
        assert_eq!(kernel_authority_step(&report), TRUSTED_KERNEL_AUTHORITY);

        let package: serde_json::Value = serde_json::from_slice(
            &fs::read(output_dir.join(run).join("proof-package.json")).expect("read package"),
        )
        .expect("proof package json");
        let mut signers = Vec::new();
        kernel_keys(&package, &mut signers);
        assert!(!signers.is_empty(), "{run} package carries signed records");
        assert!(
            signers.iter().all(|key| key == run_key),
            "{run}: {signers:?}"
        );
    }

    cleanup([output_dir]);
}
