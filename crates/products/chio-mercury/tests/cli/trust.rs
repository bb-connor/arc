//! `--trust` pinning on `mercury verify`, `inquiry export` and the pipeline exports.

use std::process::Output;

use chio_test_support::prelude::*;

use super::signed_reader::{
    export_signed_evidence, export_signed_proof_package, first_signed_receipt, mercury_proof_export,
};
use super::*;

const TRUST_MISSING_HELP: &str =
    "Pin the kernel key that signed the bundle in the trust file, obtained independently of the bundle.";
const FEATURE_UNSUPPORTED_HELP: &str =
    "Use a verifier that supports the feature, or remove it from the trust file requirements.";

const TRUSTED_KERNEL_AUTHORITY: &str =
    "every tool receipt, child receipt, and checkpoint signer is present in the trusted Mercury kernel-key set";

fn mercury(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .args(args)
        .output()
        .test_expect("run mercury")
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
        .test_expect("report carries a kernel_authority step")
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
        serde_json::from_slice(&fs::read(proof_package_path).test_expect("read proof package"))
            .test_expect("proof package json");
    let receipt_id = first_signed_receipt(&package).test_expect("package embeds a signed receipt")
        ["id"]
        .as_str()
        .test_expect("receipt id")
        .to_string();
    let expected = format!(
        "urn:chio:error:attest:bundle-trust-missing [attest:error]: tool receipt {receipt_id} \
         was signed by an untrusted Mercury kernel key ({TRUST_MISSING_HELP})"
    );
    assert_eq!(output.status.code(), Some(1), "stderr={}", stderr(output));
    assert!(
        stderr(output).lines().any(|line| line == expected),
        "stderr={}",
        stderr(output)
    );
}

/// The run kernel key a pipeline summary records for one run.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunKernelKey {
    kernel_public_key: chio_core::crypto::PublicKey,
}

#[derive(serde::Deserialize)]
struct ExportSummary {
    export: RunKernelKey,
}

#[derive(serde::Deserialize)]
struct PilotSummary {
    primary: RunKernelKey,
    rollback: RunKernelKey,
}

fn read_summary<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&fs::read(path).test_expect("read run summary"))
        .test_expect("run summary carries the run kernel key")
}

/// A trust file pinning the kernel key recorded in a pipeline summary's `export` paths.
pub(super) fn run_kernel_trust_file(summary_path: &Path) -> PathBuf {
    let summary: ExportSummary = read_summary(summary_path);
    kernel_trust_file(&summary.export.kernel_public_key)
}

/// A trust file pinning `key` that also sets `member` to `value`.
fn trust_file_with(
    key: &chio_core::crypto::PublicKey,
    member: &str,
    value: serde_json::Value,
) -> PathBuf {
    let path = kernel_trust_file(key);
    let mut trust: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).test_expect("read trust file"))
            .test_expect("trust file json");
    trust[member] = value;
    fs::write(
        &path,
        serde_json::to_vec(&trust).test_expect("encode trust file"),
    )
    .test_expect("write trust file");
    path
}

fn unenforced_member_refusal(member: &str) -> String {
    format!(
        "urn:chio:error:attest:bundle-feature-unsupported [attest:error]: Mercury enforces only \
         `kernel_keys`; the trust file sets `{member}` ({FEATURE_UNSUPPORTED_HELP})"
    )
}

fn has_line(output: &Output, expected: &str) -> bool {
    stderr(output).lines().any(|line| line == expected)
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
        serde_json::from_slice(&proof_verify.stdout).test_expect("proof report json");
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
        serde_json::from_slice(&inquiry_verify.stdout).test_expect("inquiry report json");
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
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).test_expect("report json");
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
    let keys: PilotSummary = read_summary(&output_dir.join("pilot-summary.json"));
    for (run, run_key) in [("primary", keys.primary), ("rollback", keys.rollback)] {
        let run_key = run_key.kernel_public_key.to_hex();
        let report: serde_json::Value = serde_json::from_slice(
            &fs::read(output_dir.join(run).join("proof-verification.json"))
                .test_expect("read proof verification"),
        )
        .test_expect("proof verification json");
        assert_eq!(kernel_authority_step(&report), TRUSTED_KERNEL_AUTHORITY);

        let package: serde_json::Value = serde_json::from_slice(
            &fs::read(output_dir.join(run).join("proof-package.json")).test_expect("read package"),
        )
        .test_expect("proof package json");
        let mut signers = Vec::new();
        kernel_keys(&package, &mut signers);
        assert!(!signers.is_empty(), "{run} package carries signed records");
        assert!(
            signers.iter().all(|key| *key == run_key),
            "{run}: {signers:?}"
        );
    }

    cleanup([output_dir]);
}

#[test]
fn mercury_refuses_trust_members_it_does_not_enforce() {
    let (proof_package_path, mut paths) = export_signed_proof_package("chio-mercury-unenforced");
    let kernel = Keypair::from_seed(&[58; 32]).public_key();
    let members = [
        (
            "checkpoint_keys",
            serde_json::json!([Keypair::from_seed(&[60; 32]).public_key().to_hex()]),
        ),
        (
            "checkpoint_trust_anchor",
            serde_json::json!({
                "publicationIdentity": {"kind": "local_log", "identity": "local-log-1"},
                "trustAnchorIdentity": {"kind": "transparency_root", "identity": "root-set-1"},
                "trustAnchorRef": "anchor-root-1",
                "signerCertRef": "cert-chain-1",
                "publicationProfileVersion": "profile-1"
            }),
        ),
        ("required_columns", serde_json::json!(["decision"])),
    ];
    for (member, value) in members {
        let trust = trust_file_with(&kernel, member, value);
        let output = mercury(&[
            "verify".as_ref(),
            "--input".as_ref(),
            proof_package_path.as_os_str(),
            "--trust".as_ref(),
            trust.as_os_str(),
        ]);
        assert_eq!(output.status.code(), Some(1), "stderr={}", stderr(&output));
        assert!(output.stdout.is_empty());
        assert!(
            has_line(&output, &unenforced_member_refusal(member)),
            "stderr={}",
            stderr(&output)
        );
        paths.push(trust);
    }
    cleanup(paths);
}

#[test]
fn mercury_and_chio_verify_agree_on_the_same_trust_file() {
    let evidence = export_signed_evidence("chio-mercury-parity");
    let proof_package_path = unique_path("chio-mercury-parity-proof-package", ".json");
    let export = mercury_proof_export(&evidence, &[&evidence.bundle_manifest], &proof_package_path);
    assert!(export.status.success(), "stderr={}", stderr(&export));
    let mut paths = evidence.cleanup.clone();
    paths.push(proof_package_path.clone());

    let chio_verify = |trust: &Path| {
        let trust = chio_bundle_verify::read_trust_file(trust).test_expect("read trust file");
        chio_bundle_verify::verify_bundle(&evidence.evidence_dir, &trust, None)
            .map(|verified| verified.report.exit_class(&trust))
    };
    let mercury_verify = |trust: &Path| {
        mercury(&[
            "verify".as_ref(),
            "--input".as_ref(),
            proof_package_path.as_os_str(),
            "--trust".as_ref(),
            trust.as_os_str(),
        ])
    };

    let accepted = chio_verify(&evidence.trust).test_expect("chio-verify accepts");
    assert_eq!(accepted.code(), 0);
    let output = mercury_verify(&evidence.trust);
    assert_eq!(output.status.code(), Some(0), "stderr={}", stderr(&output));

    let kernel = Keypair::from_seed(&[58; 32]).public_key();
    let identity_root = trust_file_with(
        &kernel,
        "required_columns",
        serde_json::json!(["identity_root"]),
    );
    let refused = chio_verify(&identity_root).test_expect("chio-verify reports");
    assert_eq!(refused.code(), 10);
    let output = mercury_verify(&identity_root);
    assert_eq!(output.status.code(), Some(1), "stderr={}", stderr(&output));
    assert!(
        has_line(&output, &unenforced_member_refusal("required_columns")),
        "stderr={}",
        stderr(&output)
    );

    let untrusted = untrusted_signer();
    let error = chio_verify(&untrusted).test_unwrap_err();
    assert_eq!(
        error.code_urn(),
        Some("urn:chio:error:attest:bundle-trust-missing")
    );
    assert_eq!(error.exit_class().code(), 50);
    let output = mercury_verify(&untrusted);
    assert_eq!(output.status.code(), Some(1), "stderr={}", stderr(&output));
    assert!(
        stderr(&output)
            .lines()
            .any(|line| line
                .starts_with("urn:chio:error:attest:bundle-trust-missing [attest:error]: ")),
        "stderr={}",
        stderr(&output)
    );

    paths.extend([identity_root, untrusted]);
    cleanup(paths);
}

#[test]
fn mercury_proof_export_refuses_a_manifest_without_a_signed_reference() {
    let evidence = export_signed_evidence("chio-mercury-unreferenced");
    let mut manifest = sample_mercury_bundle_manifest();
    manifest.bundle_id = "bundle-unreferenced".to_string();
    let unreferenced = unique_path("chio-mercury-unreferenced-manifest", ".json");
    fs::write(
        &unreferenced,
        serde_json::to_vec_pretty(&manifest).test_expect("encode bundle manifest"),
    )
    .test_expect("write bundle manifest");
    let proof_package_path = unique_path("chio-mercury-unreferenced-proof-package", ".json");
    let output = mercury_proof_export(
        &evidence,
        &[&evidence.bundle_manifest, &unreferenced],
        &proof_package_path,
    );
    assert_eq!(output.status.code(), Some(1), "stderr={}", stderr(&output));
    assert!(
        has_line(
            &output,
            "validation error: packaged Mercury bundle manifest has no signed receipt reference: \
             bundle-unreferenced"
        ),
        "stderr={}",
        stderr(&output)
    );
    assert!(!proof_package_path.exists());
    let mut paths = evidence.cleanup;
    paths.push(unreferenced);
    cleanup(paths);
}
