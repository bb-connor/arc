//! The verification report that crosses the buyer boundary carries the
//! stable rejection code and a fixed phrase, never the verifier's rendered
//! diagnostic.

use std::error::Error;

use chio_attest_buyer::verify_proof_package_json;
use chio_attest_buyer_core::report::{
    verifier_report_from_json, VerifierFailure, WITHHELD_FAILURE_DETAIL,
};

const PACKAGE_JSON: &str =
    include_str!("../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json");
const TRUST_BUNDLE_JSON: &str =
    include_str!("../../../../examples/chio-3vendor/fixtures/verifier-trust-bundle.json");
const CONTEXT_JSON: &str =
    include_str!("../../../../examples/chio-3vendor/fixtures/verification-context.json");

/// Move a tool receipt's timestamp. The receipt keeps the id its workflow
/// step and co-signed envelope name, so the tamper reaches the bilateral
/// verifier and is caught there.
fn tampered_package_json() -> Result<String, Box<dyn Error>> {
    let mut package: serde_json::Value = serde_json::from_str(PACKAGE_JSON)?;
    let timestamp = &mut package["toolReceipts"][0]["timestamp"];
    let moved = timestamp
        .as_u64()
        .ok_or("tool receipt carries no timestamp")?
        + 1;
    *timestamp = serde_json::Value::from(moved);
    Ok(serde_json::to_string(&package)?)
}

/// Every hexadecimal run in the text long enough to be a digest, a key, or
/// a key fingerprint.
fn hex_runs(text: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut run = String::new();
    for character in text.chars().chain(std::iter::once('\n')) {
        if character.is_ascii_digit() || ('a'..='f').contains(&character) {
            run.push(character);
            continue;
        }
        if run.len() >= 48 {
            runs.push(std::mem::take(&mut run));
        } else {
            run.clear();
        }
    }
    runs.sort();
    runs.dedup();
    runs
}

#[test]
fn untampered_package_verifies_through_the_buyer_boundary() -> Result<(), Box<dyn Error>> {
    let report = verify_proof_package_json(PACKAGE_JSON, TRUST_BUNDLE_JSON, CONTEXT_JSON)?;
    assert!(report.accepted);
    assert_eq!(report.failure_code, None);
    Ok(())
}

#[test]
fn tampered_package_report_crosses_the_boundary_as_a_code() -> Result<(), Box<dyn Error>> {
    let tampered = tampered_package_json()?;
    let secrets = hex_runs(&tampered);
    assert!(
        secrets.len() > 4,
        "fixture should carry several digests and fingerprints"
    );

    let report = verify_proof_package_json(&tampered, TRUST_BUNDLE_JSON, CONTEXT_JSON)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("subject.digest_mismatch")
    );
    assert!(report.json.contains("subject.digest_mismatch"));
    assert!(report.json.contains(WITHHELD_FAILURE_DETAIL));

    // A struct literal pins the whole failure object that crossed the
    // boundary, so no field can carry a digest, a fingerprint, or a policy
    // verdict.
    let exported = verifier_report_from_json(&report.json)?;
    assert_eq!(
        exported.failure,
        Some(VerifierFailure {
            code: "subject.digest_mismatch".to_string(),
            phase: "federation".to_string(),
            detail: WITHHELD_FAILURE_DETAIL.to_string(),
        })
    );

    for secret in secrets {
        assert!(
            !report.json.contains(&secret),
            "exported report leaks a package digest or fingerprint: {secret}"
        );
    }
    Ok(())
}
