//! Signed certification checks and the entries publish records for them.

use chio_core::Keypair;

use super::*;
use crate::certify::artifact::sign_artifact;
use crate::certify::schema::{
    CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER, CERTIFICATION_SCHEMA,
    CRITERIA_PROFILE_ALL_PASS_V1, EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1,
    GENERATED_REPORT_MEDIA_TYPE_MARKDOWN,
};
use crate::certify::types::{
    CertificationCheckBody, CertificationEvidence, CertificationFinding, CertificationSummary,
    CertificationTarget, CertificationVerdict,
};

pub(crate) type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

pub(crate) const CHECKED_AT: u64 = 1_710_000_000;
const SIGNER_SEED: u8 = 81;

/// A signed check for `tool_server_id` whose single finding carries `pad`
/// extra ASCII bytes.
pub(crate) fn artifact(tool_server_id: &str, pad: usize) -> Fallible<SignedCertificationCheck> {
    let digest = "0".repeat(64);
    let body = CertificationCheckBody {
        schema: CERTIFICATION_SCHEMA.to_string(),
        criteria_profile: CRITERIA_PROFILE_ALL_PASS_V1.to_string(),
        checked_at: CHECKED_AT,
        target: CertificationTarget {
            tool_server_id: tool_server_id.to_string(),
            tool_server_name: Some("Capacity Fixture".to_string()),
        },
        verdict: CertificationVerdict::Pass,
        summary: CertificationSummary {
            scenario_count: 1,
            result_count: 1,
            evaluated_peer_count: 1,
            pass_count: 1,
            fail_count: 0,
            unsupported_count: 0,
            skipped_count: 0,
            xfail_count: 0,
            missing_scenarios_count: 0,
            unknown_results_count: 0,
        },
        criteria: Vec::new(),
        evidence: CertificationEvidence {
            evidence_profile: EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1.to_string(),
            scenarios_dir: "scenarios".to_string(),
            results_dir: "results".to_string(),
            normalized_scenarios_sha256: digest.clone(),
            normalized_results_sha256: digest.clone(),
            generated_report_sha256: digest,
            generated_report_bytes: 1,
            generated_report_media_type: GENERATED_REPORT_MEDIA_TYPE_MARKDOWN.to_string(),
            provenance_mode: CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER.to_string(),
            report_output: None,
        },
        findings: vec![CertificationFinding {
            kind: "note".to_string(),
            message: format!("capacity fixture {}", "p".repeat(pad)),
            scenario_id: None,
            peer: None,
            deployment_mode: None,
            transport: None,
            status: None,
        }],
    };
    Ok(sign_artifact(
        body,
        &Keypair::from_seed(&[SIGNER_SEED; 32]),
    )?)
}

/// The entry publish records for `artifact` at `published_at`.
pub(crate) fn published_entry(
    artifact: SignedCertificationCheck,
    published_at: u64,
) -> Fallible<CertificationRegistryEntry> {
    verify_signed_certification_check(&artifact)?;
    let artifact_id = certification_artifact_id(&artifact)?;
    Ok(CertificationRegistryEntry {
        artifact_sha256: artifact_id.clone(),
        artifact_id,
        tool_server_id: artifact.body.target.tool_server_id.clone(),
        tool_server_name: artifact.body.target.tool_server_name.clone(),
        verdict: artifact.body.verdict,
        checked_at: artifact.body.checked_at,
        published_at,
        status: CertificationRegistryState::Active,
        superseded_at: None,
        superseded_by: None,
        revoked_at: None,
        revoked_reason: None,
        dispute: None,
        artifact,
    })
}
