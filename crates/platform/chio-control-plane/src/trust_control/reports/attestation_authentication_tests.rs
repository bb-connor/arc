use super::*;
use crate::policy::RuntimeAssuranceIssuancePolicy;
use chio_appraisal::{
    AttestationVerifierFamily, RuntimeAttestationAppraisalReasonCode,
    RuntimeAttestationAppraisalVerdict, RuntimeAttestationImportDisposition,
    RuntimeAttestationImportReasonCode, RuntimeAttestationImportedAppraisalPolicy,
    RuntimeAttestationNormalizedClaimConfidence, AZURE_MAA_ATTESTATION_SCHEMA,
};
use chio_core::capability::trust_policy::{AttestationTrustPolicy, AttestationTrustRule};
use chio_test_support::prelude::*;

fn unsigned_evidence() -> RuntimeAttestationEvidence {
    let now = unix_timestamp_now().test_expect("clock for observation fixture");
    RuntimeAttestationEvidence {
        schema: AZURE_MAA_ATTESTATION_SCHEMA.to_owned(),
        verifier: "https://maa.contoso.test".to_owned(),
        tier: RuntimeAssuranceTier::Verified,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "a".repeat(64),
        runtime_identity: Some("spiffe://chio/runtime/caller".to_owned()),
        workload_identity: None,
        claims: Some(serde_json::json!({"azureMaa": {"attestationType": "sgx"}})),
    }
}

fn matching_policy() -> RuntimeAssuranceIssuancePolicy {
    RuntimeAssuranceIssuancePolicy {
        tiers: Vec::new(),
        attestation_trust_policy: Some(AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "matching-unsigned-claims".to_owned(),
                schema: AZURE_MAA_ATTESTATION_SCHEMA.to_owned(),
                verifier: "https://maa.contoso.test".to_owned(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_owned()],
                required_assertions: BTreeMap::new(),
            }],
        }),
    }
}

fn assert_report_is_observation(report: &RuntimeAttestationAppraisalReport) {
    assert!(!report.policy_outcome.accepted);
    assert_eq!(
        report.policy_outcome.effective_tier,
        RuntimeAssuranceTier::None
    );
    assert!(report.policy_outcome.reason.is_some());
    assert_eq!(
        report.appraisal.verdict,
        RuntimeAttestationAppraisalVerdict::Rejected
    );
    assert_eq!(report.appraisal.effective_tier, RuntimeAssuranceTier::None);
    assert!(!report
        .appraisal
        .reason_codes
        .contains(&RuntimeAttestationAppraisalReasonCode::EvidenceVerified));
    assert_eq!(
        report.appraisal.normalized_assertions["attestationType"],
        "sgx"
    );
    assert_eq!(
        report.appraisal.normalized_assertions["runtimeIdentity"],
        "spiffe://chio/runtime/caller"
    );
    assert!(report
        .appraisal
        .normalized_claims
        .iter()
        .all(|claim| claim.confidence == RuntimeAttestationNormalizedClaimConfidence::Derived));
    let artifact = report
        .appraisal
        .artifact
        .as_ref()
        .test_expect("portable observation artifact");
    assert_eq!(
        artifact.policy.verdict,
        RuntimeAttestationAppraisalVerdict::Rejected
    );
    assert_eq!(artifact.policy.effective_tier, RuntimeAssuranceTier::None);
    assert!(!artifact
        .policy
        .reason_codes
        .contains(&RuntimeAttestationAppraisalReasonCode::EvidenceVerified));
    assert_eq!(
        artifact.claims.normalized_assertions["attestationType"],
        "sgx"
    );
    assert!(artifact
        .claims
        .normalized_claims
        .iter()
        .all(|claim| claim.confidence == RuntimeAttestationNormalizedClaimConfidence::Derived));
}

#[test]
fn raw_attestation_export_without_policy_is_only_observation() {
    let directory = chio_test_support::private_tempdir().test_expect("private export fixture");
    let seed = directory.path().join("authority.seed");
    let authority =
        load_behavioral_feed_signing_keypair(Some(&seed), None).test_expect("local authority");
    let report = build_signed_runtime_attestation_appraisal_report(
        Some(&seed),
        None,
        None,
        &unsigned_evidence(),
    )
    .test_expect("signed observation");
    assert_eq!(report.signer_key, authority.public_key());
    assert!(report.verify_signature().test_expect("export signature"));
    assert!(!report.body.policy_outcome.trust_policy_configured);
    assert_report_is_observation(&report.body);
}

#[test]
fn raw_attestation_export_matching_policy_is_only_observation() {
    let directory = chio_test_support::private_tempdir().test_expect("private export fixture");
    let seed = directory.path().join("authority.seed");
    let evidence = unsigned_evidence();
    let policy = matching_policy();
    let resolved = evidence
        .resolve_effective_runtime_assurance(
            policy.attestation_trust_policy.as_ref(),
            unix_timestamp_now().test_expect("clock"),
        )
        .test_expect("unsigned selectors match the rule");
    assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
    let report = build_signed_runtime_attestation_appraisal_report(
        Some(&seed),
        None,
        Some(&policy),
        &evidence,
    )
    .test_expect("signed observation");
    assert!(report.verify_signature().test_expect("export signature"));
    assert!(report.body.policy_outcome.trust_policy_configured);
    assert_report_is_observation(&report.body);
}

#[test]
fn raw_attestation_export_import_cannot_restore_authority() {
    for configured in [false, true] {
        let directory = chio_test_support::private_tempdir().test_expect("private result fixture");
        let seed = directory.path().join("authority.seed");
        let authority =
            load_behavioral_feed_signing_keypair(Some(&seed), None).test_expect("local authority");
        let policy = matching_policy();
        let signed_result = build_signed_runtime_attestation_appraisal_result(
            Some(&seed),
            None,
            configured.then_some(&policy),
            &RuntimeAttestationAppraisalResultExportRequest {
                issuer: "trusted-exporter".to_owned(),
                runtime_attestation: unsigned_evidence(),
            },
        )
        .test_expect("signed observation result");
        assert_eq!(signed_result.signer_key, authority.public_key());
        assert!(signed_result
            .verify_signature()
            .test_expect("result signature"));
        let imported = build_runtime_attestation_appraisal_import_report(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["trusted-exporter".to_owned()],
                    trusted_signer_keys: vec![authority.public_key().to_hex()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
                    max_result_age_seconds: Some(120),
                    max_evidence_age_seconds: Some(120),
                    maximum_effective_tier: Some(RuntimeAssuranceTier::Verified),
                    required_claims: BTreeMap::new(),
                },
            },
            unix_timestamp_now().test_expect("import time"),
        );
        assert_eq!(
            imported.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        assert_eq!(
            imported.local_policy_outcome.effective_tier,
            RuntimeAssuranceTier::None
        );
        assert!(imported
            .local_policy_outcome
            .reason_codes
            .contains(&RuntimeAttestationImportReasonCode::ExporterPolicyRejected));
    }
}
