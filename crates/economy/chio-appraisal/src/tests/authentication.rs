use super::*;

#[test]
fn unsigned_claims_cannot_cross_the_attestation_trust_boundary() {
    for (schema, family) in [
        (
            AZURE_MAA_ATTESTATION_SCHEMA,
            AttestationVerifierFamily::AzureMaa,
        ),
        (
            AWS_NITRO_ATTESTATION_SCHEMA,
            AttestationVerifierFamily::AwsNitro,
        ),
        (
            GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
            AttestationVerifierFamily::GoogleAttestation,
        ),
        (
            ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA,
            AttestationVerifierFamily::EnterpriseVerifier,
        ),
    ] {
        let mut evidence = sample_evidence();
        evidence.schema = schema.to_owned();
        evidence.tier = RuntimeAssuranceTier::Verified;
        evidence.evidence_sha256 = "a".repeat(64);
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "matching-caller-claims".to_owned(),
                schema: schema.to_owned(),
                verifier: evidence.verifier.clone(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(family),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: Vec::new(),
                required_assertions: BTreeMap::new(),
            }],
        };
        // Matching a locally configured claim rule cannot authenticate its input.
        let matched = evidence
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .test_expect("all caller-controlled policy selectors should match");
        assert_eq!(matched.effective_tier, RuntimeAssuranceTier::Verified);
        let rejected = verify_runtime_attestation_record(&evidence, Some(&policy), 150);
        assert!(
            matches!(
                rejected,
                Err(RuntimeAttestationVerificationError::UnauthenticatedEvidence)
            ),
            "unsigned {family:?} fields must not produce an accepted record: {rejected:?}"
        );
    }
}

#[test]
fn signed_attestation_requires_the_local_authority_key() {
    let authority = crate::crypto::Keypair::generate();
    let caller = crate::crypto::Keypair::generate();
    let signed = SignedExportEnvelope::sign(sample_evidence(), &caller).test_unwrap();
    let policy = sample_trust_policy();
    assert!(matches!(
        verify_signed_runtime_attestation_record(
            &signed,
            &authority.public_key(),
            Some(&policy),
            150
        ),
        Err(RuntimeAttestationVerificationError::UntrustedSigner)
    ));
    // Replacing the declared signer cannot transfer a valid signature to the local pin.
    let mut replaced_signer = signed;
    replaced_signer.signer_key = authority.public_key();
    assert!(matches!(
        verify_signed_runtime_attestation_record(
            &replaced_signer,
            &authority.public_key(),
            Some(&policy),
            150
        ),
        Err(RuntimeAttestationVerificationError::InvalidSignature)
    ));
}

#[test]
fn signed_attestation_binds_every_authority_bearing_field() {
    let authority = crate::crypto::Keypair::generate();
    let signed = SignedExportEnvelope::sign(sample_evidence(), &authority).test_unwrap();
    let policy = sample_trust_policy();
    for mutation in 0..9 {
        let mut modified = signed.clone();
        match mutation {
            0 => modified.body.evidence_sha256 = "forged-digest".to_owned(),
            1 => modified.body.verifier = "https://different.test".to_owned(),
            2 => modified.body.schema = AWS_NITRO_ATTESTATION_SCHEMA.to_owned(),
            3 => modified.body.tier = RuntimeAssuranceTier::Verified,
            4 => modified.body.issued_at += 1,
            5 => modified.body.expires_at += 1,
            6 => modified.body.runtime_identity = Some("spiffe://attacker.test/worker".to_owned()),
            7 => modified.body.claims = Some(json!({"azureMaa":{"attestationType":"tdx"}})),
            8 => modified.body.workload_identity = None,
            _ => unreachable!(),
        }
        assert!(
            matches!(
                verify_signed_runtime_attestation_record(
                    &modified,
                    &authority.public_key(),
                    Some(&policy),
                    150
                ),
                Err(RuntimeAttestationVerificationError::InvalidSignature)
            ),
            "unsigned mutation {mutation} must fail authentication before policy appraisal"
        );
    }
}

#[test]
fn valid_signatures_do_not_bypass_policy_freshness_or_identity_binding() {
    let authority = crate::crypto::Keypair::generate();
    let policy = sample_trust_policy();
    let signed = SignedExportEnvelope::sign(sample_evidence(), &authority).test_unwrap();
    for now in [99, 201] {
        assert!(verify_signed_runtime_attestation_record(
            &signed,
            &authority.public_key(),
            Some(&policy),
            now
        )
        .is_err());
    }
    let mut old = sample_evidence();
    old.expires_at = 500;
    let old = SignedExportEnvelope::sign(old, &authority).test_unwrap();
    assert!(verify_signed_runtime_attestation_record(
        &old,
        &authority.public_key(),
        Some(&policy),
        250
    )
    .is_err());

    let mut conflicting = sample_evidence();
    conflicting.runtime_identity = Some("spiffe://attacker.test/worker".to_owned());
    let conflicting = SignedExportEnvelope::sign(conflicting, &authority).test_unwrap();
    assert!(matches!(
        verify_signed_runtime_attestation_record(
            &conflicting,
            &authority.public_key(),
            Some(&policy),
            150
        ),
        Err(RuntimeAttestationVerificationError::InvalidWorkloadIdentity(_))
    ));
    let mut unmatched = policy;
    unmatched.rules[0].verifier = "https://different.test".to_owned();
    assert!(matches!(
        verify_signed_runtime_attestation_record(
            &signed,
            &authority.public_key(),
            Some(&unmatched),
            150
        ),
        Err(RuntimeAttestationVerificationError::TrustPolicy(_))
    ));
    let observation =
        verify_signed_runtime_attestation_record(&signed, &authority.public_key(), None, 150)
            .test_unwrap();
    assert!(!observation.is_locally_accepted());
    assert_eq!(observation.effective_tier(), RuntimeAssuranceTier::None);
}
