#[test]
fn runtime_attestation_trust_policy_rebinds_effective_tier() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: Some(60),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };

    let resolved = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect("resolve effective tier");
    assert_eq!(resolved.raw_tier, RuntimeAssuranceTier::Attested);
    assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
    assert_eq!(resolved.matched_rule.as_deref(), Some("azure-contoso"));
}

#[test]
fn runtime_attestation_trust_policy_rejects_stale_verified_evidence() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 400,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: Some(30),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };

    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("stale evidence should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::EvidenceTooOld { .. }
    ));
}

#[test]
fn runtime_attestation_trust_policy_rejects_disallowed_attestation_type() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sev_snp"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: None,
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };

    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("unexpected attestation type should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::DisallowedAttestationType { .. }
    ));
}

#[test]
fn runtime_attestation_trust_policy_rejects_untrusted_verifier() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.untrusted.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: None,
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: None,
            allowed_attestation_types: Vec::new(),
            required_assertions: BTreeMap::new(),
        }],
    };

    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("untrusted verifier should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::UntrustedEvidence { .. }
    ));
}

#[test]
fn runtime_attestation_trust_policy_matches_google_family_and_required_assertions() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest-google".to_string(),
        runtime_identity: Some(
            "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1".to_string(),
        ),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV",
                "secureBoot": "enabled"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "google-confidential".to_string(),
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
            max_evidence_age_seconds: Some(60),
            allowed_attestation_types: vec!["confidential_vm".to_string()],
            required_assertions: BTreeMap::from([
                ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                ("secureBoot".to_string(), "enabled".to_string()),
            ]),
        }],
    };

    let resolved = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect("google attestation should satisfy appraisal-aware trust policy");
    assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
    assert_eq!(
        resolved.matched_rule.as_deref(),
        Some("google-confidential")
    );
}

#[test]
fn runtime_attestation_trust_policy_rejects_missing_required_assertion() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest-google".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "google-confidential".to_string(),
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
            max_evidence_age_seconds: Some(60),
            allowed_attestation_types: vec!["confidential_vm".to_string()],
            required_assertions: BTreeMap::from([(
                "secureBoot".to_string(),
                "enabled".to_string(),
            )]),
        }],
    };

    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("missing secureBoot assertion should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::MissingAssertion { .. }
    ));
}

#[test]
fn runtime_attestation_trust_policy_covers_remaining_fail_closed_paths() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "secureBoot": "enabled"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: None,
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };
    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("missing attestationType should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::MissingAttestationType { .. }
    ));

    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest-google".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_INTEL_TDX",
                "secureBoot": "enabled"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "google-confidential".to_string(),
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
            max_evidence_age_seconds: None,
            allowed_attestation_types: vec!["confidential_vm".to_string()],
            required_assertions: BTreeMap::from([(
                "hardwareModel".to_string(),
                "GCP_AMD_SEV".to_string(),
            )]),
        }],
    };
    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("mismatched required assertion should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::AssertionMismatch { .. }
    ));

    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.unsupported.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: None,
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "unsupported".to_string(),
            schema: "chio.runtime-attestation.unsupported.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: None,
            max_evidence_age_seconds: None,
            allowed_attestation_types: Vec::new(),
            required_assertions: BTreeMap::new(),
        }],
    };
    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("unsupported evidence schema should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::UnsupportedEvidence { .. }
    ));
}

#[test]
fn operation_serde_roundtrip() {
    let ops = vec![
        Operation::Invoke,
        Operation::ReadResult,
        Operation::Delegate,
    ];
    let json = serde_json::to_string(&ops).unwrap();
    let restored: Vec<Operation> = serde_json::from_str(&json).unwrap();
    assert_eq!(ops, restored);
}

#[test]
fn attenuation_serde_roundtrip() {
    let attenuations = vec![
        Attenuation::RemoveTool {
            server_id: "srv".to_string(),
            tool_name: "danger".to_string(),
        },
        Attenuation::RemoveOperation {
            server_id: "srv".to_string(),
            tool_name: "tool".to_string(),
            operation: Operation::Delegate,
        },
        Attenuation::AddConstraint {
            server_id: "srv".to_string(),
            tool_name: "tool".to_string(),
            constraint: Constraint::PathPrefix("/safe".to_string()),
        },
        Attenuation::ReduceBudget {
            server_id: "srv".to_string(),
            tool_name: "tool".to_string(),
            max_invocations: 5,
        },
        Attenuation::ShortenExpiry {
            new_expires_at: 9999,
        },
    ];

    let json = serde_json::to_string_pretty(&attenuations).unwrap();
    let restored: Vec<Attenuation> = serde_json::from_str(&json).unwrap();
    assert_eq!(attenuations, restored);
}

#[test]
fn ed25519_capability_token_is_byte_identical_without_algorithm_field() {
    // Pre-existing Ed25519 tokens must serialize without any `algorithm`
    // envelope field, so captured on-disk receipts and capability
    // artifacts continue to round-trip through the schema validators.
    let kp = Keypair::generate();
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-compat".to_string(),
        issuer: kp.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();
    let json = serde_json::to_value(&token).unwrap();
    assert!(
        json.get("algorithm").is_none(),
        "Ed25519 tokens must omit the `algorithm` envelope field"
    );
    assert!(token.verify_signature().unwrap());
}

#[test]
fn capability_token_backend_signing_with_ed25519_verifies() {
    let keypair = Keypair::from_seed(&[42_u8; 32]);
    let backend = crate::crypto::Ed25519Backend::new(Keypair::from_seed(&[42_u8; 32]));
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-backend".to_string(),
        issuer: backend.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let keypair_token = CapabilityToken::sign(body.clone(), &keypair).unwrap();
    let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
    assert_eq!(
        token.algorithm,
        Some(crate::crypto::SigningAlgorithm::Ed25519)
    );
    assert!(token.verify_signature().unwrap());
    assert_eq!(
        serde_json::to_vec(&token).unwrap(),
        serde_json::to_vec(&keypair_token).unwrap()
    );
}

#[test]
fn capability_token_backend_rejects_same_algorithm_wrong_key_signature() {
    let backend = SameAlgorithmWrongKeyBackend {
        advertised_keypair: Keypair::generate(),
        signing_keypair: Keypair::generate(),
    };
    let body =
        capability_backend_test_body(backend.public_key(), "cap-backend-same-algorithm-wrong-key");

    match CapabilityToken::sign_with_backend(body, &backend).unwrap_err() {
        Error::InvalidSignature(reason) => assert_eq!(
            reason,
            "signing backend returned a signature from a different identity"
        ),
        error => panic!("expected invalid signature, got {error:?}"),
    }
}

#[test]
fn capability_token_backend_rejects_public_key_algorithm_mismatch() {
    let backend = CapabilityAlgorithmMismatchBackend {
        keypair: Keypair::generate(),
    };
    let body = capability_backend_test_body(
        backend.public_key(),
        "cap-backend-public-key-algorithm-mismatch",
    );

    match CapabilityToken::sign_with_backend(body, &backend).unwrap_err() {
        Error::InvalidSignature(reason) => assert_eq!(
            reason,
            "signing backend algorithm does not match public key"
        ),
        error => panic!("expected invalid signature, got {error:?}"),
    }
}

#[test]
fn capability_token_backend_rejects_returned_signature_algorithm_mismatch() {
    let backend = CapabilitySignatureAlgorithmMismatchBackend {
        keypair: Keypair::generate(),
    };
    let body = capability_backend_test_body(
        backend.public_key(),
        "cap-backend-signature-algorithm-mismatch",
    );

    match CapabilityToken::sign_with_backend(body, &backend).unwrap_err() {
        Error::InvalidSignature(reason) => assert_eq!(
            reason,
            "signing backend returned a signature from a different identity"
        ),
        error => panic!("expected invalid signature, got {error:?}"),
    }
}

#[cfg(feature = "fips")]
#[test]
fn capability_token_p256_round_trip() {
    // A capability token signed with P-256 verifies when reconstructed
    // through the exact same API path the kernel uses
    // (`verify_signature` -> `PublicKey::verify_canonical`).
    let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-p256".to_string(),
        issuer: backend.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
    assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P256));
    assert!(token.verify_signature().unwrap());

    // Round-trip through JSON (the wire format the kernel receives).
    let wire = serde_json::to_string(&token).unwrap();
    assert!(wire.contains("\"p256:"));
    assert!(wire.contains("\"algorithm\":\"p256\""));
    let restored: CapabilityToken = serde_json::from_str(&wire).unwrap();
    assert!(restored.verify_signature().unwrap());
}

#[cfg(feature = "fips")]
#[test]
fn capability_token_p384_round_trip() {
    let backend = crate::crypto::P384Backend::generate().expect("p384 backend");
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-p384".to_string(),
        issuer: backend.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
    assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P384));
    assert!(token.verify_signature().unwrap());
}

#[cfg(feature = "fips")]
#[test]
fn capability_token_p256_tampered_body_fails() {
    let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-tamper".to_string(),
        issuer: backend.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let mut token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
    token.id = "cap-tampered".to_string();
    assert!(!token.verify_signature().unwrap());
}

#[cfg(feature = "fips")]
#[test]
fn governed_approval_token_p256_verifies() {
    let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
    let subject = Keypair::generate();
    let body = GovernedApprovalTokenBody {
        id: "approval-p256".to_string(),
        approver: backend.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: "hash-xyz".to_string(),
        threshold_proposal_hash: None,
        request_id: "req-1".to_string(),
        issued_at: 1000,
        expires_at: 2000,
        decision: GovernedApprovalDecision::Approved,
    };
    let token = GovernedApprovalToken::sign_with_backend(body, &backend).unwrap();
    assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P256));
    assert!(token.verify_signature().unwrap());
}

// ----- `delegate` mint helper -----------------------------------

#[cfg(feature = "delegation")]
fn delegate_parent_token(
    parent_kp: &Keypair,
    subject_kp: &Keypair,
    scope: ChioScope,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-parent".to_string(),
        issuer: parent_kp.public_key(),
        subject: subject_kp.public_key(),
        scope,
        issued_at,
        expires_at,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, parent_kp).unwrap()
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_mints_signed_link_for_subset_scope() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope.clone(), 1000, 2000);
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    let receipt = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [7_u8; 16],
    )
    .unwrap();

    assert!(receipt.link.verify_signature().unwrap());
    assert_eq!(
        receipt.link.scope_hash,
        Some(scope_hash(&parent_scope).unwrap())
    );
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_widening_scope() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    // Child tries to add a non-parent operation, widening the parent.
    let widened = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::ReadResult],
    )]);

    let err = delegate(
        &parent,
        &widened,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_parent_without_delegate_operation() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope.clone(), 1000, 2000);

    let err = delegate(
        &parent,
        &parent_scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_extending_expiry() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    let attenuation = crate::delegation_receipt::ScopeAttenuation {
        steps: vec![],
        child_expires_at: Some(3000), // > parent.expires_at
        budget_share_bps: None,
    };
    let err = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));

    // sanity: at-or-below parent expiry is accepted.
    let ok = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation {
            steps: vec![],
            child_expires_at: Some(1800),
            budget_share_bps: None,
        },
        1500,
        [0_u8; 16],
    );
    assert!(ok.is_ok());
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_wrong_delegator_key() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let imposter = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    let err = delegate(
        &parent,
        &scope,
        &imposter, // not parent.subject
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_tampered_parent_signature() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let mut parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    parent.id = "cap-parent-tampered".to_string();

    let err = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();

    assert!(matches!(err, Error::SignatureVerificationFailed));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_parent_before_issued_at() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    let err = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        999,
        [0_u8; 16],
    )
    .unwrap_err();

    assert!(matches!(
        err,
        Error::CapabilityNotYetValid { not_before: 1000 }
    ));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_signed_at_at_or_after_parent_expiry() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    let err = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        2000, // == parent.expires_at
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

// ---------------------------------------------------------------------------
// Time-checked verify entry points fold the validity window into the
// signature-verification path so "signature-valid" cannot diverge from
// "unexpired". Each checked entry point is fail-closed and signature-first.
// ---------------------------------------------------------------------------

fn bac573_capability_token(issued_at: u64, expires_at: u64) -> (Keypair, CapabilityToken) {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "bac573-cap".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![make_grant(
            "srv-a",
            "file_read",
            vec![Operation::Invoke],
        )]),
        issued_at,
        expires_at,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();
    (kp, token)
}

#[test]
fn bac573_capability_token_verify_at_within_window_passes() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    assert!(token.verify_signature_at(1500).unwrap());
    // Boundaries: issued_at is inclusive, expires_at is exclusive.
    assert!(token.verify_signature_at(1000).unwrap());
}

#[test]
fn bac573_capability_token_verify_at_expired_is_rejected() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    // now == expires_at and now > expires_at both reject (fail-closed).
    assert!(matches!(
        token.verify_signature_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_signature_at(9999),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
}

#[test]
fn bac573_capability_token_verify_at_not_yet_valid_is_rejected() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    assert!(matches!(
        token.verify_signature_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_capability_token_verify_at_bad_signature_fails_before_time_check() {
    // An expired token whose signature is ALSO invalid must report the
    // signature failure (Ok(false)), not the time error: signature is checked
    // first, so the time window cannot leak through a forged token.
    let (_kp, mut token) = bac573_capability_token(1000, 2000);
    token.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!token.verify_signature_at(9999).unwrap());
    // And in-window with a broken signature is still a plain rejection.
    assert!(!token.verify_signature_at(1500).unwrap());
}

#[test]
fn bac573_capability_token_verify_with_floor_at_folds_time_and_floor() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    // In-window + allowed floor verifies.
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::AllowClassical, 1500),
        Ok(true)
    ));
    // In-window but floor rejects classical: floor error, not a time error.
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::PqRequired, 1500),
        Err(CapabilityFloorVerifyError::RejectedByCryptoFloor { .. })
    ));
    // Floor + signature pass but expired: surfaced as Crypto(CapabilityExpired).
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::AllowClassical, 2000),
        Err(CapabilityFloorVerifyError::Crypto(
            Error::CapabilityExpired { expires_at: 2000 }
        ))
    ));
    // Not yet valid: surfaced as Crypto(CapabilityNotYetValid).
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::AllowClassical, 999),
        Err(CapabilityFloorVerifyError::Crypto(
            Error::CapabilityNotYetValid { not_before: 1000 }
        ))
    ));
}

#[test]
fn bac573_capability_token_verify_with_floor_at_bad_signature_fails_first() {
    let (_kp, mut token) = bac573_capability_token(1000, 2000);
    // Break the signature, then verify an expired window.
    token.subject = Keypair::generate().public_key();
    // Expired AND broken signature: floor ok, signature fails -> Ok(false),
    // never the time error.
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::AllowClassical, 9999),
        Ok(false)
    ));
}

fn bac573_approval_token(issued_at: u64, expires_at: u64) -> (Keypair, GovernedApprovalToken) {
    let approver = Keypair::generate();
    let body = GovernedApprovalTokenBody {
        id: "bac573-approval".to_string(),
        approver: approver.public_key(),
        subject: Keypair::generate().public_key(),
        governed_intent_hash: "intent-hash".to_string(),
        threshold_proposal_hash: None,
        request_id: "req-1".to_string(),
        issued_at,
        expires_at,
        decision: GovernedApprovalDecision::Approved,
    };
    let token = GovernedApprovalToken::sign(body, &approver).unwrap();
    (approver, token)
}

#[test]
fn bac573_approval_token_verify_at_window_enforced() {
    let (_approver, token) = bac573_approval_token(1000, 2000);
    assert!(token.verify_signature_at(1500).unwrap());
    assert!(matches!(
        token.verify_signature_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_signature_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_approval_token_verify_at_bad_signature_fails_first() {
    let (_approver, mut token) = bac573_approval_token(1000, 2000);
    // Break the signature; expired and forged -> signature failure first.
    token.subject = Keypair::generate().public_key();
    assert!(!token.verify_signature_at(9999).unwrap());
}

fn bac573_upstream_proof(
    issued_at: u64,
    expires_at: u64,
) -> (Keypair, GovernedUpstreamCallChainProof) {
    let signer = Keypair::generate();
    let proof = GovernedUpstreamCallChainProof::sign(
        GovernedUpstreamCallChainProofBody {
            signer: signer.public_key(),
            subject: Keypair::generate().public_key(),
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
            issued_at,
            expires_at,
        },
        &signer,
    )
    .unwrap();
    (signer, proof)
}

#[test]
fn bac573_upstream_proof_verify_at_window_enforced() {
    let (_signer, proof) = bac573_upstream_proof(1000, 2000);
    assert!(proof.verify_signature_at(1500).unwrap());
    assert!(matches!(
        proof.verify_signature_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        proof.verify_signature_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_upstream_proof_verify_at_bad_signature_fails_first() {
    let (_signer, mut proof) = bac573_upstream_proof(1000, 2000);
    proof.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!proof.verify_signature_at(9999).unwrap());
}

fn bac573_continuation_token(
    issued_at: u64,
    expires_at: u64,
) -> (Keypair, CallChainContinuationToken) {
    let signer = Keypair::generate();
    let subject = Keypair::generate();
    let token = CallChainContinuationToken::sign(
        CallChainContinuationTokenBody {
            schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
            token_id: "continuation-1".to_string(),
            signer: signer.public_key(),
            subject: subject.public_key(),
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            parent_receipt_hash: Some("receipt-hash-1".to_string()),
            parent_session_anchor: None,
            current_subject: subject.public_key().to_hex(),
            delegator_subject: "delegator-subject".to_string(),
            origin_subject: "origin-subject".to_string(),
            parent_capability_id: Some("cap-parent-1".to_string()),
            delegation_link_hash: Some("delegation-link-hash-1".to_string()),
            governed_intent_hash: Some("intent-hash-1".to_string()),
            audience: None,
            nonce: Some("nonce-1".to_string()),
            issued_at,
            expires_at,
        },
        &signer,
    )
    .unwrap();
    (signer, token)
}

#[test]
fn bac573_continuation_token_verify_at_window_enforced() {
    let (_signer, token) = bac573_continuation_token(1000, 2000);
    assert!(token.verify_signature_at(1500).unwrap());
    assert!(matches!(
        token.verify_signature_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_signature_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_continuation_token_verify_at_bad_signature_fails_first() {
    let (_signer, mut token) = bac573_continuation_token(1000, 2000);
    token.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!token.verify_signature_at(9999).unwrap());
}

// ---------------------------------------------------------------------------
// Attenuation-step narrowing + parent-relative budget_share_bps.
// ---------------------------------------------------------------------------

#[cfg(feature = "delegation")]
fn capped_grant(
    server: &str,
    tool: &str,
    ops: Vec<Operation>,
    max_invocations: Option<u32>,
    max_total_cost: Option<MonetaryAmount>,
) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: ops,
        constraints: vec![],
        max_invocations,
        max_cost_per_invocation: None,
        max_total_cost,
        dpop_required: None,
    }
}

/// A valid narrowing step (reduce max_invocations below the parent cap) is
/// accepted and rides onto the signed link.
#[cfg(feature = "delegation")]
#[test]
fn delegate_accepts_valid_narrowing_step() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
        Some(10),
        None,
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child scope narrows max_invocations 10 -> 4; the step mirrors that.
    let child_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke],
        Some(4),
        None,
    )]);
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::ReduceBudget {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        max_invocations: 4,
    }]);

    let receipt = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [9_u8; 16],
    )
    .unwrap();
    assert!(receipt.link.verify_signature().unwrap());
    assert_eq!(receipt.link.attenuations.len(), 1);
}

/// A widening step (raise max_invocations above the parent cap) is rejected
/// fail-closed even though the child *scope* itself is a subset.
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_widening_step() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
        Some(10),
        None,
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child scope is a valid subset (max 5 <= 10), so subset validation passes,
    // but the step claims a budget of 50 invocations -- a widening.
    let child_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke],
        Some(5),
        None,
    )]);
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::ReduceBudget {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        max_invocations: 50, // > parent cap 10
    }]);

    let err = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// A step targeting a tool the parent never held is a widening and rejected.
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_step_for_unknown_tool() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::AddConstraint {
        server_id: "srv-a".to_string(),
        tool_name: "tool-NOT-IN-PARENT".to_string(),
        constraint: Constraint::MaxLength(8),
    }]);

    let err = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// A monetary cost step in a different currency than the parent's cap is
/// rejected (same currency required for a meaningful narrowing comparison).
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_cost_step_currency_switch() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
        None,
        Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        }),
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let child_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke],
        None,
        Some(MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        }),
    )]);

    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::ReduceTotalCost {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        // Lower number but different currency: not a valid narrowing.
        max_total_cost: MonetaryAmount {
            units: 1,
            currency: "EUR".to_string(),
        },
    }]);

    let err = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// A child budget_share_bps within the parent's share is accepted; one that
/// exceeds the parent's share is rejected parent-relative.
#[cfg(feature = "delegation")]
#[test]
fn delegate_enforces_parent_relative_budget_share() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    // Parent only holds 30% of the budget; re-sign as an attenuated token so the
    // budget_share_bps is covered by the signature and verify_signature() passes.
    let plain = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let attenuated_parent = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: plain.body(),
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&plain.scope).unwrap(),
                child_scope_hash: scope_hash(&plain.scope).unwrap(),
                normalized_subset_proof: compute_attenuation_witness(&plain.scope, &plain.scope)
                    .unwrap(),
                aggregate_family_preservation: None,
            },
            budget_share_bps: Some(3_000),
        },
        &issuer,
    )
    .unwrap();
    assert!(attenuated_parent.verify_signature().unwrap());
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    // A child claiming 50% exceeds the parent's 30% -> reject.
    let over = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: Some(5_000),
    };
    let err = delegate(
        &attenuated_parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        over,
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));

    // A child claiming 20% is within the parent's 30% -> accept.
    let within = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: Some(2_000),
    };
    let ok = delegate(
        &attenuated_parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        within,
        1500,
        [1_u8; 16],
    );
    assert!(ok.is_ok());
}

/// When the parent is budget-attenuated (holds a reduced `budget_share_bps`), a
/// child that omits its own `budget_share_bps` is rejected fail-closed:
/// downstream admission treats a missing child share as the full 100% ceiling,
/// so omission would silently widen the parent's reduced share. A child that
/// states an explicit share `<=` the parent's is accepted.
#[cfg(feature = "delegation")]
#[test]
fn delegate_requires_child_share_under_attenuated_parent() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    // Parent only holds 30% of the budget; re-sign as an attenuated token so the
    // budget_share_bps is covered by the signature and verify_signature() passes.
    let plain = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let attenuated_parent = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: plain.body(),
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&plain.scope).unwrap(),
                child_scope_hash: scope_hash(&plain.scope).unwrap(),
                normalized_subset_proof: compute_attenuation_witness(&plain.scope, &plain.scope)
                    .unwrap(),
                aggregate_family_preservation: None,
            },
            budget_share_bps: Some(3_000),
        },
        &issuer,
    )
    .unwrap();
    assert!(attenuated_parent.verify_signature().unwrap());
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    // Child OMITS budget_share_bps while the parent holds a reduced 30% share ->
    // reject: an absent child share would widen to the full budget downstream.
    let omitted = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: None,
    };
    let err = delegate(
        &attenuated_parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        omitted,
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));

    // Child states an explicit share within the parent's 30% -> accept.
    let within = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: Some(2_500),
    };
    let ok = delegate(
        &attenuated_parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        within,
        1500,
        [2_u8; 16],
    );
    assert!(ok.is_ok());
}
