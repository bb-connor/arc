use super::*;

fn two_issuer_passport() -> AgentPassport {
    let subject = Keypair::from_seed(&[31u8; 32]);
    let credentials = [32u8, 33u8]
        .into_iter()
        .map(|seed| {
            issue_reputation_credential(
                &Keypair::from_seed(&[seed; 32]),
                sample_scorecard(&subject.public_key().to_hex()),
                sample_evidence(),
                1_710_000_000,
                1_710_086_400,
            )
            .expect("credential")
        })
        .collect();
    build_agent_passport(
        &did_from_public_key(subject.public_key()).to_string(),
        credentials,
    )
    .expect("passport")
}

fn record_with_digests(credential_digests: Vec<String>) -> PassportLifecycleRecord {
    let subject = Keypair::from_seed(&[34u8; 32]);
    let issuer = Keypair::from_seed(&[35u8; 32]);
    PassportLifecycleRecord {
        passport_id: "sha256:digest-record".to_string(),
        subject: did_from_public_key(subject.public_key()).to_string(),
        issuers: vec![did_from_public_key(issuer.public_key()).to_string()],
        issuer_count: 1,
        credential_digests,
        published_at: 1_710_000_000,
        updated_at: 1_710_000_000,
        status: PassportLifecycleState::Active,
        superseded_by: None,
        revoked_at: None,
        revoked_reason: None,
        distribution: PassportStatusDistribution::default(),
        valid_until: "2026-03-28T00:00:00Z".to_string(),
    }
}

#[test]
fn a_credential_digest_is_the_sha256_of_the_issuer_signed_body() {
    let passport = two_issuer_passport();
    for credential in &passport.credentials {
        let digest = credential_digest(credential).expect("digest");
        assert_eq!(
            digest,
            sha256_hex(&canonical_json_bytes(&credential.unsigned).expect("canonical body"))
        );
        assert_eq!(digest.len(), 64);
    }
    let digests = passport_credential_digests(&passport).expect("digests");
    assert_eq!(digests.len(), 2);
    assert!(digests.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn a_filtered_presentation_keeps_the_credential_digests() {
    let passport = two_issuer_passport();
    let kept = passport.credentials[1].unsigned.issuer.clone();
    let filtered = present_agent_passport(
        &passport,
        &PassportPresentationOptions {
            issuer_allowlist: [kept].into_iter().collect(),
            max_credentials: None,
        },
    )
    .expect("filtered presentation");
    assert_ne!(
        passport_artifact_id(&filtered).expect("filtered id"),
        passport_artifact_id(&passport).expect("original id")
    );
    let original = passport_credential_digests(&passport).expect("original digests");
    let presented = passport_credential_digests(&filtered).expect("presented digests");
    assert_eq!(
        presented,
        vec![credential_digest(&passport.credentials[1]).expect("digest")]
    );
    assert!(presented.iter().all(|digest| original.contains(digest)));
}

#[test]
fn a_record_without_credential_digests_is_refused() {
    let digest = "ab".repeat(32);
    let valid = record_with_digests(vec![digest.clone()]);
    valid.validate().expect("a record with one digest is valid");
    let mut encoded = serde_json::to_value(&valid).expect("encoded record");
    assert_eq!(encoded["credentialDigests"], json!([digest]));
    encoded
        .as_object_mut()
        .expect("record object")
        .remove("credentialDigests");
    assert!(serde_json::from_value::<PassportLifecycleRecord>(encoded).is_err());

    for digests in [
        Vec::new(),
        vec!["AB".repeat(32)],
        vec!["ab".repeat(31)],
        vec![format!("sha256:{}", "ab".repeat(32))],
        vec!["cd".repeat(32), "ab".repeat(32)],
        vec!["ab".repeat(32), "ab".repeat(32)],
    ] {
        let error = record_with_digests(digests.clone())
            .validate()
            .expect_err("malformed credential digests must be refused");
        assert!(
            matches!(error, CredentialError::InvalidPassportLifecycle(_)),
            "{digests:?}: {error}"
        );
    }
}

#[test]
fn a_credential_digest_ignores_every_proof_field() {
    let passport = two_issuer_passport();
    let credential = &passport.credentials[0];
    let digest = credential_digest(credential).expect("digest");
    let mutations: [fn(&mut CredentialProof); 5] = [
        |proof| proof.created = "2030-01-01T00:00:00Z".to_string(),
        |proof| proof.proof_type = "AnotherProof".to_string(),
        |proof| proof.proof_purpose = "authentication".to_string(),
        |proof| proof.verification_method = "did:chio:other#key-1".to_string(),
        |proof| proof.proof_value = "00".repeat(64),
    ];
    for mutate in mutations {
        let mut mutated = credential.clone();
        mutate(&mut mutated.proof);
        assert_ne!(mutated, *credential);
        assert_eq!(credential_digest(&mutated).expect("mutated digest"), digest);
    }

    let mut retimed = credential.clone();
    retimed.proof.created = "2030-01-01T00:00:00Z".to_string();
    verify_reputation_credential(&retimed, &passport_issuers(&passport), 1_710_000_100)
        .expect("proof.created is outside the signed body");

    let mut rebodied = credential.clone();
    rebodied.unsigned.expiration_date = "2030-01-01T00:00:00Z".to_string();
    assert_ne!(
        credential_digest(&rebodied).expect("rebodied digest"),
        digest
    );
}
