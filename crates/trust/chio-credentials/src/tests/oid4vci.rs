use super::*;

#[test]
fn oid4vci_passport_metadata_offer_and_response_validate() {
    let issuer = Keypair::from_seed(&[1u8; 32]);
    let subject = Keypair::from_seed(&[7u8; 32]);
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&subject.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .expect("credential");
    let subject_did = did_from_public_key(subject.public_key());
    let passport =
        build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

    let metadata =
        default_oid4vci_passport_issuer_metadata("https://trust.example.com").expect("meta");
    let offer = build_oid4vci_passport_offer(
        &metadata,
        CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID,
        "pre-auth-code",
        &passport,
        1_710_000_300,
    )
    .expect("offer");
    offer
        .validate_against_metadata(&metadata)
        .expect("offer valid");

    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre auth code")
            .to_string(),
    };
    token_request.validate().expect("token request valid");

    let credential_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_OID4VCI_FORMAT.to_string()),
        subject: passport.subject.clone(),
    };
    let resolved_configuration_id = credential_request
        .validate_against_metadata(&metadata)
        .expect("credential request valid");
    assert_eq!(
        resolved_configuration_id,
        CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID
    );

    let response = Oid4vciCredentialResponse::new(CHIO_PASSPORT_OID4VCI_FORMAT, passport.clone())
        .expect("response");
    response
        .validate(
            1_710_000_100,
            Some(CHIO_PASSPORT_OID4VCI_FORMAT),
            Some(&passport.subject),
        )
        .expect("credential response valid");
}

#[test]
fn oid4vci_credential_request_rejects_subject_and_format_mismatch() {
    let metadata =
        default_oid4vci_passport_issuer_metadata("https://trust.example.com").expect("meta");
    let request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some("wrong-format".to_string()),
        subject: "did:example:not-chio".to_string(),
    };

    let error = request
        .validate_against_metadata(&metadata)
        .expect_err("mismatched request should fail");
    assert!(matches!(
        error,
        CredentialError::Did(_) | CredentialError::InvalidOid4vciCredentialRequest(_)
    ));
}

#[test]
fn oid4vci_metadata_and_response_can_carry_passport_status_distribution() {
    let issuer = Keypair::from_seed(&[2u8; 32]);
    let subject = Keypair::from_seed(&[8u8; 32]);
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&subject.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .expect("credential");
    let subject_did = did_from_public_key(subject.public_key());
    let passport =
        build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
    let passport_id = passport_artifact_id(&passport).expect("passport id");

    let distribution = PassportStatusDistribution {
        resolve_urls: vec![
            "https://trust.example.com/v1/public/passport/statuses/resolve".to_string(),
        ],
        cache_ttl_secs: Some(300),
    };
    let metadata = default_oid4vci_passport_issuer_metadata_with_status_distribution(
        "https://trust.example.com",
        distribution.clone(),
    )
    .expect("metadata with status distribution");
    metadata.validate().expect("metadata valid");
    assert_eq!(
        metadata
            .chio_profile
            .as_ref()
            .expect("chio profile")
            .passport_status_distribution,
        distribution
    );

    let response = Oid4vciCredentialResponse::new_with_status_reference(
        CHIO_PASSPORT_OID4VCI_FORMAT,
        passport.clone(),
        Some(Oid4vciChioPassportStatusReference {
            passport_id: passport_id.clone(),
            distribution: distribution.clone(),
        }),
    )
    .expect("response");
    response
        .validate(
            1_710_000_100,
            Some(CHIO_PASSPORT_OID4VCI_FORMAT),
            Some(&passport.subject),
        )
        .expect("credential response with status reference valid");
}

#[test]
fn oid4vci_metadata_with_signing_key_advertises_portable_projection() {
    let issuer = Keypair::from_seed(&[5u8; 32]);
    let metadata = default_oid4vci_passport_issuer_metadata_with_signing_key(
        "https://trust.example.com",
        PassportStatusDistribution::default(),
        Some(&issuer.public_key()),
    )
    .expect("portable metadata");
    metadata.validate().expect("portable metadata valid");

    assert_eq!(
        metadata.jwks_uri.as_deref(),
        Some("https://trust.example.com/.well-known/jwks.json")
    );
    let portable_configuration = metadata
        .credential_configurations_supported
        .get(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID)
        .expect("portable credential configuration");
    assert_eq!(
        portable_configuration.format,
        CHIO_PASSPORT_SD_JWT_VC_FORMAT
    );
    let portable_profile = portable_configuration
        .portable_profile
        .as_ref()
        .expect("portable profile");
    assert_eq!(
        portable_profile.type_metadata_url,
        "https://trust.example.com/.well-known/chio-passport-sd-jwt-vc"
    );
    assert_eq!(
        portable_profile.portable_identity_binding.subject_binding,
        portable_profile.subject_binding
    );
    assert_eq!(
        portable_profile.portable_identity_binding.issuer_identity,
        portable_profile.issuer_identity
    );
    assert_eq!(
        portable_profile
            .portable_identity_binding
            .chio_provenance_anchor,
        "did:chio"
    );
    assert!(portable_profile
        .portable_claim_catalog
        .selectively_disclosable_claims
        .iter()
        .any(|claim| claim == "chio_issuer_dids"));
    assert_eq!(portable_profile.proof_family, "dc+sd-jwt");
    assert!(portable_profile.supports_selective_disclosure);

    let jwt_vc_configuration = metadata
        .credential_configurations_supported
        .get(CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID)
        .expect("jwt vc credential configuration");
    assert_eq!(
        jwt_vc_configuration.format,
        CHIO_PASSPORT_JWT_VC_JSON_FORMAT
    );
    let jwt_vc_profile = jwt_vc_configuration
        .portable_profile
        .as_ref()
        .expect("jwt vc portable profile");
    assert_eq!(
        jwt_vc_profile.type_metadata_url,
        "https://trust.example.com/.well-known/chio-passport-jwt-vc-json"
    );
    assert_eq!(jwt_vc_profile.proof_family, "vc+jwt");
    assert!(!jwt_vc_profile.supports_selective_disclosure);
    assert!(jwt_vc_profile
        .portable_claim_catalog
        .always_disclosed_claims
        .iter()
        .any(|claim| claim == "vc.credentialSubject.chioPassportId"));

    let type_metadata = build_chio_passport_sd_jwt_type_metadata("https://trust.example.com")
        .test_ok("type metadata");
    assert_eq!(type_metadata.format, CHIO_PASSPORT_SD_JWT_VC_FORMAT);
    assert_eq!(
        type_metadata.jwks_url,
        "https://trust.example.com/.well-known/jwks.json"
    );
    assert_eq!(
        type_metadata.portable_identity_binding.subject_binding,
        type_metadata.subject_binding
    );
    assert_eq!(
        type_metadata.portable_identity_binding.issuer_identity,
        type_metadata.issuer_identity
    );
    assert!(type_metadata
        .portable_claim_catalog
        .optional_claims
        .iter()
        .any(|claim| claim == "chio_passport_status"));

    let jwt_vc_type_metadata =
        build_chio_passport_jwt_vc_json_type_metadata("https://trust.example.com")
            .expect("jwt vc type metadata");
    assert_eq!(
        jwt_vc_type_metadata.format,
        CHIO_PASSPORT_JWT_VC_JSON_FORMAT
    );
    assert_eq!(
        jwt_vc_type_metadata.jwks_url,
        "https://trust.example.com/.well-known/jwks.json"
    );
    assert_eq!(jwt_vc_type_metadata.proof_family, "vc+jwt");
    assert!(!jwt_vc_type_metadata.supports_selective_disclosure);
    assert!(jwt_vc_type_metadata
        .portable_claim_catalog
        .always_disclosed_claims
        .iter()
        .any(|claim| claim == "vc.credentialSubject.chioIssuerDids"));

    let jwks = build_portable_issuer_jwks("https://trust.example.com", &issuer.public_key())
        .expect("jwks");
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].alg, "EdDSA");
}
