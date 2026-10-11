use super::*;

#[test]
fn portable_sd_jwt_passport_projection_roundtrip_verifies() {
    let issuer = Keypair::from_seed(&[6u8; 32]);
    let subject = Keypair::from_seed(&[9u8; 32]);
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

    let envelope = issue_chio_passport_sd_jwt_vc(
        &passport,
        "https://trust.example.com",
        &issuer,
        1_710_000_100,
        None,
    )
    .expect("portable envelope");
    let verification =
        verify_chio_passport_sd_jwt_vc(&envelope.compact, &issuer.public_key(), 1_710_000_200)
            .test_ok("portable verification");
    assert_eq!(verification.passport_id, passport_id);
    assert_eq!(verification.subject_did, passport.subject);
    assert_eq!(verification.issuer, "https://trust.example.com");

    let (jwt, disclosures) = envelope.compact.split_once('~').expect("disclosures");
    let parts: Vec<_> = jwt.split('.').collect();
    for (header, expected) in [
        (r#"{"alg":"none","typ":"dc+sd-jwt"}"#, "must declare EdDSA"),
        (r#"{"alg":"EdDSA","typ":"JWT"}"#, "must declare EdDSA"),
        (
            r#"{"alg":"EdDSA","alg":"EdDSA","typ":"dc+sd-jwt"}"#,
            "header is not valid JSON",
        ),
    ] {
        let signing_input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), parts[1]);
        let signature = URL_SAFE_NO_PAD.encode(issuer.sign(signing_input.as_bytes()).to_bytes());
        let malformed = format!("{signing_input}.{signature}~{disclosures}");
        let error = verify_chio_passport_sd_jwt_vc(&malformed, &issuer.public_key(), 1_710_000_200)
            .expect_err("valid signature cannot bypass the header contract");
        assert!(error.to_string().contains(expected), "{error}");
    }
    let oversized = "!".repeat(jwt_decode::MAX_ENCODED_JSON_BYTES + 1);
    assert!(parse_sd_jwt_disclosure(&oversized)
        .expect_err("bound before decoding")
        .to_string()
        .contains("disclosure exceeds size limit"));

    let response = Oid4vciCredentialResponse::new_portable_sd_jwt(
        CHIO_PASSPORT_SD_JWT_VC_FORMAT,
        envelope.compact.clone(),
        envelope.passport_id.clone(),
        envelope.subject_did.clone(),
        None,
        envelope.issuer_jwk.clone(),
    )
    .expect("portable response");
    response
        .validate(
            1_710_000_200,
            Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT),
            Some(&passport.subject),
        )
        .expect("portable response valid");
    assert_eq!(response.subject_hint(), Some(passport.subject.as_str()));
    assert_eq!(response.passport_id_hint(), Some(passport_id.as_str()));
    assert_eq!(
        response
            .credential
            .write_output_bytes()
            .expect("portable output bytes"),
        envelope.compact.as_bytes()
    );
}
