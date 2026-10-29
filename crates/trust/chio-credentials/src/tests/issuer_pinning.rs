use super::*;

const VERIFY_AT: u64 = 1_710_000_120;

fn issuer_did(seed: u8) -> String {
    did_from_public_key(Keypair::from_seed(&[seed; 32]).public_key()).to_string()
}

fn allowlist(issuers: &[String]) -> BTreeSet<String> {
    issuers.iter().cloned().collect()
}

fn challenge_for(issuers: BTreeSet<String>) -> PassportPresentationChallenge {
    create_passport_presentation_challenge(
        "https://rp.example.com",
        "nonce-pin",
        1_710_000_050,
        1_710_000_350,
        PassportPresentationOptions {
            issuer_allowlist: issuers,
            max_credentials: None,
        },
        None,
    )
    .expect("challenge")
}

#[test]
fn passport_from_untrusted_issuer_is_refused() {
    let passport = sample_passport(7, 66);
    let trusted = allowlist(&[issuer_did(1)]);

    let error = verify_agent_passport(&passport, &trusted, VERIFY_AT)
        .expect_err("self-made issuer must not verify");

    assert!(matches!(
        error,
        CredentialError::CredentialIssuerNotTrusted(issuer) if issuer == issuer_did(66)
    ));
}

#[test]
fn credential_from_untrusted_issuer_is_refused() {
    let passport = sample_passport(7, 66);
    let trusted = allowlist(&[issuer_did(1)]);

    let error = verify_reputation_credential(&passport.credentials[0], &trusted, VERIFY_AT)
        .expect_err("self-made issuer must not verify");

    assert!(matches!(
        error,
        CredentialError::CredentialIssuerNotTrusted(issuer) if issuer == issuer_did(66)
    ));
}

#[test]
fn trusted_issuer_passport_verifies() {
    let passport = sample_passport(7, 1);
    let trusted = trusted_set(&[&Keypair::from_seed(&[1u8; 32])]);

    let verification = verify_agent_passport(&passport, &trusted, VERIFY_AT).expect("verify");

    assert_eq!(verification.issuer, Some(issuer_did(1)));
}

#[test]
fn empty_trusted_issuer_set_is_refused() {
    let passport = sample_passport(7, 1);
    let empty = BTreeSet::new();

    assert!(matches!(
        verify_agent_passport(&passport, &empty, VERIFY_AT),
        Err(CredentialError::TrustedIssuersMissing)
    ));
    assert!(matches!(
        verify_reputation_credential(&passport.credentials[0], &empty, VERIFY_AT),
        Err(CredentialError::TrustedIssuersMissing)
    ));
    assert!(matches!(
        trusted_issuers_from_keys(&[]),
        Err(CredentialError::TrustedIssuersMissing)
    ));
}

#[test]
fn verifier_policy_with_empty_issuer_allowlist_is_refused() {
    let passport = sample_passport(7, 1);
    let policy = PassportVerifierPolicy::default();

    assert!(matches!(
        policy.validate(),
        Err(CredentialError::VerifierPolicyIssuerAllowlistMissing)
    ));
    assert!(matches!(
        evaluate_agent_passport(&passport, VERIFY_AT, &policy),
        Err(CredentialError::VerifierPolicyIssuerAllowlistMissing)
    ));
}

#[test]
fn presentation_options_with_empty_issuer_allowlist_are_refused() {
    let passport = sample_passport(7, 1);

    assert!(matches!(
        present_agent_passport(&passport, &PassportPresentationOptions::default()),
        Err(CredentialError::PresentationIssuerAllowlistMissing)
    ));

    let holder = Keypair::from_seed(&[7u8; 32]);
    let challenge = challenge_for(BTreeSet::new());
    assert!(matches!(
        respond_to_passport_presentation_challenge(&holder, &passport, &challenge, 1_710_000_100),
        Err(CredentialError::PresentationIssuerAllowlistMissing)
    ));
}

#[test]
fn presentation_without_verifier_held_issuers_is_refused() {
    let passport = sample_passport(7, 1);
    let holder = Keypair::from_seed(&[7u8; 32]);
    let challenge = challenge_for(allowlist(&[issuer_did(1)]));
    let response =
        respond_to_passport_presentation_challenge(&holder, &passport, &challenge, 1_710_000_100)
            .expect("response");

    assert!(matches!(
        verify_passport_presentation_response(&response, None, VERIFY_AT),
        Err(CredentialError::PresentationTrustedIssuersMissing)
    ));
    assert!(matches!(
        verify_passport_presentation_response_with_policy(&response, None, VERIFY_AT, None, None),
        Err(CredentialError::PresentationTrustedIssuersMissing)
    ));
}

#[test]
fn presentation_with_empty_resolved_policy_allowlist_is_refused() {
    let passport = sample_passport(7, 1);
    let holder = Keypair::from_seed(&[7u8; 32]);
    let challenge = challenge_for(allowlist(&[issuer_did(1)]));
    let response =
        respond_to_passport_presentation_challenge(&holder, &passport, &challenge, 1_710_000_100)
            .expect("response");

    assert!(matches!(
        verify_passport_presentation_response_with_policy(
            &response,
            None,
            VERIFY_AT,
            Some(&PassportVerifierPolicy::default()),
            None,
        ),
        Err(CredentialError::PresentationTrustedIssuersMissing)
    ));
}

#[test]
fn presenter_supplied_allowlist_and_policy_are_not_a_trust_source() {
    let attacker_passport = sample_passport(7, 66);
    let holder = Keypair::from_seed(&[7u8; 32]);
    let verifier_challenge = challenge_for(allowlist(&[issuer_did(1)]));
    let attacker_challenge = create_passport_presentation_challenge(
        "https://rp.example.com",
        "nonce-pin",
        1_710_000_050,
        1_710_000_350,
        PassportPresentationOptions {
            issuer_allowlist: allowlist(&[issuer_did(66)]),
            max_credentials: None,
        },
        Some(PassportVerifierPolicy {
            issuer_allowlist: allowlist(&[issuer_did(66)]),
            ..PassportVerifierPolicy::default()
        }),
    )
    .expect("attacker challenge");
    let response = respond_to_passport_presentation_challenge(
        &holder,
        &attacker_passport,
        &attacker_challenge,
        1_710_000_100,
    )
    .expect("attacker response");
    let verifier_policy = PassportVerifierPolicy {
        issuer_allowlist: allowlist(&[issuer_did(1)]),
        ..PassportVerifierPolicy::default()
    };

    let error = verify_passport_presentation_response_with_policy(
        &response,
        None,
        VERIFY_AT,
        Some(&verifier_policy),
        None,
    )
    .expect_err("presenter allowlist must not grant trust");
    assert!(matches!(
        error,
        CredentialError::PresentationIssuerNotAllowed(issuer) if issuer == issuer_did(66)
    ));

    assert!(matches!(
        verify_passport_presentation_response(&response, Some(&verifier_challenge), VERIFY_AT),
        Err(CredentialError::ChallengeMismatch)
    ));
    assert!(matches!(
        verify_passport_presentation_response(&response, None, VERIFY_AT),
        Err(CredentialError::PresentationTrustedIssuersMissing)
    ));
}

#[test]
fn holder_structural_inspection_accepts_any_issuer() {
    let passport = sample_passport(7, 66);

    let inspection: PassportStructuralInspection =
        inspect_agent_passport_structure(&passport, VERIFY_AT).expect("inspection");

    assert_eq!(inspection.issuers, vec![issuer_did(66)]);
    assert_eq!(
        inspection.passport_id,
        passport_artifact_id(&passport).expect("id")
    );
    let type_name = std::any::type_name::<PassportStructuralInspection>();
    assert!(type_name.ends_with("PassportStructuralInspection"));
    assert!(!type_name.to_ascii_lowercase().contains("verif"));

    let holder = Keypair::from_seed(&[7u8; 32]);
    let challenge = challenge_for(allowlist(&[issuer_did(66)]));
    respond_to_passport_presentation_challenge(&holder, &passport, &challenge, 1_710_000_100)
        .expect("holder responds without trusting the issuer");
}

#[test]
fn holder_structural_inspection_refuses_tampered_structure() {
    let mut passport = sample_passport(7, 66);
    passport.credentials[0].proof.proof_type = "AnotherProof".to_string();

    assert!(matches!(
        inspect_agent_passport_structure(&passport, VERIFY_AT),
        Err(CredentialError::InvalidProofType)
    ));
}

#[test]
fn cross_issuer_portfolio_requires_trusted_issuers() {
    let passport = sample_passport(5, 66);
    let portfolio = CrossIssuerPortfolio {
        schema: CROSS_ISSUER_PORTFOLIO_SCHEMA.to_string(),
        portfolio_id: "portfolio-pin".to_string(),
        subject: passport.subject.clone(),
        entries: vec![CrossIssuerPortfolioEntry {
            entry_id: "native".to_string(),
            profile_family: PASSPORT_SCHEMA.to_string(),
            source_kind: CrossIssuerPortfolioEntryKind::Native,
            source: None,
            passport,
            lifecycle: None,
            certification_refs: Vec::new(),
            migration_id: None,
        }],
        migrations: Vec::new(),
    };

    assert!(matches!(
        verify_cross_issuer_portfolio(&portfolio, &allowlist(&[issuer_did(1)]), VERIFY_AT),
        Err(CredentialError::CredentialIssuerNotTrusted(issuer)) if issuer == issuer_did(66)
    ));
}

#[test]
fn portable_projection_refuses_untrusted_issuer() {
    let passport = sample_passport(7, 66);
    let signer = Keypair::from_seed(&[1u8; 32]);

    assert!(matches!(
        issue_chio_passport_sd_jwt_vc(
            &passport,
            "https://trust.example.com",
            &signer,
            &trusted_set(&[&signer]),
            VERIFY_AT,
            None,
        ),
        Err(CredentialError::CredentialIssuerNotTrusted(issuer)) if issuer == issuer_did(66)
    ));
}

#[test]
fn oid4vp_request_with_empty_issuer_allowlist_is_refused() {
    let issuer = Keypair::from_seed(&[22u8; 32]);
    let subject = Keypair::from_seed(&[23u8; 32]);
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
    let envelope = issue_chio_passport_sd_jwt_vc(
        &passport,
        "https://trust.example.com",
        &issuer,
        &trusted_set(&[&issuer]),
        1_710_000_100,
        None,
    )
    .expect("portable envelope");
    let request = Oid4vpRequestObject {
        client_id: "https://verifier.example.com".to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        response_uri: "https://verifier.example.com/v1/public/passport/oid4vp/direct-post"
            .to_string(),
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        nonce: "nonce-1".to_string(),
        state: "state-1".to_string(),
        iat: 1_710_000_100,
        exp: 1_710_000_400,
        jti: "oid4vp-1".to_string(),
        request_uri: "https://verifier.example.com/v1/public/passport/oid4vp/requests/oid4vp-1"
            .to_string(),
        dcql_query: Oid4vpDcqlQuery {
            credentials: vec![Oid4vpRequestedCredential {
                id: "chio-passport".to_string(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                claims: vec!["chio_issuer_dids".to_string()],
                issuer_allowlist: Vec::new(),
            }],
        },
        identity_assertion: None,
    };
    let response_jwt =
        respond_to_oid4vp_request(&subject, &envelope.compact, &request, 1_710_000_200)
            .expect("respond to oid4vp request");

    let error = verify_oid4vp_direct_post_response(
        &response_jwt,
        &request,
        &issuer.public_key(),
        1_710_000_220,
    )
    .expect_err("empty allowlist must refuse");
    assert!(matches!(
        error,
        CredentialError::Oid4vpIssuerAllowlistMissing
    ));
}
