//! OID4VP artifacts signed by weak Ed25519 keys are refused.

use super::*;

/// The Ed25519 identity point. With the signature `(R = identity, s = 0)`
/// it satisfies the cofactorless verification equation for every message.
const WEAK_ED25519_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";

fn universal_signature_jwt(typ: &str, payload: &Value) -> String {
    let header = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!({ "alg": "EdDSA", "typ": typ })).expect("jwt header"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("jwt payload"));
    let mut signature = [0u8; 64];
    signature[0] = 1;
    format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn weak_key_oid4vp_request() -> Oid4vpRequestObject {
    Oid4vpRequestObject {
        client_id: "https://verifier.example.com".to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        response_uri: "https://verifier.example.com/v1/public/passport/oid4vp/direct-post"
            .to_string(),
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        nonce: "nonce-weak".to_string(),
        state: "state-weak".to_string(),
        iat: 1_710_000_100,
        exp: 1_710_000_400,
        jti: "oid4vp-weak".to_string(),
        request_uri: "https://verifier.example.com/v1/public/passport/oid4vp/requests/oid4vp-weak"
            .to_string(),
        dcql_query: Oid4vpDcqlQuery {
            credentials: vec![Oid4vpRequestedCredential {
                id: "chio-passport".to_string(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                claims: vec!["chio_issuer_dids".to_string()],
                issuer_allowlist: vec!["https://trust.example.com".to_string()],
            }],
        },
        identity_assertion: None,
    }
}

#[test]
fn oid4vp_request_object_signed_by_weak_verifier_key_is_rejected() {
    let weak_key = chio_core::PublicKey::from_hex(WEAK_ED25519_KEY).test_ok("weak key");
    let request = weak_key_oid4vp_request();
    let forged = universal_signature_jwt(
        OID4VP_REQUEST_OBJECT_TYP,
        &serde_json::to_value(&request).expect("request payload"),
    );

    let error = verify_signed_oid4vp_request_object(&forged, &weak_key, 1_710_000_200)
        .expect_err("weak verifier key must not authenticate a request object");
    assert!(matches!(
        error,
        CredentialError::InvalidOid4vpRequest(ref message)
            if message == "OID4VP request JWT signature verification failed"
    ));
}

#[test]
fn oid4vp_response_bound_to_weak_holder_key_is_rejected() {
    let issuer = Keypair::from_seed(&[24u8; 32]);
    let weak_holder = chio_core::PublicKey::from_hex(WEAK_ED25519_KEY).test_ok("weak key");
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&weak_holder.to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .expect("credential");
    let passport = build_agent_passport(
        &did_from_public_key(weak_holder.clone()).to_string(),
        vec![credential],
    )
    .expect("passport");
    let envelope = issue_chio_passport_sd_jwt_vc(
        &passport,
        "https://trust.example.com",
        &issuer,
        1_710_000_100,
        None,
    )
    .expect("portable envelope");
    let request = weak_key_oid4vp_request();
    let requested = &request.dcql_query.credentials[0];
    let thumbprint = PortableEd25519Jwk::from_public_key(&weak_holder)
        .test_ok("holder jwk")
        .thumbprint()
        .test_ok("holder thumbprint");
    let claims = Oid4vpDirectPostResponseClaims {
        iss: thumbprint.clone(),
        sub: thumbprint,
        aud: request.response_uri.clone(),
        iat: 1_710_000_200,
        exp: 1_710_000_400,
        nonce: request.nonce.clone(),
        state: request.state.clone(),
        vp_token: filter_portable_disclosures(&envelope.compact, &requested.claims)
            .test_ok("filtered vp token"),
        presentation_submission: Oid4vpPresentationSubmission {
            id: request.jti.clone(),
            definition_id: "chio-passport-sd-jwt-vc".to_string(),
            descriptor_map: vec![Oid4vpDescriptorMap {
                id: requested.id.clone(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                path: "$.vp_token".to_string(),
            }],
        },
    };
    let forged = universal_signature_jwt(
        OID4VP_RESPONSE_OBJECT_TYP,
        &serde_json::to_value(claims).expect("response payload"),
    );

    let error =
        verify_oid4vp_direct_post_response(&forged, &request, &issuer.public_key(), 1_710_000_220)
            .expect_err("weak holder key must not authenticate a presentation");
    assert!(matches!(
        error,
        CredentialError::InvalidOid4vpResponse(ref message)
            if message == "OID4VP response JWT signature verification failed"
    ));
}
