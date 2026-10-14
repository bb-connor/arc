use super::*;

#[test]
fn passport_public_discovery_endpoints_require_authority_signing_key() {
    if skip_when_loopback_bind_denied(
        "passport_public_discovery_endpoints_require_authority_signing_key",
    ) {
        return;
    }

    let issuance_registry_path = unique_path("passport-public-discovery-registry", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-public-discovery-service-token";

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_passport_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &issuance_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    for path in [
        "/v1/public/passport/discovery/issuer",
        "/v1/public/passport/discovery/verifier",
        "/v1/public/passport/discovery/transparency",
    ] {
        let response = client
            .get(format!("{base_url}{path}"))
            .send()
            .expect("fetch public discovery endpoint");
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    }
}

#[test]
fn passport_public_discovery_surfaces_are_signed_and_informational_only() {
    if skip_when_loopback_bind_denied(
        "passport_public_discovery_surfaces_are_signed_and_informational_only",
    ) {
        return;
    }

    let issuance_registry_path = unique_path("passport-public-discovery-portable", ".json");
    let verifier_db_path = unique_path("passport-public-discovery-verifier", ".sqlite");
    let status_registry_path = unique_path("passport-public-discovery-status", ".json");
    let authority_seed_path = unique_path("passport-public-discovery-authority", ".seed");
    let authority = Keypair::generate();
    write_private_file(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-public-discovery-portable-token";

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_oid4vp_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
        &verifier_db_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let issuer_discovery: SignedPublicIssuerDiscovery = client
        .get(format!("{base_url}/v1/public/passport/discovery/issuer"))
        .send()
        .expect("fetch issuer discovery")
        .error_for_status()
        .expect("issuer discovery status")
        .json()
        .expect("parse issuer discovery");
    verify_signed_public_issuer_discovery(&issuer_discovery).expect("verify issuer discovery");
    assert_eq!(
        issuer_discovery.body.metadata_url,
        format!("{base_url}/.well-known/openid-credential-issuer")
    );
    assert!(issuer_discovery.body.import_guardrails.informational_only);
    assert!(
        issuer_discovery
            .body
            .import_guardrails
            .requires_explicit_policy_import
    );
    assert!(
        issuer_discovery
            .body
            .import_guardrails
            .requires_manual_review
    );

    let verifier_discovery: SignedPublicVerifierDiscovery = client
        .get(format!("{base_url}/v1/public/passport/discovery/verifier"))
        .send()
        .expect("fetch verifier discovery")
        .error_for_status()
        .expect("verifier discovery status")
        .json()
        .expect("parse verifier discovery");
    verify_signed_public_verifier_discovery(&verifier_discovery)
        .expect("verify verifier discovery");
    assert_eq!(
        verifier_discovery.body.metadata_url,
        format!("{base_url}{OID4VP_VERIFIER_METADATA_PATH}")
    );
    assert_eq!(
        verifier_discovery.body.jwks_uri,
        format!("{base_url}/.well-known/jwks.json")
    );
    assert!(verifier_discovery
        .body
        .request_uri_prefix
        .starts_with(&format!("{base_url}/v1/public/passport/oid4vp/requests/")));

    let transparency: SignedPublicDiscoveryTransparency = client
        .get(format!(
            "{base_url}/v1/public/passport/discovery/transparency"
        ))
        .send()
        .expect("fetch discovery transparency")
        .error_for_status()
        .expect("discovery transparency status")
        .json()
        .expect("parse discovery transparency");
    verify_signed_public_discovery_transparency(&transparency)
        .expect("verify discovery transparency");
    assert_eq!(transparency.body.entries.len(), 2);
    assert!(transparency
        .body
        .entries
        .iter()
        .any(|entry| entry.metadata_url
            == format!("{base_url}/.well-known/openid-credential-issuer")));
    assert!(transparency
        .body
        .entries
        .iter()
        .any(|entry| entry.metadata_url == format!("{base_url}{OID4VP_VERIFIER_METADATA_PATH}")));
    assert!(transparency.body.import_guardrails.informational_only);
}
