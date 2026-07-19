#[test]
fn passport_portable_lifecycle_stale_state_fails_closed_on_offer_and_public_resolution() {
    if skip_when_loopback_bind_denied(
        "passport_portable_lifecycle_stale_state_fails_closed_on_offer_and_public_resolution",
    ) {
        return;
    }

    let passport_path = unique_path("passport-portable-lifecycle-stale", ".json");
    let authority_seed_path = unique_path("passport-portable-lifecycle-stale-issuer", ".seed");
    let issuance_registry_path = unique_path("passport-portable-lifecycle-stale-registry", ".json");
    let status_registry_path = unique_path("passport-portable-lifecycle-stale-statuses", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-portable-lifecycle-stale-service-token";
    let now = current_unix_secs();

    let authority = Keypair::generate();
    chio_control_plane::persist_authority_keypair(&authority_seed_path, &authority)
        .expect("write authority seed");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now.saturating_add(86_400),
        "portable-lifecycle-stale",
    );

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_passport_lifecycle_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let publish = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "status",
            "publish",
            "--input",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("publish stale passport");
    assert!(
        publish.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish.stdout),
        String::from_utf8_lossy(&publish.stderr)
    );
    let publish_json: serde_json::Value =
        serde_json::from_slice(&publish.stdout).expect("parse publish response");
    let passport_id = publish_json["passportId"]
        .as_str()
        .expect("passport id")
        .to_string();

    let mut registry_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&status_registry_path).expect("read status registry"))
            .expect("parse status registry");
    let stale_timestamp = now.saturating_sub(301);
    registry_json["passports"][&passport_id]["publishedAt"] = serde_json::json!(stale_timestamp);
    registry_json["passports"][&passport_id]["updatedAt"] = serde_json::json!(stale_timestamp);
    fs::write(
        &status_registry_path,
        serde_json::to_vec_pretty(&registry_json).expect("serialize status registry"),
    )
    .expect("write status registry");

    let resolve_json: serde_json::Value = client
        .get(format!(
            "{base_url}/v1/public/passport/statuses/resolve/{passport_id}"
        ))
        .send()
        .expect("resolve stale status")
        .error_for_status()
        .expect("stale status response")
        .json()
        .expect("parse stale resolution");
    assert_eq!(resolve_json["state"], "stale");
    assert_eq!(resolve_json["source"], "registry:trust-control");

    let stale_offer = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create stale portable issuance offer");
    assert_eq!(stale_offer.status(), reqwest::StatusCode::BAD_REQUEST);
    let stale_offer_body = stale_offer.text().expect("read stale offer body");
    assert!(stale_offer_body.contains("stale lifecycle state"));
}

#[test]
fn passport_issuance_local_portable_offer_requires_signing_seed() {
    let passport_path = unique_path("passport-portable-local", ".json");
    let issuance_registry_path = unique_path("passport-portable-local-registry", ".json");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let now = current_unix_secs();
    write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now.saturating_add(3600),
        "portable-local",
    );

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--issuer-url",
            "https://trust.example.com",
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
            "--credential-configuration-id",
            CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        ])
        .output()
        .expect("run local portable issuance offer");
    assert!(
        !offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    let error_text = format!(
        "{}{}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    assert!(error_text.contains("unsupported credential_configuration_id"));
}

#[test]
fn passport_portable_metadata_endpoints_require_signing_key_configuration() {
    if skip_when_loopback_bind_denied(
        "passport_portable_metadata_endpoints_require_signing_key_configuration",
    ) {
        return;
    }

    let issuance_registry_path = unique_path("passport-portable-metadata-registry", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-portable-metadata-service-token";

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

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    metadata.validate().expect("validate issuer metadata");
    assert!(metadata.jwks_uri.is_none());
    assert!(!metadata
        .credential_configurations_supported
        .contains_key(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID));
    assert!(!metadata
        .credential_configurations_supported
        .contains_key(CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID));

    let jwks = client
        .get(format!("{base_url}/.well-known/jwks.json"))
        .send()
        .expect("fetch jwks without signing key");
    assert_eq!(jwks.status(), reqwest::StatusCode::NOT_FOUND);

    let type_metadata = client
        .get(format!("{base_url}/.well-known/chio-passport-sd-jwt-vc"))
        .send()
        .expect("fetch type metadata without signing key");
    assert_eq!(type_metadata.status(), reqwest::StatusCode::NOT_FOUND);

    let jwt_vc_type_metadata = client
        .get(format!("{base_url}/.well-known/chio-passport-jwt-vc-json"))
        .send()
        .expect("fetch jwt vc type metadata without signing key");
    assert_eq!(
        jwt_vc_type_metadata.status(),
        reqwest::StatusCode::NOT_FOUND
    );
}

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
    chio_control_plane::persist_authority_keypair(&authority_seed_path, &authority)
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
