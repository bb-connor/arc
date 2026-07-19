#[test]
fn mcp_serve_http_dedicated_jwt_sessions_require_exact_bearer_continuity_and_separate_admin_token()
{
    skip_when_loopback_denied!(mcp_serve_http_dedicated_jwt_sessions_require_exact_bearer_continuity_and_separate_admin_token);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token_a = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let (session_id, protocol_version) = initialize_session(&client, &base_url, &token_a);
    let trust = get_admin_session_trust(&client, &base_url, admin_token, &session_id);
    assert_eq!(trust.status(), reqwest::StatusCode::OK);
    let trust: Value = trust.json().expect("session trust json");
    assert_eq!(
        trust["ownership"]["hostedIsolation"].as_str(),
        Some("dedicated_per_session")
    );
    assert_eq!(
        trust["ownership"]["hostedIdentityProfile"].as_str(),
        Some("strong_dedicated_session")
    );

    let token_b = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 600,
        }),
    );
    let tools_list = post_json(
        &client,
        &base_url,
        &token_b,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(tools_list.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(tools_list
        .text()
        .expect("dedicated continuity body")
        .contains("authenticated authorization context does not match session"));

    let admin_unauthorized = get_admin_authority(&client, &base_url, &token_b);
    assert_eq!(
        admin_unauthorized.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    let admin_authorized = get_admin_authority(&client, &base_url, admin_token);
    assert_eq!(admin_authorized.status(), reqwest::StatusCode::OK);
    let admin_authorized: Value = admin_authorized.json().expect("authority json");
    assert_eq!(admin_authorized["configured"], true);
}

#[test]
fn mcp_serve_http_shared_owner_jwt_sessions_keep_weak_compatibility_continuity() {
    skip_when_loopback_denied!(
        mcp_serve_http_shared_owner_jwt_sessions_keep_weak_compatibility_continuity
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let jwt_signing_key = Keypair::generate();
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "shared-owner jwt MCP server",
        |candidate| {
            spawn_http_server_with_shared_owner_and_jwt_auth(
                &dir,
                candidate,
                &jwt_signing_key.public_key().to_hex(),
                issuer,
                audience,
                admin_token,
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let token_a = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let (session_id, protocol_version) = initialize_session(&client, &base_url, &token_a);
    let trust = get_admin_session_trust(&client, &base_url, admin_token, &session_id);
    assert_eq!(trust.status(), reqwest::StatusCode::OK);
    let trust: Value = trust.json().expect("session trust json");
    assert_eq!(
        trust["ownership"]["hostedIsolation"].as_str(),
        Some("shared_hosted_owner_compatibility")
    );
    assert_eq!(
        trust["ownership"]["hostedIdentityProfile"].as_str(),
        Some("weak_shared_hosted_owner_compatibility")
    );

    let token_b = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 600,
        }),
    );
    let tools_list = post_json(
        &client,
        &base_url,
        &token_b,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(tools_list.status(), reqwest::StatusCode::OK);
    let (tools_list, notifications) = read_sse_until_response(tools_list, json!(2), |_| {});
    assert!(notifications.is_empty());
    assert!(!tools_list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .is_empty());
}

#[test]
fn mcp_serve_http_identity_federation_derives_stable_subjects_from_jwt_principals() {
    skip_when_loopback_denied!(
        mcp_serve_http_identity_federation_derives_stable_subjects_from_jwt_principals
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth_and_identity_federation(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
        Some(&federation_seed_path),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token_for = |subject: &str, exp_offset: u64| {
        sign_jwt(
            &jwt_signing_key,
            &json!({
                "iss": issuer,
                "sub": subject,
                "aud": audience,
                "scope": "mcp:invoke tools.read",
                "client_id": format!("client-{subject}"),
                "tid": "tenant-123",
                "org_id": "org-789",
                "groups": ["eng", "ops"],
                "roles": ["operator"],
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_secs()
                    + exp_offset,
            }),
        )
    };

    let token_a = token_for("user-123", 300);
    let (session_a, protocol_a) = initialize_session(&client, &base_url, &token_a);
    let token_b = token_for("user-123", 600);
    let (session_b, protocol_b) = initialize_session(&client, &base_url, &token_b);
    let token_c = token_for("user-456", 900);
    let (session_c, protocol_c) = initialize_session(&client, &base_url, &token_c);

    let trust_a: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_a)
        .json()
        .expect("session A trust json");
    let trust_b: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_b)
        .json()
        .expect("session B trust json");
    let trust_c: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_c)
        .json()
        .expect("session C trust json");

    let subject_a = trust_a["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session A subject key")
        .to_string();
    let subject_b = trust_b["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session B subject key")
        .to_string();
    let subject_c = trust_c["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session C subject key")
        .to_string();
    assert_eq!(subject_a, subject_b);
    assert_ne!(subject_a, subject_c);
    let enterprise_subject_a = trust_a["authContext"]["method"]["enterpriseIdentity"]["subjectKey"]
        .as_str()
        .expect("session A enterprise subject key")
        .to_string();
    let enterprise_subject_b = trust_b["authContext"]["method"]["enterpriseIdentity"]["subjectKey"]
        .as_str()
        .expect("session B enterprise subject key")
        .to_string();
    let enterprise_subject_c = trust_c["authContext"]["method"]["enterpriseIdentity"]["subjectKey"]
        .as_str()
        .expect("session C enterprise subject key")
        .to_string();
    assert_eq!(enterprise_subject_a, enterprise_subject_b);
    assert_ne!(enterprise_subject_a, enterprise_subject_c);
    assert_eq!(
        trust_a["authContext"]["method"]["principal"].as_str(),
        Some("oidc:https://issuer.example#sub:user-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["principal"].as_str(),
        Some("oidc:https://issuer.example#sub:user-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["tenantId"].as_str(),
        Some("tenant-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["organizationId"].as_str(),
        Some("org-789")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["groups"],
        json!(["eng", "ops"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["roles"],
        json!(["operator"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["principal"]
            .as_str(),
        Some("sub")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["groups"]
            .as_str(),
        Some("groups")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["roles"]
            .as_str(),
        Some("roles")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["clientId"].as_str(),
        Some("client-user-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["organizationId"].as_str(),
        Some("org-789")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["groups"],
        json!(["eng", "ops"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["roles"],
        json!(["operator"])
    );
    assert_eq!(
        trust_c["authContext"]["method"]["principal"].as_str(),
        Some("oidc:https://issuer.example#sub:user-456")
    );

    for (session_id, protocol_version, token, message) in [
        (&session_a, &protocol_a, &token_a, "same-subject-a"),
        (&session_b, &protocol_b, &token_b, "same-subject-b"),
        (&session_c, &protocol_c, &token_c, "different-subject"),
    ] {
        let tool_call = post_json(
            &client,
            &base_url,
            token,
            Some(session_id),
            Some(protocol_version),
            &json!({
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "echo_json",
                    "arguments": {"message": message}
                }
            }),
        );
        assert_eq!(tool_call.status(), reqwest::StatusCode::OK);
        let (tool_call, notifications) = read_sse_until_response(tool_call, json!(41), |_| {});
        assert!(notifications.is_empty());
        assert_eq!(tool_call["result"]["structuredContent"]["echo"], message);
    }

    let receipts = get_admin_tool_receipts(
        &client,
        &base_url,
        admin_token,
        &[("toolName", "echo_json"), ("limit", "10")],
    );
    assert_eq!(receipts.status(), reqwest::StatusCode::OK);
    let receipts: Value = receipts.json().expect("receipt list json");
    let subject_keys = receipts["receipts"]
        .as_array()
        .expect("receipt array")
        .iter()
        .map(|receipt| {
            receipt["metadata"]["attribution"]["subject_key"]
                .as_str()
                .expect("receipt attribution subject")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        subject_keys
            .iter()
            .filter(|subject| *subject == &subject_a)
            .count(),
        2
    );
    assert_eq!(
        subject_keys
            .iter()
            .filter(|subject| *subject == &subject_c)
            .count(),
        1
    );
}

#[test]
fn mcp_serve_http_admin_health_reports_runtime_state() {
    skip_when_loopback_denied!(mcp_serve_http_admin_health_reports_runtime_state);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth_and_identity_federation(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
        Some(&federation_seed_path),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-health",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let _ = initialize_session(&client, &base_url, &token);

    let health = get_admin_health(&client, &base_url, admin_token);
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    let health: Value = health.json().expect("admin health json");
    assert_eq!(health["ok"], true);
    assert_eq!(health["server"]["serverId"], "wrapped-http-mock");
    assert_eq!(health["auth"]["mode"], "jwt_bearer");
    assert_eq!(health["stores"]["receiptsConfigured"], true);
    assert_eq!(health["stores"]["revocationsConfigured"], true);
    assert_eq!(health["federation"]["identityFederationConfigured"], true);
    assert_eq!(health["server"]["sharedHostedOwner"], false);
    assert!(
        health["sessions"]["activeCount"].as_u64().unwrap_or(0) >= 1,
        "expected at least one active session in admin health"
    );
}

#[test]
fn mcp_serve_http_oidc_discovery_verifies_jwt_and_uses_azure_ad_profile_mapping() {
    skip_when_loopback_denied!(
        mcp_serve_http_oidc_discovery_verifies_jwt_and_uses_azure_ad_profile_mapping
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let idp_listen = reserve_listen_addr();
    let oidc_signing_key = Keypair::generate();
    let (idp_root, issuer, discovery_url) =
        write_oidc_discovery_fixture(&dir, idp_listen, "tenant/v2.0", &oidc_signing_key);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut idp_server = spawn_static_http_fixture_server(&idp_root, idp_listen);
    wait_for_http_fixture_url(&client, &discovery_url, &mut idp_server);

    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server with OIDC discovery",
        |listen| {
            spawn_http_server_with_oidc_discovery_and_identity_federation(
                &dir,
                listen,
                &discovery_url,
                Some("azure-ad"),
                audience,
                admin_token,
                Some(&federation_seed_path),
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let token_for = |exp_offset: u64| {
        sign_jwt(
            &oidc_signing_key,
            &json!({
                "iss": issuer,
                "sub": "opaque-subject",
                "oid": "object-123",
                "appid": "client-abc",
                "tid": "tenant-azure",
                "aud": audience,
                "scope": "mcp:invoke tools.read",
                "groups": ["ops", "eng"],
                "roles": ["operator"],
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_secs()
                    + exp_offset,
            }),
        )
    };

    let token_a = token_for(300);
    let (session_a, _) = initialize_session(&client, &base_url, &token_a);
    let token_b = token_for(600);
    let (session_b, _) = initialize_session(&client, &base_url, &token_b);

    let trust_a: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_a)
        .json()
        .expect("session A trust json");
    let trust_b: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_b)
        .json()
        .expect("session B trust json");

    let subject_a = trust_a["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session A subject key")
        .to_string();
    let subject_b = trust_b["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session B subject key")
        .to_string();
    assert_eq!(subject_a, subject_b);
    let expected_principal = format!("oidc:{issuer}#oid:object-123");
    assert_eq!(
        trust_a["authContext"]["method"]["principal"].as_str(),
        Some(expected_principal.as_str())
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["principal"].as_str(),
        Some(expected_principal.as_str())
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["principal"]
            .as_str(),
        Some("oid")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["clientId"]
            .as_str(),
        Some("appid")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["objectId"].as_str(),
        Some("object-123")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["clientId"].as_str(),
        Some("client-abc")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-azure")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["groups"],
        json!(["eng", "ops"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["roles"],
        json!(["operator"])
    );

    let metadata = get_protected_resource_metadata(&client, &base_url);
    assert_eq!(metadata.status(), reqwest::StatusCode::OK);
    let metadata: Value = metadata.json().expect("protected metadata json");
    assert_eq!(
        metadata["authorization_servers"][0].as_str(),
        Some(issuer.as_str())
    );
    assert_eq!(
        metadata["chio_authorization_profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );
    assert_eq!(
        metadata["chio_authorization_profile"]["senderConstraints"]["subjectBinding"].as_str(),
        Some("capability_subject")
    );
}

#[test]
fn mcp_serve_http_oidc_discovery_verifies_rs256_tokens() {
    skip_when_loopback_denied!(mcp_serve_http_oidc_discovery_verifies_rs256_tokens);
    use rsa::traits::PublicKeyParts as _;

    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let idp_listen = reserve_listen_addr();
    let rsa_private_key =
        rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("generate rsa key");
    let rsa_public_key = rsa_private_key.to_public_key();
    let (idp_root, issuer, discovery_url) = write_oidc_discovery_fixture_with_jwks(
        &dir,
        idp_listen,
        "rsa",
        json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "rsa-key-1",
                "n": URL_SAFE_NO_PAD.encode(rsa_public_key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(rsa_public_key.e().to_bytes_be()),
            }]
        }),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut idp_server = spawn_static_http_fixture_server(&idp_root, idp_listen);
    wait_for_http_fixture_url(&client, &discovery_url, &mut idp_server);

    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server with OIDC discovery RS256",
        |listen| {
            spawn_http_server_with_oidc_discovery_and_identity_federation(
                &dir,
                listen,
                &discovery_url,
                None,
                audience,
                admin_token,
                Some(&federation_seed_path),
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");
    let token = sign_jwt_rs256(
        &rsa_private_key,
        &json!({
            "iss": issuer,
            "sub": "rsa-user",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
        "rsa-key-1",
    );
    let (session_id, _) = initialize_session(&client, &base_url, &token);
    let trust: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_id)
        .json()
        .expect("session trust json");
    assert_eq!(
        trust["authContext"]["method"]["principal"].as_str(),
        Some(format!("oidc:{issuer}#sub:rsa-user").as_str())
    );
}

#[test]
fn mcp_serve_http_oidc_discovery_verifies_es256_tokens() {
    skip_when_loopback_denied!(mcp_serve_http_oidc_discovery_verifies_es256_tokens);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let idp_listen = reserve_listen_addr();
    let signing_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let x = encoded.x().expect("p256 x coordinate");
    let y = encoded.y().expect("p256 y coordinate");
    let (idp_root, issuer, discovery_url) = write_oidc_discovery_fixture_with_jwks(
        &dir,
        idp_listen,
        "ec",
        json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "kid": "ec-key-1",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
            }]
        }),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut idp_server = spawn_static_http_fixture_server(&idp_root, idp_listen);
    wait_for_http_fixture_url(&client, &discovery_url, &mut idp_server);

    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server with OIDC discovery ES256",
        |listen| {
            spawn_http_server_with_oidc_discovery_and_identity_federation(
                &dir,
                listen,
                &discovery_url,
                None,
                audience,
                admin_token,
                Some(&federation_seed_path),
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");
    let token = sign_jwt_es256(
        &signing_key,
        &json!({
            "iss": issuer,
            "sub": "ec-user",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
        "ec-key-1",
    );
    let (session_id, _) = initialize_session(&client, &base_url, &token);
    let trust: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_id)
        .json()
        .expect("session trust json");
    assert_eq!(
        trust["authContext"]["method"]["principal"].as_str(),
        Some(format!("oidc:{issuer}#sub:ec-user").as_str())
    );
}

#[test]
fn mcp_serve_http_token_introspection_verifies_opaque_tokens_and_derives_stable_subjects() {
    skip_when_loopback_denied!(
        mcp_serve_http_token_introspection_verifies_opaque_tokens_and_derives_stable_subjects
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let introspection_listen = reserve_listen_addr();
    let introspection_script = write_introspection_server_script(&dir);
    let introspection_responses_path = dir.join("introspection-responses.json");
    let issuer = "https://issuer.example/introspection";
    let audience = "chio-mcp";
    let token_a = "opaque-token-a";
    let token_b = "opaque-token-b";
    fs::write(
        &introspection_responses_path,
        serde_json::to_vec_pretty(&json!({
            token_a: {
                "active": true,
                "token_type": "Bearer",
                "iss": issuer,
                "sub": "opaque-user",
                "aud": audience,
                "scope": "mcp:invoke tools.read",
                "client_id": "confidential-client",
                "tid": "tenant-opaque",
                "org_id": "org-opaque",
                "groups": ["eng", "ops"],
                "roles": ["operator"],
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_secs()
                    + 300,
            },
            token_b: {
                "active": true,
                "token_type": "Bearer",
                "iss": issuer,
                "sub": "opaque-user",
                "aud": audience,
                "scope": "mcp:invoke tools.read",
                "client_id": "confidential-client",
                "tid": "tenant-opaque",
                "org_id": "org-opaque",
                "groups": ["eng", "ops"],
                "roles": ["operator"],
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time after epoch")
                    .as_secs()
                    + 600,
            }
        }))
        .expect("serialize introspection responses"),
    )
    .expect("write introspection responses");
    let client_id = "chio-edge";
    let client_secret = "top-secret";
    let expected_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{client_id}:{client_secret}"))
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut introspection_server = spawn_introspection_server(
        &introspection_script,
        introspection_listen,
        &introspection_responses_path,
        Some(&expected_auth),
    );
    wait_for_http_fixture_url(
        &client,
        &format!("http://{}/health", introspection_listen),
        &mut introspection_server,
    );

    let admin_token = "admin-secret";
    let federation_seed_path = dir.join("identity-federation.seed");
    let introspection_url = format!("http://{}/introspect", introspection_listen);
    let (listen, _server) = spawn_with_bind_retry(
        &client,
        "remote MCP server with token introspection",
        |listen| {
            spawn_http_server_with_token_introspection_and_identity_federation(
                &dir,
                listen,
                &introspection_url,
                client_id,
                client_secret,
                issuer,
                audience,
                admin_token,
                Some(&federation_seed_path),
            )
        },
        wait_for_server_result,
    );
    let base_url = format!("http://{listen}");

    let (session_a, _) = initialize_session(&client, &base_url, token_a);
    let (session_b, _) = initialize_session(&client, &base_url, token_b);

    let trust_a: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_a)
        .json()
        .expect("session A trust json");
    let trust_b: Value = get_admin_session_trust(&client, &base_url, admin_token, &session_b)
        .json()
        .expect("session B trust json");

    let subject_a = trust_a["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session A subject key")
        .to_string();
    let subject_b = trust_b["capabilities"][0]["subjectPublicKey"]
        .as_str()
        .expect("session B subject key")
        .to_string();
    assert_eq!(subject_a, subject_b);
    assert_eq!(
        trust_a["authContext"]["method"]["principal"].as_str(),
        Some(format!("oidc:{issuer}#sub:opaque-user").as_str())
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["principal"].as_str(),
        Some(format!("oidc:{issuer}#sub:opaque-user").as_str())
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["providerKind"].as_str(),
        Some("oauth_introspection")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["enterpriseIdentity"]["attributeSources"]["principal"]
            .as_str(),
        Some("sub")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["clientId"].as_str(),
        Some("confidential-client")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["tenantId"].as_str(),
        Some("tenant-opaque")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["organizationId"].as_str(),
        Some("org-opaque")
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["groups"],
        json!(["eng", "ops"])
    );
    assert_eq!(
        trust_a["authContext"]["method"]["federatedClaims"]["roles"],
        json!(["operator"])
    );
}

#[test]
fn mcp_serve_http_rejects_session_reuse_when_authenticated_principal_changes() {
    skip_when_loopback_denied!(
        mcp_serve_http_rejects_session_reuse_when_authenticated_principal_changes
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let token_a = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let (session_id, protocol_version) = initialize_session(&client, &base_url, &token_a);

    let token_b = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-456",
            "aud": audience,
            "scope": "mcp:invoke tools.read",
            "client_id": "client-other",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 600,
        }),
    );
    let response = post_json(
        &client,
        &base_url,
        &token_b,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

#[test]
fn mcp_serve_http_rejects_jwt_with_wrong_audience() {
    skip_when_loopback_denied!(mcp_serve_http_rejects_jwt_with_wrong_audience);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let issuer = "https://issuer.example";
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        issuer,
        audience,
        admin_token,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let wrong_audience_token = sign_jwt(
        &jwt_signing_key,
        &json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": "wrong-audience",
            "scope": "mcp:invoke tools.read",
            "client_id": "client-abc",
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time after epoch")
                .as_secs()
                + 300,
        }),
    );
    let response = post_raw(
        &client,
        &base_url,
        Some(&wrong_audience_token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get("WWW-Authenticate")
        .expect("www-authenticate header")
        .to_str()
        .expect("www-authenticate string");
    assert!(challenge.contains("resource_metadata="));
    assert!(challenge.contains("scope=\"mcp:invoke\""));

    let metadata = get_protected_resource_metadata(&client, &base_url);
    assert_eq!(metadata.status(), reqwest::StatusCode::OK);
    let metadata: Value = metadata.json().expect("metadata json");
    assert_eq!(metadata["resource"].as_str(), Some(audience));
    assert_eq!(metadata["authorization_servers"][0].as_str(), Some(issuer));
    assert!(metadata["scopes_supported"]
        .as_array()
        .expect("scopes array")
        .iter()
        .any(|scope| scope.as_str() == Some("mcp:invoke")));
    assert_eq!(
        metadata["chio_authorization_profile"]["senderConstraints"]["proofTypesSupported"][0]
            .as_str(),
        Some("chio_dpop_v1")
    );
}

#[test]
fn mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer() {
    skip_when_loopback_denied!(
        mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let issuer = format!("{base_url}/oauth");
    let audience = "chio-mcp";
    let admin_token = "admin-secret";
    let authorization_endpoint = "https://auth.example.com/oauth2/authorize";
    let token_endpoint = "https://auth.example.com/oauth2/token";
    let jwt_signing_key = Keypair::generate();
    let _server = spawn_http_server_with_jwt_auth_and_local_discovery(
        &dir,
        listen,
        &jwt_signing_key.public_key().to_hex(),
        &issuer,
        audience,
        admin_token,
        authorization_endpoint,
        token_endpoint,
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    wait_for_server(&client, &base_url);

    let protected = get_protected_resource_metadata(&client, &base_url);
    assert_eq!(protected.status(), reqwest::StatusCode::OK);
    let protected: Value = protected.json().expect("protected metadata json");
    assert_eq!(
        protected["authorization_servers"][0].as_str(),
        Some(issuer.as_str())
    );
    assert_eq!(
        protected["chio_authorization_profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );

    let auth_metadata = get_oauth_authorization_server_metadata(&client, &base_url, "/oauth");
    assert_eq!(auth_metadata.status(), reqwest::StatusCode::OK);
    let auth_metadata: Value = auth_metadata.json().expect("auth metadata json");
    assert_eq!(auth_metadata["issuer"].as_str(), Some(issuer.as_str()));
    assert_eq!(
        auth_metadata["authorization_endpoint"].as_str(),
        Some(authorization_endpoint)
    );
    assert_eq!(
        auth_metadata["token_endpoint"].as_str(),
        Some(token_endpoint)
    );
    assert!(auth_metadata["response_types_supported"]
        .as_array()
        .expect("response types")
        .iter()
        .any(|value| value.as_str() == Some("code")));
    assert!(auth_metadata["code_challenge_methods_supported"]
        .as_array()
        .expect("code challenge methods")
        .iter()
        .any(|value| value.as_str() == Some("S256")));
    assert!(auth_metadata["scopes_supported"]
        .as_array()
        .expect("scopes supported")
        .iter()
        .any(|value| value.as_str() == Some("mcp:invoke")));
    assert_eq!(
        auth_metadata["chio_authorization_profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );
    assert_eq!(
        auth_metadata["chio_authorization_profile"]["senderConstraints"]["proofTypesSupported"][0]
            .as_str(),
        Some("chio_dpop_v1")
    );
}

#[test]
fn mcp_serve_http_requires_both_accept_types_and_json_content_type() {
    skip_when_loopback_denied!(mcp_serve_http_requires_both_accept_types_and_json_content_type);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "integration-test",
                "version": "0.1.0"
            }
        }
    });

    let bad_accept = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json",
        "application/json",
        &init_body,
    );
    assert_eq!(bad_accept.status(), reqwest::StatusCode::NOT_ACCEPTABLE);

    let bad_content_type = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "text/plain",
        &init_body,
    );
    assert_eq!(
        bad_content_type.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[test]
fn mcp_serve_http_sets_explicit_response_mode_headers() {
    skip_when_loopback_denied!(mcp_serve_http_sets_explicit_response_mode_headers);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let initialize = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    assert_eq!(
        initialize
            .headers()
            .get("x-chio-mcp-response-mode")
            .and_then(|value| value.to_str().ok()),
        Some("initialize_sse")
    );
    let session_id = initialize
        .headers()
        .get("MCP-Session-Id")
        .expect("session id header")
        .to_str()
        .expect("session id string")
        .to_string();
    let (initialize, init_messages) = read_sse_until_response(initialize, json!(1), |_| {});
    assert!(init_messages.is_empty());
    let protocol_version = initialize["result"]["protocolVersion"]
        .as_str()
        .expect("protocol version")
        .to_string();

    let initialized = post_notification(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    assert_eq!(
        initialized
            .headers()
            .get("x-chio-mcp-response-mode")
            .and_then(|value| value.to_str().ok()),
        Some("post_notification_accepted")
    );
    assert_eq!(initialized.status(), reqwest::StatusCode::ACCEPTED);

    let tools_list = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(
        tools_list
            .headers()
            .get("x-chio-mcp-response-mode")
            .and_then(|value| value.to_str().ok()),
        Some("post_request_sse")
    );
    let (tools_list, notifications) = read_sse_until_response(tools_list, json!(2), |_| {});
    assert!(notifications.is_empty());
    assert!(tools_list["result"]["tools"].is_array());

    let get_stream = get_session_stream(
        &client,
        &base_url,
        token,
        &session_id,
        Some(&protocol_version),
        None,
    );
    assert_eq!(
        get_stream
            .headers()
            .get("x-chio-mcp-response-mode")
            .and_then(|value| value.to_str().ok()),
        Some("get_sse_live")
    );
    assert_eq!(get_stream.status(), reqwest::StatusCode::OK);
}

#[test]
fn mcp_serve_http_rejects_initialize_with_session_header_without_issuing_session() {
    skip_when_loopback_denied!(
        mcp_serve_http_rejects_initialize_with_session_header_without_issuing_session
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_raw(
        &client,
        &base_url,
        Some(token),
        Some("bogus-session"),
        "application/json, text/event-stream",
        "application/json",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.headers().get("MCP-Session-Id").is_none());
}

#[test]
fn mcp_serve_http_rejects_initialize_without_request_id() {
    skip_when_loopback_denied!(mcp_serve_http_rejects_initialize_without_request_id);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.headers().get("MCP-Session-Id").is_none());
}

#[test]
fn mcp_serve_http_rejects_malformed_jsonrpc_body() {
    skip_when_loopback_denied!(mcp_serve_http_rejects_malformed_jsonrpc_body);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_bytes(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "application/json",
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25""#,
    );
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().expect("parse malformed request response");
    assert_eq!(body["error"]["code"], -32700);
    assert!(body["error"]["message"]
        .as_str()
        .expect("parse error message")
        .contains("invalid JSON"));
}
