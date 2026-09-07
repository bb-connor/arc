use super::*;
use p256::ecdsa::signature::Signer as _;
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::pss::BlindedSigningKey as RsaPssSigningKey;
use rsa::rand_core::OsRng;
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};

fn sign_jwt_with_header(
    header: Value,
    claims: &serde_json::Value,
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize JWT header"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize JWT claims"));
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes()));
    format!("{signing_input}.{signature}")
}

fn sign_jwt_rs256(
    private_key: &rsa::RsaPrivateKey,
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    let signing_key = RsaPkcs1v15SigningKey::<Sha256>::new(private_key.clone());
    sign_jwt_with_header(
        json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| signing_key.sign(message).to_vec(),
    )
}

fn sign_jwt_es256(
    signing_key: &p256::ecdsa::SigningKey,
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    sign_jwt_with_header(
        json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| {
            let signature: p256::ecdsa::Signature = signing_key.sign(message);
            signature.to_bytes().to_vec()
        },
    )
}

fn sign_jwt_ps256(
    private_key: &rsa::RsaPrivateKey,
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    let signing_key = RsaPssSigningKey::<Sha256>::new(private_key.clone());
    sign_jwt_with_header(
        json!({
            "alg": "PS256",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| signing_key.sign_with_rng(&mut OsRng, message).to_vec(),
    )
}

fn sign_jwt_es384(
    signing_key: &p384::ecdsa::SigningKey,
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    sign_jwt_with_header(
        json!({
            "alg": "ES384",
            "typ": "JWT",
            "kid": kid,
        }),
        claims,
        |message| {
            let signature: p384::ecdsa::Signature = signing_key.sign(message);
            signature.to_bytes().to_vec()
        },
    )
}

fn test_introspection_verifier(
    issuer: Option<&str>,
    audience: Option<&str>,
    required_scopes: &[&str],
) -> IntrospectionBearerVerifier {
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    IntrospectionBearerVerifier {
        client: HttpClient::builder().build().expect("build http client"),
        introspection_url: Url::parse("http://127.0.0.1:9/introspect")
            .expect("parse introspection url"),
        client_id: None,
        client_secret: None,
        issuer: issuer.map(ToOwned::to_owned),
        audience: audience.map(ToOwned::to_owned),
        required_scopes: required_scopes
            .iter()
            .map(|scope| (*scope).to_string())
            .collect(),
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store,
        sender_dpop_config,
        egress_contract: None,
    }
}

#[test]
fn jwt_bearer_verifier_builds_oauth_session_auth_context() {
    let keypair = Keypair::generate();
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    let token = sign_jwt(
        &keypair,
        &json!({
            "iss": "https://issuer.example",
            "sub": "user-123",
            "aud": "chio-mcp",
            "scope": "tools.read tools.write",
            "client_id": "client-abc",
            "tid": "tenant-123",
            "org_id": "org-789",
            "groups": ["ops", "eng"],
            "roles": ["reviewer", "operator"],
            "exp": unix_now() + 300,
        }),
    );
    let verifier = JwtBearerVerifier {
        key_source: JwtVerificationKeySource::Static(keypair.public_key()),
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("chio-mcp".to_string()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store,
        sender_dpop_config,
    };

    let auth_context = verifier
        .authenticate_token(
            &token,
            &empty_header_map(),
            Some("http://localhost:3000".to_string()),
            None,
            "POST",
            "chio-mcp",
        )
        .unwrap();
    assert_eq!(auth_context.transport, SessionTransport::StreamableHttp);
    assert_eq!(
        auth_context.origin.as_deref(),
        Some("http://localhost:3000")
    );

    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal,
            issuer,
            subject,
            audience,
            scopes,
            federated_claims,
            enterprise_identity,
            token_fingerprint,
        } => {
            assert_eq!(
                principal.as_deref(),
                Some("oidc:https://issuer.example#sub:user-123")
            );
            assert_eq!(issuer.as_deref(), Some("https://issuer.example"));
            assert_eq!(subject.as_deref(), Some("user-123"));
            assert_eq!(audience.as_deref(), Some("chio-mcp"));
            assert_eq!(
                scopes,
                &vec!["tools.read".to_string(), "tools.write".to_string()]
            );
            assert_eq!(federated_claims.client_id.as_deref(), Some("client-abc"));
            assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
            assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
            assert_eq!(
                federated_claims.groups,
                vec!["eng".to_string(), "ops".to_string()]
            );
            assert_eq!(
                federated_claims.roles,
                vec!["operator".to_string(), "reviewer".to_string()]
            );
            assert_eq!(
                token_fingerprint.as_deref(),
                Some(sha256_hex(token.as_bytes()).as_str())
            );
            let enterprise_identity = enterprise_identity
                .as_ref()
                .expect("enterprise identity should be populated");
            assert_eq!(enterprise_identity.provider_id, "https://issuer.example");
            assert_eq!(enterprise_identity.provider_record_id, None);
            assert_eq!(enterprise_identity.provider_kind, "oidc_jwks");
            assert_eq!(
                enterprise_identity.federation_method,
                EnterpriseFederationMethod::Jwt
            );
            assert_eq!(
                enterprise_identity.principal,
                "oidc:https://issuer.example#sub:user-123"
            );
            assert_eq!(
                enterprise_identity.subject_key,
                derive_enterprise_subject_key(
                    "https://issuer.example",
                    "oidc:https://issuer.example#sub:user-123",
                )
            );
            assert_eq!(enterprise_identity.tenant_id.as_deref(), Some("tenant-123"));
            assert_eq!(
                enterprise_identity.organization_id.as_deref(),
                Some("org-789")
            );
            assert_eq!(
                enterprise_identity.attribute_sources.get("principal"),
                Some(&"sub".to_string())
            );
            assert_eq!(
                enterprise_identity.attribute_sources.get("groups"),
                Some(&"groups".to_string())
            );
            assert_eq!(
                enterprise_identity.attribute_sources.get("roles"),
                Some(&"roles".to_string())
            );
        }
        other => panic!("unexpected auth method: {other:?}"),
    }
}

#[test]
fn jwt_bearer_verifier_authenticates_rs256_jwks_token() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = private_key.to_public_key();
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    let token = sign_jwt_rs256(
        &private_key,
        &json!({
            "iss": "https://issuer.example",
            "sub": "user-rsa",
            "aud": "chio-mcp",
            "scope": "tools.read",
            "exp": unix_now() + 300,
        }),
        "rsa-key-1",
    );
    let verifier = JwtBearerVerifier {
        key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
            keys_by_kid: HashMap::from([(
                "rsa-key-1".to_string(),
                JwtResolvedJwkPublicKey {
                    key: JwtResolvedPublicKey::Rsa(public_key),
                    alg_hint: Some("RS256".to_string()),
                },
            )]),
            anonymous_keys: vec![],
        }),
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("chio-mcp".to_string()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store,
        sender_dpop_config,
    };

    let auth_context = verifier
        .authenticate_token(
            &token,
            &empty_header_map(),
            Some("http://localhost:3000".to_string()),
            None,
            "POST",
            "chio-mcp",
        )
        .unwrap();
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal, subject, ..
        } => {
            assert_eq!(
                principal.as_deref(),
                Some("oidc:https://issuer.example#sub:user-rsa")
            );
            assert_eq!(subject.as_deref(), Some("user-rsa"));
        }
        other => panic!("unexpected auth method: {other:?}"),
    }
}

#[test]
fn jwt_bearer_verifier_authenticates_es256_jwks_token() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    let token = sign_jwt_es256(
        &signing_key,
        &json!({
            "iss": "https://issuer.example",
            "sub": "user-ec",
            "aud": "chio-mcp",
            "scope": "tools.read",
            "exp": unix_now() + 300,
        }),
        "ec-key-1",
    );
    let verifier = JwtBearerVerifier {
        key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
            keys_by_kid: HashMap::from([(
                "ec-key-1".to_string(),
                JwtResolvedJwkPublicKey {
                    key: JwtResolvedPublicKey::P256(*signing_key.verifying_key()),
                    alg_hint: Some("ES256".to_string()),
                },
            )]),
            anonymous_keys: vec![],
        }),
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("chio-mcp".to_string()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store,
        sender_dpop_config,
    };

    let auth_context = verifier
        .authenticate_token(&token, &empty_header_map(), None, None, "POST", "chio-mcp")
        .unwrap();
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal, subject, ..
        } => {
            assert_eq!(
                principal.as_deref(),
                Some("oidc:https://issuer.example#sub:user-ec")
            );
            assert_eq!(subject.as_deref(), Some("user-ec"));
        }
        other => panic!("unexpected auth method: {other:?}"),
    }
}

#[test]
fn jwt_bearer_verifier_authenticates_ps256_jwks_token() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = private_key.to_public_key();
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    let token = sign_jwt_ps256(
        &private_key,
        &json!({
            "iss": "https://issuer.example",
            "sub": "user-pss",
            "aud": "chio-mcp",
            "scope": "tools.read",
            "exp": unix_now() + 300,
        }),
        "pss-key-1",
    );
    let verifier = JwtBearerVerifier {
        key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
            keys_by_kid: HashMap::from([(
                "pss-key-1".to_string(),
                JwtResolvedJwkPublicKey {
                    key: JwtResolvedPublicKey::Rsa(public_key),
                    alg_hint: Some("PS256".to_string()),
                },
            )]),
            anonymous_keys: vec![],
        }),
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("chio-mcp".to_string()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store,
        sender_dpop_config,
    };

    let auth_context = verifier
        .authenticate_token(&token, &empty_header_map(), None, None, "POST", "chio-mcp")
        .unwrap();
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal, subject, ..
        } => {
            assert_eq!(
                principal.as_deref(),
                Some("oidc:https://issuer.example#sub:user-pss")
            );
            assert_eq!(subject.as_deref(), Some("user-pss"));
        }
        other => panic!("unexpected auth method: {other:?}"),
    }
}

#[test]
fn jwt_bearer_verifier_authenticates_es384_jwks_token() {
    let signing_key = p384::ecdsa::SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
    let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
    let token = sign_jwt_es384(
        &signing_key,
        &json!({
            "iss": "https://issuer.example",
            "sub": "user-es384",
            "aud": "chio-mcp",
            "scope": "tools.read",
            "exp": unix_now() + 300,
        }),
        "ec384-key-1",
    );
    let verifier = JwtBearerVerifier {
        key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
            keys_by_kid: HashMap::from([(
                "ec384-key-1".to_string(),
                JwtResolvedJwkPublicKey {
                    key: JwtResolvedPublicKey::P384(*signing_key.verifying_key()),
                    alg_hint: Some("ES384".to_string()),
                },
            )]),
            anonymous_keys: vec![],
        }),
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("chio-mcp".to_string()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store,
        sender_dpop_config,
    };

    let auth_context = verifier
        .authenticate_token(&token, &empty_header_map(), None, None, "POST", "chio-mcp")
        .unwrap();
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal, subject, ..
        } => {
            assert_eq!(
                principal.as_deref(),
                Some("oidc:https://issuer.example#sub:user-es384")
            );
            assert_eq!(subject.as_deref(), Some("user-es384"));
        }
        other => panic!("unexpected auth method: {other:?}"),
    }
}

#[test]
fn introspection_bearer_verifier_accepts_active_token_with_resource_claim() {
    let verifier = test_introspection_verifier(
        Some("https://issuer.example"),
        Some("chio-mcp"),
        &["mcp:invoke"],
    );
    let auth_context = verifier
        .session_auth_context_from_introspection(super::IntrospectionSessionAuthInput {
            token: "opaque-token",
            headers: &empty_header_map(),
            introspection: OAuthIntrospectionResponse {
                active: true,
                token_type: Some("Bearer".to_string()),
                claims: JwtClaims {
                    iss: Some("https://issuer.example".to_string()),
                    sub: Some("opaque-user".to_string()),
                    aud: None,
                    scope: Some("mcp:invoke tools.read".to_string()),
                    scp: vec![],
                    client_id: Some("client-123".to_string()),
                    jti: None,
                    oid: None,
                    azp: None,
                    appid: None,
                    tid: Some("tenant-123".to_string()),
                    tenant_id: None,
                    org_id: Some("org-789".to_string()),
                    organization_id: None,
                    groups: vec!["ops".to_string(), "eng".to_string()],
                    roles: vec!["operator".to_string()],
                    resource: Some("chio-mcp".to_string()),
                    authorization_details: None,
                    chio_transaction_context: None,
                    cnf: None,
                    exp: Some(unix_now() + 300),
                    nbf: None,
                },
            },
            origin: Some("http://localhost:3000".to_string()),
            protected_resource_metadata: None,
            expected_method: "POST",
            expected_target: "chio-mcp",
        })
        .unwrap();
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal,
            issuer,
            subject,
            audience,
            scopes,
            federated_claims,
            enterprise_identity,
            token_fingerprint,
        } => {
            assert_eq!(
                principal.as_deref(),
                Some("oidc:https://issuer.example#sub:opaque-user")
            );
            assert_eq!(issuer.as_deref(), Some("https://issuer.example"));
            assert_eq!(subject.as_deref(), Some("opaque-user"));
            assert_eq!(audience.as_deref(), Some("chio-mcp"));
            assert_eq!(
                scopes,
                &vec!["mcp:invoke".to_string(), "tools.read".to_string()]
            );
            assert_eq!(federated_claims.client_id.as_deref(), Some("client-123"));
            assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
            assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
            assert_eq!(
                federated_claims.groups,
                vec!["eng".to_string(), "ops".to_string()]
            );
            assert_eq!(federated_claims.roles, vec!["operator".to_string()]);
            assert_eq!(
                token_fingerprint.as_deref(),
                Some(sha256_hex(b"opaque-token").as_str())
            );
            let enterprise_identity = enterprise_identity
                .as_ref()
                .expect("enterprise identity should be populated");
            assert_eq!(enterprise_identity.provider_kind, "oauth_introspection");
            assert_eq!(
                enterprise_identity.federation_method,
                EnterpriseFederationMethod::Introspection
            );
            assert_eq!(
                enterprise_identity.subject_key,
                derive_enterprise_subject_key(
                    "https://issuer.example",
                    "oidc:https://issuer.example#sub:opaque-user",
                )
            );
        }
        other => panic!("unexpected auth method: {other:?}"),
    }
}

#[test]
fn introspection_bearer_verifier_rejects_inactive_token() {
    let verifier = test_introspection_verifier(None, None, &[]);
    let error = verifier
        .session_auth_context_from_introspection(super::IntrospectionSessionAuthInput {
            token: "opaque-token",
            headers: &empty_header_map(),
            introspection: OAuthIntrospectionResponse {
                active: false,
                token_type: Some("Bearer".to_string()),
                claims: JwtClaims {
                    iss: None,
                    sub: Some("opaque-user".to_string()),
                    aud: None,
                    scope: None,
                    scp: vec![],
                    client_id: None,
                    jti: None,
                    oid: None,
                    azp: None,
                    appid: None,
                    tid: None,
                    tenant_id: None,
                    org_id: None,
                    organization_id: None,
                    groups: Vec::new(),
                    roles: Vec::new(),
                    resource: None,
                    authorization_details: None,
                    chio_transaction_context: None,
                    cnf: None,
                    exp: None,
                    nbf: None,
                },
            },
            origin: None,
            protected_resource_metadata: None,
            expected_method: "POST",
            expected_target: "chio-mcp",
        })
        .unwrap_err();
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
}

fn sign_jwt(keypair: &Keypair, claims: &serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "JWT"
        }))
        .unwrap(),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header}.{payload}");
    let signature = keypair.sign(signing_input.as_bytes()).to_bytes();
    let signature = URL_SAFE_NO_PAD.encode(signature);
    format!("{signing_input}.{signature}")
}
