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
    IntrospectionBearerVerifier {
        clock: RemoteClock::default(),
        client: client_builder_with_contract(&HttpEgressContract::permissive_for_tests(
            "127.0.0.1:9",
        ))
        .build()
        .expect("build http client"),
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
        egress_contract: None,
    }
}

#[test]
fn jwt_bearer_verifier_builds_oauth_session_auth_context() {
    let keypair = Keypair::generate();
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
        clock: RemoteClock::default(),
        key_source: JwtVerificationKeySource::Static(keypair.public_key()),
        issuer: Some("https://issuer.example".to_string()),
        audience: Some("chio-mcp".to_string()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
    };

    let auth_context = verifier
        .authenticate_token(
            &token,
            &empty_header_map(),
            Some("http://localhost:3000".to_string()),
            None,
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
        clock: RemoteClock::default(),
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
    };

    let auth_context = verifier
        .authenticate_token(
            &token,
            &empty_header_map(),
            Some("http://localhost:3000".to_string()),
            None,
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
        clock: RemoteClock::default(),
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
    };

    let auth_context = verifier
        .authenticate_token(&token, &empty_header_map(), None, None)
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
        clock: RemoteClock::default(),
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
    };

    let auth_context = verifier
        .authenticate_token(&token, &empty_header_map(), None, None)
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
        clock: RemoteClock::default(),
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
    };

    let auth_context = verifier
        .authenticate_token(&token, &empty_header_map(), None, None)
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
            headers: (&empty_header_map()).into(),
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
            headers: (&empty_header_map()).into(),
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
    let signature = keypair.sign_exempt(chio_core::crypto::ExemptFormat::JwsSigningInput, signing_input.as_bytes()).to_bytes();
    let signature = URL_SAFE_NO_PAD.encode(signature);
    format!("{signing_input}.{signature}")
}

fn inbound_sender_verifier(key: &Keypair) -> JwtBearerVerifier {
    JwtBearerVerifier {
        clock: RemoteClock::default(),
        key_source: JwtVerificationKeySource::Static(key.public_key()),
        issuer: Some("https://issuer.example".into()),
        audience: Some("chio-mcp".into()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
    }
}

#[test]
fn inbound_authority_jwt_rejects_weak_key_forgery() {
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    let key = PublicKey::from_bytes(&identity).unwrap();
    let mut signature = [0_u8; 64];
    signature[0] = 1;
    let token = sign_jwt_with_header(
        json!({"alg": "EdDSA", "typ": "JWT"}),
        &json!({"iss": "https://issuer.example", "aud": "chio-mcp",
            "sub": "forged-subject", "exp": unix_now() + 300}),
        |_| signature.to_vec(),
    );
    let signed_input = token.rsplit_once('.').unwrap().0.as_bytes();
    assert!(chio_core::crypto::verify_exempt(
        &key,
        chio_core::crypto::ExemptFormat::JwsSigningInput,
        signed_input,
        &Ed25519Signature::from_bytes(&signature)
    )
    .is_ok());
    for key_source in [
        JwtVerificationKeySource::Static(key.clone()),
        JwtVerificationKeySource::Jwks(JwtJwksKeySet {
            keys_by_kid: Default::default(),
            anonymous_keys: vec![JwtResolvedJwkPublicKey {
                alg_hint: Some("EdDSA".into()),
                key: JwtResolvedPublicKey::Ed25519(key.clone()),
            }],
        }),
    ] {
        let mut verifier = inbound_sender_verifier(&Keypair::generate());
        verifier.key_source = key_source;
        assert!(verifier
            .authenticate_token(&token, &empty_header_map(), None, None)
            .is_err());
    }
}

#[test]
fn inbound_authority_jwt_unknown_empty_or_null_confirmation_never_becomes_bearer() {
    let key = Keypair::generate();
    let verifier = inbound_sender_verifier(&key);
    let outcomes = [json!({"jkt":"unverified-thumbprint"}), json!({"unknown":"ignored"}),
        json!({}), Value::Null, json!({"chioSenderKey":null}), json!({"x5t#S256":""})]
        .into_iter().map(|cnf| {
            let token = sign_jwt(&key, &json!({"iss":"https://issuer.example", "aud":"chio-mcp", "sub":"sender", "exp":unix_now()+300, "cnf":cnf}));
            match verifier.authenticate_token(&token, &HeaderMap::new(), None, None) {
                Ok(_) => StatusCode::OK,
                Err(response) => response.status(),
            }
        }).collect::<Vec<_>>();
    assert_eq!(outcomes, vec![StatusCode::UNAUTHORIZED; 6]);
}

#[test]
fn inbound_authority_jwt_caller_headers_cannot_claim_transport_identity() {
    let key = Keypair::generate();
    let verifier = inbound_sender_verifier(&key);
    let thumbprint = "a".repeat(64);
    let token = sign_jwt(
        &key,
        &json!({"iss":"https://issuer.example", "aud":"chio-mcp", "sub":"sender", "exp":unix_now()+300, "cnf":{"x5t#S256":thumbprint}}),
    );
    let headers = HeaderMap::from_iter([
        (
            HeaderName::from_static(CHIO_MTLS_THUMBPRINT_HEADER),
            HeaderValue::from_str(&thumbprint).unwrap(),
        ),
        (
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("127.0.0.1"),
        ),
    ]);
    let result = verifier.authenticate_token(&token, &headers, None, None);
    let status = match result {
        Ok(_) => StatusCode::OK,
        Err(response) => response.status(),
    };
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[test]
fn inbound_authority_dpop_bound_jwt_is_refused_and_never_a_bearer() {
    let issuer = Keypair::generate();
    let sender = Keypair::generate();
    let verifier = inbound_sender_verifier(&issuer);
    let now = verifier.clock.seconds().unwrap();
    let token = sign_jwt(
        &issuer,
        &json!({"iss":"https://issuer.example","aud":"chio-mcp","sub":"sender","exp":now+300,"jti":"subject-bootstrap","cnf":{"chioSenderKey":sender.public_key().to_hex()}}),
    );
    let presented = HeaderMap::from_iter([(
        HeaderName::from_static(DPOP_HEADER),
        HeaderValue::from_static("presented-proof"),
    )]);
    for headers in [HeaderMap::new(), presented] {
        let response = verifier
            .authenticate_token(&token, &headers, None, None)
            .expect_err("a DPoP-bound token has no usable proof path");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let cause = response
            .extensions()
            .get::<Arc<SenderConstraintError>>()
            .expect("typed sender refusal");
        assert!(matches!(
            cause.as_ref(),
            SenderConstraintError::DpopUnavailable
        ));
        assert_eq!(
            cause.to_string(),
            "urn:chio:error:transport:dpop-sender-proof-unavailable"
        );
    }
}

#[test]
fn inbound_authority_plain_bearer_presenting_dpop_is_refused() {
    let issuer = Keypair::generate();
    let verifier = inbound_sender_verifier(&issuer);
    let now = verifier.clock.seconds().unwrap();
    let token = sign_jwt(
        &issuer,
        &json!({"iss":"https://issuer.example","aud":"chio-mcp","sub":"sender","exp":now+300}),
    );
    let headers = HeaderMap::from_iter([(
        HeaderName::from_static(DPOP_HEADER),
        HeaderValue::from_static("presented-proof"),
    )]);
    let response = verifier
        .authenticate_token(&token, &headers, None, None)
        .expect_err("a presented Chio DPoP proof is refused");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(matches!(
        response
            .extensions()
            .get::<Arc<SenderConstraintError>>()
            .map(AsRef::as_ref),
        Some(SenderConstraintError::DpopUnavailable)
    ));
}

async fn refusal(result: Result<SessionAuthContext, Response>) -> (StatusCode, String) {
    let response = result.expect_err("bearer token must be refused");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("read refusal body");
    (
        status,
        String::from_utf8(body.to_vec()).expect("utf-8 refusal body"),
    )
}

fn introspection_claims(iss: Option<&str>, exp: Option<u64>) -> JwtClaims {
    JwtClaims {
        iss: iss.map(ToOwned::to_owned),
        sub: Some("opaque-user".to_string()),
        aud: Some(JwtAudience::Single("chio-mcp".to_string())),
        scope: None,
        scp: vec![],
        client_id: None,
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
        exp,
        nbf: None,
    }
}

fn introspect(
    verifier: &IntrospectionBearerVerifier,
    claims: JwtClaims,
) -> Result<SessionAuthContext, Response> {
    verifier.session_auth_context_from_introspection(super::IntrospectionSessionAuthInput {
        token: "opaque-token",
        headers: (&empty_header_map()).into(),
        introspection: OAuthIntrospectionResponse {
            active: true,
            token_type: Some("Bearer".to_string()),
            claims,
        },
        origin: None,
        protected_resource_metadata: None,
    })
}

#[tokio::test]
async fn jwt_bearer_verifier_rejects_token_without_exp() {
    let key = Keypair::generate();
    let verifier = inbound_sender_verifier(&key);
    let now = verifier.clock.seconds().expect("clock");
    let token = sign_jwt(
        &key,
        &json!({"iss": "https://issuer.example", "aud": "chio-mcp", "sub": "user", "iat": now}),
    );
    assert_eq!(
        refusal(verifier.authenticate_token(&token, &empty_header_map(), None, None)).await,
        (
            StatusCode::UNAUTHORIZED,
            "JWT bearer token has no exp".to_string()
        )
    );
}

#[tokio::test]
async fn introspection_bearer_verifier_rejects_token_without_exp() {
    let verifier =
        test_introspection_verifier(Some("https://issuer.example"), Some("chio-mcp"), &[]);
    let now = verifier.clock.seconds().expect("clock");
    assert!(introspect(
        &verifier,
        introspection_claims(Some("https://issuer.example"), Some(now + 300))
    )
    .is_ok());
    assert_eq!(
        refusal(introspect(
            &verifier,
            introspection_claims(Some("https://issuer.example"), None)
        ))
        .await,
        (
            StatusCode::UNAUTHORIZED,
            "bearer token has no exp".to_string()
        )
    );
}

#[tokio::test]
async fn jwt_bearer_verifier_rejects_issuer_mismatch() {
    let key = Keypair::generate();
    let verifier = inbound_sender_verifier(&key);
    let exp = verifier.clock.seconds().expect("clock") + 300;
    for claims in [
        json!({"iss": "https://other.example", "aud": "chio-mcp", "sub": "user", "exp": exp}),
        json!({"iss": "https://issuer.example/", "aud": "chio-mcp", "sub": "user", "exp": exp}),
        json!({"aud": "chio-mcp", "sub": "user", "exp": exp}),
    ] {
        let token = sign_jwt(&key, &claims);
        assert_eq!(
            refusal(verifier.authenticate_token(&token, &empty_header_map(), None, None)).await,
            (
                StatusCode::UNAUTHORIZED,
                "JWT bearer issuer mismatch".to_string()
            )
        );
    }
}

#[tokio::test]
async fn introspection_bearer_verifier_rejects_missing_or_mismatched_issuer() {
    let verifier =
        test_introspection_verifier(Some("https://issuer.example"), Some("chio-mcp"), &[]);
    let exp = verifier.clock.seconds().expect("clock") + 300;
    for iss in [
        None,
        Some("https://other.example"),
        Some("https://issuer.example/"),
    ] {
        assert_eq!(
            refusal(introspect(&verifier, introspection_claims(iss, Some(exp)))).await,
            (
                StatusCode::UNAUTHORIZED,
                "bearer token issuer mismatch".to_string()
            )
        );
    }
}

#[test]
fn local_authorization_server_rejects_subject_token_without_exp() {
    let server = test_local_authorization_server();
    let subject_token = sign_jwt(
        &server.signing_key,
        &json!({"iss": server.issuer, "aud": server.default_audience, "sub": "operator",
            "scope": "mcp:invoke", "client_id": "client-abc"}),
    );
    let form: TokenRequestForm = serde_json::from_value(json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
    }))
    .expect("token exchange form");
    let response = server
        .exchange_subject_token((&empty_header_map()).into(), form)
        .expect_err("subject token without exp must be refused");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let cause = response
        .extensions()
        .get::<Arc<OAuthRejection>>()
        .expect("local OAuth cause");
    assert_eq!(cause.kind, OAuthError::InvalidGrant);
    assert_eq!(cause.local_detail(), "subject token has no exp");
}

const TEST_RESOURCE_METADATA_URL: &str =
    "https://edge.example/.well-known/oauth-protected-resource/mcp";

fn test_protected_resource_metadata() -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: "chio-mcp".to_string(),
        resource_metadata_url: TEST_RESOURCE_METADATA_URL.to_string(),
        authorization_servers: vec!["https://issuer.example".to_string()],
        scopes_supported: vec!["mcp:invoke".to_string()],
        chio_authorization_profile: Value::Null,
    }
}

async fn challenge(result: Result<SessionAuthContext, Response>) -> (StatusCode, String, String) {
    let response = result.expect_err("bearer token must be refused");
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .expect("www-authenticate header")
        .to_str()
        .expect("challenge string")
        .to_string();
    let (status, body) = refusal(Err(response)).await;
    (status, challenge, body)
}

#[tokio::test]
async fn invalid_token_challenge_carries_error_invalid_token() {
    let metadata = test_protected_resource_metadata();
    let key = Keypair::generate();
    let verifier = inbound_sender_verifier(&key);
    let exp = verifier.clock.seconds().expect("clock") + 300;
    let token = sign_jwt(
        &key,
        &json!({"iss": "https://issuer.example", "aud": "other", "sub": "user", "exp": exp}),
    );
    assert_eq!(
        challenge(verifier.authenticate_token(
            &token,
            &empty_header_map(),
            None,
            Some(&metadata)))
        .await,
        (
            StatusCode::UNAUTHORIZED,
            format!(
                "Bearer error=\"invalid_token\", resource_metadata=\"{TEST_RESOURCE_METADATA_URL}\", scope=\"mcp:invoke\""
            ),
            "JWT bearer audience mismatch".to_string(),
        )
    );
    assert_eq!(
        challenge(
            extract_bearer_token(&empty_header_map(), Some(&metadata)).map(|_| unreachable!())
        )
        .await,
        (
            StatusCode::UNAUTHORIZED,
            format!(
                "Bearer resource_metadata=\"{TEST_RESOURCE_METADATA_URL}\", scope=\"mcp:invoke\""
            ),
            "missing bearer token".to_string(),
        )
    );
}

#[tokio::test]
async fn missing_required_scope_answers_403_insufficient_scope_challenge() {
    let metadata = test_protected_resource_metadata();
    let key = Keypair::generate();
    let mut verifier = inbound_sender_verifier(&key);
    verifier.required_scopes = vec!["mcp:invoke".to_string()];
    let exp = verifier.clock.seconds().expect("clock") + 300;
    let token = sign_jwt(
        &key,
        &json!({"iss": "https://issuer.example", "aud": "chio-mcp", "sub": "user",
            "scope": "tools.read", "exp": exp}),
    );
    let expected_challenge = format!(
        "Bearer error=\"insufficient_scope\", scope=\"mcp:invoke\", resource_metadata=\"{TEST_RESOURCE_METADATA_URL}\""
    );
    assert_eq!(
        challenge(verifier.authenticate_token(&token, &empty_header_map(), None, Some(&metadata)))
            .await,
        (
            StatusCode::FORBIDDEN,
            expected_challenge.clone(),
            "JWT bearer token is missing required scope".to_string(),
        )
    );

    let introspection = test_introspection_verifier(
        Some("https://issuer.example"),
        Some("chio-mcp"),
        &["mcp:invoke"],
    );
    let mut claims = introspection_claims(Some("https://issuer.example"), Some(exp));
    claims.scope = Some("tools.read".to_string());
    let result = introspection.session_auth_context_from_introspection(
        super::IntrospectionSessionAuthInput {
            token: "opaque-token",
            headers: (&empty_header_map()).into(),
            introspection: OAuthIntrospectionResponse {
                active: true,
                token_type: Some("Bearer".to_string()),
                claims,
            },
            origin: None,
            protected_resource_metadata: Some(&metadata),
        },
    );
    assert_eq!(
        challenge(result).await,
        (
            StatusCode::FORBIDDEN,
            expected_challenge,
            "bearer token is missing required scope".to_string(),
        )
    );
}

#[tokio::test]
async fn introspection_bearer_verifier_rejects_audience_mismatch() {
    let verifier =
        test_introspection_verifier(Some("https://issuer.example"), Some("chio-mcp"), &[]);
    let exp = verifier.clock.seconds().expect("clock") + 300;
    let mut other_audience = introspection_claims(Some("https://issuer.example"), Some(exp));
    other_audience.aud = Some(JwtAudience::Single("other-mcp".to_string()));
    let mut no_audience = introspection_claims(Some("https://issuer.example"), Some(exp));
    no_audience.aud = None;
    let mut other_resource = introspection_claims(Some("https://issuer.example"), Some(exp));
    other_resource.aud = None;
    other_resource.resource = Some("other-mcp".to_string());
    for claims in [other_audience, no_audience, other_resource] {
        assert_eq!(
            refusal(introspect(&verifier, claims)).await,
            (
                StatusCode::UNAUTHORIZED,
                "bearer token audience mismatch".to_string()
            )
        );
    }
}
