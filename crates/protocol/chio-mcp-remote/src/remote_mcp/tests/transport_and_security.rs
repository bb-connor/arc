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
        let signing_key =
            p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
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
        let signing_key =
            p384::ecdsa::SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
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

    #[test]
    fn build_federated_principal_prefers_subject_over_client_id() {
        let principal = build_federated_principal(
            &JwtClaims {
                iss: Some("https://issuer.example/".to_string()),
                sub: Some("user-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: Some("client-abc".to_string()),
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
            None,
            None,
            JwtProviderProfile::Generic,
        )
        .unwrap();
        assert_eq!(principal, "oidc:https://issuer.example#sub:user-123");
    }

    #[test]
    fn build_federated_principal_azure_ad_prefers_oid_and_appid() {
        let principal = build_federated_principal(
            &JwtClaims {
                iss: Some("https://login.microsoftonline.com/example/v2.0".to_string()),
                sub: Some("subject-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: None,
                jti: None,
                oid: Some("object-456".to_string()),
                azp: None,
                appid: Some("app-789".to_string()),
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
            None,
            None,
            JwtProviderProfile::AzureAd,
        )
        .unwrap();
        assert_eq!(
            principal,
            "oidc:https://login.microsoftonline.com/example/v2.0#oid:object-456"
        );
    }

    #[test]
    fn build_federated_claims_normalizes_enterprise_identity_metadata() {
        let federated_claims = build_federated_claims(
            &JwtClaims {
                iss: Some("https://issuer.example".to_string()),
                sub: Some("user-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: None,
                jti: None,
                oid: Some("object-456".to_string()),
                azp: Some("client-azp".to_string()),
                appid: Some("client-app".to_string()),
                tid: Some("tenant-123".to_string()),
                tenant_id: Some("tenant-fallback".to_string()),
                org_id: Some("org-789".to_string()),
                organization_id: Some("org-fallback".to_string()),
                groups: vec![
                    " ops ".to_string(),
                    "eng".to_string(),
                    "eng".to_string(),
                    "".to_string(),
                ],
                roles: vec![" reviewer ".to_string(), "operator".to_string()],
                resource: None,
                authorization_details: None,
                chio_transaction_context: None,
                cnf: None,
                exp: None,
                nbf: None,
            },
            JwtProviderProfile::AzureAd,
        );
        assert_eq!(federated_claims.client_id.as_deref(), Some("client-azp"));
        assert_eq!(federated_claims.object_id.as_deref(), Some("object-456"));
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
    }

    #[test]
    fn provider_profile_can_derive_standard_oidc_discovery_url_from_issuer() {
        let config = RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_token: None,
            auth_jwt_public_key: Some(Keypair::generate().public_key().to_hex()),
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: Some(JwtProviderProfile::Okta),
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: Some("https://id.example.com/oauth2/default".to_string()),
            auth_jwt_audience: None,
            admin_token: Some("admin-token".to_string()),
            control_url: None,
            control_token: None,
            remote_authority_workload_token: None,
            control_authority_public_key: None,
            control_authority_trusted_public_keys: Vec::new(),
            control_authority_successors: Vec::new(),
            control_authority_key_log_policy_path: None,
            control_authority_key_log_verifier_db_path: None,
            remote_authority_tenant_id: None,
            remote_authority_workload_id: None,
            remote_authority_workload_seed_path: None,
            remote_authority_session_admission_seed_path: None,
            remote_kernel_evidence_seed_path: None,
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec![],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            keyring_config_path: None,
            broker_config_path: None,
            authority_db_path: None,
            budget_db_path: None,
            aggregate_invocation_admission: false,
            admission_operation_db_path: None,
            approval_db_path: None,
            approver_directory_path: None,
            threshold_proposal_authority_public_key: None,
            session_db_path: None,
            resume_hmac_keyring_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            signed_manifest_path: None,
            manifest_public_key: None,
            native_launch_factory: test_native_launch_factory(),
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
            egress_contract: None,
        };

        let discovery_url = resolve_identity_provider_discovery_url(&config)
            .unwrap()
            .expect("discovery url");
        assert_eq!(
            discovery_url.as_str(),
            "https://id.example.com/oauth2/default/.well-known/openid-configuration"
        );
    }

    fn spawn_localhost_json_server(
        body: &'static str,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let bind_ip = ("localhost", 0)
            .to_socket_addrs()
            .expect("resolve localhost")
            .next()
            .map(|addr| addr.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let listener = std::net::TcpListener::bind(std::net::SocketAddr::new(bind_ip, 0))
            .expect("bind localhost test server");
        let addr = listener.local_addr().expect("read local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write JSON response");
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn oidc_fetch_uses_contract_backed_client_for_hostname_url() {
        let (addr, handle) = spawn_localhost_json_server("{\"ok\":true}");
        let url = Url::parse(&format!(
            "http://localhost:{}/.well-known/openid-configuration",
            addr.port()
        ))
        .expect("parse OIDC URL");
        let contract =
            HttpEgressContract::permissive_for_tests(&format!("localhost:{}", addr.port()));

        let json: Value =
            fetch_identity_provider_json(&url, "test OIDC discovery", Some(&contract))
                .await
                .expect("OIDC fetch uses contract-backed reqwest client");

        assert_eq!(json["ok"].as_bool(), Some(true));
        handle.join().expect("join localhost JSON server");
    }

    #[tokio::test]
    async fn oidc_fetch_rejects_special_use_address_contract() {
        let url = Url::parse("http://169.254.169.254/.well-known/openid-configuration")
            .expect("parse link-local OIDC URL");
        let contract = HttpEgressContract {
            tenant_egress_namespace: "chio-mcp-remote-oidc-test".to_string(),
            allowed_schemes: std::collections::BTreeSet::from(["http".to_string()]),
            allowed_authority_set: std::collections::BTreeSet::from(
                ["169.254.169.254".to_string()],
            ),
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 64 * 1024,
        };

        let error =
            fetch_identity_provider_json::<Value>(&url, "test OIDC discovery", Some(&contract))
                .await
                .expect_err("link-local OIDC URL should fail closed");
        let message = error.to_string();
        assert!(
            message.contains("HttpEgressContract") && message.contains("link-local"),
            "unexpected OIDC egress denial: {message}"
        );
    }

    #[test]
    fn identity_federation_derives_stable_keypair_per_principal() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seed_path = std::env::temp_dir().join(format!(
            "chio-identity-federation-seed-{}-{nonce}.seed",
            std::process::id()
        ));

        let first =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-123")
                .unwrap();
        let second =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-123")
                .unwrap();
        let other =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-456")
                .unwrap();

        assert_eq!(first.public_key().to_hex(), second.public_key().to_hex());
        assert_ne!(first.public_key().to_hex(), other.public_key().to_hex());
    }

    #[test]
    fn jwt_remote_auth_requires_separate_admin_token() {
        let config = RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_token: None,
            auth_jwt_public_key: Some(Keypair::generate().public_key().to_hex()),
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: None,
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: None,
            auth_jwt_audience: None,
            admin_token: None,
            control_url: None,
            control_token: None,
            remote_authority_workload_token: None,
            control_authority_public_key: None,
            control_authority_trusted_public_keys: Vec::new(),
            control_authority_successors: Vec::new(),
            control_authority_key_log_policy_path: None,
            control_authority_key_log_verifier_db_path: None,
            remote_authority_tenant_id: None,
            remote_authority_workload_id: None,
            remote_authority_workload_seed_path: None,
            remote_authority_session_admission_seed_path: None,
            remote_kernel_evidence_seed_path: None,
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec![],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            keyring_config_path: None,
            broker_config_path: None,
            authority_db_path: None,
            budget_db_path: None,
            aggregate_invocation_admission: false,
            admission_operation_db_path: None,
            approval_db_path: None,
            approver_directory_path: None,
            threshold_proposal_authority_public_key: None,
            session_db_path: None,
            resume_hmac_keyring_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            signed_manifest_path: None,
            manifest_public_key: None,
            native_launch_factory: test_native_launch_factory(),
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
            egress_contract: None,
        };

        let error = build_remote_auth_state(&config, "127.0.0.1:0".parse().unwrap(), None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--admin-token"));
    }

    #[test]
    fn static_bearer_remote_auth_requires_separate_admin_token() {
        let mut config = test_remote_config();
        config.admin_token = None;

        let error = build_remote_auth_state(
            &config,
            "127.0.0.1:0".parse().unwrap(),
            None,
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("--admin-token"));
    }

    #[test]
    fn static_bearer_remote_auth_rejects_every_shared_privilege_token_pair() {
        for (auth_token, admin_token, control_token, expected) in [
            (
                "shared-token",
                "shared-token",
                "control-token",
                "--admin-token must differ from --auth-token",
            ),
            (
                "auth-token",
                "shared-token",
                "shared-token",
                "--admin-token must differ from --control-token",
            ),
            (
                "shared-token",
                "admin-token",
                "shared-token",
                "--auth-token must differ from --control-token",
            ),
        ] {
            let mut config = test_remote_config();
            config.auth_token = Some(auth_token.to_string());
            config.admin_token = Some(admin_token.to_string());
            config.control_token = Some(control_token.to_string());

            let error = build_remote_auth_state(
                &config,
                "127.0.0.1:0".parse().unwrap(),
                None,
                None,
            )
            .unwrap_err()
            .to_string();

            assert!(error.contains(expected), "unexpected error: {error}");
        }
    }

    #[test]
    fn remote_auth_state_rejects_unusable_static_bearer_tokens() {
        for (field, value) in [
            ("--auth-token", ""),
            ("--auth-token", " remote-auth-token"),
            ("--auth-token", "remote-auth-token\n"),
            ("--admin-token", ""),
            ("--admin-token", " admin-token"),
            ("--admin-token", "admin-token\r"),
        ] {
            let mut config = test_remote_config();
            match field {
                "--auth-token" => config.auth_token = Some(value.to_string()),
                "--admin-token" => config.admin_token = Some(value.to_string()),
                other => panic!("unexpected field {other}"),
            }

            let error =
                build_remote_auth_state(&config, "127.0.0.1:0".parse().unwrap(), None, None)
                    .unwrap_err()
                    .to_string();

            assert!(error.contains(field), "error should name {field}: {error}");
            assert!(
                error.contains("must be non-empty, unpadded, and control-free"),
                "error should describe usable bearer requirements: {error}"
            );
        }
    }

    #[test]
    fn shared_upstream_notification_fanout_copies_notifications_and_prunes_dead_queues() {
        let subscribers = Arc::new(StdMutex::new(Vec::new()));
        let stats = SharedUpstreamNotificationStats::default();
        let queue_a = Arc::new(StdMutex::new(VecDeque::new()));
        let queue_b = Arc::new(StdMutex::new(VecDeque::new()));
        let dropped_queue = Arc::new(StdMutex::new(VecDeque::new()));
        if let Ok(mut guard) = subscribers.lock() {
            guard.push(Arc::downgrade(&queue_a));
            guard.push(Arc::downgrade(&queue_b));
            guard.push(Arc::downgrade(&dropped_queue));
        }
        drop(dropped_queue);

        fan_out_shared_upstream_notifications(
            &subscribers,
            &stats,
            vec![
                json!({"jsonrpc": "2.0", "method": "notifications/resources/list_changed"}),
                json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
            ],
        );

        let queue_a = queue_a.lock().unwrap();
        let queue_b = queue_b.lock().unwrap();
        assert_eq!(queue_a.len(), 2);
        assert_eq!(queue_b.len(), 2);
        assert_eq!(
            queue_a[0]["method"].as_str(),
            Some("notifications/resources/list_changed")
        );
        assert_eq!(
            queue_a[1]["method"].as_str(),
            Some("notifications/tools/list_changed")
        );
        assert_eq!(queue_a.as_slices(), queue_b.as_slices());
        drop(queue_a);
        drop(queue_b);

        let subscriber_count = subscribers.lock().unwrap().len();
        assert_eq!(subscriber_count, 2);
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
