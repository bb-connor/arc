use super::*;
use chio_core::crypto::Keypair;
use std::error::Error;

const UNAVAILABLE: &str = "urn:chio:error:transport:dpop-sender-proof-unavailable";

fn weak_sender_key() -> PublicKey {
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    PublicKey::from_bytes(&identity).expect("encoded Ed25519 identity point")
}

fn dpop_header(value: &'static [u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        DPOP_HEADER,
        HeaderValue::from_bytes(value).expect("test header bytes"),
    );
    headers
}

fn assert_unavailable(error: SenderConstraintError) {
    assert!(matches!(error, SenderConstraintError::DpopUnavailable));
    assert_eq!(error.to_string(), UNAVAILABLE);
}

#[test]
fn sender_confirmation_rejects_weak_key_decoding() {
    let claims = serde_json::json!({"chioSenderKey": weak_sender_key().to_hex()});
    assert!(serde_json::from_value::<ChioSenderConstraintClaims>(claims).is_err());
}

#[tokio::test]
async fn sender_dpop_public_key_token_request_is_refused() {
    for key in [
        Keypair::generate().public_key().to_hex(),
        weak_sender_key().to_hex(),
    ] {
        let response = build_request_sender_constraint(Some(&key), None, None, None)
            .expect_err("a Chio DPoP sender binding cannot be issued");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let cause = response
            .extensions()
            .get::<Arc<SenderConstraintError>>()
            .expect("typed sender refusal");
        assert_eq!(cause.to_string(), UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("read refusal body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON refusal body");
        assert_eq!(value["error"], "invalid_request");
        assert!(!String::from_utf8_lossy(&body).contains(&key));
    }
}

#[test]
fn dpop_bound_confirmation_is_refused_with_or_without_a_proof() {
    let claims = ChioSenderConstraintClaims {
        chio_sender_key: Some(Keypair::generate().public_key().to_hex()),
        ..Default::default()
    };
    for headers in [HeaderMap::new(), dpop_header(b"presented-proof")] {
        assert_unavailable(
            sender_constraint::validate_sender_constraint(Some(&claims), &headers)
                .expect_err("a DPoP-bound confirmation never degrades to a bearer"),
        );
    }
}

#[test]
fn presented_dpop_proof_is_refused_for_every_confirmation() {
    let mtls = ChioSenderConstraintClaims {
        mtls_thumbprint_sha256: Some("thumbprint".into()),
        ..Default::default()
    };
    for claims in [None, Some(&mtls)] {
        for headers in [
            dpop_header(b"presented-proof"),
            dpop_header(b"private-marker\xff"),
        ] {
            assert_unavailable(
                sender_constraint::validate_sender_constraint(claims, &headers)
                    .expect_err("a presented DPoP proof is refused"),
            );
        }
    }
}

#[test]
fn sender_headers_cannot_claim_transport_bindings() {
    for (header, claims) in [
        (
            CHIO_MTLS_THUMBPRINT_HEADER,
            ChioSenderConstraintClaims {
                mtls_thumbprint_sha256: Some("thumbprint".into()),
                ..Default::default()
            },
        ),
        (
            CHIO_RUNTIME_ATTESTATION_HEADER,
            ChioSenderConstraintClaims {
                chio_attestation_sha256: Some("attestation".into()),
                ..Default::default()
            },
        ),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header,
            HeaderValue::from_bytes(b"private-marker\xff").expect("test header bytes"),
        );
        let error = sender_constraint::validate_sender_constraint(Some(&claims), &headers)
            .expect_err("caller headers are not transport identity");
        assert!(matches!(
            error,
            SenderConstraintError::MtlsBinding | SenderConstraintError::UnsupportedSchema
        ));
        assert!(error.source().is_none());
        assert!(!format!("{error:?} {error}").contains("private-marker"));
    }
}

#[tokio::test]
async fn sender_key_rejection_keeps_decode_source_out_of_the_wire_response() {
    let response = build_request_sender_constraint(Some("private-invalid-key"), None, None, None)
        .expect_err("an undecodable sender key is refused");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("read refusal body");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON refusal body");
    assert_eq!(value["error"], "invalid_request");
    assert!(!String::from_utf8_lossy(&body).contains("private-invalid-key"));
}

fn bearer_with_dpop(token: &str) -> HeaderMap {
    let mut headers = dpop_header(b"presented-proof");
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer header"),
    );
    headers
}

fn assert_unavailable_response(response: Response) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let cause = response
        .extensions()
        .get::<Arc<SenderConstraintError>>()
        .expect("typed sender refusal");
    assert_eq!(cause.to_string(), UNAVAILABLE);
}

#[tokio::test]
async fn static_bearer_presenting_dpop_is_refused() {
    let auth_mode = RemoteAuthMode::StaticBearer {
        token: "static-token".into(),
    };
    let response =
        authenticate_session_request(&bearer_with_dpop("static-token"), &auth_mode, None)
            .await
            .expect_err("a presented DPoP proof never rides a static bearer");
    assert_unavailable_response(response);
    let mut plain = HeaderMap::new();
    plain.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer static-token"),
    );
    assert!(authenticate_session_request(&plain, &auth_mode, None)
        .await
        .is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_credential_presenting_dpop_is_refused_before_lookup(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let mut config = test_remote_config();
    config.policy_path = directory.path().join("policy.yaml");
    std::fs::write(
        &config.policy_path,
        "kernel:\n  allow_ephemeral_receipt_log: true\n  durable_admission_mode: all\n",
    )?;
    config.session_db_path = Some(directory.path().join("sessions.db"));
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(directory.path()));
    config.wrapped_args.clear();
    config.test_transport = Some(Arc::new(TestSessionTransport));
    configure_signed_manifest(&mut config, directory.path());
    let factory = RemoteSessionFactory::new(config.clone())?;
    let state = RemoteAppState {
        sessions: Arc::new(RemoteSessionLedger::new(
            config.clock.clone(),
            config.lifecycle_policy()?,
            None,
            None,
        )?),
        factory: Arc::new(factory),
        auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
            token: "remote-auth-token".into(),
        }),
        enterprise_provider_registry: None,
        admin_token: Some("admin-token".into()),
        protected_resource_metadata: None,
        authorization_server_metadata: None,
        local_auth_server: None,
    };
    let headers = bearer_with_dpop("chio_session_v1_presented");
    let response = remote_mcp_session_credentials::authenticate_request(
        &state,
        SenderRequest::from(&headers),
        "POST",
        MCP_ENDPOINT_PATH,
    )
    .await
    .err()
    .ok_or("a session credential with a DPoP header was admitted")?;
    assert_unavailable_response(response);
    Ok(())
}
