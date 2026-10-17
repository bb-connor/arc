//! Bearer admission matches enterprise provider records from the registry
//! file each authenticated request reads, so an operator mutation governs the
//! next request without a restart.

use super::*;
use chio_control_plane::enterprise_federation::EnterpriseProviderRegistry;

const ISSUER: &str = "https://issuer.enterprise.example";

fn provider_record(enabled: bool) -> serde_json::Value {
    json!({
        "provider_id": "enterprise-login",
        "kind": "oidc_jwks",
        "enabled": enabled,
        "provenance": {
            "configured_from": "manual",
            "source_ref": "operator",
            "trust_material_ref": "jwks:enterprise-login",
            "subject_mapping_source": "manual"
        },
        "trust_boundary": {
            "allowed_issuers": [ISSUER],
            "allowed_tenants": ["tenant-123"],
            "allowed_organizations": ["org-789"]
        },
        "issuer": ISSUER,
        "jwks_url": "https://issuer.enterprise.example/jwks",
        "tenant_id": "tenant-123",
        "organization_id": "org-789",
        "subject_mapping": {
            "principal_source": "sub",
            "tenant_id_field": "tid",
            "organization_id_field": "org_id",
            "groups_field": "groups",
            "roles_field": "roles"
        }
    })
}

fn write_registry(path: &std::path::Path, enabled: bool) {
    let registry = json!({
        "version": "chio.enterprise-providers.v1",
        "providers": { "enterprise-login": provider_record(enabled) }
    });
    std::fs::write(path, serde_json::to_vec(&registry).unwrap()).unwrap();
}

fn signed_token(keypair: &Keypair) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "JWT"
        }))
        .unwrap(),
    );
    let claims = json!({
        "iss": ISSUER,
        "sub": "user-123",
        "aud": "chio-mcp",
        "scope": "mcp:invoke",
        "tid": "tenant-123",
        "org_id": "org-789",
        "exp": unix_now() + 300,
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(keypair.sign(signing_input.as_bytes()).to_bytes());
    format!("{signing_input}.{signature}")
}

fn jwt_verifier(config: &RemoteServeHttpConfig) -> Arc<JwtBearerVerifier> {
    let registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "remote_mcp",
    )
    .unwrap();
    let auth_mode =
        build_remote_auth_mode(config, "127.0.0.1:3000".parse().unwrap(), None, registry).unwrap();
    match auth_mode {
        RemoteAuthMode::JwtBearer { verifier } => verifier,
        other => panic!("unexpected auth mode: {other:?}"),
    }
}

fn authenticate(verifier: &JwtBearerVerifier, token: &str) -> Result<SessionAuthContext, Response> {
    verifier.authenticate_token(token, &empty_header_map(), None, None, "POST", "chio-mcp")
}

fn provider_record_id(auth_context: &SessionAuthContext) -> Option<String> {
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            enterprise_identity,
            ..
        } => enterprise_identity
            .as_ref()
            .and_then(|identity| identity.provider_record_id.clone()),
        other => panic!("unexpected auth method: {other:?}"),
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    keypair: Keypair,
    verifier: Arc<JwtBearerVerifier>,
}

impl Fixture {
    fn started_with_enabled_provider() -> Self {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        write_registry(&path, true);
        let keypair = Keypair::generate();
        let mut config = test_remote_config();
        config.auth_token = None;
        config.auth_jwt_public_key = Some(keypair.public_key().to_hex());
        config.auth_jwt_issuer = Some(ISSUER.to_string());
        config.auth_jwt_audience = Some("chio-mcp".to_string());
        config.enterprise_providers_file = Some(path.clone());
        let verifier = jwt_verifier(&config);
        Self {
            _directory: directory,
            path,
            keypair,
            verifier,
        }
    }
}

#[test]
fn a_provider_disabled_after_startup_no_longer_admits_its_record() {
    let fixture = Fixture::started_with_enabled_provider();
    let token = signed_token(&fixture.keypair);
    let admitted = authenticate(&fixture.verifier, &token).unwrap();
    assert_eq!(
        provider_record_id(&admitted).as_deref(),
        Some("enterprise-login")
    );

    write_registry(&fixture.path, false);
    let next = authenticate(&fixture.verifier, &token).unwrap();
    assert_eq!(
        provider_record_id(&next),
        None,
        "a bearer request after the provider was disabled matched the startup record"
    );
}

#[tokio::test]
async fn a_provider_registry_corrupted_after_startup_refuses_the_next_request() {
    let fixture = Fixture::started_with_enabled_provider();
    let token = signed_token(&fixture.keypair);
    authenticate(&fixture.verifier, &token).unwrap();

    std::fs::write(&fixture.path, b"{\"version\":").unwrap();
    let expected = EnterpriseProviderRegistry::load(&fixture.path)
        .expect_err("a truncated registry loaded")
        .to_string();
    let refused = authenticate(&fixture.verifier, &token)
        .expect_err("a corrupted provider registry still admitted");
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(refused.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&body), expected);
}
