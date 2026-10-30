//! Bearer admission reads enterprise provider records from the registry file
//! on each authenticated request through the bounded reader, so an operator
//! mutation governs the next request and an unusable registry refuses it.

use super::*;
use chio_control_plane::enterprise_federation::load_enterprise_provider_registry;

pub(super) const ISSUER: &str = "https://issuer.enterprise.example";

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

fn write_registry_record(path: &std::path::Path, record: serde_json::Value) {
    let registry = json!({
        "version": "chio.enterprise-providers.v1",
        "providers": { "enterprise-login": record }
    });
    std::fs::write(path, serde_json::to_vec(&registry).unwrap()).unwrap();
}

pub(super) fn write_registry(path: &std::path::Path, enabled: bool) {
    write_registry_record(path, provider_record(enabled));
}

/// Writes a registry one byte over the bounded reader's limit.
pub(super) fn write_oversized_registry(path: &std::path::Path) {
    let document = br#"{"version":"chio.enterprise-providers.v1","providers":{}}"#;
    let mut bytes = document.to_vec();
    bytes.resize(16 * 1024 * 1024 + 1, b' ');
    std::fs::write(path, bytes).unwrap();
}

pub(super) fn signed_token(keypair: &Keypair) -> String {
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
    let signature = URL_SAFE_NO_PAD.encode(
        keypair
            .sign_exempt(
                chio_core::crypto::ExemptFormat::JwsSigningInput,
                signing_input.as_bytes(),
            )
            .to_bytes(),
    );
    format!("{signing_input}.{signature}")
}

pub(super) fn jwt_verifier(config: &RemoteServeHttpConfig) -> Arc<JwtBearerVerifier> {
    let registry = enterprise_provider_registry_file(
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

pub(super) fn authenticate(
    verifier: &JwtBearerVerifier,
    token: &str,
) -> Result<SessionAuthContext, Response> {
    verifier.authenticate_token(token, &empty_header_map(), None, None)
}

fn enterprise_identity(auth_context: &SessionAuthContext) -> Option<EnterpriseIdentityContext> {
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            enterprise_identity,
            ..
        } => enterprise_identity.clone(),
        other => panic!("unexpected auth method: {other:?}"),
    }
}

fn provider_record_id(auth_context: &SessionAuthContext) -> Option<String> {
    enterprise_identity(auth_context).and_then(|identity| identity.provider_record_id)
}

/// Asserts a 503 whose body is exactly the refusal message and whose local
/// cause is the refusal itself.
async fn assert_registry_refusal(
    refused: Response,
    expected_message: &str,
) -> Arc<EnterpriseProviderRegistryRefusal> {
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    let refusal = refused
        .extensions()
        .get::<Arc<EnterpriseProviderRegistryRefusal>>()
        .cloned()
        .expect("registry refusal attached as the local cause");
    assert_eq!(refusal.to_string(), expected_message);
    let body = axum::body::to_bytes(refused.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&body), expected_message);
    refusal
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

    fn admitted(&self) -> SessionAuthContext {
        let admitted = authenticate(&self.verifier, &signed_token(&self.keypair)).unwrap();
        assert_eq!(
            provider_record_id(&admitted).as_deref(),
            Some("enterprise-login")
        );
        admitted
    }

    fn next_request(&self) -> Result<SessionAuthContext, Response> {
        authenticate(&self.verifier, &signed_token(&self.keypair))
    }
}

#[test]
fn a_provider_disabled_after_startup_no_longer_admits_its_record() {
    let fixture = Fixture::started_with_enabled_provider();
    let admitted = fixture.admitted();

    write_registry(&fixture.path, false);
    let next = fixture.next_request().unwrap();
    assert_eq!(
        provider_record_id(&next),
        None,
        "a bearer request after the provider was disabled matched the startup record"
    );
    let refused = validate_session_auth_context(&next, &admitted)
        .expect_err("a session admitted under the enabled provider continued after disable");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
}

#[test]
fn subject_mapping_and_trust_material_changes_govern_the_next_request() {
    let fixture = Fixture::started_with_enabled_provider();
    let admitted = fixture.admitted();
    let admitted_identity = enterprise_identity(&admitted).unwrap();
    assert_eq!(
        admitted_identity
            .attribute_sources
            .get("tenantId")
            .map(String::as_str),
        Some("tid")
    );

    let mut record = provider_record(true);
    record["subject_mapping"]["tenant_id_field"] = json!("tenant");
    record["provenance"]["trust_material_ref"] = json!("jwks:rotated");
    write_registry_record(&fixture.path, record);
    let next = fixture.next_request().unwrap();
    let next_identity = enterprise_identity(&next).unwrap();
    assert_eq!(
        next_identity
            .attribute_sources
            .get("tenantId")
            .map(String::as_str),
        Some("tenant")
    );
    assert_eq!(
        next_identity.trust_material_ref.as_deref(),
        Some("jwks:rotated")
    );
    let refused = validate_session_auth_context(&next, &admitted)
        .expect_err("a session continued under a remapped provider record");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_provider_registry_corrupted_after_startup_refuses_the_next_request() {
    let fixture = Fixture::started_with_enabled_provider();
    fixture.admitted();

    std::fs::write(&fixture.path, b"{\"version\":").unwrap();
    let expected_cause = load_enterprise_provider_registry(&fixture.path)
        .expect_err("a truncated registry loaded")
        .to_string();
    let refused = fixture
        .next_request()
        .expect_err("a corrupted provider registry still admitted");
    let refusal = assert_registry_refusal(
        refused,
        "urn:chio:error:transport:provider-registry-invalid",
    )
    .await;
    let EnterpriseProviderRegistryRefusal::Invalid(cause) = refusal.as_ref() else {
        panic!("expected an invalid registry refusal, got {refusal:?}");
    };
    assert_eq!(cause.to_string(), expected_cause);
}

#[tokio::test]
async fn a_provider_registry_oversized_at_request_time_refuses_the_request() {
    let fixture = Fixture::started_with_enabled_provider();
    fixture.admitted();

    write_oversized_registry(&fixture.path);
    let refused = fixture
        .next_request()
        .expect_err("an oversized provider registry still admitted");
    let refusal = assert_registry_refusal(
        refused,
        "urn:chio:error:transport:provider-registry-oversized",
    )
    .await;
    let EnterpriseProviderRegistryRefusal::Oversized(CliError::SignedJson(
        chio_core::canonical::UntrustedJsonError::TooLarge { bytes, bound },
    )) = refusal.as_ref()
    else {
        panic!("expected an oversized registry refusal, got {refusal:?}");
    };
    assert_eq!(*bound, 16 * 1024 * 1024);
    assert_eq!(*bytes, bound + 1);
}

#[tokio::test]
async fn a_provider_registry_unreadable_at_request_time_refuses_the_request() {
    let fixture = Fixture::started_with_enabled_provider();
    fixture.admitted();

    std::fs::remove_file(&fixture.path).unwrap();
    let expected_cause = load_enterprise_provider_registry(&fixture.path)
        .expect_err("a missing registry loaded")
        .to_string();
    let refused = fixture
        .next_request()
        .expect_err("an unreadable provider registry still admitted");
    let refusal = assert_registry_refusal(
        refused,
        "urn:chio:error:transport:provider-registry-unreadable",
    )
    .await;
    let EnterpriseProviderRegistryRefusal::Unreadable(cause) = refusal.as_ref() else {
        panic!("expected an unreadable registry refusal, got {refusal:?}");
    };
    assert_eq!(cause.to_string(), expected_cause);
}

#[test]
fn startup_refuses_an_unreadable_provider_registry_with_its_cause() {
    let directory = chio_test_support::private_tempdir().unwrap();
    let path = directory.path().join("enterprise-providers.json");
    let expected = load_enterprise_provider_registry(&path)
        .expect_err("a missing registry loaded")
        .to_string();
    let error = enterprise_provider_registry_file(Some(&path), "remote_mcp")
        .expect_err("startup accepted a missing provider registry");
    assert_eq!(error.to_string(), expected);
}
